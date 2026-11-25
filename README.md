# vCenter vmdir SRP authentication bypass (PoC)

Proof of concept for an authentication bypass in the SRP implementation of
`vmdird`, the VMware vCenter directory service (observed on vCenter 8.0.3,
build 24322831, LDAP on port 389).

The server's `cyrus-sasl` SRP path only checks `A <= 0` at step 2 of RFC 5054
and never rejects `A == 0 (mod N)`. Sending the public value `A = N` forces:

```
u = H(A | B)
S = (A * v^u)^b mod N = 0        (because A mod N == 0)
K = SHA1(i2b(S)) = SHA1(b"")     <- public constant
```

With `K` known and every other input public, the client proof `M1` can be
forged, so the SASL bind succeeds for **any identity that already exists** in
the directory, without knowing its password. The resulting LDAP session
supports search, add and modify, which is enough to create an SSO
administrator or reset an existing password.

## Requirements

Python 3.8+ only. The PoC uses the standard library exclusively (`socket`,
`ssl`, `hashlib`, `hmac`, `json`, `argparse`), so there is nothing to install.

## Usage

Read-only validation (bind + rootDSE, no writes):

```bash
python3 poc_vcenter.py -t 192.0.2.10 --check
```

Enumerate users and groups with a single broad search:

```bash
python3 poc_vcenter.py -t 192.0.2.10 --enum
```

Create an administrator (three sessions, one client PDU each):

```bash
python3 poc_vcenter.py -t 192.0.2.10 --create-admin \
    --new-user svcbackup --new-pass 'Xyz!2026abc'
```

Add an existing user to the administrative group:

```bash
python3 poc_vcenter.py -t 192.0.2.10 --group-add svcbackup
```

Against a live vmdird use `--mac-in warn`: the server signs its own records
with a MAC convention that the client cannot reproduce past the first record
(see *Limitations*), and `warn` keeps the session usable.

```bash
python3 poc_vcenter.py -t 192.0.2.10 --enum --mac-in warn
```

Capture the binary session traffic and analyse the layer convention offline:

```bash
python3 poc_vcenter.py -t 192.0.2.10 --check --capture cap.jsonl
python3 poc_vcenter.py --analyze cap.jsonl
```

Run the built-in self-test (no network, no target required):

```bash
python3 poc_vcenter.py --self-test
```

## Options

| Option | Meaning |
| --- | --- |
| `-t, --target` | vCenter host name or address |
| `--port` | `389` (cleartext) or `636`; defaults to 636 with `--tls` |
| `--tls` | use LDAPS |
| `--identity` | identity to impersonate (must exist), default `administrator@vsphere.local` |
| `--base` | base DN, default `dc=vsphere,dc=local` |
| `--check` | bind + rootDSE only (read-only) |
| `--enum` | list users and groups |
| `--create-admin` | create a user and place it in Administrators |
| `--new-user`, `--new-pass` | credentials for `--create-admin` / `--reset-pass` |
| `--reset-pass USER` | replace an existing `userPassword` |
| `--group-add USER` | add an existing user to the administrative group |
| `--group-dn` | target group DN, default `cn=Administrators,cn=Builtin,{base}` |
| `--mac` | HMAC convention of the layer: `auto`, `plain`, `cipher` |
| `--seq` | starting record sequence (`0` then `1` by default) |
| `--pad` | force PKCS#7 padding before AES (`0` or `1`) |
| `--ack` | shape of the final csrp ack: `empty`, `m2`, `wrapped`, `wrapped-m2` |
| `--mac-in` | validation of server records: `strict`, `warn`, `off` |
| `--no-seq-auto` | do not auto-adjust the incoming record sequence |
| `--capture`, `--analyze` | record / analyse the binary session traffic |
| `--debug` | hexdump of the LDAP traffic |
| `--self-test` | run the internal test suite |

## How the bind is forged

1. `negotiate_options()` sends the `L` string advertised by the server and
   selects integrity (`HMAC-SHA-1`) plus confidentiality (`AES`).
2. Step 2 sends `A = N`, the forged `M1`, the negotiated options and the client
   IV, wrapped in the SASL layer.
3. The server computes `S = 0`, derives `K = SHA1(b"")` and accepts the forged
   `M1`, answering with a challenge that carries no usable secret.
4. The client installs the layer with the public key, sends the final ack and
   keeps the authenticated LDAP session.

## Post-bypass account creation

The directory rejects `userPrincipalName` in an `add` with
`code=21 constraintViolation`, while the same value is accepted through
`modify`. Account creation is therefore split into three sessions, because
vmdird accepts a single wrapped client PDU per connection:

1. `add` the user with `userPassword` only;
2. `modify` the `userPrincipalName`;
3. `modify` the group membership.

Skipping step 2 leaves an account that exists but cannot log in to the vCenter
panel.

## Limitations observed on vmdird 8.0.3

These are server properties, not defects of the PoC:

- **One wrapped client PDU per session.** From the second PDU on, the MAC the
  server expects is no longer `HMAC(K, ct|u32be(seq))` and the connection is
  dropped. Every action therefore opens a fresh session.
- **Server record MAC.** The MAC on the server's own records verifies for the
  first record (`seq 0`) but not for the following ones, for the same HMAC
  state reason. The client still decrypts them, so `--mac-in warn` keeps the
  session alive.

## Self-test

`--self-test` runs a local simulation and exercises BER encoding, the SRP
fields, AES-128/OFB with FIPS-197 and SRP layer vectors, option negotiation,
the final-field layouts, a vulnerable mock `vmdird`, a patched mock (with the
`A mod N` validation), a mock without a verifier, the shifted-sequence case and
the offline `--analyze` path.

## Disclaimer

Use this code only against systems you own or are explicitly authorised to
test. It performs real writes (account creation, password reset, group
membership) when the corresponding flags are used.
