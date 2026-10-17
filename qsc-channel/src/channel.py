"""Quantum-safe secure channel: 1-RTT server-authenticated handshake + AES-256-GCM record layer.

Flow:  C -> S ClientHello(ver, suite, nonce_c, kem_pk)
       S -> C ServerHello(ver, suite, nonce_s, kem_ct, sig(transcript), finished_s)
       C -> S ClientFinished(HMAC)           then application records in both directions.
transcript_hash = SHA-256(ClientHello || ServerHello-without-sig/finished): binds version, suite id, both nonces and
all KEM public values. NOTE: pure-Python PQ backends are NOT constant-time (see kem.py / sig.py).
No global mutable state: every connection owns its own objects.
"""
import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from .aead import AEADError, Direction
from .kem import KEMS, KEMError
from .problem import PROTOCOL_VERSION, RECORD_MAX, SUITE_SIG, SUITES
from .sig import SIGS

NONCE_LEN = 32
FIN_LEN = 32
CTX_SERVER_SIG = b"QSC-v1 server signature"
HDR_LEN = 12  # seq(8) || plaintext_len(4)
TAG_LEN = 16
DIR_C2S, DIR_S2C = b"\x01", b"\x02"


class HandshakeError(Exception):
    """Local failure only; details are never sent to the peer."""


def wire_suite(kem_name):
    return f"{kem_name}/{SUITE_SIG[kem_name]}".encode()


def make_identities():
    """Long-term server signature keys for every signature scheme: {sig_name: (pk, sk)}."""
    return {name: cls.keygen() for name, cls in SIGS.items()}


# ---------------------------------------------------------------- encoding helpers
def _hello_head(suite_id, nonce):
    return PROTOCOL_VERSION + bytes([len(suite_id)]) + suite_id + nonce


def _parse_head(msg):
    vl = len(PROTOCOL_VERSION)
    if len(msg) < vl + 1 or msg[:vl] != PROTOCOL_VERSION:
        raise HandshakeError("bad version")
    sl = msg[vl]
    off = vl + 1 + sl
    if len(msg) < off + NONCE_LEN:
        raise HandshakeError("truncated hello")
    return msg[vl + 1:off], msg[off:off + NONCE_LEN], off + NONCE_LEN


def _suite_from_wire(suite_id):
    for kem_name in SUITES:
        if wire_suite(kem_name) == suite_id:
            return kem_name
    raise HandshakeError("unsupported suite")


# ---------------------------------------------------------------- key schedule
def _expand(prk, label, th, length=32):
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=b"QSC-v1 " + label + th).derive(prk)


def _schedule(ss, nonce_c, nonce_s, th):
    prk = hmac.new(nonce_c + nonce_s, ss, hashlib.sha256).digest()   # HKDF-Extract
    return {"c2s_key": _expand(prk, b"c2s key", th), "s2c_key": _expand(prk, b"s2c key", th),
            "c2s_iv": _expand(prk, b"c2s iv", th, 4), "s2c_iv": _expand(prk, b"s2c iv", th, 4),
            "conf_key": _expand(prk, b"finished", th)}


def _finished(conf_key, who, th):
    return hmac.new(conf_key, who + th, hashlib.sha256).digest()


# ---------------------------------------------------------------- record layer
class Session:
    def __init__(self, role, keys):
        c2s = Direction(keys["c2s_key"], keys["c2s_iv"])
        s2c = Direction(keys["s2c_key"], keys["s2c_iv"])
        if role == "client":
            self._tx, self._rx, self._txd, self._rxd = c2s, s2c, DIR_C2S, DIR_S2C
            self.send_key, self.recv_key = keys["c2s_key"], keys["s2c_key"]
        else:
            self._tx, self._rx, self._txd, self._rxd = s2c, c2s, DIR_S2C, DIR_C2S
            self.send_key, self.recv_key = keys["s2c_key"], keys["c2s_key"]

    def send(self, data):
        """Chunk `data` into records of <= RECORD_MAX plaintext bytes. Empty data -> one empty record."""
        chunks = [data[i:i + RECORD_MAX] for i in range(0, len(data), RECORD_MAX)] or [b""]
        out = []
        for ch in chunks:
            hdr = self._tx.seq.to_bytes(8, "big") + len(ch).to_bytes(4, "big")
            out.append(hdr + self._tx.seal(ch, self._txd + hdr))
        return out

    def recv(self, records):
        parts = []
        for rec in records:
            if len(rec) < HDR_LEN + TAG_LEN:
                raise AEADError("short record")
            hdr, ct = rec[:HDR_LEN], rec[HDR_LEN:]
            if int.from_bytes(hdr[:8], "big") != self._rx.seq:
                raise AEADError("bad sequence number (replay/reorder/drop)")
            plen = int.from_bytes(hdr[8:], "big")
            if plen > RECORD_MAX or plen != len(ct) - TAG_LEN:
                raise AEADError("bad record length")
            parts.append(self._rx.open(ct, self._rxd + hdr))
        return b"".join(parts)


# ---------------------------------------------------------------- handshake
class Client:
    """One connection. require_auth=False exists ONLY for the unauthenticated negative control."""

    def __init__(self, suite, pinned_pk=None, require_auth=True):
        if suite not in KEMS:
            raise ValueError("unknown suite")
        if require_auth and pinned_pk is None:
            raise ValueError("authenticated mode needs the pinned server public key")
        self.suite, self.pinned_pk, self.require_auth = suite, pinned_pk, require_auth
        self._ch = self._sk = None

    def start(self):
        kem = KEMS[self.suite]
        pk, self._sk = kem.keygen()
        self._ch = _hello_head(wire_suite(self.suite), os.urandom(NONCE_LEN)) + pk
        return self._ch

    def finish(self, sh):
        """Process ServerHello. Signature is verified BEFORE decapsulation / key use. Returns (ClientFinished, Session)."""
        kem, sig_cls = KEMS[self.suite], SIGS[SUITE_SIG[self.suite]]
        suite_id, nonce_s, off = _parse_head(sh)
        if suite_id != wire_suite(self.suite):
            raise HandshakeError("suite mismatch (downgrade?)")
        sig_len = sig_cls.SIG_LEN if self.require_auth else 0
        if len(sh) != off + kem.CT_LEN + sig_len + FIN_LEN:
            raise HandshakeError("bad ServerHello length")
        body = sh[:off + kem.CT_LEN]
        ct = body[off:]
        sig = sh[len(body):len(body) + sig_len]
        fin_s = sh[len(body) + sig_len:]
        th = hashlib.sha256(self._ch + body).digest()      # uses OUR copy of ClientHello
        if self.require_auth and not sig_cls.verify(self.pinned_pk, CTX_SERVER_SIG + th, sig):
            raise HandshakeError("server signature invalid")
        try:
            ss = kem.decaps(self._sk, ct)
        except KEMError as e:
            raise HandshakeError("bad KEM ciphertext") from e
        nonce_c = _parse_head(self._ch)[1]
        keys = _schedule(ss, nonce_c, nonce_s, th)
        if not hmac.compare_digest(fin_s, _finished(keys["conf_key"], b"server", th)):
            raise HandshakeError("server Finished invalid")
        return _finished(keys["conf_key"], b"client", th), Session("client", keys)


class Server:
    """Immutable per-process config; accept() creates a fresh per-connection state."""

    def __init__(self, identities=None, signed=True):
        if signed and not identities:
            raise ValueError("signed mode needs identities")
        self.identities, self.signed = identities, signed

    def accept(self, ch):
        suite_id, nonce_c, off = _parse_head(ch)
        suite = _suite_from_wire(suite_id)
        kem, sig_cls = KEMS[suite], SIGS[SUITE_SIG[suite]]
        if len(ch) != off + kem.PK_LEN:
            raise HandshakeError("bad ClientHello length")
        try:
            ct, ss = kem.encaps(ch[off:])
        except KEMError as e:
            raise HandshakeError("bad client KEM key") from e
        nonce_s = os.urandom(NONCE_LEN)
        body = _hello_head(suite_id, nonce_s) + ct
        th = hashlib.sha256(ch + body).digest()
        sig = b""
        if self.signed:
            sig = sig_cls.sign(self.identities[sig_cls.name][1], CTX_SERVER_SIG + th)
        keys = _schedule(ss, nonce_c, nonce_s, th)
        sh = body + sig + _finished(keys["conf_key"], b"server", th)
        return sh, PendingServer(keys, th)


class PendingServer:
    def __init__(self, keys, th):
        self._keys, self._th = keys, th

    def finish(self, client_finished):
        if not hmac.compare_digest(client_finished, _finished(self._keys["conf_key"], b"client", self._th)):
            raise HandshakeError("client Finished invalid")
        return Session("server", self._keys)


# ---------------------------------------------------------------- transport accounting + driver
@dataclass
class ByteCounter:
    c2s: int = 0
    s2c: int = 0
    messages: list = field(default_factory=list)   # (label, direction, nbytes)

    def record(self, label, direction, data):
        n = len(data)
        if direction == "c2s":
            self.c2s += n
        else:
            self.s2c += n
        self.messages.append((label, direction, n))
        return data


@dataclass
class HandshakeResult:
    client: Session
    server: Session
    counter: ByteCounter
    client_ns: int
    server_ns: int


def run_handshake(client, server, counter=None, mitm=None):
    """Drive the 3 messages through an in-memory pipe. `mitm(label, data) -> data` may modify messages in flight.
    Raises HandshakeError on failure. Times client-side and server-side compute separately."""
    counter = counter or ByteCounter()
    hop = (lambda label, data: mitm(label, data)) if mitm else (lambda label, data: data)
    pc = time.perf_counter_ns

    t = pc()
    ch = client.start()
    cns = pc() - t
    counter.record("ClientHello", "c2s", ch)
    t = pc()
    sh, pending = server.accept(hop("ClientHello", ch))
    sns = pc() - t
    counter.record("ServerHello", "s2c", sh)
    t = pc()
    cf, csess = client.finish(hop("ServerHello", sh))
    cns += pc() - t
    counter.record("ClientFinished", "c2s", cf)
    t = pc()
    ssess = pending.finish(hop("ClientFinished", cf))
    sns += pc() - t
    return HandshakeResult(csess, ssess, counter, cns, sns)
