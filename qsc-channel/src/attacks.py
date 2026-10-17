"""Attack demonstrations. Each returns an AttackResult; tests assert attack_succeeded == expected.
`attack_succeeded=True` means the attacker achieved its goal (read data / forced acceptance)."""
from dataclasses import dataclass

from .aead import AEADError
from .channel import ByteCounter, Client, HandshakeError, Server, _parse_head, make_identities, run_handshake, wire_suite
from .kem import KEMS
from .problem import SUITE_CLASSIC, SUITE_SIG

SECRET = b"TOP-SECRET-APPLICATION-DATA-" * 4


@dataclass
class AttackResult:
    name: str
    suite: str
    attack_succeeded: bool
    detail: str = ""


def _pinned(ids, suite):
    return ids[SUITE_SIG[suite]][0]


def passive_eavesdropper(suite, ids):
    """Attacker records every byte on the wire; it must not see the plaintext or any key."""
    wire = []
    r = run_handshake(Client(suite, _pinned(ids, suite)), Server(ids), mitm=lambda label, d: wire.append(d) or d)
    records = r.client.send(SECRET)
    wire.extend(records)
    blob = b"".join(wire)
    leaked = SECRET in blob or r.client.send_key in blob or r.client.recv_key in blob
    return AttackResult("passive_eavesdropper", suite, leaked, f"observed {len(blob)} bytes on wire")


def mitm_fake_server(suite, ids, attacker_ids):
    """Attacker answers the client with its OWN server (own signing key, not the pinned one)."""
    c = Client(suite, _pinned(ids, suite))
    sh, _ = Server(attacker_ids).accept(c.start())
    try:
        c.finish(sh)
        return AttackResult("mitm_fake_server_signed", suite, True, "client accepted forged server")
    except HandshakeError as e:
        return AttackResult("mitm_fake_server_signed", suite, False, str(e))


def mitm_substitute_kem(suite, ids):
    """In flight, attacker replaces the client's KEM public key with its own so the (real) server encapsulates to it."""
    atk_pk, _ = KEMS[suite].keygen()

    def mitm(label, data):
        if label == "ClientHello":
            off = _parse_head(data)[2]
            return data[:off] + atk_pk
        return data

    try:
        run_handshake(Client(suite, _pinned(ids, suite)), Server(ids), mitm=mitm)
        return AttackResult("mitm_substitute_kem_signed", suite, True, "handshake completed")
    except HandshakeError as e:
        return AttackResult("mitm_substitute_kem_signed", suite, False, str(e))


def mitm_unsigned_control(suite):
    """NEGATIVE CONTROL: without authentication the attacker relays AND reads everything."""
    client, real_server = Client(suite, require_auth=False), Server(signed=False)
    atk_server, atk_client = Server(signed=False), Client(suite, require_auth=False)
    sh_a, pend_a = atk_server.accept(client.start())                 # attacker plays server towards client
    cf, client_sess = client.finish(sh_a)
    atk_to_client = pend_a.finish(cf)
    sh_r, pend_r = real_server.accept(atk_client.start())            # attacker plays client towards real server
    cf2, atk_to_server = atk_client.finish(sh_r)
    server_sess = pend_r.finish(cf2)
    seen = atk_to_client.recv(client_sess.send(SECRET))              # attacker decrypts client traffic
    delivered = server_sess.recv(atk_to_server.send(seen))           # and re-encrypts to the real server
    ok = seen == SECRET and delivered == SECRET
    return AttackResult("mitm_unsigned_control", suite, ok, "attacker read + relayed plaintext" if ok else "failed")


def downgrade(ids, suite):
    """Attacker swaps the hybrid ClientHello for a classical one; server happily answers classical."""
    fake_ch = Client(SUITE_CLASSIC, _pinned(ids, SUITE_CLASSIC)).start()
    try:
        run_handshake(Client(suite, _pinned(ids, suite)), Server(ids),
                      mitm=lambda label, d: fake_ch if label == "ClientHello" else d)
        return AttackResult("downgrade", suite, True, "client accepted weaker suite")
    except HandshakeError as e:
        return AttackResult("downgrade", suite, False, str(e))


def tamper_positions(n):
    return sorted({0, 3, 6, 7, 20, 27, 28, 40, 59, n // 4, n // 2, 3 * n // 4, n - 33, n - 1} & set(range(n)))


def tamper_handshake(suite, ids, label, pos):
    def mitm(lb, d):
        if lb != label:
            return d
        b = bytearray(d)
        b[pos] ^= 0x01
        return bytes(b)

    try:
        run_handshake(Client(suite, _pinned(ids, suite)), Server(ids), mitm=mitm)
        return AttackResult(f"tamper_{label}@{pos}", suite, True, "handshake completed despite tampering")
    except HandshakeError as e:
        return AttackResult(f"tamper_{label}@{pos}", suite, False, str(e))


def tamper_all(suite, ids):
    """Flip one bit at many positions of each handshake message; every attempt must fail."""
    probe = run_handshake(Client(suite, _pinned(ids, suite)), Server(ids))
    sizes = {lbl: n for lbl, _, n in probe.counter.messages}
    return [tamper_handshake(suite, ids, lbl, p) for lbl, n in sizes.items() for p in tamper_positions(n)]


def record_attacks(suite, ids):
    """Tamper / drop / reorder / replay on the record layer; each must be rejected."""
    def fresh():
        r = run_handshake(Client(suite, _pinned(ids, suite)), Server(ids))
        return r.client, r.server

    def attempt(name, mutate):
        c, s = fresh()
        recs = c.send(b"A" * 40000)                       # 3 records
        try:
            s.recv(mutate(list(recs)))
            return AttackResult(name, suite, True, "receiver accepted manipulated records")
        except AEADError as e:
            return AttackResult(name, suite, False, str(e))

    def flip(r):
        b = bytearray(r[1])
        b[20] ^= 1
        r[1] = bytes(b)
        return r

    return [attempt("record_tamper", flip),
            attempt("record_drop", lambda r: [r[0], r[2]]),
            attempt("record_reorder", lambda r: [r[1], r[0], r[2]]),
            attempt("record_replay", lambda r: [r[0], r[0], r[1], r[2]])]


__all__ = ["AttackResult", "passive_eavesdropper", "mitm_fake_server", "mitm_substitute_kem", "mitm_unsigned_control",
           "downgrade", "tamper_all", "record_attacks", "make_identities", "ByteCounter", "wire_suite"]
