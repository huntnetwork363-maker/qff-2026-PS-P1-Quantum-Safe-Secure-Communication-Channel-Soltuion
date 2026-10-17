import hashlib
import random

import pytest

from src.aead import AEADError
from src.channel import ByteCounter, Client, HandshakeError, Server, make_identities, run_handshake, wire_suite
from src.problem import EXPECTED_SIZES as S
from src.problem import RECORD_MAX, SUITE_CLASSIC, SUITE_HYBRID, SUITE_PQ, SUITE_SIG, SUITES


@pytest.fixture(scope="module")
def ids():
    return make_identities()


def hs(ids, suite):
    return run_handshake(Client(suite, ids[SUITE_SIG[suite]][0]), Server(ids))


@pytest.mark.parametrize("suite", SUITES)
def test_all_suites_end_to_end_and_keys_agree(ids, suite):
    r = hs(ids, suite)
    assert r.client.send_key == r.server.recv_key and r.client.recv_key == r.server.send_key
    assert r.client.send_key != r.client.recv_key            # roles/directions are really separate keys
    assert r.server.recv(r.client.send(b"ping")) == b"ping"
    assert r.client.recv(r.server.send(b"pong")) == b"pong"


@pytest.mark.parametrize("n", [0, 1, 16384, 16385, 100_000])
def test_chunk_boundaries(ids, n):
    r = hs(ids, SUITE_CLASSIC)
    data = random.Random(42).randbytes(n)
    recs = r.client.send(data)
    assert len(recs) == max(1, -(-n // RECORD_MAX))
    assert r.server.recv(recs) == data


@pytest.mark.parametrize("n", [1_000, 100_000, 10_000_000])
def test_payload_sizes_byte_exact(ids, n):
    r = hs(ids, SUITE_HYBRID)
    data = random.Random(42).randbytes(n)
    got = r.server.recv(r.client.send(data))
    assert hashlib.sha256(got).digest() == hashlib.sha256(data).digest()


def test_handshake_sizes_match_components(ids):
    r = hs(ids, SUITE_HYBRID)
    m = {lbl: n for lbl, _, n in r.counter.messages}
    head = 6 + 1 + len(wire_suite(SUITE_HYBRID)) + 32
    assert m["ClientHello"] == head + S["hybrid_pk"]
    assert m["ServerHello"] == head + S["hybrid_ct"] + S["mldsa65_sig"] + 32
    assert m["ClientFinished"] == 32
    assert r.counter.c2s == m["ClientHello"] + 32 and r.counter.s2c == m["ServerHello"]
    c = hs(ids, SUITE_CLASSIC).counter                      # classical: ECDSA 64-byte sig
    head_c = 6 + 1 + len(wire_suite(SUITE_CLASSIC)) + 32
    assert {lbl: n for lbl, _, n in c.messages}["ServerHello"] == head_c + S["ecdh_pk"] + S["ecdsa_sig"] + 32


def test_connections_do_not_share_state(ids):
    a, b = hs(ids, SUITE_CLASSIC), hs(ids, SUITE_CLASSIC)
    assert a.client.send_key != b.client.send_key
    recs = a.client.send(b"x")
    with pytest.raises(AEADError):
        b.server.recv(recs)                                  # other connection cannot read it
    assert a.server.recv(recs) == b"x"


def test_sequence_starts_at_zero_both_sides(ids):
    r = hs(ids, SUITE_CLASSIC)
    assert r.client.send(b"a")[0][:8] == bytes(8) and r.server.send(b"a")[0][:8] == bytes(8)


def test_wrong_pinned_key_rejected(ids):
    other = make_identities()
    with pytest.raises(HandshakeError):
        run_handshake(Client(SUITE_PQ, other[SUITE_SIG[SUITE_PQ]][0]), Server(ids))


def test_authenticated_client_requires_pinned_key():
    with pytest.raises(ValueError):
        Client(SUITE_PQ)


def test_unsupported_suite_and_garbage_rejected(ids):
    with pytest.raises(HandshakeError):
        Server(ids).accept(b"garbage-not-a-hello" * 3)
    with pytest.raises(HandshakeError):
        Server(ids).accept(b"")


def test_byte_counter_directions():
    c = ByteCounter()
    c.record("a", "c2s", b"123")
    c.record("b", "s2c", b"12345")
    assert (c.c2s, c.s2c) == (3, 5)
