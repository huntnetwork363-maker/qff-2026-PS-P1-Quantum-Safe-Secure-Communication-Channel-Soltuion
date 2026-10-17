import pytest

from src.aead import MAX_SEQ, AEADError, Direction

K = bytes(range(32))
P = b"\x00\x01\x02\x03"


def pair():
    return Direction(K, P), Direction(K, P)


def test_roundtrip_and_aad():
    s, r = pair()
    ct = s.seal(b"hello", b"hdr")
    assert r.open(ct, b"hdr") == b"hello"


def test_tampered_ciphertext_fails_and_does_not_advance():
    s, r = pair()
    ct = s.seal(b"hello", b"h")
    bad = bytearray(ct)
    bad[0] ^= 1
    with pytest.raises(AEADError):
        r.open(bytes(bad), b"h")
    assert r.seq == 0 and r.open(ct, b"h") == b"hello"     # genuine record still accepted afterwards


def test_tampered_aad_fails():
    s, r = pair()
    ct = s.seal(b"x", b"aad1")
    with pytest.raises(AEADError):
        r.open(ct, b"aad2")


def test_wrong_key_fails():
    s = Direction(K, P)
    r = Direction(bytes(32), P)
    with pytest.raises(AEADError):
        r.open(s.seal(b"x", b""), b"")


def test_wrong_nonce_prefix_fails():
    s, r = Direction(K, P), Direction(K, b"\xff\xff\xff\xff")
    with pytest.raises(AEADError):
        r.open(s.seal(b"x", b""), b"")


def test_replay_and_reorder_rejected():
    s, r = pair()
    c0, c1 = s.seal(b"a", b""), s.seal(b"b", b"")
    with pytest.raises(AEADError):
        r.open(c1, b"")                                    # reorder: c1 before c0
    assert r.open(c0, b"") == b"a"
    with pytest.raises(AEADError):
        r.open(c0, b"")                                    # replay of c0
    assert r.open(c1, b"") == b"b"


def test_nonces_never_repeat():
    s = Direction(K, P)
    seen = set()
    for _ in range(2000):
        s.seal(b"", b"")
        assert s.last_nonce not in seen
        seen.add(s.last_nonce)


def test_counter_exhaustion_guard():
    s = Direction(K, P, start_seq=MAX_SEQ - 1)
    s.seal(b"last", b"")
    with pytest.raises(AEADError):
        s.seal(b"too many", b"")


def test_bad_key_or_prefix_length():
    with pytest.raises(ValueError):
        Direction(b"short", P)
    with pytest.raises(ValueError):
        Direction(K, b"abc")
