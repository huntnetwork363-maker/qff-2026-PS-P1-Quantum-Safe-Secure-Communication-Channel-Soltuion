import os

import pytest

from src.problem import EXPECTED_SIZES as S
from src.sig import MLDSA65, SIGS, EcdsaP256

MSG = b"transcript-hash-" * 2


@pytest.mark.parametrize("sig", SIGS.values(), ids=lambda s: s.name)
def test_valid_and_negative(sig):
    pk, sk = sig.keygen()
    s = sig.sign(sk, MSG)
    assert len(s) == sig.SIG_LEN and sig.verify(pk, MSG, s)
    bad_msg = bytes([MSG[0] ^ 1]) + MSG[1:]
    assert not sig.verify(pk, bad_msg, s)                       # flipped bit in message
    for pos in (0, len(s) // 2, len(s) - 1):                    # flipped bit in signature
        bs = bytearray(s)
        bs[pos] ^= 0x01
        assert not sig.verify(pk, MSG, bytes(bs))
    pk2, _ = sig.keygen()
    assert not sig.verify(pk2, MSG, s)                          # wrong public key


@pytest.mark.parametrize("sig", SIGS.values(), ids=lambda s: s.name)
def test_verify_never_raises(sig):
    pk, sk = sig.keygen()
    s = sig.sign(sk, MSG)
    for junk in (b"", b"\x00" * 3, os.urandom(sig.SIG_LEN), s[:-1], s + b"x"):
        assert sig.verify(pk, MSG, junk) is False
    assert sig.verify(b"", MSG, s) is False
    assert sig.verify(None, MSG, s) is False


def test_sizes():
    pk, sk = MLDSA65.keygen()
    assert len(pk) == S["mldsa65_pk"] and len(MLDSA65.sign(sk, MSG)) == S["mldsa65_sig"]
    pk, sk = EcdsaP256.keygen()
    assert len(EcdsaP256.sign(sk, MSG)) == S["ecdsa_sig"]
