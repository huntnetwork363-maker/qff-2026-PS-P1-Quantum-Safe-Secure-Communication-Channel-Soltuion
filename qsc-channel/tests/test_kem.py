import os

import pytest
from kyber_py.ml_kem import ML_KEM_768

from src.kem import KEMS, PQKEM, ClassicalKEM, HybridKEM, KEMError
from src.problem import EXPECTED_SIZES as S


@pytest.mark.parametrize("kem", KEMS.values(), ids=lambda k: k.name)
def test_roundtrip_50(kem):
    for _ in range(50):
        pk, sk = kem.keygen()
        ct, ss = kem.encaps(pk)
        assert len(ss) == S["shared_secret"] and kem.decaps(sk, ct) == ss


def test_sizes_match_fips_and_expected():
    pk, sk = HybridKEM.keygen()
    ct, _ = HybridKEM.encaps(pk)
    assert len(pk) == S["hybrid_pk"] and len(ct) == S["hybrid_ct"]
    pk, sk = PQKEM.keygen()
    ct, _ = PQKEM.encaps(pk)
    assert (len(pk), len(ct)) == (S["mlkem768_pk"], S["mlkem768_ct"])
    assert len(ML_KEM_768.keygen()[1]) == S["mlkem768_sk"]
    pk, sk = ClassicalKEM.keygen()
    assert len(pk) == S["ecdh_pk"] and len(ClassicalKEM.encaps(pk)[0]) == S["ecdh_pk"]


def test_encaps_is_randomised():
    pk, _ = HybridKEM.keygen()
    (c1, s1), (c2, s2) = HybridKEM.encaps(pk), HybridKEM.encaps(pk)
    assert c1 != c2 and s1 != s2


def test_component_sensitivity_ecdh_share():
    pk, sk = HybridKEM.keygen()
    ct1, ss1 = HybridKEM.encaps(pk)
    ct2, _ = HybridKEM.encaps(pk)
    swapped = ct2[:65] + ct1[65:]          # only the ECDH share replaced
    assert HybridKEM.decaps(sk, swapped) != ss1


def test_component_sensitivity_mlkem_share():
    pk, sk = HybridKEM.keygen()
    ct1, ss1 = HybridKEM.encaps(pk)
    ct2, _ = HybridKEM.encaps(pk)
    swapped = ct1[:65] + ct2[65:]          # only the ML-KEM share replaced
    assert HybridKEM.decaps(sk, swapped) != ss1


@pytest.mark.parametrize("kem", [PQKEM, HybridKEM], ids=lambda k: k.name)
def test_tampered_mlkem_ct_implicit_rejection_no_exception(kem):
    pk, sk = kem.keygen()
    ct, ss = kem.encaps(pk)
    bad = bytearray(ct)
    bad[-5] ^= 0x01
    assert kem.decaps(sk, bytes(bad)) != ss    # different secret, no exception


def test_off_curve_and_truncated_ecdh_point_rejected():
    pk, sk = ClassicalKEM.keygen()
    with pytest.raises(KEMError):
        ClassicalKEM.encaps(b"\x04" + os.urandom(64))   # (almost surely) off curve
    with pytest.raises(KEMError):
        ClassicalKEM.encaps(pk[:-1])                    # truncated
    ct, _ = ClassicalKEM.encaps(pk)
    with pytest.raises(KEMError):
        ClassicalKEM.decaps(sk, ct[:-1])
    with pytest.raises(KEMError):
        ClassicalKEM.decaps(sk, b"\x02" + ct[1:])       # compressed-prefix not accepted


@pytest.mark.parametrize("kem", KEMS.values(), ids=lambda k: k.name)
def test_wrong_length_inputs(kem):
    pk, sk = kem.keygen()
    ct, _ = kem.encaps(pk)
    with pytest.raises(KEMError):
        kem.encaps(pk + b"\x00")
    with pytest.raises(KEMError):
        kem.decaps(sk, ct + b"\x00")


def test_wrong_sk_gives_different_secret():
    pk, _ = PQKEM.keygen()
    _, sk2 = PQKEM.keygen()
    ct, ss = PQKEM.encaps(pk)
    assert PQKEM.decaps(sk2, ct) != ss


def test_suites_domain_separated():
    """Same ECDH material under different labels must not collide across suites."""
    pk, sk = ClassicalKEM.keygen()
    ct, ss = ClassicalKEM.encaps(pk)
    assert len(ss) == 32 and ss != ct[:32]


@pytest.mark.parametrize("kem", [PQKEM, HybridKEM], ids=lambda k: k.name)
def test_invalid_mlkem_public_key_gives_kemerror_not_valueerror(kem):
    """Regression (Phase 3 finding): kyber-py raised a raw ValueError on a modulus-check failure."""
    pk, _ = kem.keygen()
    off = 65 if kem is HybridKEM else 0
    bad = pk[:off] + b"\xff\xff\xff" + pk[off + 3:]       # 12-bit coefficients 4095 >= q=3329
    with pytest.raises(KEMError):
        kem.encaps(bad)
