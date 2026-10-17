"""Hybrid KEM (ECDH P-256 + ML-KEM-768) with a transcript-bound HKDF combiner, plus classical/PQ baselines.

SECURITY NOTE: we write NO primitives; we only compose library calls. The ML-KEM backend (kyber-py) is a
pure-Python research implementation: NOT constant-time and NOT production-grade. Benchmark/research use only.

Interface (all three suites): keygen() -> (pk, sk); encaps(pk) -> (ct, ss); decaps(sk, ct) -> ss (32 bytes).
"""
from importlib import metadata

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768

from .problem import PROTOCOL_VERSION, SUITE_CLASSIC, SUITE_HYBRID, SUITE_PQ

BACKEND_NAME = "cryptography+kyber-py"
BACKEND_VERSION = f"cryptography {metadata.version('cryptography')}; kyber-py {metadata.version('kyber-py')}"

ECDH_PK = 65
MLKEM_PK = 1184
MLKEM_CT = 1088


class KEMError(ValueError):
    """Malformed key/ciphertext (wrong length, off-curve point...)."""


def _combine(label, public_parts, ikm):
    """HKDF-SHA256(salt=none, ikm, info=version/label || all public values) -> 32 bytes."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=PROTOCOL_VERSION + b"/" + label + b"".join(public_parts)).derive(ikm)


def _ec_gen():
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = sk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return sk, pk


def _ec_load(pk):
    if len(pk) != ECDH_PK or pk[0] != 4:
        raise KEMError("bad ECDH point encoding")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk)  # validates on-curve
    except ValueError as e:
        raise KEMError("ECDH point not on curve") from e


def _mlkem_encaps(mpk):
    try:
        return ML_KEM_768.encaps(bytes(mpk))
    except ValueError as e:                      # kyber-py raises ValueError on its FIPS 203 modulus check
        raise KEMError("invalid ML-KEM public key") from e


def _mlkem_decaps(msk, ct):
    try:
        return ML_KEM_768.decaps(msk, bytes(ct))
    except ValueError as e:
        raise KEMError("invalid ML-KEM ciphertext") from e


def _check_len(b, n, what):
    if not isinstance(b, (bytes, bytearray)) or len(b) != n:
        raise KEMError(f"{what}: expected {n} bytes")


class ClassicalKEM:
    name, PK_LEN, CT_LEN = SUITE_CLASSIC, ECDH_PK, ECDH_PK

    @classmethod
    def keygen(cls):
        sk, pk = _ec_gen()
        return pk, (sk, pk)

    @classmethod
    def encaps(cls, pk):
        _check_len(pk, cls.PK_LEN, "pk")
        peer = _ec_load(bytes(pk))
        esk, ct = _ec_gen()
        return ct, _combine(b"classical", [pk, ct], esk.exchange(ec.ECDH(), peer))

    @classmethod
    def decaps(cls, sk, ct):
        esk, pk = sk
        _check_len(ct, cls.CT_LEN, "ct")
        return _combine(b"classical", [pk, ct], esk.exchange(ec.ECDH(), _ec_load(bytes(ct))))


class PQKEM:
    name, PK_LEN, CT_LEN = SUITE_PQ, MLKEM_PK, MLKEM_CT

    @classmethod
    def keygen(cls):
        pk, sk = ML_KEM_768.keygen()
        return pk, (sk, pk)

    @classmethod
    def encaps(cls, pk):
        _check_len(pk, cls.PK_LEN, "pk")
        ss_m, ct = _mlkem_encaps(pk)
        return ct, _combine(b"pq", [pk, ct], ss_m)

    @classmethod
    def decaps(cls, sk, ct):
        msk, pk = sk
        _check_len(ct, cls.CT_LEN, "ct")
        return _combine(b"pq", [pk, ct], _mlkem_decaps(msk, ct))  # implicit rejection: no exception


class HybridKEM:
    """pk = ecdh_pk(65) || mlkem_pk(1184); ct = ecdh_eph_pk(65) || mlkem_ct(1088).
    ss = HKDF(ikm = ss_ecdh || ss_mlkem (this order, both sides),
              info = ver/hybrid || pk_c || ct_ecdh || mlkem_pk || mlkem_ct)."""
    name, PK_LEN, CT_LEN = SUITE_HYBRID, ECDH_PK + MLKEM_PK, ECDH_PK + MLKEM_CT

    @classmethod
    def keygen(cls):
        esk, epk = _ec_gen()
        mpk, msk = ML_KEM_768.keygen()
        pk = epk + mpk
        return pk, (esk, msk, pk)

    @classmethod
    def encaps(cls, pk):
        _check_len(pk, cls.PK_LEN, "pk")
        pk = bytes(pk)
        epk_c, mpk = pk[:ECDH_PK], pk[ECDH_PK:]
        esk, epk_s = _ec_gen()
        ss_e = esk.exchange(ec.ECDH(), _ec_load(epk_c))
        ss_m, ct_m = _mlkem_encaps(mpk)
        return epk_s + ct_m, _combine(b"hybrid", [epk_c, epk_s, mpk, ct_m], ss_e + ss_m)

    @classmethod
    def decaps(cls, sk, ct):
        esk, msk, pk = sk
        _check_len(ct, cls.CT_LEN, "ct")
        ct = bytes(ct)
        epk_s, ct_m = ct[:ECDH_PK], ct[ECDH_PK:]
        epk_c, mpk = pk[:ECDH_PK], pk[ECDH_PK:]
        ss_e = esk.exchange(ec.ECDH(), _ec_load(epk_s))
        ss_m = _mlkem_decaps(msk, ct_m)
        return _combine(b"hybrid", [epk_c, epk_s, mpk, ct_m], ss_e + ss_m)


KEMS = {SUITE_CLASSIC: ClassicalKEM, SUITE_PQ: PQKEM, SUITE_HYBRID: HybridKEM}
