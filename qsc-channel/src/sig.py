"""Signature wrappers: ML-DSA-65 (FIPS 204, pure-Python backend: not constant-time) and ECDSA-P256 (classical baseline).
verify() NEVER raises: any malformed input returns False (no exception-type oracle)."""
from importlib import metadata

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from dilithium_py.ml_dsa import ML_DSA_65

from .problem import SIG_ECDSA, SIG_MLDSA65

SIG_BACKEND_VERSION = f"cryptography {metadata.version('cryptography')}; dilithium-py {metadata.version('dilithium-py')}"


class MLDSA65:
    name, PK_LEN, SIG_LEN = SIG_MLDSA65, 1952, 3309

    @staticmethod
    def keygen():
        pk, sk = ML_DSA_65.keygen()
        return pk, sk

    @staticmethod
    def sign(sk, msg):
        return ML_DSA_65.sign(sk, msg)

    @classmethod
    def verify(cls, pk, msg, sig):
        try:
            if len(sig) != cls.SIG_LEN or len(pk) != cls.PK_LEN:
                return False
            return bool(ML_DSA_65.verify(pk, msg, sig))
        except Exception:
            return False


class EcdsaP256:
    name, PK_LEN, SIG_LEN = SIG_ECDSA, 65, 64

    @staticmethod
    def keygen():
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return pk, sk

    @staticmethod
    def sign(sk, msg):
        r, s = decode_dss_signature(sk.sign(msg, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")  # fixed 64-byte r||s

    @classmethod
    def verify(cls, pk, msg, sig):
        try:
            if len(sig) != cls.SIG_LEN:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk).verify(der, msg, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
        except Exception:
            return False


SIGS = {SIG_MLDSA65: MLDSA65, SIG_ECDSA: EcdsaP256}
