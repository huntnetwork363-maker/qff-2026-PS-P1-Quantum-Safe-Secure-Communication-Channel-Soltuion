"""Independent cross-check of the ML-KEM backend (kyber-py) against a second implementation (mlkem).
Neither library offers NIST KAT vectors offline, so interoperability in BOTH directions is our KAT substitute."""
import pytest

mlkem = pytest.importorskip("mlkem")
from kyber_py.ml_kem import ML_KEM_768  # noqa: E402

M = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_768)


def test_kyberpy_key_other_encaps_kyberpy_decaps():
    for _ in range(10):
        ek, dk = ML_KEM_768.keygen()
        ss, ct = M.encaps(mlkem.EncapsKey.from_bytes(ek))
        assert len(ct) == 1088 and ML_KEM_768.decaps(dk, ct) == ss


def test_other_key_kyberpy_encaps_other_decaps():
    for _ in range(10):
        ek, dk = M.key_gen()
        ss, ct = ML_KEM_768.encaps(ek.to_bytes())
        assert M.decaps(dk, ct) == ss
