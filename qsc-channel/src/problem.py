"""PS-P1: protocol constants (suite ids, sizes, labels). Suite ids are bound into the handshake transcript."""

SUITE_HYBRID = "P256+MLKEM768"
SUITE_CLASSIC = "P256"
SUITE_PQ = "MLKEM768"
SUITES = (SUITE_CLASSIC, SUITE_PQ, SUITE_HYBRID)

SIG_MLDSA65 = "MLDSA65"
SIG_ECDSA = "ECDSAP256"
# classical baseline uses a classical signature; the PQ-bearing suites use ML-DSA-65
SUITE_SIG = {SUITE_CLASSIC: SIG_ECDSA, SUITE_PQ: SIG_MLDSA65, SUITE_HYBRID: SIG_MLDSA65}

PROTOCOL_VERSION = b"QSC-v1"
RECORD_MAX = 16 * 1024  # max plaintext bytes per record

EXPECTED_SIZES = {
    "ecdh_pk": 65, "mlkem768_pk": 1184, "mlkem768_ct": 1088, "mlkem768_sk": 2400,
    "shared_secret": 32, "mldsa65_sig": 3309, "mldsa65_pk": 1952, "ecdsa_sig": 64,
    "hybrid_pk": 65 + 1184, "hybrid_ct": 65 + 1088,
}
