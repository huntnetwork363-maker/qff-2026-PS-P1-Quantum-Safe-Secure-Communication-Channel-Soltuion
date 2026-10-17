import pytest

from src import attacks as A
from src.channel import make_identities
from src.problem import SUITE_CLASSIC, SUITE_HYBRID, SUITE_PQ, SUITES


@pytest.fixture(scope="module")
def ids():
    return make_identities()


@pytest.mark.parametrize("suite", SUITES)
def test_passive_eavesdropper_learns_nothing(ids, suite):
    assert not A.passive_eavesdropper(suite, ids).attack_succeeded


@pytest.mark.parametrize("suite", SUITES)
def test_mitm_signed_is_rejected(ids, suite):
    assert not A.mitm_fake_server(suite, ids, make_identities()).attack_succeeded
    r = A.mitm_substitute_kem(suite, ids)
    assert not r.attack_succeeded and "signature" in r.detail


@pytest.mark.parametrize("suite", SUITES)
def test_mitm_unsigned_NEGATIVE_CONTROL_succeeds(suite):
    assert A.mitm_unsigned_control(suite).attack_succeeded    # shows WHY authentication is mandatory


@pytest.mark.parametrize("suite", [SUITE_PQ, SUITE_HYBRID])
def test_downgrade_rejected(ids, suite):
    r = A.downgrade(ids, suite)
    assert not r.attack_succeeded and "suite" in r.detail


@pytest.mark.parametrize("suite", [SUITE_CLASSIC, SUITE_HYBRID])
def test_every_tampered_handshake_byte_fails(ids, suite):
    results = A.tamper_all(suite, ids)
    assert len(results) >= 30
    bad = [r.name for r in results if r.attack_succeeded]
    assert not bad, bad


def test_record_attacks_rejected(ids):
    rs = A.record_attacks(SUITE_CLASSIC, ids)
    assert len(rs) == 4 and not any(r.attack_succeeded for r in rs)
