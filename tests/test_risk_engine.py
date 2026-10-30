import pytest

from services.risk_engine import ALLOW, BLOCK, REVIEW, STEP_UP, evaluate

# Umbrales de prueba explícitos (mismos valores que los reales) para no depender de THRESHOLDS.
TEST_THRESHOLDS = [(0, ALLOW), (30, STEP_UP), (60, REVIEW), (85, BLOCK)]

# Señales de una petición "limpia": todo comprobado y nada sospechoso.
CLEAN = {"is_hosting": False, "timezone_matches_country": True, "timezone": "Europe/Madrid"}


@pytest.mark.parametrize("score, action", [
    (29, ALLOW), (30, STEP_UP),
    (59, STEP_UP), (60, REVIEW),
    (84, REVIEW), (85, BLOCK),
])
def test_threshold_limits(score, action):
    # Un solo peso con el valor exacto que se quiere probar.
    result = evaluate({**CLEAN, "is_hosting": True}, weights={"hosting_ip": score},
                      thresholds=TEST_THRESHOLDS)
    assert result.score == score
    assert result.action == action


def test_clean_request_scores_zero():
    result = evaluate(CLEAN)
    assert (result.score, result.action, result.reasons, result.unverified) == (
        0, ALLOW, [], ["device_reuse_low", "device_reuse_high"])


def test_hosting_alone_is_25_allow():
    result = evaluate({**CLEAN, "is_hosting": True})
    assert result.score == 25
    assert result.action == ALLOW
    assert result.reasons == ["hosting_ip"]


def test_hosting_and_mismatch_is_35_step_up():
    result = evaluate({**CLEAN, "is_hosting": True, "timezone_matches_country": False})
    assert result.score == 35
    assert result.action == STEP_UP
    assert result.reasons == ["hosting_ip", "tz_country_mismatch"]


def test_utc_timezone_adds_tz_utc():
    # Con "UTC" el país no se puede comparar: matches llega en None.
    result = evaluate({"is_hosting": False, "timezone_matches_country": None, "timezone": "UTC"})
    assert result.score == 5
    assert result.reasons == ["tz_utc"]
    assert result.unverified == ["tz_country_mismatch", "device_reuse_low", "device_reuse_high"]


def test_none_signals_add_zero_and_are_unverified():
    result = evaluate({"is_hosting": None, "timezone_matches_country": None, "timezone": None})
    assert result.score == 0
    assert result.action == ALLOW
    assert result.reasons == []
    assert result.unverified == ["hosting_ip", "tz_country_mismatch", "tz_utc",
                                 "device_reuse_low", "device_reuse_high"]


def test_score_is_capped_at_100():
    weights = {"hosting_ip": 80, "tz_country_mismatch": 80}
    result = evaluate({**CLEAN, "is_hosting": True, "timezone_matches_country": False},
                      weights=weights, thresholds=TEST_THRESHOLDS)
    assert result.score == 100
    assert result.action == BLOCK


def test_weight_without_rule_is_unverified():
    # Futuras señales (comportamiento, dispositivo, grafo) aún no tienen regla.
    result = evaluate(CLEAN, weights={"hosting_ip": 25, "senal_futura": 40})
    assert result.score == 0
    assert result.unverified == ["senal_futura"]


@pytest.mark.parametrize("bad_signals", [None, "no-es-dict", 42])
def test_never_raises(bad_signals):
    result = evaluate(bad_signals)
    assert result.action == ALLOW
    assert result.score == 0
