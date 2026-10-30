import logging
import time

import pytest
from fastapi.testclient import TestClient

from app import main
from services import fingerprint_store, risk_engine
from services.fingerprint_match import FAMILY_THRESHOLD, family_size, similarity
from services.risk_engine import evaluate

client = TestClient(main.app)

# Huella plana (forma de la tabla) de un equipo de escritorio típico.
DEVICE = {
    "canvas_hash": "a" * 64,
    "webgl_renderer": "ANGLE (Intel, Intel(R) HD Graphics 530 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "hardware_concurrency": 8,
    "screen_w": 1920,
    "screen_h": 1080,
    "color_depth": 24,
    "languages": ["es-MX", "es"],
    "platform": "Win32",
    "max_touch_points": 0,
    "timezone": "America/Mexico_City",
}

# La misma huella con la forma que manda frontend/collector.js.
BROWSER_FINGERPRINT = {
    "canvasHash": "a" * 64,
    "webglRenderer": "ANGLE (Intel, Intel(R) HD Graphics 530 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "hardwareConcurrency": 8,
    "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
    "languages": ["es-MX", "es"],
    "platform": "Win32",
    "maxTouchPoints": 0,
}


# --- Comparación pura ---

def test_same_device_after_browser_update_is_same_family():
    # Solo cambia el canvas (pesa 0.20): queda en 0.80, por encima de 0.75.
    updated = {**DEVICE, "canvas_hash": "b" * 64}
    assert similarity(DEVICE, updated) == pytest.approx(0.80)
    assert similarity(DEVICE, updated) >= FAMILY_THRESHOLD


def test_two_different_devices_are_not_family():
    other = {
        **DEVICE,
        "canvas_hash": "c" * 64,
        "webgl_renderer": "Apple M1",
        "hardware_concurrency": 4,
        "screen_w": 1440,
        "screen_h": 900,
        "platform": "MacIntel",
    }
    # Solo coinciden idiomas, zona y puntos táctiles: 0.25.
    assert similarity(DEVICE, other) == pytest.approx(0.25)
    assert similarity(DEVICE, other) < FAMILY_THRESHOLD


def test_none_attribute_is_excluded_and_weights_renormalized():
    # Sin canvas en una huella, el canvas distinto de la otra no cuenta como diferencia.
    no_canvas = {**DEVICE, "canvas_hash": None}
    other_canvas = {**DEVICE, "canvas_hash": "z" * 64}
    assert similarity(no_canvas, other_canvas) == pytest.approx(1.0)
    # Con el webgl distinto, el 0.20 se reparte sobre 0.80 de peso comparable: 0.60 / 0.80 = 0.75.
    assert similarity(no_canvas, {**other_canvas, "webgl_renderer": "otra GPU"}) == pytest.approx(0.75)


def test_languages_use_jaccard():
    # {es-MX, es} contra {es}: 1 en común de 2 distintos = 0.5 -> 0.90 + 0.10 * 0.5.
    assert similarity(DEVICE, {**DEVICE, "languages": ["es"]}) == pytest.approx(0.95)
    assert similarity(DEVICE, {**DEVICE, "languages": ["en"]}) == pytest.approx(0.90)


@pytest.mark.parametrize("a, b", [(None, DEVICE), ({}, DEVICE), (DEVICE, {**DEVICE, "languages": 5})])
def test_similarity_never_raises(a, b):
    assert 0.0 <= similarity(a, b) <= 1.0


def test_family_size_counts_distinct_other_accounts():
    candidates = [
        {**DEVICE, "email_hmac": "mio"},
        {**DEVICE, "email_hmac": "otro-1"},
        {**DEVICE, "email_hmac": "otro-1"},
        {**DEVICE, "email_hmac": "otro-2", "canvas_hash": "b" * 64},
        {**DEVICE, "email_hmac": "lejano", "webgl_renderer": "x", "canvas_hash": "y", "languages": ["fr"]},
    ]
    assert family_size(DEVICE, "mio", candidates) == 2


# --- Reglas del motor ---

@pytest.mark.parametrize("size, reasons", [
    (0, []),
    (1, ["device_reuse_low"]),
    (2, ["device_reuse_low"]),
    (3, ["device_reuse_high"]),
    (7, ["device_reuse_high"]),
])
def test_device_reuse_rules(size, reasons):
    result = evaluate({"is_hosting": False, "timezone_matches_country": True,
                       "timezone": "Europe/Madrid", "device_family_size": size})
    assert result.reasons == reasons
    assert result.unverified == ["form_too_fast", "keystroke_uniform", "dwell_uniform", "mouse_linear",
        "no_mouse_movement", "no_keyboard_events", "behavior_missing"]


# --- Integración con /register ---

def _register(email, fingerprint=BROWSER_FINGERPRINT, timezone="America/Mexico_City"):
    return client.post("/register", json={"email": email, "timezone": timezone, "fingerprint": fingerprint})


def test_farm_of_six_accounts_reaches_device_reuse_high(fake_audit, fake_fingerprints):
    for number in range(1, 7):
        assert _register(f"cuenta{number}@example.com").status_code == 200

    sizes = [record["signals"]["device_family_size"] for record in fake_audit]
    reasons = [record["reasons"] for record in fake_audit]
    assert sizes == [0, 1, 2, 3, 4, 5]
    assert reasons == [["behavior_missing"], ["device_reuse_low", "behavior_missing"],
                       ["device_reuse_low", "behavior_missing"], ["device_reuse_high", "behavior_missing"],
                       ["device_reuse_high", "behavior_missing"], ["device_reuse_high", "behavior_missing"]]
    # A partir de la cuarta cuenta: 35 + 10 (sin bloque behavior) = 45 puntos -> step_up.
    assert [record["action"] for record in fake_audit] == ["allow"] * 3 + ["step_up"] * 3
    assert len(fake_fingerprints.rows) == 6


def test_same_email_again_is_not_its_own_family(fake_audit):
    _register("misma@example.com")
    _register("misma@example.com")
    assert fake_audit[1]["signals"]["device_family_size"] == 0


def test_store_failure_keeps_200_and_signal_unverified(fake_audit, fake_fingerprints, caplog):
    fake_fingerprints.fail = True
    with caplog.at_level(logging.WARNING):
        response = _register("maria.perez@example.com")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    record = fake_audit[0]
    assert record["signals"]["device_family_size"] is None
    assert "device_reuse_low" in record["unverified"]
    assert "device_reuse_high" in record["unverified"]
    assert "No se pudieron leer huellas candidatas: ConnectionError" in caplog.text
    assert "maria.perez" not in caplog.text


def test_slow_store_times_out_as_unverified(monkeypatch, fake_audit):
    def slow_query(fingerprint, limit):
        time.sleep(1)
        return []

    monkeypatch.setattr(fingerprint_store, "_query_candidates", slow_query)
    start = time.perf_counter()
    response = _register("lento@example.com")
    elapsed = time.perf_counter() - start

    assert response.status_code == 200
    assert fake_audit[0]["signals"]["device_family_size"] is None
    # No espera el segundo completo: corta cerca de los 150 ms.
    assert elapsed < 0.6


def test_missing_stable_attribute_is_unverified(fake_audit):
    fingerprint = {**BROWSER_FINGERPRINT, "platform": None}
    _register("sin-plataforma@example.com", fingerprint)
    assert fake_audit[0]["signals"]["device_family_size"] is None


def test_without_fingerprint_signal_is_none_and_nothing_stored(fake_audit, fake_fingerprints):
    client.post("/register", json={"email": "sin-huella@example.com"})
    assert fake_audit[0]["signals"]["device_family_size"] is None
    assert fake_fingerprints.rows == []


def test_block_and_rejections_do_not_store_fingerprint(monkeypatch, fake_fingerprints):
    # Con un peso de prueba, la cuarta cuenta de la granja llega a block.
    monkeypatch.setitem(risk_engine.WEIGHTS, "device_reuse_high", 90)
    for number in range(1, 4):
        _register(f"granja{number}@example.com")
    assert _register("granja4@example.com").status_code == 403
    assert _register("alguien@mailinator.com").status_code == 400
    # Solo las 3 primeras (allow) quedaron guardadas.
    assert len(fake_fingerprints.rows) == 3


def test_stored_fingerprint_has_hmac_not_email(fake_fingerprints):
    _register("Maria.Perez@Example.com")
    row = fake_fingerprints.rows[0]
    assert "maria" not in str(row).lower()
    assert len(row["email_hmac"]) == 64
    assert (row["platform"], row["screen_w"], row["timezone"]) == ("Win32", 1920, "America/Mexico_City")


def test_audit_record_keeps_same_columns(fake_audit):
    _register("columnas@example.com")
    assert set(fake_audit[0]) == {"email_hmac", "ip", "asn", "country", "timezone", "signals",
                                  "score", "action", "reasons", "unverified"}
