import re
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main
from services import asn_lookup, geo_lookup
from services.asn_lookup import AsnDatabase
from services.behavior_signals import Behavior, compute_behavior_signals, parse_behavior
from services.geo_lookup import GeoDatabase
from services.risk_engine import evaluate

client = TestClient(main.app)

# Comportamiento de una persona normal: ninguna señal se cumple.
HUMAN = {
    "key_count": 20,
    "dwell_mean_ms": 95.0,
    "dwell_std_ms": 30.0,
    "flight_mean_ms": 140.0,
    "flight_std_ms": 60.0,
    "paste_used": False,
    "mouse_move_count": 120,
    "path_length_px": 2400.0,
    "net_displacement_px": 900.0,
    "straightness": 0.375,
    "speed_cv": 0.9,
    "click_count": 2,
    "pointer_kind": "mouse",
    "time_to_submit_ms": 9000.0,
}

SIX_SIGNALS = ["form_too_fast", "keystroke_uniform", "dwell_uniform",
               "mouse_linear", "no_mouse_movement", "no_keyboard_events"]

# Agregados crudos que NO deben llegar al audit log (solo time_to_submit_ms y pointer_kind sí).
RAW_AGGREGATES = ["key_count", "dwell_mean_ms", "dwell_std_ms", "flight_mean_ms", "flight_std_ms",
                  "paste_used", "mouse_move_count", "path_length_px", "net_displacement_px",
                  "straightness", "speed_cv", "click_count"]


def _signals(**changes):
    return compute_behavior_signals(Behavior(**{**HUMAN, **changes}))


# --- Cada señal en su umbral exacto ---

def test_example_human_triggers_nothing():
    result = _signals()
    assert all(result[name] is False for name in SIX_SIGNALS)
    assert result["behavior_missing"] is False


@pytest.mark.parametrize("ms, expected", [(1999.9, True), (2000, False)])
def test_form_too_fast_threshold(ms, expected):
    assert _signals(time_to_submit_ms=ms)["form_too_fast"] is expected


@pytest.mark.parametrize("keys, std, expected", [(8, 14.9, True), (8, 15, False), (7, 1.0, None)])
def test_keystroke_uniform_threshold(keys, std, expected):
    assert _signals(key_count=keys, flight_std_ms=std)["keystroke_uniform"] is expected


@pytest.mark.parametrize("keys, std, expected", [(8, 7.9, True), (8, 8, False), (7, 1.0, None)])
def test_dwell_uniform_threshold(keys, std, expected):
    assert _signals(key_count=keys, dwell_std_ms=std)["dwell_uniform"] is expected


@pytest.mark.parametrize("moves, straightness, expected", [
    (20, 0.9801, True),
    (20, 0.98, False),
    (19, 1.0, None),
])
def test_mouse_linear_threshold(moves, straightness, expected):
    assert _signals(mouse_move_count=moves, straightness=straightness)["mouse_linear"] is expected


@pytest.mark.parametrize("moves, expected", [(0, True), (1, False)])
def test_no_mouse_movement_threshold(moves, expected):
    result = _signals(mouse_move_count=moves, path_length_px=0, net_displacement_px=0, straightness=None)
    assert result["no_mouse_movement"] is expected


@pytest.mark.parametrize("keys, paste, expected", [
    (0, False, True),
    (0, True, False),
    (1, False, False),
    (0, None, None),
])
def test_no_keyboard_events_threshold(keys, paste, expected):
    assert _signals(key_count=keys, paste_used=paste)["no_keyboard_events"] is expected


# --- Datos faltantes, exención táctil, bloque ausente ---

def test_empty_block_leaves_signals_unverified():
    result = compute_behavior_signals(Behavior())
    assert all(result[name] is None for name in SIX_SIGNALS)
    assert result["behavior_missing"] is False


def test_missing_block_sets_behavior_missing():
    result = compute_behavior_signals(None)
    assert result["behavior_missing"] is True
    assert all(result[name] is None for name in SIX_SIGNALS)


def test_touch_exempts_mouse_signals():
    # Sin ratón en móvil: las dos señales de ratón quedan en None aunque los datos "se cumplan".
    result = _signals(pointer_kind="touch", mouse_move_count=50, straightness=1.0)
    assert result["mouse_linear"] is None
    assert result["no_mouse_movement"] is None
    # Las de teclado y tiempo se siguen evaluando.
    assert result["keystroke_uniform"] is False
    assert result["form_too_fast"] is False


def test_unknown_pointer_leaves_mouse_signals_unverified():
    result = _signals(pointer_kind="unknown", mouse_move_count=0)
    assert result["mouse_linear"] is None
    assert result["no_mouse_movement"] is None


# --- Validación del bloque ---

@pytest.mark.parametrize("raw", [
    {**HUMAN, "key_count": -1},
    {**HUMAN, "time_to_submit_ms": 86_400_001},
    {**HUMAN, "mouse_move_count": 501},
    {**HUMAN, "straightness": 1.5},
    {**HUMAN, "pointer_kind": "robot"},
    {**HUMAN, "key_count": "muchas"},
    {**HUMAN, "speed_cv": float("nan")},
    {**HUMAN, "net_displacement_px": 5000.0, "path_length_px": 100.0},
    "no-es-un-objeto",
    [1, 2, 3],
])
def test_invalid_block_is_ignored(raw):
    assert parse_behavior(raw) is None


def test_extra_fields_are_dropped():
    parsed = parse_behavior({**HUMAN, "keys": ["h", "o", "l", "a"], "mouse_path": [[10, 20], [30, 40]]})
    assert parsed is not None
    dumped = parsed.model_dump()
    assert "keys" not in dumped
    assert "mouse_path" not in dumped


# --- Pesos en el motor ---

@pytest.mark.parametrize("name, weight", [
    ("form_too_fast", 30), ("keystroke_uniform", 25), ("dwell_uniform", 15), ("mouse_linear", 20),
    ("no_mouse_movement", 5), ("no_keyboard_events", 10), ("behavior_missing", 10),
])
def test_each_behavior_signal_adds_its_weight(name, weight):
    signals = {key: False for key in SIX_SIGNALS + ["behavior_missing"]}
    result = evaluate({**signals, name: True, "is_hosting": False,
                       "timezone_matches_country": True, "timezone": "Europe/Madrid", "device_family_size": 0})
    assert result.score == weight
    assert result.reasons == [name]
    assert result.unverified == []


def test_score_stays_capped_at_100():
    signals = {key: True for key in SIX_SIGNALS}
    result = evaluate({**signals, "is_hosting": True, "timezone_matches_country": False,
                       "timezone": "Europe/Madrid", "device_family_size": 5, "behavior_missing": False})
    assert result.score == 100


# --- Integración con /register ---

def _register(behavior, email="persona@example.com", **extra):
    return client.post("/register", json={"email": email, "behavior": behavior, **extra})


@pytest.mark.parametrize("bad", [{**HUMAN, "key_count": -5}, "texto", 12345, [HUMAN]])
def test_invalid_block_never_breaks_register(fake_audit, bad):
    response = _register(bad)
    assert response.status_code == 200
    record = fake_audit[0]
    assert "behavior_missing" in record["reasons"]
    assert all(name in record["unverified"] for name in SIX_SIGNALS)


def test_human_behavior_adds_no_points(fake_audit):
    assert _register(HUMAN).json() == {"status": "ok"}
    record = fake_audit[0]
    assert not any(name in record["reasons"] for name in SIX_SIGNALS + ["behavior_missing"])


def test_audit_stores_booleans_but_not_raw_aggregates(fake_audit):
    _register({**HUMAN, "time_to_submit_ms": 1500.0})
    stored = fake_audit[0]["signals"]
    assert stored["form_too_fast"] is True
    assert stored["behavior_missing"] is False
    assert stored["time_to_submit_ms"] == 1500.0
    assert stored["pointer_kind"] == "mouse"
    assert not any(name in stored for name in RAW_AGGREGATES)


def test_raw_keys_and_coordinates_are_never_stored(fake_audit, monkeypatch):
    monkeypatch.setenv("DEBUG_CLIENT_IP_HEADER", "true")
    raw = {**HUMAN, "keys": ["q", "w", "e", "r", "t", "y"], "mouse_path": [[123, 456], [789, 1011]]}
    response = _register(raw)
    # Sin el email_hmac: un hash hexadecimal podría contener "123" por casualidad.
    stored = str({key: value for key, value in fake_audit[0].items() if key != "email_hmac"})
    for leaked in ["'q'", "'keys'", "mouse_path", "123", "456", "789", "1011"]:
        assert leaked not in stored
    assert "mouse_path" not in response.text
    assert '"keys"' not in response.text


COLLECTOR = Path(__file__).resolve().parents[1] / "frontend" / "collector.js"

ALLOWED_BEHAVIOR_KEYS = set(RAW_AGGREGATES) | {"pointer_kind", "time_to_submit_ms"}


def test_collector_payload_has_only_aggregates():
    # Sin un navegador en la CI, se revisa el objeto que arma collectBehavior en el código fuente.
    source = COLLECTOR.read_text(encoding="utf-8")
    body = source.split("function collectBehavior(", 1)[1].split("\n}\n", 1)[0]
    returned = body.split("return {", 1)[1]
    keys = set(re.findall(r"^    (\w+):", returned, flags=re.MULTILINE))
    assert keys == ALLOWED_BEHAVIOR_KEYS
    # Nada que identifique la tecla ni coordenadas crudas sale en el objeto enviado.
    for forbidden in ["event.key", "event.code", "clientX", "clientY", "keyDownAt"]:
        assert forbidden not in returned


# --- Caso completo que llega a block ---

def _int(ip: str) -> int:
    return int(IPv4Address(ip))


FINGERPRINT = {
    "canvasHash": "a" * 64,
    "webglRenderer": "ANGLE (Intel HD 530)",
    "hardwareConcurrency": 8,
    "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
    "languages": ["es-MX", "es"],
    "platform": "Win32",
    "maxTouchPoints": 0,
}


def test_end_to_end_reaches_block(fake_audit, fake_fingerprints, monkeypatch):
    # IP de hosting en US y zona de Madrid: hosting 25 + mismatch 10.
    monkeypatch.setattr(main, "asn_db", AsnDatabase({16: {_int("3.5.0.0"): 64512}}))
    monkeypatch.setattr(main, "geo_db", GeoDatabase([_int("3.5.0.0")], [_int("3.5.255.255")], ["US"]))
    monkeypatch.setattr(asn_lookup, "_hosting_asns", frozenset({64512}))
    monkeypatch.setattr(geo_lookup, "_country_timezones", {"US": frozenset({"America/New_York"})})
    monkeypatch.setenv("DEBUG_CLIENT_IP_HEADER", "true")

    # Tres cuentas previas con el mismo dispositivo (sin header: IP de TestClient, sin hosting).
    for number in range(1, 4):
        _register(HUMAN, email=f"granja{number}@example.com", timezone="Europe/Madrid", fingerprint=FINGERPRINT)

    # La cuarta: reuse_high 35 + formulario enviado en 0.5 s, 30.
    response = client.post(
        "/register",
        json={"email": "granja4@example.com", "timezone": "Europe/Madrid", "fingerprint": FINGERPRINT,
              "behavior": {**HUMAN, "time_to_submit_ms": 500.0}},
        headers={main.DEBUG_IP_HEADER: "3.5.0.10"},
    )
    assert response.status_code == 403
    assert response.json()["status"] == "blocked"
    record = fake_audit[-1]
    assert record["score"] == 100
    assert record["action"] == "block"
    assert record["reasons"] == ["hosting_ip", "tz_country_mismatch", "device_reuse_high", "form_too_fast"]
