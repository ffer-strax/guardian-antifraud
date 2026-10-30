import logging
from ipaddress import IPv4Address

import pytest
from fastapi.testclient import TestClient

from app import main
from services import asn_lookup, geo_lookup, risk_engine
from services.asn_lookup import AsnDatabase
from services.geo_lookup import GeoDatabase

# Sin "with", TestClient no ejecuta el lifespan: nunca se cargan los archivos reales.
client = TestClient(main.app)

# IPs de prueba: los números son inventados, solo importa que caigan en estos rangos.
ES_IP = "2.136.0.10"
HOSTING_IP = "3.5.0.10"
HOSTING_ASN = 64512


def _int(ip: str) -> int:
    return int(IPv4Address(ip))


@pytest.fixture
def small_dbs(monkeypatch):
    asn_db = AsnDatabase({16: {_int("2.136.0.0"): 3352, _int("3.5.0.0"): HOSTING_ASN}})
    geo_db = GeoDatabase(
        [_int("2.136.0.0"), _int("3.5.0.0")],
        [_int("2.139.255.255"), _int("3.5.255.255")],
        ["ES", "US"],
    )
    monkeypatch.setattr(main, "asn_db", asn_db)
    monkeypatch.setattr(main, "geo_db", geo_db)
    monkeypatch.setattr(asn_lookup, "_hosting_asns", frozenset({HOSTING_ASN}))
    monkeypatch.setattr(geo_lookup, "_country_timezones", {
        "ES": frozenset({"Europe/Madrid", "Atlantic/Canary", "Africa/Ceuta"}),
        "MX": frozenset({"America/Mexico_City"}),
    })


@pytest.fixture
def debug_mode(monkeypatch, small_dbs):
    monkeypatch.setenv("DEBUG_CLIENT_IP_HEADER", "true")


def _register(ip: str | None = None, timezone: str | None = None, email: str = "user@example.com"):
    body = {"email": email}
    if timezone is not None:
        body["timezone"] = timezone
    headers = {main.DEBUG_IP_HEADER: ip} if ip is not None else {}
    return client.post("/register", json=body, headers=headers)


def test_es_ip_with_canary_timezone_matches(debug_mode):
    response = _register(ES_IP, "Atlantic/Canary")
    assert response.status_code == 200
    assert response.json()["debug_signals"] == {
        "asn": 3352,
        "is_hosting": False,
        "country": "ES",
        "timezone_matches_country": True,
        "device_family_size": None,
        "form_too_fast": None,
        "keystroke_uniform": None,
        "dwell_uniform": None,
        "mouse_linear": None,
        "no_mouse_movement": None,
        "no_keyboard_events": None,
        "behavior_missing": True,
        "time_to_submit_ms": None,
        "pointer_kind": None,
    }


def test_es_ip_with_mexico_timezone_does_not_match(debug_mode):
    signals = _register(ES_IP, "America/Mexico_City").json()["debug_signals"]
    assert signals["timezone_matches_country"] is False


def test_without_timezone_match_is_none(debug_mode):
    signals = _register(ES_IP).json()["debug_signals"]
    assert signals["country"] == "ES"
    assert signals["timezone_matches_country"] is None


def test_header_without_debug_mode_hides_signals(small_dbs, monkeypatch):
    monkeypatch.delenv("DEBUG_CLIENT_IP_HEADER", raising=False)
    response = _register(ES_IP, "Atlantic/Canary")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_invalid_header_is_ignored(debug_mode):
    # Se usa la IP real de TestClient ("testclient", que no es IP): todo desconocido.
    signals = _register("no-es-una-ip", "Atlantic/Canary").json()["debug_signals"]
    assert signals == {
        "asn": None,
        "is_hosting": None,
        "country": None,
        "timezone_matches_country": None,
        "device_family_size": None,
        "form_too_fast": None,
        "keystroke_uniform": None,
        "dwell_uniform": None,
        "mouse_linear": None,
        "no_mouse_movement": None,
        "no_keyboard_events": None,
        "behavior_missing": True,
        "time_to_submit_ms": None,
        "pointer_kind": None,
    }


def test_hosting_asn_detected(debug_mode):
    signals = _register(HOSTING_IP).json()["debug_signals"]
    assert signals["asn"] == HOSTING_ASN
    assert signals["is_hosting"] is True
    assert signals["country"] == "US"


def test_debug_header_never_changes_rate_limit_ip(debug_mode, monkeypatch):
    # Con otra IP en el header la petición sigue contando para la IP real.
    monkeypatch.setenv("RATE_LIMIT_IP_MAX", "1")
    assert _register(ES_IP, email="a@example.com").status_code == 200
    assert _register(HOSTING_IP, email="b@example.com").status_code == 429


def test_hosting_ip_with_mismatched_timezone_requires_verification(debug_mode, monkeypatch):
    # HOSTING_IP es de US en la base pequeña; se agrega US al mapa para que Europe/Madrid no coincida.
    monkeypatch.setattr(geo_lookup, "_country_timezones", {"US": frozenset({"America/New_York"})})
    response = _register(HOSTING_IP, "Europe/Madrid")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "verification_required"
    assert body["debug_risk"] == {
        "score": 45,
        "action": "step_up",
        "reasons": ["hosting_ip", "tz_country_mismatch", "behavior_missing"],
        "unverified": ["device_reuse_low", "device_reuse_high", "form_too_fast", "keystroke_uniform", "dwell_uniform",
                       "mouse_linear", "no_mouse_movement", "no_keyboard_events"],
    }


def test_normal_ip_is_allowed(debug_mode):
    response = _register(ES_IP, "Europe/Madrid")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["debug_risk"]["score"] == 10
    assert body["debug_risk"]["action"] == "allow"


def test_risk_hidden_without_debug_mode(small_dbs, monkeypatch):
    monkeypatch.delenv("DEBUG_CLIENT_IP_HEADER", raising=False)
    monkeypatch.setattr(geo_lookup, "_country_timezones", {"US": frozenset({"America/New_York"})})
    # Sin modo debug el header se ignora, así que tampoco hay IP de hosting: solo "ok".
    assert _register(HOSTING_IP, "Europe/Madrid").json() == {"status": "ok"}


def test_risk_engine_failure_allows_and_logs_no_personal_data(small_dbs, monkeypatch, caplog):
    # Una regla que revienta con el correo y la IP en el mensaje: si el log copiara el
    # mensaje de la excepción, esos datos aparecerían en caplog.
    def broken_rule(signals):
        raise RuntimeError("fallo con maria.perez@example.com desde testclient")

    monkeypatch.setitem(risk_engine._RULES, "hosting_ip", broken_rule)
    monkeypatch.delenv("DEBUG_CLIENT_IP_HEADER", raising=False)

    with caplog.at_level(logging.WARNING):
        response = _register(email="maria.perez@example.com")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "Fallo al evaluar el riesgo, se permite: RuntimeError" in caplog.text
    # TestClient se conecta con la IP "testclient": es lo que recibe request.client.host.
    assert "testclient" not in caplog.text
    assert "maria.perez" not in caplog.text


def test_timezone_longer_than_64_returns_422(small_dbs):
    assert _register(timezone="A" * 64).status_code == 200
    assert _register(timezone="A" * 65, email="otro@example.com").status_code == 422


def test_unloaded_dbs_give_none(monkeypatch):
    # Sin lifespan ni bases inyectadas, las señales quedan desconocidas y /register sigue igual.
    monkeypatch.setenv("DEBUG_CLIENT_IP_HEADER", "true")
    monkeypatch.setattr(main, "asn_db", None)
    monkeypatch.setattr(main, "geo_db", None)
    response = _register(ES_IP, "Atlantic/Canary")
    assert response.status_code == 200
    assert response.json()["debug_signals"]["country"] is None
