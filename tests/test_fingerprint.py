import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

# Huella con la forma exacta que manda frontend/collector.js.
VALID_FINGERPRINT = {
    "canvasHash": "a" * 64,
    "webglRenderer": "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "hardwareConcurrency": 8,
    "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
    "languages": ["es-MX", "es", "en"],
    "platform": "Win32",
    "maxTouchPoints": 0,
}


def _register(fingerprint):
    body = {"email": "user@example.com", "timezone": "America/Mexico_City", "fingerprint": fingerprint}
    return client.post("/register", json=body)


def test_valid_fingerprint_returns_200():
    response = _register(VALID_FINGERPRINT)
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_without_fingerprint_returns_200():
    response = client.post("/register", json={"email": "user@example.com"})
    assert response.status_code == 200


def test_all_null_fields_return_200():
    # Lo que el colector no puede leer llega en null.
    nulls = {key: None for key in VALID_FINGERPRINT}
    assert _register(nulls).status_code == 200


def test_extra_fields_are_ignored():
    fingerprint = {**VALID_FINGERPRINT, "audio": "x" * 5000, "screen": {"width": 800, "pixelRatio": 2}}
    assert _register(fingerprint).status_code == 200


@pytest.mark.parametrize("field, value", [
    ("canvasHash", "a" * 129),
    ("webglRenderer", "r" * 257),
    ("platform", "p" * 65),
    ("languages", ["es"] * 11),
    ("languages", ["x" * 36]),
    ("hardwareConcurrency", 257),
    ("hardwareConcurrency", -1),
    ("maxTouchPoints", 101),
    ("screen", {"width": 20001}),
    ("screen", {"height": -1}),
])
def test_out_of_limit_field_returns_422(field, value):
    assert _register({**VALID_FINGERPRINT, field: value}).status_code == 422


def test_root_serves_registration_page():
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert '<form id="register-form">' in response.text
    assert "IP Geolocation by DB-IP" in response.text


def test_collector_script_is_served():
    response = client.get("/collector.js")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/javascript")
    assert "collectFingerprint" in response.text
