import logging

import pytest
from fastapi.testclient import TestClient

from app import main
from app.main import _env_int

VAR = "RATE_LIMIT_IP_MAX"


def test_not_an_integer_uses_default_and_warns(monkeypatch, caplog):
    monkeypatch.setenv(VAR, "abc")
    with caplog.at_level(logging.WARNING):
        assert _env_int(VAR, 40) == 40
    assert VAR in caplog.text
    assert "abc" not in caplog.text  # el valor nunca aparece en el log


def test_empty_uses_default_without_warning(monkeypatch, caplog):
    monkeypatch.setenv(VAR, "")
    with caplog.at_level(logging.WARNING):
        assert _env_int(VAR, 40) == 40
    assert caplog.text == ""


def test_missing_uses_default_without_warning(monkeypatch, caplog):
    monkeypatch.delenv(VAR, raising=False)
    with caplog.at_level(logging.WARNING):
        assert _env_int(VAR, 40) == 40
    assert caplog.text == ""


def test_valid_value_is_used(monkeypatch):
    monkeypatch.setenv(VAR, "7")
    assert _env_int(VAR, 40) == 7


@pytest.mark.parametrize("value", ["0", "-5"])
def test_zero_or_negative_uses_default_and_warns(monkeypatch, caplog, value):
    monkeypatch.setenv(VAR, value)
    with caplog.at_level(logging.WARNING):
        assert _env_int(VAR, 40) == 40
    assert VAR in caplog.text


def test_register_does_not_fail_with_invalid_limit(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_IP_MAX", "abc")
    monkeypatch.setenv("RATE_LIMIT_EMAIL_WINDOW_SECONDS", "-1")
    response = TestClient(main.app).post("/register", json={"email": "user@example.com"})
    assert response.status_code == 200
