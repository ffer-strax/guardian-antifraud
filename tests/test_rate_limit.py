import logging

import redis
from fastapi.testclient import TestClient

from app import main

client = TestClient(main.app)


def test_within_limit_passes(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_IP_MAX", "3")
    for i in range(3):
        response = client.post("/register", json={"email": f"user{i}@example.com"})
        assert response.status_code == 200


def test_ip_limit_exceeded_returns_429(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_IP_MAX", "2")
    monkeypatch.setenv("RATE_LIMIT_IP_WINDOW_SECONDS", "60")
    for i in range(2):
        assert client.post("/register", json={"email": f"user{i}@example.com"}).status_code == 200

    response = client.post("/register", json={"email": "otro@example.com"})
    assert response.status_code == 429
    assert response.json() == {"detail": "rate_limited"}
    assert response.headers["Retry-After"] == "60"


def test_canonical_email_limit_exceeded_returns_429(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_EMAIL_MAX", "2")
    monkeypatch.setenv("RATE_LIMIT_EMAIL_WINDOW_SECONDS", "600")
    # Las tres variantes tienen el mismo email canónico: juanlopez@gmail.com
    assert client.post("/register", json={"email": "juan.lopez+1@gmail.com"}).status_code == 200
    assert client.post("/register", json={"email": "juanlopez@gmail.com"}).status_code == 200

    response = client.post("/register", json={"email": "Juan.Lopez+2@googlemail.com"})
    assert response.status_code == 429
    assert response.json() == {"detail": "rate_limited"}
    assert response.headers["Retry-After"] == "600"


def test_redis_down_still_returns_200(monkeypatch, caplog):
    # Cliente real apuntando a un puerto donde no hay nada: la conexión falla de verdad.
    broken = redis.Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.5)
    monkeypatch.setattr(main, "redis_client", broken)

    with caplog.at_level(logging.WARNING):
        response = client.post("/register", json={"email": "user@example.com"})

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "Redis no disponible" in caplog.text
