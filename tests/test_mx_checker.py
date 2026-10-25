import logging

import dns.exception
import dns.rdata
import dns.resolver
import redis
from fastapi.testclient import TestClient

from app import main
from services import mx_checker
from services.mx_checker import check_mx

client = TestClient(main.app)

MX = [dns.rdata.from_text("IN", "MX", "10 mx.test.")]
NULL_MX = [dns.rdata.from_text("IN", "MX", "0 .")]
A = [dns.rdata.from_text("IN", "A", "192.0.2.1")]


def fake_resolver(monkeypatch, answers):
    """answers: {"MX": lista o excepción, "A": lista o excepción}. Devuelve la lista de llamadas."""
    calls = []

    def resolve(domain, record_type, lifetime):
        calls.append((domain, record_type))
        answer = answers.get(record_type, dns.resolver.NoAnswer())
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(mx_checker, "_resolve", resolve)
    return calls


def test_domain_with_mx_is_ok(monkeypatch, fake_redis):
    fake_resolver(monkeypatch, {"MX": MX})
    assert check_mx(fake_redis, "conmx.example.com", 1.0) == "ok"


def test_domain_without_mx_but_with_a_is_ok(monkeypatch, fake_redis):
    calls = fake_resolver(monkeypatch, {"MX": dns.resolver.NoAnswer(), "A": A})
    assert check_mx(fake_redis, "soloa.example.com", 1.0) == "ok"
    assert calls == [("soloa.example.com", "MX"), ("soloa.example.com", "A")]


def test_domain_without_mx_nor_a_is_no_mail(monkeypatch, fake_redis):
    fake_resolver(monkeypatch, {"MX": dns.resolver.NoAnswer(), "A": dns.resolver.NoAnswer()})
    assert check_mx(fake_redis, "vacio.example.com", 1.0) == "no_mail"


def test_null_mx_is_no_mail(monkeypatch, fake_redis):
    fake_resolver(monkeypatch, {"MX": NULL_MX})
    assert check_mx(fake_redis, "nullmx.example.com", 1.0) == "no_mail"


def test_nxdomain_returns_400(monkeypatch):
    fake_resolver(monkeypatch, {"MX": dns.resolver.NXDOMAIN()})
    response = client.post("/register", json={"email": "user@noexiste.example.com"})
    assert response.status_code == 400
    assert response.json() == {"detail": "domain_cannot_receive_mail"}


def test_timeout_returns_200_and_is_not_cached(monkeypatch, fake_redis, caplog):
    fake_resolver(monkeypatch, {"MX": dns.exception.Timeout()})
    with caplog.at_level(logging.WARNING):
        response = client.post("/register", json={"email": "secreto@lento.example.com"})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "lento.example.com" in caplog.text
    assert "secreto" not in caplog.text  # solo el dominio, nunca la parte local
    assert "mx:lento.example.com" not in fake_redis.values


def test_redis_down_with_good_dns_returns_200(monkeypatch):
    fake_resolver(monkeypatch, {"MX": MX})
    broken = redis.Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.5)
    monkeypatch.setattr(main, "redis_client", broken)
    response = client.post("/register", json={"email": "user@conmx.example.com"})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_second_lookup_comes_from_cache(monkeypatch, fake_redis):
    calls = fake_resolver(monkeypatch, {"MX": MX})
    assert check_mx(fake_redis, "cache.example.com", 1.0) == "ok"
    assert check_mx(fake_redis, "cache.example.com", 1.0) == "ok"
    assert calls == [("cache.example.com", "MX")]  # el DNS se consultó una sola vez
    assert fake_redis.ttls["mx:cache.example.com"] == 3600
