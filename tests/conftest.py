import dns.rdata
import pytest

from app import main
from services import audit_log, mx_checker


class FakeRedis:
    """Imita solo INCR, EXPIRE, TTL, GET y SET de Redis, guardando todo en dicts."""

    def __init__(self):
        self.counts = {}
        self.ttls = {}
        self.values = {}

    def incr(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    def expire(self, key, seconds):
        self.ttls[key] = seconds
        return True

    def ttl(self, key):
        return self.ttls.get(key, -1)

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, ex=None):
        # El Redis real devuelve bytes, así que el falso también.
        self.values[key] = value.encode()
        if ex is not None:
            self.ttls[key] = ex
        return True


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    # Cada test arranca con un Redis vacío, así los contadores no se mezclan.
    fake = FakeRedis()
    monkeypatch.setattr(main, "redis_client", fake)
    return fake


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    # Ningún test sale a la red: por defecto todo dominio tiene un MX válido.
    def resolve(domain, record_type, lifetime):
        return [dns.rdata.from_text("IN", "MX", "10 mx.test.")]

    monkeypatch.setattr(mx_checker, "_resolve", resolve)


@pytest.fixture(autouse=True)
def fake_audit(monkeypatch):
    # Ningún test toca Postgres: cada escritura del audit log queda en esta lista.
    records = []
    monkeypatch.setattr(audit_log, "write_audit", records.append)
    return records
