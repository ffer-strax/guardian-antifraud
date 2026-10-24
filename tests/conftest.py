import pytest

from app import main


class FakeRedis:
    """Imita solo INCR, EXPIRE y TTL de Redis, guardando todo en un dict."""

    def __init__(self):
        self.counts = {}
        self.ttls = {}

    def incr(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    def expire(self, key, seconds):
        self.ttls[key] = seconds
        return True

    def ttl(self, key):
        return self.ttls.get(key, -1)


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    # Cada test arranca con un Redis vacío, así los contadores no se mezclan.
    fake = FakeRedis()
    monkeypatch.setattr(main, "redis_client", fake)
    return fake
