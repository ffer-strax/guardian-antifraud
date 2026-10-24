import logging

import redis

logger = logging.getLogger(__name__)


def check_rate_limit(client: redis.Redis, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
    """Ventana fija: devuelve (permitido, segundos_para_reinicio)."""
    try:
        count = client.incr(key)
        if count == 1:
            client.expire(key, window_seconds)
        ttl = client.ttl(key)
        if ttl < 0:
            # La clave quedó sin expiración (p. ej. el proceso murió entre INCR y EXPIRE).
            client.expire(key, window_seconds)
            ttl = window_seconds
        return count <= limit, ttl
    except redis.RedisError as exc:
        logger.warning("Redis no disponible, se omite el rate limit para %s: %s", key, exc)
        return True, 0
