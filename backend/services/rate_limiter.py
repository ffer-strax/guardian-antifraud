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
        logger.warning("Redis no disponible, se omite el rate limit de %s: %s", _limit_type(key), exc)
        return True, 0


def _limit_type(key: str) -> str:
    # "rl:ip:203.0.113.7" -> "ip". El identificador (IP o correo) nunca se registra.
    # maxsplit=2 porque una IPv6 también lleva ":".
    parts = key.split(":", 2)
    return parts[1] if len(parts) == 3 else "desconocido"
