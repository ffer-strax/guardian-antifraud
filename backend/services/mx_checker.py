import logging

import dns.resolver
import redis

logger = logging.getLogger(__name__)

OK = "ok"
NO_MAIL = "no_mail"
UNKNOWN = "unknown"

CACHE_TTL_SECONDS = 3600


def _resolve(domain: str, record_type: str, lifetime: float) -> list:
    """Única función que habla con el DNS; los tests la sustituyen."""
    return list(dns.resolver.resolve(domain, record_type, lifetime=lifetime))


def _records_or_empty(domain: str, record_type: str, lifetime: float) -> list:
    # NoAnswer: el dominio existe pero no tiene registros de ese tipo.
    try:
        return _resolve(domain, record_type, lifetime)
    except dns.resolver.NoAnswer:
        return []


def _is_null_mx(mx_records: list) -> bool:
    # RFC 7505: un único MX apuntando a "." significa "este dominio no recibe correo".
    return len(mx_records) == 1 and str(mx_records[0].exchange) == "."


def _query_dns(domain: str, lifetime: float) -> str:
    try:
        mx_records = _records_or_empty(domain, "MX", lifetime)
        if mx_records:
            return NO_MAIL if _is_null_mx(mx_records) else OK
        # Sin MX, el correo se entrega al registro A del dominio (RFC 5321).
        if _records_or_empty(domain, "A", lifetime):
            return OK
        return NO_MAIL
    except dns.resolver.NXDOMAIN:
        return NO_MAIL
    except Exception as exc:
        # Timeout, servidores caídos o cualquier otro fallo: no sabemos, no bloqueamos.
        logger.warning("Consulta DNS fallida para %s: %s", domain, type(exc).__name__)
        return UNKNOWN


def check_mx(client: redis.Redis, domain: str, lifetime: float) -> str:
    """Devuelve "ok", "no_mail" o "unknown". Nunca lanza excepción."""
    key = f"mx:{domain}"
    try:
        cached = client.get(key)
        if cached is not None:
            return cached.decode()
    except redis.RedisError as exc:
        logger.warning("Redis no disponible al leer la caché MX de %s: %s", domain, exc)

    status = _query_dns(domain, lifetime)

    # "unknown" no se guarda: el siguiente intento debe volver a preguntar al DNS.
    if status != UNKNOWN:
        try:
            client.set(key, status, ex=CACHE_TTL_SECONDS)
        except redis.RedisError as exc:
            logger.warning("Redis no disponible al guardar la caché MX de %s: %s", domain, exc)
    return status
