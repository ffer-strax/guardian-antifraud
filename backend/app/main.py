import logging
import os

import redis

from fastapi import FastAPI, HTTPException, Request

from pydantic import BaseModel, EmailStr

from services.email_utils import canonicalize_email, is_disposable
from services.mx_checker import NO_MAIL, check_mx
from services.rate_limiter import check_rate_limit

logger = logging.getLogger(__name__)

app = FastAPI(title="guardian-antifraud")


def _env_int(name: str, default: int) -> int:
    """Lee un entero positivo del entorno; si falta o es inválido, usa el default."""
    value = os.getenv(name, "").strip()
    if not value:
        return default
    # En los warnings va solo el nombre: el valor podría ser un secreto mal colocado.
    try:
        number = int(value)
    except ValueError:
        logger.warning("%s no es un entero, se usa el default %s", name, default)
        return default
    if number <= 0:
        logger.warning("%s debe ser mayor que 0, se usa el default %s", name, default)
        return default
    return number


_redis_timeout_seconds = _env_int("REDIS_TIMEOUT_MS", 200) / 1000

redis_client = redis.Redis.from_url(
    os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    socket_connect_timeout=_redis_timeout_seconds,
    socket_timeout=_redis_timeout_seconds,
)


def _enforce_limit(key: str, limit: int, window_seconds: int) -> None:
    allowed, retry_after = check_rate_limit(redis_client, key, limit, window_seconds)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="rate_limited",
            headers={"Retry-After": str(retry_after)},
        )


class RegisterRequest(BaseModel):
    email: EmailStr


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/register")
def register(payload: RegisterRequest, request: Request) -> dict:
    # La IP sale de la conexión TCP, nunca de cabeceras que manda el cliente.
    ip = request.client.host if request.client else "unknown"
    _enforce_limit(
        f"rl:ip:{ip}",
        _env_int("RATE_LIMIT_IP_MAX", 40),
        _env_int("RATE_LIMIT_IP_WINDOW_SECONDS", 60),
    )

    canonical = canonicalize_email(payload.email)
    domain = canonical.rpartition("@")[2]
    if is_disposable(domain):
        raise HTTPException(status_code=400, detail="disposable_domain")

    _enforce_limit(
        f"rl:email:{canonical}",
        _env_int("RATE_LIMIT_EMAIL_MAX", 5),
        _env_int("RATE_LIMIT_EMAIL_WINDOW_SECONDS", 600),
    )

    # "unknown" (timeout o error de DNS) deja pasar: no bloqueamos por fallos nuestros.
    dns_timeout_seconds = _env_int("MX_DNS_TIMEOUT_MS", 1000) / 1000
    if check_mx(redis_client, domain, dns_timeout_seconds) == NO_MAIL:
        raise HTTPException(status_code=400, detail="domain_cannot_receive_mail")
    return {"status": "ok"}
