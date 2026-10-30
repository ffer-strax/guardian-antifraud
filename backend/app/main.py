import ipaddress
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import redis

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from services import asn_lookup, audit_log, geo_lookup, risk_engine
from services.email_utils import canonicalize_email, is_disposable
from services.mx_checker import NO_MAIL, check_mx
from services.rate_limiter import check_rate_limit

logger = logging.getLogger(__name__)

DEBUG_IP_HEADER = "X-Debug-Client-IP"

# Bases de las señales: las llena el lifespan al arrancar. None = no cargada, señal desconocida.
asn_db: asn_lookup.AsnDatabase | None = None
geo_db: geo_lookup.GeoDatabase | None = None


def _debug_ip_header_enabled() -> bool:
    return os.getenv("DEBUG_CLIENT_IP_HEADER", "").strip().lower() == "true"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Se carga todo al arrancar para que la primera petición no espere los ~4 s de carga.
    # Los loaders nunca lanzan: si un archivo falla, dejan una base vacía y un warning.
    global asn_db, geo_db
    asn_db = asn_lookup.get_default_db()
    geo_db = geo_lookup.get_default_geo_db()
    geo_lookup.get_country_timezones()
    # Si Postgres aún no está listo, la app arranca igual y la tabla se crea en la primera escritura.
    audit_log.ensure_table()
    if audit_log.uses_dev_hmac_key():
        logger.warning(
            "AUDIT_HMAC_KEY vacía: se usa la clave de desarrollo para el HMAC del correo. "
            "Nunca en producción."
        )
    if _debug_ip_header_enabled():
        logger.warning(
            "DEBUG_CLIENT_IP_HEADER=true: el header %s reemplaza la IP de las señales. "
            "Solo para pruebas; nunca activarlo en producción.",
            DEBUG_IP_HEADER,
        )
    yield


app = FastAPI(title="guardian-antifraud", lifespan=lifespan)


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


def _signals_ip(client_ip: str, request: Request) -> str:
    """IP para las señales: la real, o la del header de debug si el modo está activo y es válida."""
    if not _debug_ip_header_enabled():
        return client_ip
    header_value = request.headers.get(DEBUG_IP_HEADER)
    if header_value is None:
        return client_ip
    try:
        return str(ipaddress.ip_address(header_value.strip()))
    except ValueError:
        return client_ip


def _compute_signals(ip: str, timezone: str | None) -> dict:
    """Señales informativas de la IP; cada una es None cuando no se sabe."""
    asn = asn_db.lookup(ip) if asn_db is not None else None
    # Sin ASN no se puede saber si es hosting: None, no False.
    is_hosting = asn_lookup.is_hosting_asn(asn) if asn is not None else None
    country = geo_db.lookup(ip) if geo_db is not None else None
    return {
        "asn": asn,
        "is_hosting": is_hosting,
        "country": country,
        "timezone_matches_country": geo_lookup.timezone_matches_country(country, timezone),
    }


# Qué responde /register para cada acción del motor de riesgo: (código HTTP, status).
_ACTION_RESPONSES = {
    risk_engine.ALLOW: (200, "ok"),
    risk_engine.STEP_UP: (200, "verification_required"),
    risk_engine.REVIEW: (202, "pending_review"),
    risk_engine.BLOCK: (403, "blocked"),
}


def _audit_record(canonical: str, ip: str, ip_simulated: bool, timezone: str | None, action: str,
                  reasons: list[str], signals: dict | None = None,
                  risk: risk_engine.RiskResult | None = None) -> dict:
    """Arma la fila del audit log. El correo solo viaja como HMAC, nunca en claro."""
    audit_signals = dict(signals) if signals else None
    if ip_simulated:
        # Marca las filas cuya IP vino del header de debug, también en los 400 (signals NULL).
        audit_signals = {**(audit_signals or {}), "ip_simulated": True}
    return {
        "email_hmac": audit_log.email_hmac(canonical),
        "ip": ip,
        "asn": signals["asn"] if signals else None,
        "country": signals["country"] if signals else None,
        "timezone": timezone,
        "signals": audit_signals,
        "score": risk.score if risk else None,
        "action": action,
        "reasons": reasons,
        "unverified": risk.unverified if risk else None,
    }


def _reject(background_tasks: BackgroundTasks, record: dict, detail: str) -> JSONResponse:
    # Mismo cuerpo que daba HTTPException; se devuelve en vez de lanzarse porque
    # FastAPI no ejecuta las BackgroundTasks cuando el endpoint lanza una excepción.
    background_tasks.add_task(audit_log.write_audit, record)
    return JSONResponse(status_code=400, content={"detail": detail})


# Los nombres van en camelCase porque son los mismos que manda el navegador en el JSON.
# Campos extra se ignoran (extra="ignore") y todo es opcional: lo que el colector no pudo leer llega en null.
class ScreenInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    width: int | None = Field(default=None, ge=0, le=20000)
    height: int | None = Field(default=None, ge=0, le=20000)
    colorDepth: int | None = Field(default=None, ge=0, le=64)


class Fingerprint(BaseModel):
    """Huella del navegador. Por ahora solo se valida; no se guarda ni se compara."""

    model_config = ConfigDict(extra="ignore")

    canvasHash: str | None = Field(default=None, max_length=128)
    webglRenderer: str | None = Field(default=None, max_length=256)
    hardwareConcurrency: int | None = Field(default=None, ge=0, le=256)
    screen: ScreenInfo | None = None
    languages: list[Annotated[str, Field(max_length=35)]] | None = Field(default=None, max_length=10)
    platform: str | None = Field(default=None, max_length=64)
    maxTouchPoints: int | None = Field(default=None, ge=0, le=100)


class RegisterRequest(BaseModel):
    email: EmailStr
    # Zona horaria del navegador (ej. "Europe/Madrid"); opcional. Más de 64 caracteres -> 422.
    timezone: str | None = Field(default=None, max_length=64)
    fingerprint: Fingerprint | None = None


# En el repo es <raíz>/frontend; en Docker, /code/app/main.py -> /frontend (volumen de docker-compose).
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"


@app.get("/")
def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/collector.js")
def collector() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "collector.js", media_type="text/javascript")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/register")
def register(payload: RegisterRequest, request: Request, background_tasks: BackgroundTasks) -> JSONResponse:
    # La IP sale de la conexión TCP, nunca de cabeceras que manda el cliente.
    ip = request.client.host if request.client else "unknown"
    _enforce_limit(
        f"rl:ip:{ip}",
        _env_int("RATE_LIMIT_IP_MAX", 40),
        _env_int("RATE_LIMIT_IP_WINDOW_SECONDS", 60),
    )

    # El audit guarda la misma IP que usan las señales (la del header de debug si está activo).
    signals_ip = _signals_ip(ip, request)
    ip_simulated = signals_ip != ip

    canonical = canonicalize_email(payload.email)
    domain = canonical.rpartition("@")[2]
    if is_disposable(domain):
        record = _audit_record(canonical, signals_ip, ip_simulated, payload.timezone,
                               audit_log.REJECTED, ["disposable_domain"])
        return _reject(background_tasks, record, "disposable_domain")

    _enforce_limit(
        f"rl:email:{canonical}",
        _env_int("RATE_LIMIT_EMAIL_MAX", 5),
        _env_int("RATE_LIMIT_EMAIL_WINDOW_SECONDS", 600),
    )

    # "unknown" (timeout o error de DNS) deja pasar: no bloqueamos por fallos nuestros.
    dns_timeout_seconds = _env_int("MX_DNS_TIMEOUT_MS", 1000) / 1000
    if check_mx(redis_client, domain, dns_timeout_seconds) == NO_MAIL:
        record = _audit_record(canonical, signals_ip, ip_simulated, payload.timezone,
                               audit_log.REJECTED, ["domain_cannot_receive_mail"])
        return _reject(background_tasks, record, "domain_cannot_receive_mail")

    # El rate limit de arriba siempre usa la IP real; el header de debug solo afecta aquí.
    signals = _compute_signals(signals_ip, payload.timezone)
    risk = risk_engine.evaluate({**signals, "timezone": payload.timezone})

    # Se escribe después de enviar la respuesta: el audit no suma latencia.
    record = _audit_record(canonical, signals_ip, ip_simulated, payload.timezone, risk.action,
                           risk.reasons, signals, risk)
    background_tasks.add_task(audit_log.write_audit, record)

    status_code, status = _ACTION_RESPONSES[risk.action]
    response = {"status": status}
    if _debug_ip_header_enabled():
        # Fuera del modo debug no se devuelven, para no revelar qué reglas existen.
        response["debug_signals"] = signals
        response["debug_risk"] = asdict(risk)
    return JSONResponse(status_code=status_code, content=response)
