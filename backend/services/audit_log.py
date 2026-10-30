import hashlib
import hmac
import ipaddress
import logging
import os

import psycopg
from psycopg.types.json import Jsonb

logger = logging.getLogger(__name__)

# Acción para los 400 (desechable, sin MX): el motor de riesgo no llegó a correr.
REJECTED = "rejected"

# Solo para desarrollo: con esta clave cualquiera que lea el código puede recalcular los HMAC.
DEV_HMAC_KEY = "dev-only-audit-key-no-usar-en-produccion"

# libpq no acepta menos de 2 s; evita que una escritura se cuelgue si Postgres no responde.
CONNECT_TIMEOUT_SECONDS = 2

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    email_hmac  text NOT NULL,
    ip          inet,
    asn         bigint,
    country     char(2),
    timezone    text,
    signals     jsonb,
    score       smallint,
    action      text NOT NULL,
    reasons     jsonb NOT NULL,
    unverified  jsonb
)
"""

INSERT_SQL = """
INSERT INTO audit_log
    (email_hmac, ip, asn, country, timezone, signals, score, action, reasons, unverified)
VALUES
    (%(email_hmac)s, %(ip)s, %(asn)s, %(country)s, %(timezone)s,
     %(signals)s, %(score)s, %(action)s, %(reasons)s, %(unverified)s)
"""

# Se pone en True cuando CREATE TABLE funcionó; si Postgres no estaba al arrancar, se reintenta al escribir.
_table_ready = False


def _hmac_key() -> str:
    return os.getenv("AUDIT_HMAC_KEY", "").strip() or DEV_HMAC_KEY


def uses_dev_hmac_key() -> bool:
    return _hmac_key() == DEV_HMAC_KEY


def email_hmac(canonical_email: str) -> str:
    """HMAC-SHA256 del correo canónico: permite agrupar por correo sin guardarlo en claro."""
    return hmac.new(_hmac_key().encode(), canonical_email.encode(), hashlib.sha256).hexdigest()


def _connect() -> psycopg.Connection:
    # Mismas variables y defaults que el servicio postgres de docker-compose.yml.
    return psycopg.connect(
        host=os.getenv("POSTGRES_HOST", "").strip() or "localhost",
        user=os.getenv("POSTGRES_USER", "").strip() or "guardian",
        password=os.getenv("POSTGRES_PASSWORD", "").strip() or "cambia_esto",
        dbname=os.getenv("POSTGRES_DB", "").strip() or "guardian",
        connect_timeout=CONNECT_TIMEOUT_SECONDS,
    )


def ensure_table() -> bool:
    """Crea la tabla si no existe. Devuelve False si Postgres no está disponible. Nunca lanza excepción."""
    global _table_ready
    try:
        with _connect() as conn:
            conn.execute(CREATE_TABLE_SQL)
    except Exception as exc:
        # Solo el tipo: el mensaje de psycopg puede traer host, usuario o datos del registro.
        logger.warning("No se pudo crear la tabla audit_log, se reintentará al escribir: %s",
                       type(exc).__name__)
        return False
    _table_ready = True
    return True


def _valid_ip_or_none(ip: str | None) -> str | None:
    # La columna es inet: "testclient" o "unknown" se guardan como NULL en vez de fallar el INSERT.
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def _jsonb_or_none(value):
    return Jsonb(value) if value is not None else None


def write_audit(record: dict) -> None:
    """Guarda una decisión en audit_log con una conexión nueva. Nunca lanza excepción."""
    global _table_ready
    try:
        params = {
            "email_hmac": record["email_hmac"],
            "ip": _valid_ip_or_none(record.get("ip")),
            "asn": record.get("asn"),
            "country": record.get("country"),
            "timezone": record.get("timezone"),
            "signals": _jsonb_or_none(record.get("signals")),
            "score": record.get("score"),
            "action": record["action"],
            "reasons": Jsonb(record.get("reasons") or []),
            "unverified": _jsonb_or_none(record.get("unverified")),
        }
        with _connect() as conn:
            if not _table_ready:
                conn.execute(CREATE_TABLE_SQL)
            conn.execute(INSERT_SQL, params)
        _table_ready = True
    except Exception as exc:
        # Solo el tipo de fallo: nunca correo, IP ni el mensaje de la excepción.
        logger.warning("No se pudo escribir en audit_log: %s", type(exc).__name__)
