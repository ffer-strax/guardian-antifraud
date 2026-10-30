import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

# Misma conexión (variables y defaults de postgres) que el audit log, sin duplicarla.
from services.audit_log import _connect

logger = logging.getLogger(__name__)

# Presupuesto total de la búsqueda de candidatos, conexión incluida.
READ_TIMEOUT_SECONDS = 0.15

# Atributos estables con los que se filtran candidatos (los del índice compuesto).
STABLE_KEYS = ("platform", "hardware_concurrency", "screen_w", "screen_h")

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS device_fingerprints (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at            timestamptz NOT NULL DEFAULT now(),
    email_hmac            text NOT NULL,
    ip                    inet,
    canvas_hash           text,
    webgl_renderer        text,
    hardware_concurrency  smallint,
    screen_w              integer,
    screen_h              integer,
    color_depth           smallint,
    languages             jsonb,
    platform              text,
    max_touch_points      smallint,
    timezone              text
)
"""

# Estrategia de escala: solo se compara contra huellas con estos 4 atributos iguales,
# nunca contra toda la tabla.
CREATE_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS device_fingerprints_stable_idx
    ON device_fingerprints (platform, hardware_concurrency, screen_w, screen_h)
"""

INSERT_SQL = """
INSERT INTO device_fingerprints
    (email_hmac, ip, canvas_hash, webgl_renderer, hardware_concurrency, screen_w, screen_h,
     color_depth, languages, platform, max_touch_points, timezone)
VALUES
    (%(email_hmac)s, %(ip)s, %(canvas_hash)s, %(webgl_renderer)s, %(hardware_concurrency)s,
     %(screen_w)s, %(screen_h)s, %(color_depth)s, %(languages)s, %(platform)s,
     %(max_touch_points)s, %(timezone)s)
"""

SELECT_CANDIDATES_SQL = """
SELECT email_hmac, canvas_hash, webgl_renderer, hardware_concurrency, screen_w, screen_h,
       color_depth, languages, platform, max_touch_points, timezone
FROM device_fingerprints
WHERE platform = %(platform)s
  AND hardware_concurrency = %(hardware_concurrency)s
  AND screen_w = %(screen_w)s
  AND screen_h = %(screen_h)s
ORDER BY created_at DESC
LIMIT %(limit)s
"""

# Se pone en True cuando CREATE TABLE funcionó; si Postgres no estaba al arrancar, se reintenta al escribir.
_table_ready = False

# Hilos para las lecturas: así se puede dejar de esperar a los 150 ms aunque la conexión siga colgada.
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="fingerprint-read")


def ensure_table() -> bool:
    """Crea la tabla y el índice si no existen. Devuelve False si Postgres no está. Nunca lanza excepción."""
    global _table_ready
    try:
        with _connect() as conn:
            conn.execute(CREATE_TABLE_SQL)
            conn.execute(CREATE_INDEX_SQL)
    except Exception as exc:
        logger.warning("No se pudo crear la tabla device_fingerprints, se reintentará al escribir: %s",
                       type(exc).__name__)
        return False
    _table_ready = True
    return True


def _query_candidates(fingerprint: dict, limit: int) -> list[dict]:
    with _connect() as conn:
        # Corta también en el servidor una consulta lenta, no solo la espera en Python.
        conn.execute("SET statement_timeout = '150ms'")
        with conn.cursor(row_factory=dict_row) as cursor:
            cursor.execute(SELECT_CANDIDATES_SQL, {**{key: fingerprint[key] for key in STABLE_KEYS},
                                                   "limit": limit})
            return cursor.fetchall()


def find_candidates(fingerprint: dict, limit: int = 200) -> list[dict] | None:
    """Huellas más recientes con los 4 atributos estables iguales; None si no se pudo buscar."""
    if any(fingerprint.get(key) is None for key in STABLE_KEYS):
        # Sin esos atributos no hay forma de usar el índice: la señal queda sin verificar.
        return None
    future = _executor.submit(_query_candidates, fingerprint, limit)
    try:
        return future.result(timeout=READ_TIMEOUT_SECONDS)
    except Exception as exc:
        # Incluye TimeoutError. Solo el tipo: nunca datos del usuario ni el mensaje.
        logger.warning("No se pudieron leer huellas candidatas: %s", type(exc).__name__)
        return None


def _valid_ip_or_none(ip: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def save_fingerprint(record: dict) -> None:
    """Guarda una huella con una conexión nueva. Se llama en segundo plano. Nunca lanza excepción."""
    global _table_ready
    try:
        params = {**record, "ip": _valid_ip_or_none(record.get("ip"))}
        languages = record.get("languages")
        params["languages"] = Jsonb(languages) if languages is not None else None
        with _connect() as conn:
            if not _table_ready:
                conn.execute(CREATE_TABLE_SQL)
                conn.execute(CREATE_INDEX_SQL)
            conn.execute(INSERT_SQL, params)
        _table_ready = True
    except Exception as exc:
        logger.warning("No se pudo guardar la huella: %s", type(exc).__name__)
