import bisect
import gzip
import ipaddress
import logging
import socket
import sys
import threading
import zlib
from pathlib import Path

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_DEFAULT_GEO_DB_PATH = _DATA_DIR / "dbip-country-lite-2026-10.csv.gz"
_COUNTRY_TIMEZONES_PATH = _DATA_DIR / "country_timezones.txt"

# DB-IP usa "ZZ" para rangos sin país asignado (reservados, sin anunciar, etc.).
_UNKNOWN_COUNTRY = "ZZ"

# Zonas que no son de ningún país (genéricas y variantes de UTC/GMT): no se juzgan, dan None.
NO_COUNTRY_TIMEZONES = frozenset({
    "CET", "EET", "MET", "WET", "EST", "MST", "HST",
    "EST5EDT", "CST6CDT", "MST7MDT", "PST8PDT",
    "UTC", "UCT", "Universal", "Zulu", "Etc/UTC", "Etc/UCT", "Etc/Universal", "Etc/Zulu",
    "GMT", "GMT0", "GMT+0", "GMT-0", "Greenwich", "Etc/GMT",
    "Etc/GMT0", "Etc/GMT+0", "Etc/GMT-0", "Etc/Greenwich",
})


class GeoDatabase:
    """Rangos IPv4 -> código de país, buscados con bisect sobre listas ordenadas."""

    def __init__(self, starts: list[int], ends: list[int], countries: list[str]):
        # Listas paralelas: el rango i va de starts[i] a ends[i] y es del país countries[i].
        self._starts = starts
        self._ends = ends
        self._countries = countries

    def __len__(self) -> int:
        return len(self._starts)

    def lookup(self, ip: str) -> str | None:
        """Devuelve el código de país de 2 letras o None. Nunca lanza excepción."""
        try:
            address = ipaddress.ip_address(ip.strip())
        except (ValueError, AttributeError):
            return None
        if address.version != 4:
            return None
        if address.is_private or address.is_loopback or address.is_link_local:
            return None

        ip_int = int(address)
        # bisect_right da la posición del primer inicio > ip; el anterior es el último inicio <= ip.
        index = bisect.bisect_right(self._starts, ip_int) - 1
        if index < 0 or ip_int > self._ends[index]:
            return None
        return self._countries[index]


def _ip_to_int(text: str) -> int:
    # inet_pton (en C) es mucho más rápido que ipaddress para cientos de miles de filas.
    return int.from_bytes(socket.inet_pton(socket.AF_INET, text), "big")


def _parse_row(line: str) -> tuple[int, int, str] | None:
    """Convierte "1.0.1.0,1.0.3.255,CN" en (inicio, final, país), o None si no sirve."""
    parts = line.strip().split(",")
    if len(parts) != 3:
        return None
    start_text, end_text, country = parts
    if ":" in start_text or ":" in end_text:
        return None
    if len(country) != 2 or not country.isalpha() or not country.isupper():
        return None
    # Los rangos "ZZ" no se guardan: una IP dentro de ellos no encuentra rango y da None.
    if country == _UNKNOWN_COUNTRY:
        return None
    try:
        start = _ip_to_int(start_text)
        end = _ip_to_int(end_text)
    except OSError:
        # inet_pton avisa de una IP inválida con OSError; se salta solo esa fila.
        return None
    if start > end:
        return None
    # intern hace que todas las filas de "MX" compartan el mismo objeto str en memoria.
    return start, end, sys.intern(country)


def load_country_db(path: str | Path) -> GeoDatabase:
    """Lee el CSV de DB-IP (texto plano o .gz). Si falla, devuelve una base vacía."""
    path = Path(path)
    rows: list[tuple[int, int, str]] = []
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", encoding="utf-8") as file:
            for line in file:
                parsed = _parse_row(line)
                if parsed is not None:
                    rows.append(parsed)
    except (OSError, EOFError, zlib.error, UnicodeDecodeError) as exc:
        # OSError: archivo ausente o cabecera gzip inválida. EOFError: gzip truncado.
        # zlib.error: datos comprimidos dañados. Se descarta lo leído a medias.
        logger.warning("No se pudo cargar la base de países %s: %s", path, type(exc).__name__)
        return GeoDatabase([], [], [])

    # bisect exige los inicios ordenados; no se asume que el archivo ya lo esté.
    rows.sort()
    starts = [row[0] for row in rows]
    ends = [row[1] for row in rows]
    countries = [row[2] for row in rows]
    return GeoDatabase(starts, ends, countries)


def load_country_timezones(path: str | Path) -> dict[str, frozenset[str]]:
    """Lee líneas "CC  Zona/Nombre"; ignora vacías y comentarios con "#". Si falla, mapa vacío."""
    mapping: dict[str, set[str]] = {}
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("No se pudo cargar el mapa país-zona horaria %s: %s", path, type(exc).__name__)
        return {}
    for line in lines:
        parts = line.split()
        if len(parts) != 2 or line.startswith("#"):
            continue
        country, timezone = parts
        mapping.setdefault(country, set()).add(timezone)
    return {country: frozenset(zones) for country, zones in mapping.items()}


_default_geo_db: GeoDatabase | None = None
_country_timezones: dict[str, frozenset[str]] | None = None
_lock = threading.Lock()


def get_default_geo_db() -> GeoDatabase:
    """Carga el CSV de DB-IP la primera vez y reutiliza el resultado."""
    global _default_geo_db
    if _default_geo_db is None:
        # El lock evita que dos peticiones simultáneas carguen el archivo dos veces.
        with _lock:
            if _default_geo_db is None:
                _default_geo_db = load_country_db(_DEFAULT_GEO_DB_PATH)
    return _default_geo_db


def get_country_timezones() -> dict[str, frozenset[str]]:
    """Carga country_timezones.txt la primera vez y reutiliza el resultado."""
    global _country_timezones
    if _country_timezones is None:
        with _lock:
            if _country_timezones is None:
                _country_timezones = load_country_timezones(_COUNTRY_TIMEZONES_PATH)
    return _country_timezones


def timezone_matches_country(country: str | None, timezone: str | None) -> bool | None:
    """True/False si la zona es o no del país; None si no hay información para decidir."""
    if not isinstance(country, str) or not isinstance(timezone, str):
        return None
    country = country.strip().upper()
    timezone = timezone.strip()
    if not country or not timezone:
        return None
    if timezone in NO_COUNTRY_TIMEZONES:
        return None

    zones = get_country_timezones().get(country)
    if zones is None:
        # País fuera del mapa (o mapa vacío): no sabemos, no se penaliza.
        return None
    return timezone in zones
