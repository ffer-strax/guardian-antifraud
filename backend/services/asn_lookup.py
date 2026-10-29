import gzip
import ipaddress
import logging
import socket
import threading
import zlib
from pathlib import Path

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_DEFAULT_DB_PATH = _DATA_DIR / "ipasn.dat.gz"
_HOSTING_ASNS_PATH = _DATA_DIR / "hosting_asns.txt"

# Máscara de red para cada longitud: /24 -> 0xFFFFFF00.
_MASKS = [(0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF for length in range(33)]


class AsnDatabase:
    """Tabla de prefijos IPv4 -> ASN con búsqueda por prefijo más largo."""

    def __init__(self, tables: dict[int, dict[int, int]]):
        # {longitud: {red_entera: asn}}
        self._tables = tables
        # De la más específica (/32) a la menos (/0): la primera coincidencia gana.
        self._lengths = sorted(tables, reverse=True)

    def __len__(self) -> int:
        return sum(len(table) for table in self._tables.values())

    def lookup(self, ip: str) -> int | None:
        """Devuelve el ASN de la IP o None. Nunca lanza excepción."""
        try:
            address = ipaddress.ip_address(ip.strip())
        except (ValueError, AttributeError):
            return None
        if address.version != 4:
            return None
        if address.is_private or address.is_loopback or address.is_link_local:
            return None

        ip_int = int(address)
        for length in self._lengths:
            asn = self._tables[length].get(ip_int & _MASKS[length])
            if asn is not None:
                return asn
        return None


def _parse_line(line: str) -> tuple[int, int, int] | None:
    """Convierte "1.0.0.0/24  13335" en (longitud, red_entera, asn), o None si no sirve."""
    line = line.strip()
    if not line or line.startswith(";"):
        return None
    parts = line.split()
    if len(parts) != 2:
        return None
    prefix, asn_text = parts
    if ":" in prefix:
        return None
    try:
        network_text, length_text = prefix.split("/")
        length = int(length_text)
        if not 0 <= length <= 32:
            return None
        # inet_pton (en C) es ~10 veces más rápido que ipaddress.IPv4Address al
        # cargar 1,16 millones de líneas, e igual de estricto con el formato.
        packed = socket.inet_pton(socket.AF_INET, network_text)
        network = int.from_bytes(packed, "big") & _MASKS[length]
        asn = int(asn_text)
    except (ValueError, OSError):
        # inet_pton avisa de una IP inválida con OSError; se salta solo esa línea.
        return None
    return length, network, asn


def load_asn_db(path: str | Path) -> AsnDatabase:
    """Lee un archivo ipasn (texto plano o .gz). Si falla, devuelve una base vacía."""
    path = Path(path)
    tables: dict[int, dict[int, int]] = {}
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", encoding="utf-8") as file:
            for line in file:
                parsed = _parse_line(line)
                if parsed is None:
                    continue
                length, network, asn = parsed
                tables.setdefault(length, {})[network] = asn
    except (OSError, EOFError, zlib.error, UnicodeDecodeError) as exc:
        # OSError: archivo ausente o cabecera gzip inválida. EOFError: gzip truncado.
        # zlib.error: datos comprimidos dañados. Se descarta lo leído a medias.
        logger.warning("No se pudo cargar la base ASN %s: %s", path, type(exc).__name__)
        return AsnDatabase({})
    return AsnDatabase(tables)


_default_db: AsnDatabase | None = None
_hosting_asns: frozenset[int] | None = None
_lock = threading.Lock()


def get_default_db() -> AsnDatabase:
    """Carga backend/data/ipasn.dat.gz la primera vez y reutiliza el resultado."""
    global _default_db
    if _default_db is None:
        # El lock evita que dos peticiones simultáneas carguen el archivo dos veces.
        with _lock:
            if _default_db is None:
                _default_db = load_asn_db(_DEFAULT_DB_PATH)
    return _default_db


def load_hosting_asns(path: str | Path) -> frozenset[int]:
    """Lee líneas "ASN  nombre"; ignora vacías y comentarios con "#". Si falla, conjunto vacío."""
    asns = set()
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("No se pudo cargar la lista de ASN de hosting %s: %s", path, type(exc).__name__)
        return frozenset()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            asns.add(int(line.split()[0]))
        except ValueError:
            continue
    return frozenset(asns)


def is_hosting_asn(asn: int | None) -> bool:
    global _hosting_asns
    if asn is None:
        return False
    if _hosting_asns is None:
        with _lock:
            if _hosting_asns is None:
                _hosting_asns = load_hosting_asns(_HOSTING_ASNS_PATH)
    return asn in _hosting_asns
