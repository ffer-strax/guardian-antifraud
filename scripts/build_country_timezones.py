"""Genera backend/data/country_timezones.txt a partir de zone.tab (base de datos tz de IANA).

Uso desde la raíz del repo, dentro de python:3.12-slim:
    python scripts/build_country_timezones.py
"""
import datetime
import sys
from pathlib import Path

ZONEINFO_DIR = Path("/usr/share/zoneinfo")
ZONE_TAB = ZONEINFO_DIR / "zone.tab"
# tzdata.zi empieza con "# version 2025b"; sirve para anotar qué versión se usó.
TZDATA_ZI = ZONEINFO_DIR / "tzdata.zi"
BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
OUTPUT = BACKEND_DIR / "data" / "country_timezones.txt"

# La lista de zonas sin país vive en el servicio; aquí solo se reutiliza.
sys.path.insert(0, str(BACKEND_DIR))

from services.geo_lookup import NO_COUNTRY_TIMEZONES


def read_tzdata_version() -> str:
    try:
        first_line = TZDATA_ZI.read_text(encoding="utf-8").splitlines()[0]
    except (OSError, IndexError):
        return "desconocida"
    return first_line.removeprefix("# version").strip() or "desconocida"


def read_zone_tab() -> list[tuple[str, str]]:
    """Devuelve pares (país, zona). zone.tab: "CC<tab>coordenadas<tab>Zona[<tab>comentario]"."""
    pairs = set()
    for line in ZONE_TAB.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        columns = line.split("\t")
        pairs.add((columns[0], columns[2]))
    return sorted(pairs)


def read_links() -> list[tuple[str, str]]:
    """Devuelve pares (zona actual, nombre antiguo) de las líneas "L destino alias" de tzdata.zi."""
    links = []
    try:
        lines = TZDATA_ZI.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines:
        parts = line.split()
        if len(parts) == 3 and parts[0] == "L":
            links.append((parts[1], parts[2]))
    return links


def build_aliases(pairs: list[tuple[str, str]], links: list[tuple[str, str]]):
    """Asigna cada alias solo al país de su zona actual. Devuelve (pares nuevos, omitidos, ya en zone.tab)."""
    countries_by_zone: dict[str, set[str]] = {}
    for country, zone in pairs:
        countries_by_zone.setdefault(zone, set()).add(country)

    alias_pairs = set()
    skipped_no_target = []
    skipped_own_zone = []
    for target, alias in links:
        if alias in countries_by_zone:
            # Ej. Europe/Bratislava enlaza a Europe/Prague, pero ya es la zona propia de SK
            # en zone.tab: no es un nombre antiguo y no se reasigna a CZ.
            skipped_own_zone.append(alias)
        elif target not in countries_by_zone:
            # Ej. UTC -> Etc/UTC: el destino no es de ningún país.
            skipped_no_target.append(alias)
        else:
            for country in countries_by_zone[target]:
                alias_pairs.add((country, alias))
    return sorted(alias_pairs), skipped_no_target, skipped_own_zone


def main() -> None:
    if not ZONE_TAB.exists():
        sys.exit(f"No existe {ZONE_TAB}")

    pairs = read_zone_tab()
    alias_pairs, skipped_no_target, skipped_own_zone = build_aliases(pairs, read_links())
    # CET, EST, etc. enlazan a una sola ciudad en tzdata, pero se usan en muchos países.
    excluded = sorted({zone for _, zone in alias_pairs if zone in NO_COUNTRY_TIMEZONES})
    alias_pairs = [(country, zone) for country, zone in alias_pairs if zone not in NO_COUNTRY_TIMEZONES]
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    header = [
        "# Mapa país -> zonas horarias válidas. ARCHIVO GENERADO, no editar a mano.",
        f"# Fuente: {ZONE_TAB} (tzdata {read_tzdata_version()}) en python:3.12-slim.",
        f"# Alias: {len(alias_pairs)} nombres antiguos tomados de las líneas \"L\" de {TZDATA_ZI},",
        "# cada uno asignado solo al país de su zona actual (Asia/Calcutta -> IN).",
        f"# Excluidos {len(excluded)} nombres sin país (geo_lookup.NO_COUNTRY_TIMEZONES): "
        f"{', '.join(excluded)}.",
        f"# Generado el {today} (UTC) con scripts/build_country_timezones.py.",
        "# Formato: CC  Zona/Nombre (una línea por zona; un país puede tener varias).",
    ]
    all_pairs = sorted(set(pairs) | set(alias_pairs))
    lines = header + [f"{country}  {zone}" for country, zone in all_pairs]
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    countries = len({country for country, _ in all_pairs})
    print(f"Escrito {OUTPUT}: {len(all_pairs)} zonas de {countries} países")
    print(f"  {len(pairs)} de zone.tab, {len(alias_pairs)} alias agregados")
    print(f"  {len(excluded)} nombres sin país excluidos: {', '.join(excluded)}")
    print(f"  {len(skipped_no_target)} alias omitidos (destino fuera de zone.tab): "
          f"{', '.join(skipped_no_target)}")
    print(f"  {len(skipped_own_zone)} enlaces ya en zone.tab con su propio país: "
          f"{', '.join(skipped_own_zone)}")


if __name__ == "__main__":
    main()
