"""Mide carga, consultas y memoria de la base ASN real (backend/data/ipasn.dat.gz).

Uso desde la raíz del repo:
    python scripts/measure_asn.py
"""
import random
import sys
import time
import tracemalloc
from ipaddress import IPv4Address
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from services.asn_lookup import load_asn_db

DB_PATH = BACKEND_DIR / "data" / "ipasn.dat.gz"
QUERIES = 10_000


def random_public_ips(count: int, seed: int = 42) -> list[str]:
    rng = random.Random(seed)
    ips = []
    while len(ips) < count:
        address = IPv4Address(rng.getrandbits(32))
        if address.is_global:
            ips.append(str(address))
    return ips


def main() -> None:
    if not DB_PATH.exists():
        sys.exit(f"No existe {DB_PATH}")

    start = time.perf_counter()
    db = load_asn_db(DB_PATH)
    load_seconds = time.perf_counter() - start

    # Segunda carga solo para memoria: tracemalloc vuelve lenta cada asignación
    # y, si estuviera activo arriba, inflaría el tiempo de carga ~5 veces.
    del db
    tracemalloc.start()
    db = load_asn_db(DB_PATH)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    ips = random_public_ips(QUERIES)
    start = time.perf_counter()
    found = sum(1 for ip in ips if db.lookup(ip) is not None)
    query_seconds = time.perf_counter() - start

    print(f"Python:              {sys.version.split()[0]}")
    print(f"Prefijos cargados:   {len(db):,}")
    print(f"Tiempo de carga:     {load_seconds:.2f} s")
    print(f"Memoria retenida:    {current / 1024 / 1024:.1f} MiB")
    print(f"Pico de memoria:     {peak / 1024 / 1024:.1f} MiB")
    print(f"{QUERIES:,} consultas: {query_seconds * 1000:.1f} ms "
          f"({query_seconds / QUERIES * 1_000_000:.1f} µs por consulta)")
    print(f"IPs con ASN:         {found:,} de {QUERIES:,}")


if __name__ == "__main__":
    main()
