"""Mide la latencia de POST /register de punta a punta (PR-2: p95 < 300 ms).

Es una medición SECUENCIAL, no una prueba de carga: una petición a la vez, sin concurrencia. Corre en
el host contra la API de docker compose y mide desde que sale la petición hasta que llega la
respuesta completa.

Dos escenarios:
  A) MX en caché: todos los correos son @gmail.com. Las primeras 5 peticiones son de calentamiento
     (llenan la caché MX de Redis) y no cuentan.
  B) MX en frío: 20 dominios reales distintos, una petición por dominio. Con --flush-mx se borran
     antes las claves mx:* de Redis; sin él, un dominio consultado en la última hora sigue en caché.

Solo cuentan las respuestas que llegaron al motor de riesgo (200, 202, 403). Las 400 y 429 se cuentan
aparte. Con los límites por defecto (40 registros por minuto por IP) la medición recibe 429: si pasa,
el script avisa y termina sin guardar resultados.

Uso desde la raíz del repo, con los límites subidos en la misma sesión de PowerShell:
    $env:RATE_LIMIT_IP_MAX = "1000"
    $env:RATE_LIMIT_EMAIL_MAX = "1000"
    docker compose up -d
    python scripts/measure_latency.py --flush-mx

Al terminar, para volver a los límites por defecto:
    Remove-Item Env:RATE_LIMIT_IP_MAX
    Remove-Item Env:RATE_LIMIT_EMAIL_MAX
    docker compose up -d
"""
import argparse
import hashlib
import json
import math
import platform
import subprocess
import sys
import time
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from services.email_utils import is_disposable

DEFAULT_URL = "http://localhost:8000"
DEFAULT_N = 200
DEFAULT_OUT = ROOT / "data" / "latency_results.json"
TARGET_P95_MS = 300
WARMUP = 5
REQUEST_TIMEOUT_SECONDS = 10

CACHED_DOMAIN = "gmail.com"
# Comprobados el 30-oct-2026: todos tienen MX real (ninguno es el MX nulo ".") y ninguno está en
# backend/data/disposable_domains.txt. Igual se vuelven a comprobar como desechables al arrancar.
COLD_DOMAINS = (
    "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
    "yahoo.com.mx", "icloud.com", "me.com", "proton.me", "protonmail.com",
    "aol.com", "gmx.com", "zoho.com", "yandex.com", "mail.com",
    "fastmail.com", "tutanota.com", "hey.com", "att.net", "comcast.net",
)

# Clasificación de las respuestas de /register.
SCORED = "scored"              # 200, 202 o 403: la petición llegó al motor de riesgo.
REJECTED = "rejected"          # 400: correo desechable o dominio sin correo, antes del motor.
RATE_LIMITED = "rate_limited"  # 429: límite por IP o por correo.
OTHER = "other"                # Cualquier otro código (422, 500...).
SCORED_STATUSES = (200, 202, 403)

# Forma exacta del JSON que arma frontend/collector.js (onSubmit) con los nombres que valida
# RegisterRequest en backend/app/main.py. Solo canvasHash cambia en cada petición (build_payload).
# Los 4 atributos estables (platform, hardwareConcurrency y el ancho y alto de pantalla) son iguales
# en todas: cada petición encuentra las anteriores como candidatas de device_reuse (hasta 200).
TIMEZONE = "America/Mexico_City"
FINGERPRINT = {
    "webglRenderer": "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "hardwareConcurrency": 8,
    "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
    "languages": ["es-MX", "es"],
    "platform": "Win32",
    "maxTouchPoints": 0,
}
# Segunda muestra de data/human_baseline.json (registro a mano del autor). Esa muestra no trae
# path_length_px ni net_displacement_px: se eligieron para que net / path dé su straightness.
BEHAVIOR = {
    "key_count": 26,
    "dwell_mean_ms": 219.6,
    "dwell_std_ms": 138.7,
    "flight_mean_ms": 726.6,
    "flight_std_ms": 1966.3,
    "paste_used": False,
    "mouse_move_count": 71,
    "path_length_px": 1500.0,
    "net_displacement_px": 369.9,
    "straightness": 0.2466,
    "speed_cv": 1.0496,
    "click_count": 5,
    "pointer_kind": "mouse",
    "time_to_submit_ms": 22497,
}


class MeasurementError(RuntimeError):
    pass


# --- Funciones puras: no tocan la red ni Docker ---

def classify_status(http_status: int) -> str:
    if http_status in SCORED_STATUSES:
        return SCORED
    if http_status == 400:
        return REJECTED
    if http_status == 429:
        return RATE_LIMITED
    return OTHER


def percentile(values: list[float], p: float) -> float:
    """Percentil `p` (0-100) con interpolación lineal entre los dos valores vecinos: el mismo
    resultado que statistics.quantiles(..., method="inclusive")."""
    if not values:
        raise ValueError("No hay valores para calcular el percentil")
    if not 0 <= p <= 100:
        raise ValueError(f"El percentil debe estar entre 0 y 100, no {p}")
    ordered = sorted(values)
    position = (len(ordered) - 1) * p / 100
    lower = math.floor(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def latency_stats(latencies_ms: list[float], target_ms: float = TARGET_P95_MS) -> dict:
    """p50, p95, p99, máximo y % por encima del objetivo. Sin latencias, todo en None."""
    if not latencies_ms:
        return {"n": 0, "p50_ms": None, "p95_ms": None, "p99_ms": None, "max_ms": None,
                "over_target_pct": None, "p95_below_target": None}
    p95 = percentile(latencies_ms, 95)
    over = sum(1 for value in latencies_ms if value > target_ms)
    return {
        "n": len(latencies_ms),
        "p50_ms": percentile(latencies_ms, 50),
        "p95_ms": p95,
        "p99_ms": percentile(latencies_ms, 99),
        "max_ms": max(latencies_ms),
        "over_target_pct": 100 * over / len(latencies_ms),
        "p95_below_target": p95 < target_ms,
    }


# --- Peticiones ---

def build_payload(domain: str) -> dict:
    """Correo con local-part único (así el correo canónico también lo es) y canvasHash distinto."""
    token = uuid.uuid4().hex
    fingerprint = {"canvasHash": hashlib.sha256(token.encode()).hexdigest(), **FINGERPRINT}
    return {"email": f"lat{token}@{domain}", "timezone": TIMEZONE, "fingerprint": fingerprint,
            "behavior": BEHAVIOR}


def check_health(client: httpx.Client, url: str) -> None:
    try:
        response = client.get(f"{url}/health")
    except httpx.HTTPError as exc:
        raise MeasurementError(f"La API no responde en {url}/health ({type(exc).__name__}). "
                               f"Levántala con docker compose up -d y espera unos segundos.")
    if response.status_code != 200:
        raise MeasurementError(f"{url}/health respondió HTTP {response.status_code}, no 200.")


def send_registrations(client: httpx.Client, url: str, domains: list[str]) -> list[dict]:
    """Una petición por dominio, en orden y de a una. Devuelve dominio, código HTTP y milisegundos."""
    rows = []
    for domain in domains:
        payload = build_payload(domain)
        started = time.perf_counter()
        try:
            response = client.post(f"{url}/register", json=payload)
        except httpx.HTTPError as exc:
            raise MeasurementError(f"Falló una petición a {url}/register ({type(exc).__name__}).")
        elapsed_ms = (time.perf_counter() - started) * 1000
        rows.append({"domain": domain, "http_status": response.status_code, "ms": round(elapsed_ms, 2)})
    return rows


def scenario_result(rows: list[dict]) -> dict:
    latencies = [row["ms"] for row in rows if classify_status(row["http_status"]) == SCORED]
    return {
        "status_codes": dict(sorted(Counter(row["http_status"] for row in rows).items())),
        "stats": latency_stats(latencies),
    }


# --- Caché MX en Redis ---

def _redis_cli(*args: str) -> str:
    # Lista de argumentos, sin shell: "mx:*" llega tal cual a redis-cli en Windows y en bash.
    completed = subprocess.run(
        ["docker", "compose", "exec", "-T", "redis", "redis-cli", *args],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=True,
    )
    return completed.stdout.strip()


def flush_mx_cache() -> tuple[bool, str]:
    """Borra las claves mx:* de Redis. Devuelve (si quedó vacía, detalle para la salida)."""
    try:
        keys = _redis_cli("--scan", "--pattern", "mx:*").split()
        deleted = 0
        for start in range(0, len(keys), 100):
            deleted += int(_redis_cli("DEL", *keys[start:start + 100]))
        left = _redis_cli("--scan", "--pattern", "mx:*").split()
    except subprocess.CalledProcessError as exc:
        return False, (exc.stderr or "").strip() or f"redis-cli terminó con código {exc.returncode}"
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if left:
        return False, f"después del DEL quedaron {len(left)} claves mx:*"
    return True, f"{deleted} claves mx:* borradas"


# --- Salida ---

def _ms(value: float | None) -> str:
    return "—" if value is None else f"{value:.1f}"


def render_table(stats: dict) -> str:
    over = "—" if stats["over_target_pct"] is None else f"{stats['over_target_pct']:.1f}%"
    return "\n".join([
        f"| n válidas | p50 (ms) | p95 (ms) | p99 (ms) | máximo (ms) | > {TARGET_P95_MS} ms |",
        "|---|---|---|---|---|---|",
        f"| {stats['n']} | {_ms(stats['p50_ms'])} | {_ms(stats['p95_ms'])} | {_ms(stats['p99_ms'])} "
        f"| {_ms(stats['max_ms'])} | {over} |",
    ])


def verdict(stats: dict) -> str:
    if stats["p95_below_target"] is None:
        return f"p95 < {TARGET_P95_MS} ms: sin datos (ninguna respuesta llegó al motor)"
    return f"p95 < {TARGET_P95_MS} ms: {'SÍ' if stats['p95_below_target'] else 'NO'}"


def count_kind(status_codes: dict, kind: str) -> int:
    return sum(count for code, count in status_codes.items() if classify_status(code) == kind)


def status_line(status_codes: dict) -> str:
    scored = ", ".join(f"{code}: {count}" for code, count in status_codes.items() if classify_status(code) == SCORED)
    others = ", ".join(f"{code}: {count}" for code, count in status_codes.items() if classify_status(code) == OTHER)
    return (f"Llegaron al motor: {scored or 'ninguna'}. Fuera del cálculo: 400: {count_kind(status_codes, REJECTED)}, "
            f"429: {count_kind(status_codes, RATE_LIMITED)}, otros: {others or '0'}.")


def print_scenario(title: str, notes: list[str], result: dict) -> None:
    print(f"\n### {title}\n")
    for note in notes:
        print(note)
    if notes:
        print()
    print(render_table(result["stats"]))
    print()
    print(verdict(result["stats"]))
    print(status_line(result["status_codes"]))


TRUNCATE_REMINDER = "Esta medición escribió filas en audit_log y device_fingerprints; vacíalas con TRUNCATE"
LOCALHOST_REMINDER = "Medido en localhost, sin latencia de red real."


def abort_on_rate_limit(result: dict, total_requests: int) -> None:
    limited = count_kind(result["status_codes"], RATE_LIMITED)
    if limited:
        print(status_line(result["status_codes"]), file=sys.stderr)
        print(f"Hubo {limited} respuestas 429: sube RATE_LIMIT_IP_MAX y RATE_LIMIT_EMAIL_MAX por encima de "
              f"{total_requests} (las peticiones de esta medición), recrea la API con docker compose up -d y "
              f"vuelve a medir. No se guardaron resultados.", file=sys.stderr)
        print(TRUNCATE_REMINDER, file=sys.stderr)
        sys.exit(2)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mide la latencia de POST /register, una petición a la vez.")
    parser.add_argument("--url", default=DEFAULT_URL, help="Raíz de la API")
    parser.add_argument("--n", type=int, default=DEFAULT_N, help="Peticiones medidas del escenario A")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Resultados en JSON")
    parser.add_argument("--flush-mx", action="store_true",
                        help="Antes del escenario B, borra las claves mx:* de Redis (docker compose exec)")
    args = parser.parse_args(argv)
    if args.n < 1:
        parser.error("--n debe ser al menos 1")
    args.url = args.url.rstrip("/")
    return args


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    disposable = [domain for domain in (CACHED_DOMAIN, *COLD_DOMAINS) if is_disposable(domain)]
    if disposable:
        sys.exit(f"Estos dominios están en la lista de desechables y darían 400: {', '.join(disposable)}")
    total_requests = WARMUP + args.n + len(COLD_DOMAINS)

    with httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        try:
            check_health(client, args.url)
        except MeasurementError as exc:
            sys.exit(str(exc))

        try:
            print(f"Escenario A: {WARMUP} peticiones de calentamiento + {args.n} medidas a @{CACHED_DOMAIN}...",
                  flush=True)
            rows = send_registrations(client, args.url, [CACHED_DOMAIN] * (WARMUP + args.n))
            warmup_rows, cached_rows = rows[:WARMUP], rows[WARMUP:]
            # Las 429 del calentamiento también cuentan para abortar: los límites están bajos.
            abort_on_rate_limit(scenario_result(rows), total_requests)
            cached = scenario_result(cached_rows)

            if args.flush_mx:
                flushed, flush_detail = flush_mx_cache()
            else:
                flushed, flush_detail = None, "no se pidió --flush-mx"
            print(f"Escenario B: 1 petición a cada uno de {len(COLD_DOMAINS)} dominios...", flush=True)
            cold_rows = send_registrations(client, args.url, list(COLD_DOMAINS))
            cold = scenario_result(cold_rows)
            abort_on_rate_limit(cold, total_requests)
        except MeasurementError as exc:
            print(TRUNCATE_REMINDER, file=sys.stderr)
            sys.exit(f"{exc} No se guardaron resultados.")

    print_scenario(f"Escenario A: MX en caché (@{CACHED_DOMAIN})",
                   [f"Calentamiento: se descartaron las primeras {WARMUP} peticiones (no cuentan en n)."],
                   cached)
    if flushed:
        cold_notes = [f"Caché MX vaciada antes del escenario ({flush_detail}). Se mide la primera petición de cada dominio."]
    elif flushed is False:
        cold_notes = [f"Aviso: no se pudo vaciar la caché MX ({flush_detail}); el escenario B puede no ser en frío."]
    else:
        cold_notes = ["Aviso: sin --flush-mx, un dominio consultado en la última hora sigue en la caché MX; "
                      "el escenario B puede no ser en frío."]
    print_scenario(f"Escenario B: MX en frío ({len(COLD_DOMAINS)} dominios distintos)", cold_notes, cold)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "measured_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "url": args.url,
        "target_p95_ms": TARGET_P95_MS,
        "scenarios": {
            "mx_cached": {"domain": CACHED_DOMAIN, "warmup_discarded": WARMUP,
                          "warmup_ms": [row["ms"] for row in warmup_rows], **cached,
                          "requests": cached_rows},
            "mx_cold": {"flush_mx": {"requested": args.flush_mx, "ok": flushed, "detail": flush_detail},
                        **cold, "requests": cold_rows},
        },
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

    print(f"\nResultados en {args.out}")
    print()
    print(TRUNCATE_REMINDER)
    print(LOCALHOST_REMINDER)


if __name__ == "__main__":
    main()
