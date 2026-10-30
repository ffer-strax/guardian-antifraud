"""Bots de evasión de la campaña (Fase 6). Cada nivel imita a un atacante más cuidadoso.

Nivel 1 (bot ingenuo): Chromium completo en modo headless, sin disfrazar nada, zona horaria UTC
  (la del contenedor), rellena el correo con fill() y envía al instante con Enter, sin mover el
  ratón, desde una IP de datacenter simulada.
Nivel 2 (humanización básica): la misma IP de datacenter y la misma zona UTC. Escribe tecla por
  tecla con un retraso distinto en cada una (60-220 ms), mueve el ratón en curvas de Bézier con
  ruido (25 movimientos o más) y espera 6-15 s antes de enviar.
Nivel 3 (red residencial simulada): todo lo del nivel 2, pero cada registro sale de una IP distinta
  de México que no es de hosting (elegida y verificada con asn_lookup y geo_lookup sobre las bases
  del repo), con zona America/Mexico_City, y la huella varía entre registros (viewport y pantalla,
  hardwareConcurrency, idiomas).
Nivel 3b (exención táctil): como el 3, pero emulando un móvil táctil (has_touch, is_mobile,
  viewport móvil) para que pointer_kind sea "touch" y las señales de ratón no se evalúen.

Todo lo aleatorio sale de random.Random con semillas derivadas de (semilla, nivel, índice): las
entradas de cada registro se pueden calcular sin navegador con tier_plan().

Playwright y el código de backend/ se importan DENTRO de las funciones que los usan: así los tests
corren en la CI sin Playwright y run_campaign --update-readme-from corre solo con la librería estándar.

Uso, con la API en modo debug (ver scripts/run_campaign.py):
    docker compose --profile bots run --rm bots python scripts/evasion_bot.py --tier 1 --n 3
"""
import argparse
import hashlib
import ipaddress
import json
import math
import os
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT / "backend"

API_URL = os.getenv("API_URL", "http://api:8000")
DEBUG_IP_HEADER = "X-Debug-Client-IP"
# IP de AWS (AS16509) comprobada contra las bases reales de ASN y país. Solo cambia las señales y
# el audit: el límite por IP sigue usando la IP real del contenedor.
DATACENTER_IP = "54.239.28.85"
DEFAULT_SEED = 20261030
DEFAULT_PACE_SECONDS = 2.0

KNOWN_TIERS = ("1", "2", "3", "3b")
TIER_NAMES = {
    "1": "bot ingenuo",
    "2": "humanización básica",
    "3": "red residencial",
    "3b": "exención táctil",
}

# Humanización (niveles 2, 3 y 3b).
KEY_DELAY_MS = (60, 220)          # Retraso entre una tecla y la siguiente, distinto en cada tecla.
WAIT_BEFORE_SUBMIT_S = (6, 15)    # Pausa antes de enviar, como alguien que revisa el formulario.
MOUSE_STEPS = (28, 40)            # Movimientos por trayectoria (el mínimo pedido es 25).
MOUSE_STEP_DELAY_MS = (16, 32)    # Pausa entre movimientos: el collector toma como mucho una muestra cada 16 ms.

# Red residencial (niveles 3 y 3b).
RESIDENTIAL_COUNTRY = "MX"
RESIDENTIAL_TIMEZONE = "America/Mexico_City"
MIN_POOL_SIZE = 35
MAX_POOL_ATTEMPTS = 5_000_000

# Valores plausibles para variar la huella entre registros.
DESKTOP_SIZES = [(1366, 768), (1440, 900), (1536, 864), (1600, 900), (1920, 1080), (1280, 800)]
MOBILE_SIZES = [(390, 844), (393, 852), (412, 915), (360, 800), (375, 812)]
HARDWARE_CONCURRENCY = [4, 6, 8, 12, 16]
MOBILE_HARDWARE_CONCURRENCY = [4, 6, 8]
LANGUAGES = [["es-MX", "es"], ["es-MX", "es", "en"], ["es-419", "es"], ["es-MX", "en-US", "es"]]


def ensure_implemented(tier: str) -> None:
    """Falla con un mensaje claro si el nivel no existe o todavía no está implementado."""
    if tier not in KNOWN_TIERS:
        raise ValueError(f"Nivel desconocido: {tier!r}. Los niveles son: {', '.join(KNOWN_TIERS)}")
    if tier not in TIER_NAMES:
        raise NotImplementedError(f"El nivel {tier} todavía no está implementado")


def bot_email(seed: int, tier: str, index: int) -> str:
    """Correo @gmail.com distinto por registro y siempre el mismo para la misma semilla, nivel e índice."""
    digest = hashlib.sha256(f"{seed}:{tier}:{index}".encode()).hexdigest()[:12]
    return f"bot{digest}@gmail.com"


def to_result(tier: str, index: int, http_status: int, body, seconds: float) -> dict:
    """Una fila de resultados a partir de la respuesta de /register (con o sin debug_risk)."""
    body = body if isinstance(body, dict) else {}
    risk = body.get("debug_risk")
    risk = risk if isinstance(risk, dict) else None
    return {
        "tier": tier,
        "index": index,
        "http_status": http_status,
        "status": body.get("status"),
        "score": risk["score"] if risk else None,
        "action": risk["action"] if risk else None,
        "reasons": risk["reasons"] if risk else None,
        "unverified": risk["unverified"] if risk else None,
        "seconds": round(seconds, 3),
        "has_debug_risk": risk is not None,
        "detail": body.get("detail"),  # Solo en respuestas de error (400, 422, 429).
    }


# --- Red residencial: IPs de México que no son de hosting ---

def pick_residential_ips(rng: random.Random, size: int, *, country_of, asn_of, is_hosting_asn,
                         timezone_matches, max_attempts: int = MAX_POOL_ATTEMPTS) -> list[str]:
    """IPs públicas al azar (con `rng`) que pasan las mismas comprobaciones que hace la API:
    país MX, ASN conocido y que no es de hosting, y que la zona America/Mexico_City coincide con el
    país. Una por /24, para que no parezcan vecinas."""
    ips, subnets = [], set()
    for _ in range(max_attempts):
        if len(ips) == size:
            return ips
        address = ipaddress.IPv4Address(rng.getrandbits(32))
        ip = str(address)
        subnet = ip.rsplit(".", 1)[0]
        if not address.is_global or subnet in subnets:
            continue
        country = country_of(ip)
        if country != RESIDENTIAL_COUNTRY:
            continue
        asn = asn_of(ip)
        if asn is None or is_hosting_asn(asn):
            continue
        if timezone_matches(country, RESIDENTIAL_TIMEZONE) is not True:
            continue
        ips.append(ip)
        subnets.add(subnet)
    if len(ips) == size:
        return ips
    raise RuntimeError(f"Solo se encontraron {len(ips)} IPs residenciales de {size} tras {max_attempts} intentos")


def residential_pool(seed: int, tier: str, size: int) -> list[str]:
    """Pool real: carga las bases de backend/data y elige con la semilla usando las funciones de la API."""
    sys.path.insert(0, str(BACKEND_DIR))
    from services import asn_lookup, geo_lookup  # Perezoso: solo los niveles 3 y 3b lo necesitan.

    asn_db = asn_lookup.get_default_db()
    geo_db = geo_lookup.get_default_geo_db()
    if len(asn_db) == 0 or len(geo_db) == 0:
        raise RuntimeError(f"No se cargaron las bases de IP de {BACKEND_DIR / 'data'} (¿está montado backend/?)")
    return pick_residential_ips(
        random.Random(f"{seed}:{tier}:pool"), size,
        country_of=geo_db.lookup, asn_of=asn_db.lookup,
        is_hosting_asn=asn_lookup.is_hosting_asn, timezone_matches=geo_lookup.timezone_matches_country,
    )


# --- Plan determinista de cada registro ---

def _override_script(hardware_concurrency: int, languages: list[str]) -> str:
    """Script que corre antes que la página: cambia lo que el collector lee del navegador."""
    return (
        f"Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {{get: () => {int(hardware_concurrency)}}});\n"
        f"Object.defineProperty(Navigator.prototype, 'languages', {{get: () => {json.dumps(languages)}}});\n"
    )


def _human_entry(rng: random.Random, email: str) -> dict:
    """Lo común a los niveles 2, 3 y 3b: retrasos por tecla, pausa antes de enviar y ratón."""
    return {
        "kind": "human",
        # Un retraso entre cada par de teclas consecutivas.
        "typing_delays_ms": [rng.randint(*KEY_DELAY_MS) for _ in range(len(email) - 1)],
        "wait_before_submit_ms": rng.randint(WAIT_BEFORE_SUBMIT_S[0] * 1000, WAIT_BEFORE_SUBMIT_S[1] * 1000),
        "mouse": {
            "start": [rng.randint(20, 400), rng.randint(300, 600)],
            "steps": [rng.randint(*MOUSE_STEPS), rng.randint(*MOUSE_STEPS)],
            "seed": f"{rng.getrandbits(64):016x}",
        },
        "touch": False,
    }


def tier_plan(tier: str, n: int, seed: int, ip_pool: list[str] | None = None) -> list[dict]:
    """Entradas de los `n` registros del nivel, sin abrir ningún navegador. Misma semilla, mismo plan.
    Para los niveles 3 y 3b, `ip_pool` permite pasar las IPs ya elegidas (los tests lo usan)."""
    ensure_implemented(tier)
    if tier in ("3", "3b") and ip_pool is None:
        ip_pool = residential_pool(seed, tier, max(MIN_POOL_SIZE, n))
    plan = []
    for index in range(n):
        rng = random.Random(f"{seed}:{tier}:{index}")
        email = bot_email(seed, tier, index)
        entry = {"tier": tier, "index": index, "email": email}
        if tier == "1":
            entry.update({"kind": "naive", "debug_ip": DATACENTER_IP})
        elif tier == "2":
            # La misma huella y zona que el nivel 1 (las del contenedor): solo cambia el comportamiento.
            entry.update(_human_entry(rng, email), debug_ip=DATACENTER_IP, context_options={}, init_script=None,
                         fingerprint_overrides=None)
        else:
            human = _human_entry(rng, email)
            mobile = tier == "3b"
            width, height = rng.choice(MOBILE_SIZES if mobile else DESKTOP_SIZES)
            cores = rng.choice(MOBILE_HARDWARE_CONCURRENCY if mobile else HARDWARE_CONCURRENCY)
            languages = list(rng.choice(LANGUAGES))
            context_options = {
                "timezone_id": RESIDENTIAL_TIMEZONE,
                "locale": languages[0],
                "viewport": {"width": width, "height": height},
                "screen": {"width": width, "height": height},
            }
            if mobile:
                context_options.update(has_touch=True, is_mobile=True, device_scale_factor=rng.choice([2, 3]))
                human.update(touch=True, mouse=None)
            entry.update(human, debug_ip=ip_pool[index], context_options=context_options,
                         init_script=_override_script(cores, languages),
                         fingerprint_overrides={"hardwareConcurrency": cores, "languages": languages})
        plan.append(entry)
    return plan


# --- Ratón: curvas de Bézier con ruido ---

def bezier_path(start: tuple[float, float], end: tuple[float, float], rng: random.Random,
                steps: int) -> list[tuple[float, float]]:
    """`steps` puntos de una curva de Bézier cúbica de `start` a `end`, con los puntos de control
    desplazados hacia un costado y un poco de ruido en cada punto (menos el último, que llega exacto)."""
    (x0, y0), (x3, y3) = start, end
    dx, dy = x3 - x0, y3 - y0
    length = math.hypot(dx, dy) or 1.0
    # Perpendicular a la recta: hacia ahí se curva el recorrido.
    nx, ny = -dy / length, dx / length
    side = rng.choice([-1, 1])
    bend1 = side * rng.uniform(0.15, 0.35) * length
    bend2 = side * rng.uniform(0.10, 0.30) * length
    x1, y1 = x0 + dx * 0.3 + nx * bend1, y0 + dy * 0.3 + ny * bend1
    x2, y2 = x0 + dx * 0.7 + nx * bend2, y0 + dy * 0.7 + ny * bend2
    points = []
    for step in range(1, steps + 1):
        t = step / steps
        u = 1 - t
        x = u ** 3 * x0 + 3 * u ** 2 * t * x1 + 3 * u * t ** 2 * x2 + t ** 3 * x3
        y = u ** 3 * y0 + 3 * u ** 2 * t * y1 + 3 * u * t ** 2 * y2 + t ** 3 * y3
        if step < steps:
            x, y = x + rng.gauss(0, 1.5), y + rng.gauss(0, 1.5)
        points.append((x, y))
    return points


def _center(locator, rng: random.Random) -> tuple[float, float]:
    box = locator.bounding_box()
    return (box["x"] + box["width"] * rng.uniform(0.3, 0.7), box["y"] + box["height"] * rng.uniform(0.35, 0.65))


def _move_mouse(page, start, end, rng: random.Random, steps: int) -> tuple[float, float]:
    for x, y in bezier_path(start, end, rng, steps):
        page.mouse.move(x, y)
        page.wait_for_timeout(rng.randint(*MOUSE_STEP_DELAY_MS))
    return end


# --- Registros con Playwright ---

def _is_register_post(response) -> bool:
    return response.request.method == "POST" and response.url.endswith("/register")


def _naive_registration(browser, email: str):
    """Nivel 1: contexto nuevo con los valores por defecto, fill() y Enter. Sin ratón."""
    context = browser.new_context()
    try:
        context.set_extra_http_headers({DEBUG_IP_HEADER: DATACENTER_IP})
        page = context.new_page()
        page.goto(f"{API_URL}/")
        with page.expect_response(_is_register_post) as response_info:
            page.fill("#email", email)
            # Enter envía el formulario desde el teclado: el ratón nunca se mueve.
            page.press("#email", "Enter")
        response = response_info.value
        return response.status, response.json()
    finally:
        context.close()


def _human_registration(browser, entry: dict):
    """Niveles 2, 3 y 3b: ratón en curvas (o toques en móvil), tecleo con retrasos y pausa."""
    context = browser.new_context(**entry["context_options"])
    try:
        context.set_extra_http_headers({DEBUG_IP_HEADER: entry["debug_ip"]})
        if entry["init_script"]:
            context.add_init_script(entry["init_script"])
        page = context.new_page()
        page.goto(f"{API_URL}/")
        field = page.locator("#email")
        button = page.locator("button[type=submit]")
        mouse = entry["mouse"]
        rng = random.Random(mouse["seed"]) if mouse else None

        if entry["touch"]:
            field.tap()
        else:
            position = _move_mouse(page, tuple(mouse["start"]), _center(field, rng), rng, mouse["steps"][0])
            page.mouse.click(*position)
        email = entry["email"]
        for char, delay in zip(email, entry["typing_delays_ms"] + [0]):
            page.keyboard.type(char)
            if delay:
                page.wait_for_timeout(delay)
        page.wait_for_timeout(entry["wait_before_submit_ms"])

        with page.expect_response(_is_register_post) as response_info:
            if entry["touch"]:
                button.tap()
            else:
                position = _move_mouse(page, position, _center(button, rng), rng, mouse["steps"][1])
                page.mouse.click(*position)
        response = response_info.value
        return response.status, response.json()
    finally:
        context.close()


def launch_options() -> dict:
    """Cómo se lanza Chromium para todos los niveles."""
    return {
        "headless": True,
        # Chromium completo en modo headless, no el chromium-headless-shell que Playwright usa por
        # defecto: medido con Playwright 1.64.1, el headless-shell ignora el flag de abajo.
        "channel": "chromium",
        # http://api:8000 no es https ni localhost, así que el navegador no lo trata como origen
        # seguro y no expone crypto.subtle: el collector caería al hash de respaldo fnv1a. Con este
        # flag el canvasHash sale en SHA-256, como en un navegador real servido por https.
        "args": [f"--unsafely-treat-insecure-origin-as-secure={API_URL}"],
    }


def run_tier(tier: str, n: int, pace: float, seed: int, on_result=None) -> list[dict]:
    """Hace `n` registros del nivel. Entre el inicio de un registro y el del siguiente pasan al menos
    `pace` segundos. `on_result` (opcional) recibe cada resultado apenas llega y puede cortar la corrida."""
    plan = tier_plan(tier, n, seed)
    from playwright.sync_api import sync_playwright  # Perezoso: la CI no tiene Playwright.

    results = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(**launch_options())
        try:
            for entry in plan:
                started = time.perf_counter()
                if entry["kind"] == "naive":
                    status, body = _naive_registration(browser, entry["email"])
                else:
                    status, body = _human_registration(browser, entry)
                result = to_result(tier, entry["index"], status, body, time.perf_counter() - started)
                if on_result is not None:
                    on_result(result)
                results.append(result)
                if entry["index"] < n - 1:
                    time.sleep(max(0.0, pace - (time.perf_counter() - started)))
        finally:
            browser.close()
    return results


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Corre un nivel de bot de evasión contra la API.")
    parser.add_argument("--tier", default="1", choices=KNOWN_TIERS)
    parser.add_argument("--n", type=int, default=1)
    parser.add_argument("--pace-seconds", type=float, default=DEFAULT_PACE_SECONDS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args(argv)
    for result in run_tier(args.tier, args.n, args.pace_seconds, args.seed):
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
