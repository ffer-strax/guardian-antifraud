"""Bots de evasión de la campaña (Fase 6). Cada nivel imita a un atacante más cuidadoso.

Nivel 1 (bot ingenuo): Chromium completo en modo headless, sin disfrazar nada, zona horaria UTC
(la del contenedor), rellena el correo con fill() y envía al instante con Enter, sin mover el
ratón, desde una IP de datacenter simulada. Los niveles 2, 3 y 3b todavía no existen.

Playwright se importa DENTRO de run_tier: así los tests corren en la CI sin Playwright instalado.

Uso, con la API en modo debug (ver scripts/run_campaign.py):
    docker compose --profile bots run --rm bots python scripts/evasion_bot.py --tier 1 --n 3
"""
import argparse
import hashlib
import json
import os
import time

API_URL = os.getenv("API_URL", "http://api:8000")
DEBUG_IP_HEADER = "X-Debug-Client-IP"
# IP de AWS (AS16509) comprobada contra las bases reales de ASN y país. Solo cambia las señales y
# el audit: el límite por IP sigue usando la IP real del contenedor.
DATACENTER_IP = "54.239.28.85"
DEFAULT_SEED = 20261030
DEFAULT_PACE_SECONDS = 2.0

KNOWN_TIERS = ("1", "2", "3", "3b")
TIER_NAMES = {"1": "bot ingenuo"}


def ensure_implemented(tier: str) -> None:
    """Falla con un mensaje claro si el nivel no existe o todavía no está implementado."""
    if tier not in KNOWN_TIERS:
        raise ValueError(f"Nivel desconocido: {tier!r}. Los niveles son: {', '.join(KNOWN_TIERS)}")
    if tier not in TIER_NAMES:
        raise NotImplementedError(f"El nivel {tier} todavía no está implementado; por ahora solo existe el nivel 1")


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


_REGISTRATIONS = {"1": _naive_registration}


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
    ensure_implemented(tier)
    from playwright.sync_api import sync_playwright  # Perezoso: la CI no tiene Playwright.

    results = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(**launch_options())
        try:
            for index in range(n):
                started = time.perf_counter()
                status, body = _REGISTRATIONS[tier](browser, bot_email(seed, tier, index))
                result = to_result(tier, index, status, body, time.perf_counter() - started)
                if on_result is not None:
                    on_result(result)
                results.append(result)
                if index < n - 1:
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
