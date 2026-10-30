"""Prueba de humo de Playwright en Docker (Fase 6a): un navegador real se registra UNA vez.

Abre http://api:8000/ con Chromium headless, escribe un correo nuevo, envía el formulario y muestra:
(a) el estado que enseña la página, (b) la huella y el comportamiento que mandó el navegador,
leídos del cuerpo de POST /register, y (c) cuánto tardó.

Uso desde la raíz del repo, con la API ya en marcha y respondiendo (docker compose up -d):
    docker compose --profile bots run --rm bots python scripts/bot_smoke.py

Ojo: si la API no está levantada, compose la arranca pero NO espera a que termine de cargar
(~5 s), y el bot falla con net::ERR_CONNECTION_REFUSED.
"""
import json
import sys
import time
import uuid

from playwright.sync_api import sync_playwright

TARGET_URL = "http://api:8000/"
FINGERPRINT_FIELDS = ("canvasHash", "webglRenderer", "platform", "hardwareConcurrency", "screen", "languages")


def _is_register_post(url: str, method: str) -> bool:
    return method == "POST" and url.endswith("/register")


def main() -> None:
    started = time.perf_counter()
    # Un correo distinto por corrida. gmail.com tiene MX real, así la petición llega al motor de riesgo
    # (no se envía ningún correo: la API solo consulta el DNS).
    email = f"smoke.{uuid.uuid4().hex[:12]}@gmail.com"
    sent = {}

    def capture(request) -> None:
        if _is_register_post(request.url, request.method):
            sent["body"] = request.post_data_json

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.on("request", capture)
        page.goto(TARGET_URL)
        loaded = time.perf_counter()

        # Tecla por tecla, sin pausas: así escribe un bot ingenuo.
        page.locator("#email").press_sequentially(email)
        typed = time.perf_counter()

        with page.expect_response(lambda r: _is_register_post(r.url, r.request.method)) as response_info:
            page.locator("button[type=submit]").click()
        response = response_info.value
        # La página escribe el estado después de leer la respuesta: se espera a que cambie, no un tiempo fijo.
        page.wait_for_function(
            "() => { const t = document.getElementById('result').textContent; return t && t !== 'Enviando...'; }"
        )
        shown = page.locator("#result").text_content()
        api_body = response.json()
        api_status = response.status
        browser.close()
    finished = time.perf_counter()

    body = sent.get("body")
    if body is None:
        sys.exit("No se capturó el cuerpo de POST /register")

    fingerprint = body.get("fingerprint") or {}
    print(f"Correo usado: {email}")
    print(f"(a) Estado que muestra la página: {shown}")
    print(f"    Respuesta de la API: HTTP {api_status} {json.dumps(api_body, ensure_ascii=False)}")
    print("(b) Huella que mandó el navegador:")
    print(json.dumps({field: fingerprint.get(field) for field in FINGERPRINT_FIELDS}, ensure_ascii=False, indent=2))
    print(f"    timezone: {body.get('timezone')}")
    print("    behavior tal como salió:")
    print(json.dumps(body.get("behavior"), ensure_ascii=False, indent=2))
    print(f"(c) Tiempo total: {finished - started:.2f} s "
          f"(abrir navegador y cargar: {loaded - started:.2f} s, escribir: {typed - loaded:.2f} s, "
          f"enviar y recibir respuesta: {finished - typed:.2f} s)")


if __name__ == "__main__":
    main()
