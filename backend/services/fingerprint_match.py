import logging

logger = logging.getLogger(__name__)

# Cuánto pesa cada atributo al comparar dos huellas (suman 1.0).
WEIGHTS = {
    "canvas_hash": 0.20,           # Hash del canvas: muy distintivo, pero cambia al actualizar navegador o GPU.
    "webgl_renderer": 0.20,        # Modelo de GPU y controlador: estable y bastante distintivo.
    "screen": 0.15,                # Pantalla: ancho y alto iguales a la vez.
    "hardware_concurrency": 0.10,  # Núcleos de CPU: estable, pero muchos equipos comparten el valor.
    "platform": 0.10,              # Sistema operativo reportado (Win32, MacIntel...).
    "languages": 0.10,             # Idiomas del navegador, comparados con Jaccard (no todo o nada).
    "timezone": 0.10,              # Zona horaria del navegador.
    "max_touch_points": 0.05,      # Puntos táctiles: casi siempre 0 en escritorio, aporta poco.
}

# Desde esta similitud dos huellas se consideran el mismo dispositivo ("familia").
FAMILY_THRESHOLD = 0.75


def flatten(fingerprint: dict | None, timezone: str | None) -> dict | None:
    """Pasa la huella del navegador (camelCase, pantalla anidada) a la forma plana de la tabla."""
    if not fingerprint:
        return None
    screen = fingerprint.get("screen") or {}
    return {
        "canvas_hash": fingerprint.get("canvasHash"),
        "webgl_renderer": fingerprint.get("webglRenderer"),
        "hardware_concurrency": fingerprint.get("hardwareConcurrency"),
        "screen_w": screen.get("width"),
        "screen_h": screen.get("height"),
        "color_depth": screen.get("colorDepth"),
        "languages": fingerprint.get("languages"),
        "platform": fingerprint.get("platform"),
        "max_touch_points": fingerprint.get("maxTouchPoints"),
        "timezone": timezone,
    }


def _jaccard(a: list, b: list) -> float:
    first, second = set(a), set(b)
    return len(first & second) / len(first | second)


def _compare(name: str, a: dict, b: dict) -> float | None:
    """Parecido de un atributo entre 0 y 1, o None si falta en alguna de las dos huellas."""
    if name == "screen":
        values = (a.get("screen_w"), a.get("screen_h"), b.get("screen_w"), b.get("screen_h"))
        if None in values:
            return None
        return 1.0 if values[:2] == values[2:] else 0.0
    first, second = a.get(name), b.get(name)
    if name == "languages":
        # Una lista vacía no dice nada del dispositivo: se trata igual que None.
        if not first or not second:
            return None
        return _jaccard(first, second)
    if first is None or second is None:
        return None
    return 1.0 if first == second else 0.0


def similarity(a: dict | None, b: dict | None, weights: dict = WEIGHTS) -> float:
    """Similitud de 0 a 1 entre dos huellas planas. Nunca lanza excepción."""
    try:
        if not a or not b:
            return 0.0
        total = 0.0
        matched = 0.0
        for name, weight in weights.items():
            score = _compare(name, a, b)
            # Un atributo ausente no cuenta como diferencia: se saca y los demás pesos se renormalizan.
            if score is None:
                continue
            total += weight
            matched += weight * score
        return matched / total if total > 0 else 0.0
    except Exception as exc:
        logger.warning("Fallo al comparar huellas: %s", type(exc).__name__)
        return 0.0


def family_size(current: dict | None, email_hmac: str, candidates: list[dict]) -> int:
    """Cuántas OTRAS cuentas (email_hmac distinto) tienen una huella de la misma familia."""
    others = set()
    for candidate in candidates:
        other = candidate.get("email_hmac")
        if other and other != email_hmac and similarity(current, candidate) >= FAMILY_THRESHOLD:
            others.add(other)
    return len(others)
