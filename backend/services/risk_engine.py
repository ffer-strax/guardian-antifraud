import logging
from dataclasses import dataclass, field

from services.behavior_signals import SIGNAL_NAMES as BEHAVIOR_SIGNAL_NAMES
from services.geo_lookup import NO_COUNTRY_TIMEZONES

logger = logging.getLogger(__name__)

ALLOW = "allow"
STEP_UP = "step_up"
REVIEW = "review"
BLOCK = "block"

# Puntos que suma cada regla cuando se cumple. Aquí se agregarán las de comportamiento,
# dispositivo y grafo cuando existan; una clave sin regla todavía no suma y va a unverified.
WEIGHTS = {
    "hosting_ip": 25,           # La IP pertenece a un ASN de hosting/nube (AWS, Hetzner...).
    "tz_country_mismatch": 10,  # La zona del navegador no es de ninguna del país de la IP.
    "tz_utc": 5,                # El navegador reporta una zona sin país (UTC, GMT, CET...).
    "device_reuse_low": 15,     # El mismo dispositivo ya registró 1 o 2 cuentas más.
    "device_reuse_high": 35,    # El mismo dispositivo ya registró 3 o más cuentas (granja).
    # Comportamiento: pesos HIPOTÉTICOS, a validar con la línea base humana (umbrales en behavior_signals.py).
    "form_too_fast": 30,        # Formulario enviado antes de 2 s desde que cargó la página.
    "keystroke_uniform": 25,    # 8+ teclas con tiempo entre teclas casi constante (desviación < 15 ms).
    "dwell_uniform": 15,        # 8+ teclas con tiempo de pulsación casi constante (desviación < 8 ms).
    "mouse_linear": 20,         # Ratón con 20+ muestras en línea casi recta (rectitud > 0.98).
    "no_mouse_movement": 5,     # Hay ratón pero no se movió nada.
    "no_keyboard_events": 10,   # El correo apareció sin teclas, sin pegar y sin autocompletar.
    "behavior_missing": 10,     # El cliente no mandó el bloque de comportamiento, o era inválido.
}

# Puntaje mínimo de cada acción, de menor a mayor: 0-29 allow, 30-59 step_up, 60-84 review, 85-100 block.
THRESHOLDS = [
    (0, ALLOW),
    (30, STEP_UP),
    (60, REVIEW),
    (85, BLOCK),
]

MAX_SCORE = 100


@dataclass(frozen=True)
class RiskResult:
    score: int
    action: str
    reasons: list[str] = field(default_factory=list)
    unverified: list[str] = field(default_factory=list)


def _hosting_ip(signals: dict) -> bool | None:
    return signals.get("is_hosting")


def _tz_country_mismatch(signals: dict) -> bool | None:
    # Solo False cuenta como discrepancia; None (sin información) no se penaliza.
    matches = signals.get("timezone_matches_country")
    if matches is None:
        return None
    return matches is False


def _tz_utc(signals: dict) -> bool | None:
    timezone = signals.get("timezone")
    if not isinstance(timezone, str) or not timezone.strip():
        return None
    return timezone.strip() in NO_COUNTRY_TIMEZONES


def _device_reuse_low(signals: dict) -> bool | None:
    size = signals.get("device_family_size")
    if size is None:
        return None
    return 1 <= size <= 2


def _device_reuse_high(signals: dict) -> bool | None:
    size = signals.get("device_family_size")
    if size is None:
        return None
    return size >= 3


def _precomputed(name: str):
    """Regla de comportamiento: el valor ya viene calculado en behavior_signals; solo se lee."""
    def rule(signals: dict) -> bool | None:
        value = signals.get(name)
        return value if isinstance(value, bool) else None
    return rule


# Cada regla devuelve True (se cumple), False (no se cumple) o None (no se pudo comprobar).
_RULES = {
    "hosting_ip": _hosting_ip,
    "tz_country_mismatch": _tz_country_mismatch,
    "tz_utc": _tz_utc,
    "device_reuse_low": _device_reuse_low,
    "device_reuse_high": _device_reuse_high,
    **{name: _precomputed(name) for name in BEHAVIOR_SIGNAL_NAMES},
}


def _action_for(score: int, thresholds: list[tuple[int, str]]) -> str:
    action = thresholds[0][1]
    for minimum, name in thresholds:
        if score >= minimum:
            action = name
    return action


def evaluate(signals: dict, weights: dict = WEIGHTS, thresholds: list = THRESHOLDS) -> RiskResult:
    """Suma los pesos de las reglas que se cumplen y elige la acción. Nunca lanza excepción."""
    try:
        score = 0
        reasons = []
        unverified = []
        for name, weight in weights.items():
            rule = _RULES.get(name)
            outcome = rule(signals) if rule is not None else None
            if outcome is None:
                unverified.append(name)
            elif outcome:
                score += weight
                reasons.append(name)
        score = max(0, min(MAX_SCORE, int(score)))
        return RiskResult(score, _action_for(score, thresholds), reasons, unverified)
    except Exception as exc:
        # Igual que con DNS o Redis: un fallo nuestro no bloquea al usuario.
        logger.warning("Fallo al evaluar el riesgo, se permite: %s", type(exc).__name__)
        return RiskResult(0, ALLOW, [], list(weights) if isinstance(weights, dict) else [])
