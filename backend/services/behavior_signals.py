import logging
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

logger = logging.getLogger(__name__)

# Umbrales de las señales de comportamiento. Son HIPÓTESIS a validar con la línea base humana
# (Fase 6), no hechos comprobados.
FORM_TOO_FAST_MS = 2000       # Enviar el formulario antes de 2 s desde que cargó la página.
MIN_KEYS_FOR_RHYTHM = 8       # Con menos teclas el ritmo no se puede juzgar (señal en None).
FLIGHT_STD_UNIFORM_MS = 15    # Desviación entre teclas menor a esto: ritmo de máquina.
DWELL_STD_UNIFORM_MS = 8      # Desviación del tiempo de pulsación menor a esto: ritmo de máquina.
MIN_MOVES_FOR_SHAPE = 20      # Con menos muestras de ratón la forma del recorrido no se juzga.
STRAIGHTNESS_LINEAR = 0.98    # Rectitud mayor a esto: el ratón fue en línea casi recta.

# Límites de validación: un valor fuera de rango invalida el bloque entero.
MAX_TIME_MS = 86_400_000      # 24 h desde que cargó la página.
MAX_KEYS = 5_000
MAX_INTERVAL_MS = 60_000      # Medias y desviaciones de pulsación y vuelo.
MAX_MOUSE_SAMPLES = 500       # El mismo tope de muestras que usa frontend/collector.js.
MAX_PATH_PX = 10_000_000
MAX_SPEED_CV = 1_000
MAX_CLICKS = 10_000

# Nombres de las señales (iguales a sus claves en risk_engine.WEIGHTS).
SIGNAL_NAMES = (
    "form_too_fast",
    "keystroke_uniform",
    "dwell_uniform",
    "mouse_linear",
    "no_mouse_movement",
    "no_keyboard_events",
    "behavior_missing",
)


class Behavior(BaseModel):
    """Agregados de comportamiento que manda el navegador. Nunca teclas ni coordenadas."""

    # extra="ignore": cualquier campo de más (por ejemplo, teclas crudas) se descarta.
    # allow_inf_nan=False: NaN o infinito invalidan el bloque.
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)

    key_count: int | None = Field(default=None, ge=0, le=MAX_KEYS)
    dwell_mean_ms: float | None = Field(default=None, ge=0, le=MAX_INTERVAL_MS)
    dwell_std_ms: float | None = Field(default=None, ge=0, le=MAX_INTERVAL_MS)
    flight_mean_ms: float | None = Field(default=None, ge=0, le=MAX_INTERVAL_MS)
    flight_std_ms: float | None = Field(default=None, ge=0, le=MAX_INTERVAL_MS)
    paste_used: bool | None = None
    mouse_move_count: int | None = Field(default=None, ge=0, le=MAX_MOUSE_SAMPLES)
    path_length_px: float | None = Field(default=None, ge=0, le=MAX_PATH_PX)
    net_displacement_px: float | None = Field(default=None, ge=0, le=MAX_PATH_PX)
    straightness: float | None = Field(default=None, ge=0, le=1)
    speed_cv: float | None = Field(default=None, ge=0, le=MAX_SPEED_CV)
    click_count: int | None = Field(default=None, ge=0, le=MAX_CLICKS)
    pointer_kind: Literal["mouse", "touch", "unknown"] | None = None
    time_to_submit_ms: float | None = Field(default=None, ge=0, le=MAX_TIME_MS)

    @model_validator(mode="after")
    def _net_not_longer_than_path(self):
        # La línea recta nunca es más larga que el recorrido (1 px de margen por redondeo).
        if (self.path_length_px is not None and self.net_displacement_px is not None
                and self.net_displacement_px > self.path_length_px + 1):
            raise ValueError("net_displacement_px mayor que path_length_px")
        return self


def parse_behavior(raw) -> Behavior | None:
    """Valida el bloque. Si falta o es inválido devuelve None (nunca 422 ni 500)."""
    if raw is None:
        return None
    try:
        return Behavior.model_validate(raw)
    except ValidationError:
        return None


def _keyboard_rhythm(key_count: int | None, std_ms: float | None, threshold: float) -> bool | None:
    if key_count is None or key_count < MIN_KEYS_FOR_RHYTHM or std_ms is None:
        return None
    return std_ms < threshold


def _mouse_linear(b: Behavior) -> bool | None:
    if b.mouse_move_count is None or b.mouse_move_count < MIN_MOVES_FOR_SHAPE or b.straightness is None:
        return None
    return b.straightness > STRAIGHTNESS_LINEAR


def _no_mouse_movement(b: Behavior) -> bool | None:
    if b.mouse_move_count is None:
        return None
    return b.mouse_move_count == 0


def _no_keyboard_events(b: Behavior) -> bool | None:
    if b.key_count is None:
        return None
    if b.key_count > 0:
        return False
    if b.paste_used is None:
        return None
    return not b.paste_used


def compute_behavior_signals(behavior: Behavior | None) -> dict:
    """Señales booleanas (o None) más los dos agregados que sí se guardan. Nunca lanza excepción."""
    unknown = {name: None for name in SIGNAL_NAMES}
    if behavior is None:
        # Bloque ausente o inválido: las 6 señales quedan sin verificar y behavior_missing suma.
        return {**unknown, "behavior_missing": True, "time_to_submit_ms": None, "pointer_kind": None}
    try:
        b = behavior
        # Las señales de ratón solo se juzgan con ratón: en táctil (exención) o desconocido van en None.
        has_mouse = b.pointer_kind == "mouse"
        return {
            "form_too_fast": None if b.time_to_submit_ms is None else b.time_to_submit_ms < FORM_TOO_FAST_MS,
            "keystroke_uniform": _keyboard_rhythm(b.key_count, b.flight_std_ms, FLIGHT_STD_UNIFORM_MS),
            "dwell_uniform": _keyboard_rhythm(b.key_count, b.dwell_std_ms, DWELL_STD_UNIFORM_MS),
            "mouse_linear": _mouse_linear(b) if has_mouse else None,
            "no_mouse_movement": _no_mouse_movement(b) if has_mouse else None,
            "no_keyboard_events": _no_keyboard_events(b),
            "behavior_missing": False,
            # Los únicos agregados crudos que se guardan en el audit log.
            "time_to_submit_ms": b.time_to_submit_ms,
            "pointer_kind": b.pointer_kind,
        }
    except Exception as exc:
        logger.warning("Fallo al calcular señales de comportamiento: %s", type(exc).__name__)
        return {**unknown, "time_to_submit_ms": None, "pointer_kind": None}
