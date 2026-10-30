// Colector de huella del navegador. Cada dato se lee por separado: si uno falla queda en null
// y el resto sigue. Los textos se recortan a los mismos límites que valida el servidor,
// para que un navegador raro no reciba un 422 y se quede sin poder registrarse.
"use strict";

const LIMITS = { canvasHash: 128, webglRenderer: 256, languages: 10, language: 35, platform: 64, timezone: 64 };

// Ejecuta fn y devuelve null si lanza: el colector nunca rompe la página.
function safe(fn) {
  try {
    const value = fn();
    return value === undefined ? null : value;
  } catch (error) {
    return null;
  }
}

function cut(text, max) {
  return typeof text === "string" ? text.slice(0, max) : null;
}

function intInRange(value, min, max) {
  return Number.isInteger(value) && value >= min && value <= max ? value : null;
}

// Hash de respaldo (FNV-1a de 32 bits) para cuando crypto.subtle no existe:
// solo está disponible en contextos seguros (https o localhost).
function fnv1a(text) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return "fnv1a:" + hash.toString(16).padStart(8, "0");
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

// Cada combinación de GPU, controlador y fuentes dibuja estos píxeles un poco distinto.
function drawCanvas() {
  const canvas = document.createElement("canvas");
  canvas.width = 240;
  canvas.height = 60;
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    return null;
  }
  ctx.textBaseline = "top";
  ctx.font = "16px Arial";
  ctx.fillStyle = "#f60";
  ctx.fillRect(100, 5, 80, 30);
  ctx.fillStyle = "#069";
  ctx.fillText("guardian-antifraud ñ 😀", 4, 10);
  ctx.strokeStyle = "rgba(102, 204, 0, 0.7)";
  ctx.beginPath();
  ctx.arc(200, 40, 15, 0, Math.PI * 2);
  ctx.stroke();
  return canvas.toDataURL();
}

async function canvasHash() {
  const data = safe(drawCanvas);
  if (data === null) {
    return null;
  }
  try {
    if (window.crypto && crypto.subtle) {
      return await sha256Hex(data);
    }
  } catch (error) {
    // Si SHA-256 falla, se usa el hash de respaldo.
  }
  return fnv1a(data);
}

function webglRenderer() {
  const canvas = document.createElement("canvas");
  const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
  if (!gl) {
    return null;
  }
  // Sin esta extensión el navegador solo da un nombre genérico: se deja en null.
  const info = gl.getExtension("WEBGL_debug_renderer_info");
  return info ? gl.getParameter(info.UNMASKED_RENDERER_WEBGL) : null;
}

async function collectFingerprint() {
  return {
    canvasHash: cut(await canvasHash(), LIMITS.canvasHash),
    webglRenderer: cut(safe(webglRenderer), LIMITS.webglRenderer),
    hardwareConcurrency: intInRange(safe(() => navigator.hardwareConcurrency), 0, 256),
    screen: {
      width: intInRange(safe(() => screen.width), 0, 20000),
      height: intInRange(safe(() => screen.height), 0, 20000),
      colorDepth: intInRange(safe(() => screen.colorDepth), 0, 64),
    },
    languages: safe(() => Array.from(navigator.languages)
      .slice(0, LIMITS.languages)
      .map((lang) => cut(lang, LIMITS.language))),
    platform: cut(safe(() => navigator.platform), LIMITS.platform),
    maxTouchPoints: intInRange(safe(() => navigator.maxTouchPoints), 0, 100),
  };
}

function browserTimezone() {
  return cut(safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone), LIMITS.timezone);
}

// --- Comportamiento (teclado y ratón) ---
// PRIVACIDAD: qué tecla se pulsó y las coordenadas del ratón solo viven en memoria mientras se
// calcula cada agregado; al servidor solo van números agregados (conteos, medias, desviaciones).
// Todo se acumula de forma incremental: no se guarda ninguna lista de teclas ni de posiciones.

const MOUSE_SAMPLE_INTERVAL_MS = 16;  // Como mucho una muestra de ratón cada 16 ms.
const MOUSE_MAX_SAMPLES = 500;        // Después de 500 muestras se deja de medir el ratón.
const MIN_KEYS_FOR_STATS = 4;         // Con menos teclas, medias y desviaciones van en null.
const MIN_MOVES_FOR_SHAPE = 20;       // Con menos muestras, straightness y speed_cv van en null.

// Media y desviación estándar sin guardar los valores (algoritmo de Welford).
function runningStats() {
  return { count: 0, mean: 0, m2: 0 };
}

function addSample(stats, value) {
  stats.count += 1;
  const delta = value - stats.mean;
  stats.mean += delta / stats.count;
  stats.m2 += delta * (value - stats.mean);
}

function statsStd(stats) {
  return stats.count > 0 ? Math.sqrt(stats.m2 / stats.count) : null;
}

function round(value, decimals) {
  if (value === null || !Number.isFinite(value)) {
    return null;
  }
  const factor = 10 ** decimals;
  return Math.round(value * factor) / factor;
}

const behavior = {
  keyCount: 0,
  keyDownAt: new Map(),  // Tecla física -> instante de keydown, solo hasta su keyup. Nunca se envía.
  lastKeyUpAt: null,
  dwell: runningStats(),
  flight: runningStats(),
  pasteUsed: false,
  keyDownSinceInput: false,
  fieldLengths: new Map(),  // Campo -> largo del valor (no el valor), para detectar autocompletado.
  moveCount: 0,
  lastSampleAt: -Infinity,
  firstPoint: null,
  previousPoint: null,
  pathLength: 0,
  speed: runningStats(),
  mouseSeen: false,
  touchSeen: false,
  clickCount: 0,
};

function onKeyDown(event) {
  // Mantener una tecla apretada repite keydown: solo cuenta la primera pulsación.
  if (event.repeat) {
    return;
  }
  const now = performance.now();
  behavior.keyCount += 1;
  behavior.keyDownSinceInput = true;
  if (behavior.lastKeyUpAt !== null) {
    addSample(behavior.flight, now - behavior.lastKeyUpAt);
    behavior.lastKeyUpAt = null;
  }
  behavior.keyDownAt.set(event.code || event.key, now);
}

function onKeyUp(event) {
  const now = performance.now();
  const id = event.code || event.key;
  const downAt = behavior.keyDownAt.get(id);
  if (downAt !== undefined) {
    addSample(behavior.dwell, now - downAt);
    behavior.keyDownAt.delete(id);
  }
  behavior.lastKeyUpAt = now;
}

function onPaste() {
  behavior.pasteUsed = true;
}

// Si el valor crece más de un carácter sin que haya habido una tecla, fue pegado o autocompletado.
function onInput(event) {
  const field = event.target;
  const previous = behavior.fieldLengths.get(field) || 0;
  if (!behavior.keyDownSinceInput && field.value.length - previous > 1) {
    behavior.pasteUsed = true;
  }
  behavior.fieldLengths.set(field, field.value.length);
  behavior.keyDownSinceInput = false;
}

function onMouseMove(event) {
  behavior.mouseSeen = true;
  const now = performance.now();
  if (behavior.moveCount >= MOUSE_MAX_SAMPLES || now - behavior.lastSampleAt < MOUSE_SAMPLE_INTERVAL_MS) {
    return;
  }
  const point = { x: event.clientX, y: event.clientY, t: now };
  if (behavior.previousPoint === null) {
    behavior.firstPoint = point;
  } else {
    const distance = Math.hypot(point.x - behavior.previousPoint.x, point.y - behavior.previousPoint.y);
    behavior.pathLength += distance;
    addSample(behavior.speed, distance / (now - behavior.previousPoint.t));
  }
  behavior.previousPoint = point;
  behavior.lastSampleAt = now;
  behavior.moveCount += 1;
}

function pointerKind() {
  if (behavior.touchSeen || safe(() => navigator.maxTouchPoints) > 0) {
    return "touch";
  }
  if (behavior.mouseSeen || safe(() => window.matchMedia("(pointer: fine)").matches)) {
    return "mouse";
  }
  return "unknown";
}

function startBehaviorTracking() {
  const fields = document.querySelectorAll('#email, input[type="password"]');
  fields.forEach((field) => {
    field.addEventListener("keydown", onKeyDown);
    field.addEventListener("keyup", onKeyUp);
    field.addEventListener("paste", onPaste);
    field.addEventListener("input", onInput);
  });
  document.addEventListener("mousemove", onMouseMove, { passive: true });
  document.addEventListener("touchstart", () => { behavior.touchSeen = true; }, { passive: true });
  document.addEventListener("click", () => { behavior.clickCount += 1; });
}

function collectBehavior(submittedAt) {
  const enoughKeys = behavior.keyCount >= MIN_KEYS_FOR_STATS;
  const enoughMoves = behavior.moveCount >= MIN_MOVES_FOR_SHAPE;
  const net = behavior.firstPoint === null ? 0 : Math.hypot(
    behavior.previousPoint.x - behavior.firstPoint.x,
    behavior.previousPoint.y - behavior.firstPoint.y,
  );
  const speedMean = behavior.speed.count > 0 ? behavior.speed.mean : null;
  return {
    key_count: behavior.keyCount,
    dwell_mean_ms: enoughKeys && behavior.dwell.count > 0 ? round(behavior.dwell.mean, 1) : null,
    dwell_std_ms: enoughKeys ? round(statsStd(behavior.dwell), 1) : null,
    flight_mean_ms: enoughKeys && behavior.flight.count > 0 ? round(behavior.flight.mean, 1) : null,
    flight_std_ms: enoughKeys ? round(statsStd(behavior.flight), 1) : null,
    paste_used: behavior.pasteUsed,
    mouse_move_count: behavior.moveCount,
    path_length_px: round(behavior.pathLength, 1),
    net_displacement_px: round(net, 1),
    // min(1, ...) evita que un redondeo deje la rectitud apenas por encima de 1.
    straightness: enoughMoves && behavior.pathLength > 0
      ? round(Math.min(1, net / behavior.pathLength), 4) : null,
    speed_cv: enoughMoves && speedMean > 0 ? round(statsStd(behavior.speed) / speedMean, 4) : null,
    click_count: behavior.clickCount,
    pointer_kind: pointerKind(),
    // performance.now() cuenta desde que empezó a cargar la página.
    time_to_submit_ms: round(submittedAt, 1),
  };
}

async function onSubmit(event) {
  event.preventDefault();
  // Se toma antes de calcular la huella, que puede tardar unos milisegundos.
  const submittedAt = performance.now();
  const result = document.getElementById("result");
  result.textContent = "Enviando...";

  let fingerprint = null;
  try {
    fingerprint = await collectFingerprint();
  } catch (error) {
    // Sin huella el registro funciona igual.
  }
  let behaviorSummary = null;
  try {
    behaviorSummary = collectBehavior(submittedAt);
  } catch (error) {
    // Sin comportamiento el registro funciona igual (el servidor lo marca como faltante).
  }

  const payload = {
    email: document.getElementById("email").value,
    timezone: browserTimezone(),
    fingerprint: fingerprint,
    behavior: behaviorSummary,
  };
  if (new URLSearchParams(location.search).get("debug") === "1") {
    console.log("payload /register", payload);
  }

  try {
    const response = await fetch("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    // Solo el "status"; los errores (400, 422, 429) no traen uno y se muestra el código HTTP.
    result.textContent = typeof data.status === "string" ? data.status : "error " + response.status;
  } catch (error) {
    result.textContent = "error de red";
  }
}

document.getElementById("register-form").addEventListener("submit", onSubmit);
try {
  startBehaviorTracking();
} catch (error) {
  // Si no se pueden poner los listeners, el formulario sigue funcionando.
}
