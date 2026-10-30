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

async function onSubmit(event) {
  event.preventDefault();
  const result = document.getElementById("result");
  result.textContent = "Enviando...";

  let fingerprint = null;
  try {
    fingerprint = await collectFingerprint();
  } catch (error) {
    // Sin huella el registro funciona igual.
  }

  const payload = {
    email: document.getElementById("email").value,
    timezone: browserTimezone(),
    fingerprint: fingerprint,
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
