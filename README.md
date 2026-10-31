# GUARDIÁN — Motor antifraude para CONECTA

![CI](https://github.com/ffer-strax/guardian-antifraud/actions/workflows/ci.yml/badge.svg)

Motor de riesgo que puntúa cada registro de 0 a 100 y decide qué hacer con él.
Proyecto del reto técnico "GUARDIÁN" (empresa ficticia: Conecta). Python 3.11+ / FastAPI / Redis / PostgreSQL / Docker.

> **Todos los datos son sintéticos.** No hay datos personales reales en este repositorio.

---

## Estado del proyecto (checklist de fases)

- [x] **Fase 1 — Fundamentos**
  - [x] Validación de correo: lista de dominios desechables, canonicalización de Gmail (puntos y `+sufijo`), verificación de registro MX
  - [x] Límite de peticiones por IP y por correo con Redis (responde 429)
  - [x] Tests unitarios y CI en verde (GitHub Actions)
  - [x] `docker compose up` levanta todo el stack
- [x] **Fase 2 — Detección de VPN / proxy** (alcance recortado, ver abajo)
  - [x] Clasificación por ASN con búsqueda del prefijo más largo (implementación propia) y lista de ASN de hosting
  - [x] País por IP (DB-IP Lite) y consistencia zona horaria vs. país, incluido el caso de Canarias
  - [x] Motor de riesgo (puntaje 0–100 → acción) conectado a `/register`
  - [ ] ~~Detección de fuga WebRTC~~ — **no implementada** (recorte por tiempo)
  - [ ] ~~Listas de reputación públicas (FireHOL, Spamhaus DROP)~~ — **no implementadas** (recorte por tiempo)
- [x] **Fase 3 — Huellas de dispositivo** (versión reducida: colector en JavaScript + similitud ponderada por atributo)
- [x] **Fase 4 — Biometría de comportamiento** (colector en el navegador que envía solo agregados, nunca teclas ni coordenadas; 7 señales; ver D30)
- [x] **Fase 5 — Grafo de cuentas** (detección de granjas de ≥ 4 cuentas, por lotes sobre datos sintéticos; v2 con ventana de 48 h y evidencia fuerte; **no está conectado a `/register`**; ver D31). *No se implementa el modelo de ML. (ver D34)*
- [x] **Fase 6 — Evasión adversaria** (campaña con Chromium real vía Playwright y 4 niveles de bot: 1, 2, 3 y 3b; 35 registros por nivel = 140 en total; ver D32)

### Documentación

- [ ] `DECISIONS.md` — decisiones (en curso)
- [x] `ETHICS.md` — huellas digitales y minimización de datos
- [ ] `INDUSTRY.md` — cómo se usan estas técnicas en sistemas reales (con fuentes)
- [ ] `AI_USAGE.md` — registro de uso de IA (en curso)
- [x] Análisis de PR-3 (exigencia de bloquear todas las VPN) (ver D33)

### Qué NO se hizo, y por qué

Se recortó el alcance para entregar menos cosas pero funcionando y con resultados honestos. No se implementó: aprendizaje automático, WebRTC, listas de reputación, huella de audio y fuentes, biometría completa de teclado y ratón, y prueba de carga. El flujo de verificación (correo/SMS) tampoco existe: el motor decide pedirla, pero no la ejecuta.

---

## Cómo ejecutarlo

Requisitos: Docker Desktop.

```bash
docker compose up --build
```

Espera unos 10 segundos (las bases de ASN y país se cargan al arrancar) y comprueba:

```bash
curl http://localhost:8000/health
```

Registro de prueba:

```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"email":"persona@example.com","timezone":"Europe/Madrid"}'
```

### Tests

```bash
docker run --rm -v "$PWD:/repo" -w /repo/backend python:3.12-slim \
  sh -c "pip install -q -r requirements.txt && python -m pytest ../tests -v"
```

La CI ejecuta los mismos tests en cada push.

---

## Cómo funciona `/register`

Orden de los chequeos:

1. Límite por IP (429 si se excede)
2. Canonicalización del correo y dominio desechable (400)
3. Límite por correo canónico (429)
4. Verificación MX del dominio (400 si no puede recibir correo)
5. Señales de red: ASN, hosting, país y zona horaria
6. Huella del dispositivo: cuántas otras cuentas usan un dispositivo parecido (la búsqueda tiene un tope de 150 ms)
7. Comportamiento: 7 señales calculadas con los agregados que manda el navegador
8. Motor de riesgo: puntaje y acción
9. Después de responder: se escribe la fila en `audit_log` y, salvo en bloqueos, se guarda la huella

### Señales y pesos actuales

| Señal | Peso | Comentario |
|---|---|---|
| IP de hosting / datacenter (`hosting_ip`) | 25 | ASN en la lista de hosting |
| Zona horaria no coincide con el país de la IP (`tz_country_mismatch`) | 10 | Se compara con **todas** las zonas del país |
| Zona horaria sin país: UTC, GMT, CET… (`tz_utc`) | 5 | Ambigua: servidores sin cabeza, pero también humanos |
| El mismo dispositivo ya registró 1 o 2 cuentas más (`device_reuse_low`) | 15 | Huellas parecidas en un 75 % o más (D29) |
| El mismo dispositivo ya registró 3 o más cuentas (`device_reuse_high`) | 35 | Posible granja |
| Formulario enviado en menos de 2 s desde que cargó la página (`form_too_fast`) | 30 | |
| Tiempo entre teclas casi constante (`keystroke_uniform`) | 25 | 8 o más teclas, desviación < 15 ms |
| Duración de cada pulsación casi constante (`dwell_uniform`) | 15 | 8 o más teclas, desviación < 8 ms |
| Ratón en línea casi recta (`mouse_linear`) | 20 | 20 o más muestras, rectitud > 0.98; no se evalúa en táctil |
| Hay ratón pero no se movió (`no_mouse_movement`) | 5 | No se evalúa en táctil |
| El correo apareció sin teclas, sin pegar y sin autocompletar (`no_keyboard_events`) | 10 | |
| Falta el bloque de comportamiento o es inválido (`behavior_missing`) | 10 | Atrapa al bot sin navegador, pero también a quien bloquea JavaScript |

Los pesos son **hipótesis**, no hechos comprobados: se probaron con la campaña de la Fase 6 (ver D32) y siguen sin calibrarse con datos reales. Ninguna señal sola bloquea.

### Puntaje → acción

| Puntaje | Acción | Respuesta HTTP |
|---|---|---|
| 0–29 | Permitir | 200 `{"status":"ok"}` |
| 30–59 | Permitir + pedir verificación (el paso de verificación aún no existe) | 200 `{"status":"verification_required"}` |
| 60–84 | Marcar para revisión manual (la cola aún no existe) | 202 `{"status":"pending_review"}` |
| 85–100 | Bloquear | 403 `{"status":"blocked"}` |

La respuesta normal **no** incluye puntaje ni razones, para no revelar las reglas.

### Degradación elegante

Si una fuente de señal falla (base de datos ausente, Redis caído, DNS lento), el endpoint no responde 500: puntúa con lo que tiene y marca la señal como no verificada. Los límites y trade-offs están en `DECISIONS.md`.

---

## Probar las señales (modo de IP simulada)

Dentro de Docker el servidor ve una IP privada, así que no hay ASN ni país. Para probar hay un modo de depuración, **apagado por defecto y solo para pruebas**: con él, el header `X-Debug-Client-IP` reemplaza la IP únicamente para calcular las señales (nunca para el límite de peticiones) y la respuesta incluye el detalle.

```bash
DEBUG_CLIENT_IP_HEADER=true docker compose up --build
```

(En PowerShell: `$env:DEBUG_CLIENT_IP_HEADER="true"; docker compose up --build`)

```bash
# IP de AWS + zona que no coincide -> verification_required (puntaje 45: 35 por las señales de IP y 10 por behavior_missing, porque el curl no manda comportamiento)
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" -H "X-Debug-Client-IP: 54.239.28.85" \
  -d '{"email":"prueba1@gmail.com","timezone":"America/Mexico_City"}'

# IP de España + zona de Canarias -> ok (sin falso positivo)
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" -H "X-Debug-Client-IP: 80.58.61.250" \
  -d '{"email":"prueba2@gmail.com","timezone":"Atlantic/Canary"}'
```

---

## Configuración (variables de entorno)

Todas son opcionales; si faltan o son inválidas se usa el valor por defecto (las inválidas dejan un aviso).

| Variable | Por defecto | Para qué |
|---|---|---|
| `RATE_LIMIT_IP_MAX` / `RATE_LIMIT_IP_WINDOW_SECONDS` | 40 / 60 | Peticiones por IP en la ventana |
| `RATE_LIMIT_EMAIL_MAX` / `RATE_LIMIT_EMAIL_WINDOW_SECONDS` | 5 / 600 | Peticiones por correo canónico |
| `MX_DNS_TIMEOUT_MS` | 1000 | Tiempo máximo de cada consulta DNS |
| `REDIS_TIMEOUT_MS` | 200 | Tiempo máximo de espera a Redis |
| `DEBUG_CLIENT_IP_HEADER` | (vacío = apagado) | Modo de IP simulada. **Nunca en producción** |

Ver `.env.example`.

---

## Cómo correr la campaña de evasión

La imagen de bots (Chromium real) pesa ~4 GB y la campaña tarda unos 35 min. En PowerShell, todo en la misma sesión:

```powershell
$env:DEBUG_CLIENT_IP_HEADER = "true"
docker compose up -d
docker compose --profile bots run --rm bots python scripts/run_campaign.py --tiers "1,2,3,3b" --per-tier 35
```

(En bash, la primera línea es `export DEBUG_CLIENT_IP_HEADER=true`.)

La campaña vacía `audit_log` y `device_fingerprints` antes de cada nivel y deja los resultados en `data/campaign_results.json` y `data/campaign_table.md`. Para copiar la tabla a este README (solo biblioteca estándar):

```powershell
python scripts/run_campaign.py --update-readme-from data/campaign_table.md
```

Al terminar, vacía las tablas y apaga el modo debug (el `up -d` recrea la API sin él):

```powershell
docker compose exec -T postgres psql -U guardian -d guardian -c "TRUNCATE audit_log, device_fingerprints;"
Remove-Item Env:DEBUG_CLIENT_IP_HEADER
docker compose up -d
```

---

## Resultados de evasión (Fase 6)

Esta tabla la regenera `scripts/run_campaign.py`; no se escribe a mano.

<!-- CAMPAIGN_TABLE_START -->
| Nivel | Registros | allow | step_up | review | block | Evasión estricta | Evasión laxa | Señales más frecuentes (top 3) | Score mediano | Score mínimo | Mediano sin device_reuse | Mínimo sin device_reuse | Cambian de acción sin device_reuse |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 (bot ingenuo) | 35 | 0 | 0 | 3 | 32 | 0/35 (0%) | 0/35 (0%) | form_too_fast (35), hosting_ip (35), no_mouse_movement (35) | 100 | 65 | 65 | 65 | 32/35 |
| 2 (humanización básica) | 35 | 0 | 1 | 34 | 0 | 0/35 (0%) | 1/35 (3%) | dwell_uniform (35), hosting_ip (35), tz_utc (35) | 80 | 45 | 45 | 45 | 34/35 |
| 3 (red residencial) | 35 | 22 | 13 | 0 | 0 | 22/35 (63%) | 35/35 (100%) | dwell_uniform (35), device_reuse_low (13) | 15 | 15 | 15 | 15 | 13/35 |
| 3b (exención táctil) | 35 | 14 | 21 | 0 | 0 | 14/35 (40%) | 35/35 (100%) | dwell_uniform (35), device_reuse_low (16), device_reuse_high (5) | 30 | 15 | 15 | 15 | 21/35 |
<!-- CAMPAIGN_TABLE_END -->

Contexto, decisiones y limitaciones de la campaña: [D32 en DECISIONS.md](DECISIONS.md#d32-cómo-medimos-la-evasión-campaña-con-navegador-real-y-4-niveles-de-bot).

### Lectura de la campaña

1. Esperaba que el comportamiento de teclado y navegador detuvieran al bot del nivel 3 (IP residencial, zona horaria coherente, tecleo con ritmo). Me equivoqué: 22 de 35 pasaron con allow (63 %) y 35 de 35 con evasión laxa.

2. Sin el dispositivo repetido, el nivel 1 llegaba a review (65 puntos) y el nivel 2 solo a step_up (45): en el nivel 2 lo que lo subió a review fue el dispositivo que se repetía, no el comportamiento. En el nivel 3 solo activó dwell_uniform (15 puntos), que no alcanza ni para step_up (30).

3. Agregaría una señal sobre la variación de la velocidad del mouse: imitar una distribución humana cuesta más que fingir un promedio, aunque no es imposible. No confío en las cifras tal cual: n = 35, el 63 % y el 40 % bajan por colisiones de la huella del bot (13 y 16 casos) y no por la defensa, y el bot, el motor y los umbrales los hicimos nosotros (yo y los agentes) con 5 muestras humanas.

---

## Limitaciones conocidas

- No existe flujo de verificación (correo/SMS) ni cola de revisión manual: `step_up` y `review` solo devuelven el estado (`verification_required` o `pending_review`) y dejan una fila en `audit_log`.
- El grafo de cuentas corre por lotes sobre datos sintéticos y no está integrado en `/register` (D31).
- Exención táctil: en un dispositivo táctil las señales de ratón no se evalúan, y un bot puede declararse táctil para saltárselas (nivel 3b de la campaña, D32).
- Solo IPv4: las IPv6 quedan sin país.
- Latencia (D35): p95 de 73 ms con MX en caché y 158 ms con MX en frío (n = 20), medido en localhost con una petición a la vez. No se midieron fallos de DNS o Redis, que pueden superar 300 ms, ni carga concurrente.
- Un bot que falsea su zona horaria para que coincida con su IP pasa esa señal.
- La clasificación por ASN es aproximada: un ASN de hosting puede contener rangos de otras organizaciones.
- Los pesos y umbrales no están calibrados con datos reales.
- Un bot con IP residencial coherente y tecleo con ritmo humano pasa: 22 de 35 con `allow` en el nivel 3 de la campaña (D32).

---

## Estructura del repositorio

```
backend/
  app/          # API (FastAPI): /health y /register
  services/     # email, límites, MX, ASN, país, motor de riesgo, audit log, huella, comportamiento, grafo de cuentas
  data/         # bases de datos versionadas (ver "Datos y atribuciones")
frontend/       # página de registro y colector de huella y comportamiento
bots/           # imagen de Docker con Playwright para la campaña (perfil "bots")
scripts/        # mediciones, generadores de datos (zonas horarias, cuentas sintéticas), grafo por lotes, bots y campaña de evasión
data/           # línea base humana (versionada); resultados del generador y de la campaña (ignorados por git)
tests/          # pruebas unitarias y de integración
.github/workflows/ci.yml
docker-compose.yml
```

---

## Datos y atribuciones

- **País por IP:** [IP Geolocation by DB-IP](https://db-ip.com) — DB-IP Lite (país), octubre 2026, licencia [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- **IP → ASN:** tabla generada a partir de un volcado de [RouteViews](https://www.routeviews.org/) (29-oct-2026), datos bajo licencia [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Atribución: "Este trabajo usa datos de RouteViews (https://www.routeviews.org/), DOI 10.7264/1y7v-2d90".
- **Lista de ASN de hosting:** construida a mano con consultas a bgp.tools, db-ip.com y networksdb.io (29-oct-2026); la fuente de cada bloque está en el propio archivo.
- **Zonas horarias por país:** `zone.tab` y `tzdata.zi` de tzdata 2026c, convertidos con `scripts/build_country_timezones.py`.
- **Dominios desechables:** lista pública con licencia CC0.