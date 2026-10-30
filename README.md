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
- [ ] **Fase 3 — Huellas de dispositivo** (versión reducida: colector en JavaScript + similitud ponderada por atributo)
- [ ] **Fase 4 — Biometría de comportamiento** (versión mínima: formulario sin eventos de teclado y formulario completado demasiado rápido)
- [ ] **Fase 5 — Grafo de cuentas** (detección de granjas de ≥ 4 cuentas). *No se implementa el modelo de ML.*
- [ ] **Fase 6 — Evasión adversaria** (3 bots con Playwright, campaña de ≥ 100 registros, tabla de evasión)

### Documentación

- [ ] `DECISIONS.md` — decisiones (en curso)
- [ ] `ETHICS.md` — huellas digitales y minimización de datos
- [ ] `INDUSTRY.md` — cómo se usan estas técnicas en sistemas reales (con fuentes)
- [ ] `AI_USAGE.md` — registro de uso de IA (en curso)
- [ ] Análisis de PR-3 (exigencia de bloquear todas las VPN)

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
5. Cálculo de señales (ASN, hosting, país, zona horaria, reutilización de dispositivo)
6. Motor de riesgo: puntaje y acción

### Señales y pesos actuales

| Señal | Peso | Comentario |
|---|---|---|
| IP de hosting / datacenter | 25 | ASN en la lista de hosting |
| Zona horaria no coincide con el país de la IP | 10 | Se compara con **todas** las zonas del país |
| Zona horaria `UTC` | 5 | Ambigua: servidores sin cabeza, pero también humanos |
| Dispositivo reutilizado por 1 o 2 cuentas más | 15 | Huellas con similitud ≥ 0.75 y otro correo |
| Dispositivo reutilizado por 3 o más cuentas | 35 | Patrón de granja de cuentas |

Los pesos son **hipótesis**, no hechos comprobados; se validan en la Fase 6. Ninguna señal sola bloquea.

### Puntaje → acción

| Puntaje | Acción | Respuesta HTTP |
|---|---|---|
| 0–29 | Permitir | 200 `{"status":"ok"}` |
| 30–59 | Permitir + pedir verificación | 200 `{"status":"verification_required"}` |
| 60–84 | Cola de revisión manual | 202 `{"status":"pending_review"}` |
| 85–100 | Bloquear | 403 `{"status":"blocked"}` |

Con los pesos actuales el máximo posible es 70 (hosting + zona que no coincide + dispositivo reutilizado por 3 o más cuentas), así que ya ocurren "permitir", "pedir verificación" y "revisión". Bloqueo se alcanzará al sumar las señales de comportamiento y grafo. La respuesta normal **no** incluye puntaje ni razones, para no revelar las reglas.

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
# IP de AWS + zona que no coincide -> verification_required (puntaje 35)
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

## Resultados de evasión (Fase 6)

*Pendiente.* Esta tabla la regenera `scripts/run_campaign.py`; no se escribe a mano.

| Bot | Registros | Evasión | Señal que falló |
|---|---|---|---|
| Nivel 1 — ingenuo | — | — | — |
| Nivel 2 — endurecido | — | — | — |
| Nivel 3 — ataque completo | — | — | — |

---

## Limitaciones conocidas

- La verificación en dos pasos no está implementada: solo existe el estado `verification_required`.
- Bloqueo es inalcanzable hasta agregar señales de comportamiento y grafo: hoy el puntaje máximo es 70 (hosting 25 + zona que no coincide 10 + dispositivo reutilizado 35) y bloqueo empieza en 85. Revisión ya se alcanza con esa combinación.
- Solo IPv4: las IPv6 quedan sin país.
- La latencia total de `/register` no está medida de punta a punta. La primera consulta MX de un dominio puede superar los 300 ms, y con Redis caído la espera puede ser mucho mayor (ver `DECISIONS.md`).
- Un bot que falsea su zona horaria para que coincida con su IP pasa esa señal.
- La clasificación por ASN es aproximada: un ASN de hosting puede contener rangos de otras organizaciones.
- Los pesos y umbrales no están calibrados con datos reales.

Limitaciones de la comparación de huellas (detalle en `DECISIONS.md`, D29):

- Solo comparo contra las 200 huellas más recientes que tengan la misma plataforma, el mismo número de núcleos y la misma pantalla. En una configuración muy común (por ejemplo Windows, 8 núcleos y 1920x1080) esas 200 se agotan rápido, y una cuenta antigua de una granja puede quedar fuera de la comparación.
- Un atacante que cambie uno de esos cuatro valores en cada cuenta evita la comparación, porque el índice solo encuentra candidatos que coinciden exactamente en ellos.
- Si cambian a la vez el canvas y el renderizador de WebGL, la similitud baja a 0.60 y deja de contar como el mismo dispositivo.
- Dos equipos idénticos (mismo modelo, mismo navegador) pueden salir como "el mismo dispositivo". La huella es una señal suave, no una identificación.
- Una huella con un campo del índice vacío no se compara (queda "no verificada"), así que un bot que no manda su huella no recibe penalización por reutilización.
- La lectura de candidatos ocurre dentro de la petición. Con Postgres caído cada registro con huella espera hasta 150 ms más.
- No hay caducidad: una huella guardada hoy sigue contando mientras exista en la tabla.

---

## Estructura del repositorio

```
backend/
  app/          # API (FastAPI): /health y /register
  services/     # email, límites, MX, ASN, país, motor de riesgo
  data/         # bases de datos versionadas (ver "Datos y atribuciones")
scripts/        # mediciones y generadores de datos
tests/          # pruebas unitarias y de integración
.github/workflows/ci.yml
docker-compose.yml
```

Otras scripts y carpetas (`simulate_fraud.py`, `evasion_bot.py`, `run_campaign.py`, `frontend/`) llegan con las fases siguientes.

---

## Datos y atribuciones

- **País por IP:** [IP Geolocation by DB-IP](https://db-ip.com) — DB-IP Lite (país), octubre 2026, licencia [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- **IP → ASN:** tabla generada a partir de un volcado de [Routeviews](https://www.routeviews.org/) (29-oct-2026). No se encontró una licencia explícita para estos datos; ver `ETHICS.md`.
- **Lista de ASN de hosting:** construida a mano con consultas a bgp.tools, db-ip.com y networksdb.io (29-oct-2026); la fuente de cada bloque está en el propio archivo.
- **Zonas horarias por país:** `zone.tab` y `tzdata.zi` de tzdata 2026c, convertidos con `scripts/build_country_timezones.py`.
- **Dominios desechables:** lista pública con licencia CC0.