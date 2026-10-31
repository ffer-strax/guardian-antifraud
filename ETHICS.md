# ETHICS — Huellas digitales y minimización de datos

GUARDIÁN decide si un registro es sospechoso usando datos que identifican un dispositivo y la
forma en que una persona usa un formulario. Este documento explica qué recoge, a quién puede
perjudicar, qué hice para reducir el daño y qué no resolví. Todos los datos del proyecto son
sintéticos, y nada de lo que sigue es asesoría legal: no soy abogado.

## 1. Qué datos recojo y por qué

| Dato | Para qué sirve | Qué se guarda |
|---|---|---|
| Correo | Límite por correo y agrupar cuentas | En `audit_log` y `device_fingerprints` solo un HMAC-SHA256. En Redis, la clave del límite lleva el correo canónico en claro, pero expira a los 10 minutos |
| IP | ASN (¿es hosting?), país, grupos de cuentas | La IP completa, en claro, en `audit_log` y `device_fingerprints`. En Redis, 60 s |
| Huella del navegador | Saber si varias cuentas salen del mismo equipo | Canvas (hash), tarjeta gráfica, núcleos, pantalla, idiomas, sistema, pantalla táctil y zona horaria |
| Comportamiento | Distinguir a una persona de un script | Solo agregados calculados en el navegador (cuántas teclas, variación de tiempos, rectitud del ratón, tiempo hasta enviar) |

**Minimización: lo que sí hice.**
- El navegador nunca envía qué tecla se pulsó ni coordenadas del ratón: solo números resumidos. El
  identificador de la tecla vive en memoria hasta que se suelta y se descarta (`collector.js`).
- En `audit_log` guardo solo los booleanos de las señales de comportamiento, el tiempo hasta enviar
  y el tipo de puntero; los demás agregados no se guardan.
- La huella no se guarda cuando la decisión es `block` ni en los rechazos 400, para que una cuenta
  bloqueada no cuente como "dispositivo conocido" contra otras personas.
- Cada señal que no se puede comprobar queda como "no verificada" y no suma puntos.

**Minimización: lo que no hice.**
- La IP se guarda completa. En producción iría truncada (por ejemplo a /24) y con retención limitada.
- No hay caducidad: ni `audit_log` ni `device_fingerprints` borran nada. Una huella guardada hoy
  sigue contando mientras exista.
- La página de registro no muestra aviso de privacidad ni pide consentimiento: el colector corre
  al cargar. Solo muestra la atribución a DB-IP.
- Con la configuración por defecto, la clave del HMAC es una clave de desarrollo pública
  (`AUDIT_HMAC_KEY` vacía). Entonces cualquiera con el código puede recalcular el HMAC de un correo
  conocido: en ese caso el HMAC no protege nada. El arranque lo avisa con un warning.

## 2. Quién puede salir perjudicado

Los pesos son hipótesis calibradas con 5 muestras mías, así que no medí falsos positivos en
poblaciones reales. Estos son los casos que identifiqué leyendo mi propio motor:

- **Quien usa VPN o una red en la nube.** Una IP de un ASN de hosting suma 25 (`hosting_ip`); si la
  zona horaria de su navegador no coincide con el país de esa IP suma 10 más. Total 35: se le pide
  verificación, aunque es una persona normal.
- **Familias, oficinas y cibercafés.** Si 2 o 3 personas usan el mismo equipo, la señal
  `device_reuse_low` suma 15; con 4 o más, `device_reuse_high` suma 35. En D31 documenté que un
  cibercafé con 4 o más personas en 48 h es indistinguible de una granja con estas señales.
- **Quien rellena el formulario con el autocompletado o un gestor de contraseñas.** Si envía en
  menos de 2 s suma `form_too_fast` (30). Combinado con una VPN (25 + 10) llega a 65: revisión.
  Es plausible, pero no lo medí.
- **Quien no usa teclado y ratón de la forma habitual** (dictado por voz, otros dispositivos de
  apoyo) o bloquea JavaScript: `no_keyboard_events` (10) y `behavior_missing` (10). Tampoco medido.
- **Quien tiene el sistema en UTC:** `tz_utc` suma 5.

Ninguna señal sola llega al bloqueo (el máximo individual es 35 y el bloqueo empieza en 85). Un
bloqueo exige combinar varias, por ejemplo `device_reuse_high` + `form_too_fast` + `hosting_ip` = 90.

## 3. Qué hago para reducir el daño

- **Combinar señales, nunca decidir con una.** Las débiles (zona horaria, UTC) pesan poco.
- **Falla abierta.** Si una fuente falla (DNS, Redis, Postgres), el registro pasa y la señal queda
  "no verificada" (D13, D18). Prefiero dejar pasar a un atacante que tumbar el registro de todos.
- **"No se pudo comprobar" no es "se comprobó y es malo".** Con menos de 8 teclas o 20 movimientos
  de ratón, esas señales quedan sin evaluar (D30).
- **Zonas horarias comparadas contra todas las zonas del país** (el caso de Canarias, D23) y
  nombres antiguos aceptados, para no penalizar por un detalle de configuración.
- **Escalones, no un interruptor.** Entre "permitir" y "bloquear" hay verificación (30–59) y
  revisión (60–84).
- **Las respuestas no revelan las reglas:** solo el estado. El detalle sale únicamente en el modo
  de depuración.

## 4. Lo que no resolví

- **No hay canal de apelación.** Quien recibe un bloqueo (403) no puede impugnarlo.
- **Revisión manual y verificación no existen como sistema.** Una decisión `pending_review` o
  `verification_required` solo devuelve ese estado y deja una fila en `audit_log`. No hay cola,
  pantalla ni persona asignada. Hoy `step_up` equivale a dejar pasar (D32). Por eso, en la
  práctica, ninguna decisión de mi motor pasa por una persona.
- **No medí falsos positivos** con humanos reales, ni por grupos distintos de personas (otros
  dispositivos, otros países, tecnologías de apoyo). Cualquier sesgo contra ellos no está medido.
- **Las cifras de evasión no son una medición real** (D32): son 35 registros por nivel, una semilla,
  y bot y motor los diseñé yo.
- **Transparencia contra seguridad.** No devuelvo las razones al usuario para no darle un mapa al
  atacante, pero eso también impide que alguien entienda por qué lo marcaron.

## 5. Uso indebido de lo que construí

Los bots de `scripts/` atacan solo mi propia API local, con correos inventados, y el sistema no
envía correos. La IP simulada solo funciona con `DEBUG_CLIENT_IP_HEADER=true`, apagado por
defecto; al arrancar deja un warning y hay un test de que, apagado, el encabezado se ignora.

Aun así, el repositorio es público y publica los pesos, los umbrales y los resultados donde un bot
pasa. Es lo que pide un proyecto de evaluación, pero en un sistema real no publicaría los umbrales
ni la tabla de evasión: servirían de hoja de ruta para un atacante.

## 6. Privacidad y marco legal

Consulté las fuentes el 30-oct-2026. No soy abogado y no apliqué esto a un caso real.

**México (si el servicio operara allí).**
- La Ley Federal de Protección de Datos Personales en Posesión de los Particulares se renovó: se
  publicó el 20-mar-2025, entró en vigor el 21 y la autoridad pasó del INAI a la Secretaría
  Anticorrupción y Buen Gobierno ([Garrigues](https://www.garrigues.com/es_ES/noticia/mexico-nueva-ley-federal-proteccion-datos-personales-posesion-particulares-introduce)).
- Según el [texto oficial](https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf), dato personal
  es información de una persona "identificada o identificable" (art. 2, fr. V), y los principios del
  art. 5 incluyen licitud (art. 6), finalidad (art. 11), proporcionalidad (art. 12) e información
  (art. 14). Mi interpretación, que no verifiqué con un abogado: una IP unida a una huella de
  dispositivo puede hacer identificable a alguien, así que trataría ambas como datos personales.
- El art. 26, fr. II da derecho de oposición cuando el tratamiento está destinado a evaluar, "sin
  intervención humana", aspectos personales de la persona y produce efectos no deseados o la afecta
  de forma relevante. Mi motor podría encajar: bloquea (403) sin que intervenga una persona, y como
  la cola de revisión no existe (sección 4), tampoco la hay en `review`. No lo consulté con un
  abogado ni sé si aplicaría a un antifraude.
- No evalué si mis agregados de tecleo cuentan como dato sensible o biométrico. Por sí solos no
  identifican a una persona, pero no lo verifiqué.

**Unión Europea (si hubiera usuarios allí).**
- El [Considerando 30 del GDPR](https://activemind.legal/legislation/gdpr/recital-30) dice que las
  direcciones IP y otros identificadores, combinados con más datos, pueden servir para crear
  perfiles e identificar personas.
- El [Considerando 47](https://gdpr-text.com/en/read/recital-47/) reconoce como interés legítimo el
  tratamiento "strictly necessary" para prevenir el fraude. La palabra *estrictamente necesario* me
  obliga a preguntarme si necesito todos los campos de la huella.
- El [Art. 22](https://www.activemind.legal/legislation/gdpr/article-22) da derecho a no ser objeto
  de una decisión basada solo en un tratamiento automatizado con efectos significativos. Mi
  bloqueo automático podría entrar ahí, y no resolví si alguna excepción me cubre.
- Las [directrices 2/2023 del EDPB](https://edpb.europa.eu:443/system/files/2024-10/edpb_guidelines_202302_technical_scope_art_53_eprivacydirective_v2_en_0.pdf)
  dicen que la huella de dispositivo cae dentro del Art. 5(3) de la directiva ePrivacy, pero que
  eso no significa de forma sistemática que haga falta consentimiento. No analizan las excepciones
  ni citan la prevención del fraude como una de ellas. La pregunta de si el fraude justifica leer
  la huella sin consentimiento queda **abierta**.

## 7. Fuentes de datos y licencias

Para esta prueba usé datos públicos porque son de código abierto. En producción verificaría la
licencia y los términos de cada fuente antes de usarla, buscaría la opción más conveniente, de
preferencia gratuita, y si no hubiera una con licencia clara evaluaría pagar una base comercial.

| Fuente | Qué usé | Lo que verifiqué |
|---|---|---|
| [RouteViews](https://www.routeviews.org/) | Volcado de rutas BGP (29-oct-2026) para IP→ASN | Su sitio licencia sus datos bajo **CC BY 4.0**: pide atribución y un DOI (10.7264/1y7v-2d90), que está en el README. Hay términos comerciales aparte, para quien vende productos derivados, y el permiso es revocable ([términos](https://www.routeviews.org/routeviews/licenses/)). No leí el texto completo de CC BY |
| [DB-IP Lite](https://db-ip.com/db/download/ip-to-country-lite) | País por IP | CC BY 4.0; exige un enlace a DB-IP en las páginas que usan los resultados. Lo tiene `index.html` |
| bgp.tools | Parte de la lista de ASN de hosting (consulta manual) | Sus [términos](https://bgp.tools/kb/terms-of-service) no regulan scraping, atribución ni redistribución; prohíben una carga inaceptable sobre el servicio |
| db-ip.com y networksdb.io | Resto de la lista de hosting (consulta manual) | No pude revisar los términos de networksdb.io ni los del sitio web de db-ip.com |
| tzdata 2026c | Zonas horarias por país | No verifiqué su licencia en esta ocasión |
| Lista de dominios desechables | Rechazo de correos temporales | CC0, según el repositorio de origen |