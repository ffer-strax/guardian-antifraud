# DECISIONS

## D1. Python 3.12 dentro de Docker, no el 3.15 local
- Contexto: tengo Python 3.15 instalado; el reto pide 3.11+
- Alternativas: usar 3.15 local / imagen 3.12 en contenedor
- Decisión: imagen python:3.12-slim
- Por qué: no pude verificar que las librerías soporten 3.15; 3.12 es estable

## D2. Versiones exactas fijadas
- Contexto: el reto exige que cada número sea reproducible.
- Decisión: versión exacta en requirements.txt e imágenes (postgres:16.4, redis:7.4.1).
- Por qué: mismo código, mismo resultado en cualquier máquina.
- verificadas en pypi.org el 21-oct-2026, existen pero no son las más recientes; se mantienen por reproducibilidad


## D3. Stack: FastAPI + PostgreSQL + Redis
- Contexto: el reto sugiere esta arquitectura
- El Stack es nuevo para mí; tuve que aprenderlo durante el reto; mi stack habitual es nodejs, TS y Next.js

## D4. Ninguna base de datos publica puertos al host
- Contexto: el compose publicaba Postgres (5432) y Redis (6379) para depurar.
- Alternativas: publicar para depurar / solo red interna de Docker.
- Decisión: quité ambos puertos; la API llega por la red interna (redis:6379).
- Por qué: reduce la superficie de ataque; Postgres tenía una contraseña de ejemplo conocida


## D5. Canonicalización de correo solo para Gmail
- Contexto: Gmail ignora puntos y todo lo que sigue a "+", así que un
  atacante crea muchas cuentas con un solo buzón
- Decisión: solo Gmail; en otros dominios solo minúsculas y quitar espacios
- Por qué: en otros proveedores ana.perez@ y anaperez@ pueden ser personas
  distintas; unificarlas sería un falso positivo

## D6. Validación de formato con EmailStr (email-validator==2.2.0)
- Alternativas: str con regex propia / EmailStr.
- Decisión: EmailStr
- Por qué: validar correos con regex es propenso a errores

## D7. Lista de dominios desechables local y estática
- Contexto: necesito bloquear correos temporales.
- Para este caso utilizaré el siguiente repositorio de github https://github.com/disposable-email-domains/disposable-email-domains y lo tomaré como base para mi lista de dominios.
-Licencia: CC0 1.0 Universal (CC0 1.0)
Public Domain Dedication
fecha de descarga:21 de octubre del 2026
copia estatica en el repositorio.

## D8 (planeada, aún no implementada). Geografía como señal blanda
- Decisión: comparar la zona horaria del navegador contra todas las zonas
  válidas del país de la IP, con peso bajo, sin decidir nunca por sí sola
- Por qué: Canarias (UTC+0) con IP en Madrid (UTC+1) sería un falso positivo
  con una regla fija por eso no es regla definitiva.

## D9. Rate limit: 40 peticiones por IP en 60 s
- Contexto: PR/Fase 1 pide 429 ante fuerza bruta; una IP puede ser mucha gente real (aulas, oficinas, redes móviles con CGNAT).
- Alternativas: 20 en 30 s / 40 en 120 s / 40 en 60 s.
- Decisión: 40 en 60 s.
- Por qué: 20/30 s corta ráfagas legítimas como un salón registrándose a la vez; 40/120 s deja pasar scripts lentos de ~1 por segundo

## D10. Rate limit por email canónico: 5 intentos en 600 s
- Por qué: frena al atacante que rota IPs pero reutiliza el mismo buzón de Gmail con puntos y "+".
- COMENTARIO: un usuario real que se equivoca más de 5 veces en 10 minutos queda bloqueado temporalmente.

## D11. Límites configurables por variables de entorno
- Decisión: los valores se leen de .env (RATE_LIMIT_*), con defaults en el código; .env.example lleva los mismos nombres con valores de ejemplo.
- Por qué: probar el 429 a mano con un límite bajo (lo hice con 3) y poder cambiarlo en vivo en la defensa sin tocar la lógica.
- hay que reconstruir el contenedor para que tome el cambio.

## D12. Orden de chequeos: IP → desechable → email
- Alternativas: IP → email → desechable (la que recomendó el agente).
- Decisión: IP primero, desechable después, email al final.
- Por qué: la IP cuenta todo el tráfico; la lista de desechables es una consulta local barata; el contador de email solo debe medir intentos que serían aceptados.
- repetir el mismo email desechable solo lo frena la IP, pero ese correo se rechaza siempre.

## D13. Fallo de Redis: fail-open con controles compensatorios
- Contexto: PR-5 exige degradación elegante; el rate limit depende de Redis.
- Alternativas: fail-closed (rechazar todo) / fail-open silencioso / fail-open con respaldo.
- Decisión: fail-open: si Redis falla la petición pasa y se registra un warning.
- Por qué: fail-closed convertiría tumbar Redis en un DoS contra mis propios registros, y el rate limit es solo una capa; los demás filtros siguen activos.
- Riesgo aceptado: sin Redis el límite queda desactivado y un atacante que lo tumbe se salta el freno.
- Mitigaciones hechas: puerto 6379 no expuesto al host; timeout de Redis corto y configurable.
- Mitigaciones planeadas (no implementadas): límite de respaldo en memoria, circuit breaker, marca de "no verificado" en el log de auditoría y suma de riesgo en el score.
- prefiero disponibilidad sobre seguridad en un registro de red social; no lo haría en pagos.

## D14. Tests del rate limit con Redis falso
- Alternativas: Redis real / fakeredis (dependencia nueva) / falso a mano.
- Decisión: falso a mano.
- Por qué: mis tests corren en un contenedor temporal donde localhost no es el Redis del compose; evita estado compartido y dependencias nuevas.
- Qué no prueba: el paso del tiempo, el Redis real ni la concurrencia. Verificado a mano: con límite 3, el cuarto intento dio 429 con retry-after, y tras 1 min volvió a dar 200.

## Limitaciones (añadir)
- Los 422 (formato inválido) no consumen cupo por IP porque FastAPI los rechaza antes de entrar a la función.
- Detrás de un proxy, request.client.host sería la IP del proxy; no se confía en X-Forwarded-For.
- En local con Docker, todas mis pruebas comparten una misma IP.
- Ventana fija: ráfagas posibles en el borde.
- Los endpoints son síncronos y corren en un grupo limitado de hilos (por defecto 40 en FastAPI, que no he verificado). Una consulta MX lenta ocupa un hilo hasta ~2 s. Con muchas peticiones simultáneas a dominios lentos, el servicio se saturaría aunque el rate limit por IP las frene una a una. No lo arregles hoy.
- La caché guarda una clave por cada dominio distinto que alguien envíe (TTL de 1 h), así que un atacante puede llenarla de claves arbitrarias. El rate limit lo acota pero no lo elimina.
- Un dominio solo con AAAA (IPv6) daría no_mail.

## D15. Valores por defecto de desarrollo en el compose
- Contexto: .env no se sube es mas bien un clon limpio Postgres fallaba sin contraseña y NFR-1 exige un solo comando.
- Alternativas: A) defaults en el compose / B) pedir `cp .env.example .env` en el README.
- Decisión: A, con la sintaxis ${VAR:-valor} para Postgres.
- Por qué: todo es sintético (PR-6) y el puerto está cerrado; arranca con `docker compose up`.
- Trade-off: la contraseña de ejemplo es pública, solo válida en desarrollo; en producción vendría de un gestor de secretos. Postgres solo lee estas credenciales al crear la base por primera vez.
- Verificado: renombré .env, `down -v`, `up --build -d`, los tres contenedores Up y sin errores de contraseña.

## D17. Lectura robusta de variables de entorno
- Contexto: la auditoría encontró que RATE_LIMIT_IP_MAX=abc daba 500 en cada /register y REDIS_TIMEOUT_MS=abc impedía arrancar. Lo reproduje yo.
- Decisión: _env_int nunca lanza excepción: variable ausente o vacía usa el default sin warning; texto no entero, cero o negativo usa el default con warning (solo el nombre, nunca el valor).
- Por qué: un valor de configuración malo no puede tumbar el servicio (PR-5), y una ventana en 0 desactivaría el rate limit en silencio.
- Trade-off: un valor inválido en un límite genera un warning en cada petición (ruidoso, pero visible). Una variable ausente en producción usa el default sin avisar.
- Verificado en Docker: con "abc" el endpoint responde 200 y el log muestra el warning.

## D18. Verificación MX con caché y fail-open
- Contexto: un dominio sin servidor de correo no puede recibir mensajes; pero consultar DNS es red externa que no controlo.
- Decisión: consulto MX (y A como respaldo); Null MX (RFC 7505) y NXDOMAIN cuentan como no_mail → 400. Timeout de 1 s por consulta, resultado ok/no_mail cacheado 1 h en Redis, unknown NO se cachea y deja pasar.
- Por qué: un timeout es un fallo de mi consulta, no un hecho del dominio; cachearlo dejaría pasar sin verificar durante una hora a un dominio que quizá no recibe correo
- Trade-off: con caché fría una petición puede tardar hasta ~2 s (MX + A), por encima de los 300 ms; medido ~350 ms con DNS real y 25-40 ms con caché.
- Limitaciones: un dominio solo con IPv6 (AAAA) daría no_mail; un atacante que provoque timeouts se salta el chequeo (fail-open); endpoint síncrono, una consulta lenta ocupa un hilo; la caché crece con cada dominio distinto (acotada por el rate limit).
- Pendiente: marcar "no verificado" en el log de auditoría y sumar riesgo en el score.

## D20: lookup propio con prefijo más largo, y pyasn solo para generar el archivo. Razón: la imagen slim no trae compilador y en PyPI solo hay código fuente. Fuente: RIB de Routeviews del 29-oct-2026, 1 159 994 prefijos IPv4, .gz de 4 MB.

## D21: socket.inet_pton en vez de ipaddress para leer el archivo, tras medir 37 s frente a 3.9 s. Mi prompt decía “usa ipaddress”, y cambiaste la regla con datos.
- Números medidos por ti: carga 2.92 s, 123.2 MiB retenidos, pico de 139.1 MiB, 24.6 µs por consulta.

# Limitaciones: la carga perezosa hace que la primera petición espere ~3 s (hay que cargar al arrancar); la base vacía por fallo no se reintenta; solo IPv4; cada proceso cargaría su propia copia en memoria.

## D23: Señal de zona horaria vs. país de la IP

Contexto: el navegador muestra su zona horaria y la IP muestra un país.
Si no coinciden, puede ser un bot o un VPN. Pero países como España
tienen varias zonas válidas (Europe/Madrid, Africa/Ceuta,
Atlantic/Canary), así que comparo contra TODAS las zonas del país, no
contra una sola.

Decisión:
- El mapa país -> zonas sale de zone.tab (tzdata 2026c), se genera con
  un script y se versiona. El servicio no lee zone.tab en runtime.
- Agregué 124 nombres antiguos (Asia/Calcutta, Europe/Kiev) desde
  tzdata.zi, cada uno solo al país de su nombre actual, para no penalizar
  a navegadores que aún los reportan.
- Nombres sin país (UTC, GMT, CET, EST y similares, 29 en total) dan
  None: sin información, no se penaliza desde esta función.
- Un timezone desconocido que no está en esa lista da False.

Por qué: es una señal débil y fácil de falsear. Nunca decide sola y su
peso es bajo. Prefiero no penalizar a un humano por un detalle de
configuración antes que castigarlo sin evidencia.

## D24: Mi propio buscador de ASN
Qué problema había: necesito saber de qué red es una IP (por ejemplo, si es de Amazon o de un proveedor de casa). La librería pyasn no se instala en la imagen de Docker: no trae versión precompilada y la imagen slim no tiene el compilador gcc.
Qué elegí: escribí mi propio buscador en Python. Guardo los prefijos agrupados por longitud y busco desde el más largo (/32) hasta el más corto (/0). El primero que coincide gana, así que un /24 le gana a un /16. Usé pyasn una sola vez, fuera del proyecto, para convertir los datos de Routeviews (29-oct-2026, 1,159,994 prefijos) a un archivo que sí versioné (4 MB comprimido).
Qué descarté y por qué: pyasn en producción, porque obligaría a instalar un compilador en la imagen y a depender de una versión que solo declara soporte hasta 3.11. También descarté recorrer todas las redes una por una en cada consulta, porque con más de un millón de prefijos sería demasiado lento para el límite de 300 ms.
Qué pierdo con esto: tengo que mantener mi propio código. El archivo de datos es una foto de un día y se va quedando viejo. No encontré una licencia explícita de Routeviews y lo digo en ETHICS.md. Y el buscador usa unos 123 MiB de memoria por proceso.
Cómo lo comprobé: carga en 2.92 s y 24.6 microsegundos por consulta, medido con scripts/measure_asn.py. Hay tests para el prefijo más largo, IP privadas, IPv6 y archivos dañados.

## D25: Leer las IP con inet_pton y no con ipaddress
Qué problema había: al cargar el archivo, convertir 1.16 millones de líneas con el módulo ipaddress tardaba 37 segundos.
Qué elegí: usar socket.inet_pton al cargar, que tarda unos 3 segundos. Cuando llega una IP de un cliente sí uso ipaddress, porque ahí necesito saber si es privada o de loopback, y es una sola IP por petición.
Qué descarté y por qué: ipaddress para la carga, porque 37 s es inaceptable al arrancar. Esto lo decidí con una medición, no con una suposición.
Qué pierdo con esto: el código es un poco menos claro y depende de cómo el sistema operativo entiende las direcciones. Por eso hay tests que revisan que las líneas mal formadas se salten una por una.

## D26: País de la IP con DB-IP Lite
Qué problema había: necesito el país de cada IP, sin pagar (NFR-3).
Qué elegí: DB-IP Lite, versión país, octubre de 2026. Es gratis, con licencia CC BY 4.0, y la uso con atribución. El archivo trae 710,834 filas; al cargar solo conservo 362,108 rangos IPv4 y verifiqué el MD5 contra el publicado. Carga en 1.2 s y usa 31 MiB.
Qué descarté y por qué: las bases que piden registrarse con una cuenta y una clave de licencia (verifica esto antes de afirmarlo en la defensa), porque complican el docker-compose up de un solo comando.
Qué pierdo con esto: es menos exacta que la versión de pago (su propio índice de exactitud es 81 contra 93). Solo da país, no ciudad. Ignoro IPv6, así que un usuario con IPv6 se queda sin país. Y hay que poner el enlace "IP Geolocation by DB-IP" en las páginas que usen estos datos.

## D27: Zona horaria contra país (el caso de Canarias)
Qué problema había: si la

## D28: Audit log en PostgreSQL (PR-4)
Qué problema había: cada decisión debe quedar registrada con las señales que la produjeron, y sin guardar el correo en claro.
Qué elegí:
- Una tabla audit_log en PostgreSQL con la fecha, el correo cifrado, la IP, el ASN, el país, la zona horaria, las señales, el puntaje, la acción y las razones.
- El correo se guarda como HMAC-SHA256 con una clave secreta (AUDIT_HMAC_KEY). Un hash simple se podría revertir probando correos conocidos.
- La escritura ocurre después de responder (BackgroundTasks), para no sumar tiempo a los 300 ms. Por eso los dos rechazos 400 ahora devuelven una respuesta en vez de lanzar una excepción: FastAPI no ejecuta las tareas en segundo plano si el endpoint lanza una. El código y el cuerpo de la respuesta son los mismos.
- La tabla se crea al arrancar (CREATE TABLE IF NOT EXISTS). Si Postgres no está listo, la app arranca igual y la crea en la primera escritura.
- Los rechazos 400 (dominio desechable, sin MX) se guardan como "rejected" con puntaje vacío, para no mezclarlos con los bloqueos del motor de riesgo.
- La columna ip guarda la IP usada para las señales. En modo debug eso puede ser una IP simulada, y en ese caso se marca "ip_simulated": true dentro de signals.
- No se audita el 429 ni el 422: un ataque de volumen inundaría la tabla.
- psycopg 3 con binario incluido (psycopg[binary]==3.3.6), sin ORM ni migraciones.
Qué descarté y por qué:
- SQLAlchemy y un sistema de migraciones: demasiado para lo que necesito y más difícil de explicar.
- Guardar la IP real de la conexión: dentro de Docker es siempre 172.18.0.1, y en la Fase 5 el grafo vería toda la campaña como una sola granja.
- psycopg con libpq del sistema: obliga a cambiar el Dockerfile.
Qué pierdo con esto:
- Si Postgres está caído, esa decisión se pierde: no hay cola ni reintento. El audit es de mejor esfuerzo.
- Si Postgres no responde (en vez de rechazar), cada escritura espera hasta 2 s ocupando un hilo.
- Una conexión nueva por escritura (sin pool).
- La IP se guarda en claro y el log de acceso de uvicorn también la imprime. En producción iría truncada a /24 y con retención limitada (va en ETHICS.md).
- La clave HMAC y la contraseña de Postgres tienen valores de desarrollo por defecto. Nunca en producción.
Cómo lo comprobé: tests con un escritor falso (la CI no tiene Postgres), y a mano contra un Postgres real: filas correctas, sin correo en claro, 200 con Postgres detenido y aviso sin datos personales.