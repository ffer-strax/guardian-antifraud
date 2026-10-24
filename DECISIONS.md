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

## D4. Puerto de Postgres expuesto al host; Redis solo en red interna
- Contexto: el compose publicaba Postgres (5432) y Redis (6379) para depurar.
- Decisión: Redis ya no se publica (la API llega por la red interna de Docker: redis:6379). Postgres tampoco se publica.
- Por qué: el puerto de Redis facilitaba manipularlo o tumbarlo (ver D13)redis-cli`.
- Sin puerto publicado no puedo conectarme con herramientas externas.
- En producción ninguna base de datos sería accesible desde fuera.

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