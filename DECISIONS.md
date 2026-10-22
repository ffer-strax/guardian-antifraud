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

## D4. Puertos 5432 y 6379 expuestos al host
- Contexto: el compose publica Postgres y Redis
- Alternativas: solo red interna de Docker / publicar puertos
- Decisión: publicados por ahora facilita depurar en local
- Observación: en producción Postgres y Redis no deben ser accesibles desde fuera deben de estar detras de un firewall

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

