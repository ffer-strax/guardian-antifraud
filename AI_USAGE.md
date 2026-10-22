# AI_USAGE

| Fecha | Tarea | ¿La resolvió la IA? | Dónde falló | Cómo lo recuperé |
|-------|-------|---------------------|-------------|------------------|
| 20-oct | Instalar Python y Docker | Parcial | Python 3.15 es muy reciente; no pude verificar compatibilidad de librerías | Fijé python:3.12-slim en el Dockerfile; el Python local solo para comandos |
| 20-oct | Esqueleto FastAPI + compose | Sí | Los contenedores quedaron en "Created" porque corté el `up` | `docker compose up -d` y verifiqué con `docker compose ps` |
| 20-oct | Endpoint /register | Sí, con deuda | Aceptaba "string" como email (`str`) | Corregido el 21-oct con `EmailStr` |
| 20-oct | Versión de FastAPI | No confiable | Una respuesta de buscador sugería 0.143.x sin fuente | Mantuve la versión fija; verifiqué en pypi.org |
| 21-oct | Validación de email, canonicalización Gmail, dominios desechables | Sí | Dejó el esqueleto sin commitear y desapareció `.env.example` (el agente lo detectó y preguntó) | Recreé `.env.example` y separé los commits por cambio lógico |
| 21-oct | Verificación de versiones | Parcial | Versiones elegidas de memoria por el agente | Verificadas en pypi.org el 21-oct-2026: existen, pero no son las más recientes (email-validator 2.3.0 ya salió). Se mantienen fijas por reproducibilidad |
| 21-oct | Versiones de Postgres/Redis | No confiable | Una fuente sugería postgres:18.6 y redis:8.10.2 sin poder confirmarlas | Mantuve 16.4 y 7.4.1; pendiente contrastar con Docker Hub (Tags) |
| 21-oct | Lista de dominios desechables | Parcial | La lista inicial del agente era de 20 dominios escritos a mano | Reemplazada por la del repo disposable-email-domains (CC0), 9913 líneas |