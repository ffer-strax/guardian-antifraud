| Fecha | Tarea | ¿La resolvió la IA? | Dónde falló | Cómo lo recuperé |
|-------|-------|---------------------|-------------|------------------|
| 20-oct | Instalar Python y Docker | Parcial | Python 3.15 es muy reciente; duda de compatibilidad con librerías | Fijé python:3.12-slim en el Dockerfile; local solo para comandos |
| 20-oct | Esqueleto FastAPI + compose | Sí | No levanté los servicios; quedaron en "Created" porque corté el `up` | Usé `docker compose up -d` y verifiqué con `ps` |
| 20-oct | Endpoint /register | Sí, con deuda | Acepta "string" como email (`str` en vez de `EmailStr`) | Pendiente: validación real mañana |
| 20-oct | Versión de FastAPI | No confiable | Una respuesta de buscador sugería 0.143.x sin fuente verificable | Dejé la versión fija; revisar en pypi.org antes de entregar |