# Imagen para los bots de prueba (Fase 6). Solo se construye con: docker compose --profile bots ...
#
# La imagen oficial de Playwright trae los navegadores, pero NO el paquete de Python.
# La versión de la imagen y la del paquete deben ser la misma: cada versión de playwright espera
# una revisión exacta de Chromium. Una sola variable fija las dos.
ARG PLAYWRIGHT_VERSION=1.64.1

FROM mcr.microsoft.com/playwright/python:v${PLAYWRIGHT_VERSION}-noble

ARG PLAYWRIGHT_VERSION
# psycopg: la campaña vacía audit_log y device_fingerprints entre niveles. Misma versión que backend/requirements.txt.
# pydantic: solo para importar el motor de riesgo desde backend/ (montado en solo lectura). No está en
# backend/requirements.txt porque llega con fastapi; 2.14.2 es la versión instalada en el contenedor api.
RUN pip install --no-cache-dir "playwright==${PLAYWRIGHT_VERSION}" "psycopg[binary]==3.3.6" "pydantic==2.14.2"

WORKDIR /work
