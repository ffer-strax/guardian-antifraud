# Imagen para los bots de prueba (Fase 6). Solo se construye con: docker compose --profile bots ...
#
# La imagen oficial de Playwright trae los navegadores, pero NO el paquete de Python.
# La versión de la imagen y la del paquete deben ser la misma: cada versión de playwright espera
# una revisión exacta de Chromium. Una sola variable fija las dos.
ARG PLAYWRIGHT_VERSION=1.64.1

FROM mcr.microsoft.com/playwright/python:v${PLAYWRIGHT_VERSION}-noble

ARG PLAYWRIGHT_VERSION
RUN pip install --no-cache-dir "playwright==${PLAYWRIGHT_VERSION}"

WORKDIR /work
