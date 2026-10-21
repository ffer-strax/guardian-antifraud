## D1. Python 3.12 dentro de Docker, no el 3.15 local
- Contexto: tengo Python 3.15 instalado; el reto pide 3.11+.
- Alternativas: usar 3.15 local / imagen 3.12 en contenedor.
- Decisión: imagen python:3.12-slim.
- Por qué: reproducibilidad y librerías con soporte probado.
- Trade-off: mi versión local difiere de la del contenedor.