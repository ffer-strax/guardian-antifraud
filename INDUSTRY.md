# INDUSTRY — Dónde encajan mis tres semanas en sistemas reales

Este documento compara lo que construí en GUARDIÁN con lo que describen fuentes públicas de sistemas reales. Una advertencia: las empresas no publican sus detalles internos, así que solo afirmo lo que dicen sus propias páginas o artículos académicos, y marco al final lo que no pude verificar. Consulté todo el 30-oct-2026.

## 1. Red e IP: `hosting_ip` y zona horaria

**Qué hace la industria.** En publicidad digital, el Media Rating Council (MRC) trata el tráfico de centros de datos como tráfico inválido. Su guía recomienda empezar por las IP de los tres mayores proveedores de hosting (Amazon AWS, Google y Microsoft), mantener las listas bajo revisión continua y complementarlas con otras fuentes. También excluye los "routing artifacts" de usuarios legítimos y la navegación legítima desde máquinas virtuales, pide excepciones para limitar falsos positivos y exige "minimizar los falsos positivos materiales" [1].

**Qué hice yo.** Clasifico la IP por ASN con datos de RouteViews y una lista de ASN de hosting que armé a mano (D24). Es la misma idea que la guía del MRC. Y como esa guía, trato la IP de hosting como una señal con excepciones, no como una prueba (D33).

**Dónde me quedo corto.** Mi lista es pequeña y solo cubre IPv4. Un bot con IP residencial no aparece como hosting: en el nivel 3 de mi campaña pasaron 22 de 35 (D32). Las páginas de Cloudflare que leí (Bot Management y Turnstile) no mencionan reputación de IP o ASN como mecanismo, así que no puedo decir cómo la usan.

## 2. Huella de dispositivo

**Qué hace la industria.** La huella funciona: en el estudio de Eckersley (EFF, 2010), 83.6 % de las huellas eran únicas [2]. Pero cambian. Según el trabajo FP-Stalker, 45.52 % de las huellas tenían al menos un cambio después de un día [2]. Por eso proponen enlazar huellas que evolucionan, con una variante basada en reglas y otra híbrida con aprendizaje automático. Con 98,598 huellas de 1,905 navegadores, lograron seguir a un navegador 54.48 días en promedio y a 26 % de ellos más de 100 días [3]. Cloudflare, por su parte, usa un motor de JavaScript para identificar navegadores sin interfaz ("headless") y otras huellas maliciosas, y ofrece la huella TLS (JA3/JA4) como campo [4].

**Qué hice yo.** Un colector en JavaScript y un comparador por similitud ponderada por atributo con umbral 0.75, que busca candidatos solo entre huellas con cuatro atributos estables iguales para no comparar contra todos los usuarios (D29). Un hash exacto fallaría con cada actualización del navegador, que es justo lo que muestra FP-Stalker. Mi enfoque se parece, en la idea, a su variante de reglas.

**Dónde me quedo corto.** No lo probé con huellas reales que evolucionan, solo con datos sintéticos. En la campaña, la propia huella de mis bots chocaba entre sí (13 y 16 casos) y eso infló los resultados. No recojo huella de audio ni fuentes, y no implementé la huella TLS.

## 3. Comportamiento

**Qué hace la industria.** Turnstile, de Cloudflare, ejecuta pequeños desafíos de JavaScript sin interacción (prueba de trabajo, prueba de espacio, sondeo de APIs del navegador y otras comprobaciones de rarezas del navegador y señales de comportamiento humano) y ajusta la dificultad a cada visitante [5]. En banca, BioCatch dice medir el ritmo de tecleo, la duración de los clics y cómo se sostiene el teléfono, y compara la sesión con las sesiones anteriores del mismo usuario; también dice detectar datos pegados durante el alta [6]. Es un artículo de prensa con afirmaciones de la empresa y sin cifras de rendimiento. La referencia académica es más prudente: Killourhy y Maxion probaron 14 detectores con 51 personas escribiendo la misma contraseña 400 veces; el mejor tuvo una tasa de error igual (EER) de 9.6 %, y concluyen que la dinámica de tecleo aún no sirve como único método de control de acceso [7].

**Qué hice yo.** Siete señales calculadas en el navegador que solo envían agregados, nunca teclas ni coordenadas (D30), con umbrales contrastados con 5 muestras mías.

**Dónde me quedo corto.** Los bancos comparan contra el historial del mismo usuario; en un registro no hay historial, así que solo separo "persona" de "script". Mi campaña coincide con la cautela de Killourhy y Maxion: un bot con ritmo humano pasó (nivel 3). El comportamiento solo es una señal débil.

## 4. Grafo de cuentas

**Qué hace la industria.** SybilRank (Cao et al., NSDI 2012) ordena a los usuarios por su probabilidad de ser falsos usando propiedades del grafo social. En Tuenti, una red social española, cerca de 90 % de las 200,000 cuentas que marcó como más probablemente falsas merecieron suspensión, frente a cerca de 5 % con los reportes de usuarios [8]. Facebook, con Deep Entity Classification (USENIX Security 2021), parte de que la posición y la actividad de una cuenta en el grafo son difíciles de falsificar a gran escala. Combina características de las conexiones directas y lejanas, y entrena con pocas etiquetas humanas de alta precisión y muchas etiquetas automáticas más ruidosas; estima una reducción de 27 % de cuentas abusivas respecto a otros sistemas [9].

**Qué hice yo.** Un grafo por lotes que agrupa cuentas conectadas por familia de dispositivo o subred de IP y marca clústeres de 4 o más, con ventana de 48 horas y evidencia fuerte (D31). Mi primera versión marcó 53 cuentas legítimas; la corrección salió de medir la causa.

**Dónde me quedo corto.** Mi grafo no es social: uso identificadores compartidos, no amistades. No está conectado a `/register`, no tiene etiquetas ni datos reales y no escala a millones de cuentas.

## 5. Puntaje y acciones

**Qué hace la industria.** Stripe Radar usa modelos de IA con cientos de factores por pago y datos de toda su red. Da un puntaje de 0 a 99 (65 o más es riesgo elevado; 75 o más, alto) y sus reglas pueden permitir, bloquear, pedir autenticación 3DS o enviar a revisión. Por defecto bloquea el riesgo alto y deja pasar el elevado, que puede ir a una cola de revisión. Se alimenta del reporte de fraudes: reembolsar un pago como fraudulento agrega el correo y la tarjeta a las listas de bloqueo. Además, para un pequeño subconjunto de pagos modifica el puntaje reportado, para medir la tasa de falsos positivos y el recall [10]. Cloudflare Bot Management combina un motor de heurísticas, un motor de ML que "representa la mayoría de las detecciones", un motor opcional de detección de anomalías no supervisado y detecciones por JavaScript [4].

**Qué hice yo.** Una suma de pesos de 0 a 100 con cuatro acciones: permitir, verificar, revisar y bloquear. La estructura se parece a la de Radar. Cada decisión deja en `audit_log` las señales que la produjeron (PR-4).

**Dónde me quedo corto.** Ellos aprenden y yo uso pesos fijos que son hipótesis. Ellos tienen retroalimentación y miden falsos positivos con tráfico real; yo no mido ninguno. Y mi verificación y mi cola de revisión no existen (D32).

## 6. Lo que no construí

- **ML con etiquetas reales (D34).** Cloudflare, Stripe y Facebook coinciden en usar modelos entrenados con etiquetas y retroalimentación. Yo no tengo etiquetas reales.
- **Verificación y revisión reales.** Turnstile adapta el desafío al riesgo y Radar ofrece 3DS y cola de revisión. En mi sistema, `step_up` equivale a dejar pasar.
- **Medición con tráfico real.** Todas mis cifras son sintéticas.

En resumen, mis tres semanas cubren la primera capa de un sistema real: señales, puntaje, acciones y auditoría. Lo que falta es el ciclo de aprendizaje y retroalimentación, que es donde esos sistemas ganan su precisión.

## Lo que no pude verificar

- **Meta.** Las páginas del centro de transparencia de Meta solo me devolvieron metadatos. Sobre Meta cito únicamente el artículo académico de Deep Entity Classification, y no afirmo nada más de sus sistemas internos.
- **Cloudflare.** Sus páginas que leí no describen reputación de IP o ASN ni análisis de comportamiento para Bot Management; puede que existan en otra documentación.
- **Las cifras 83.6 % y 45.52 %** vienen de una revisión académica (arXiv 1905.01051), no de los artículos originales.
- **BioCatch** es un artículo de prensa, sin cifras de rendimiento.
- **La guía del MRC** sobre tráfico de centros de datos puede haberse actualizado en versiones posteriores de sus normas de tráfico inválido.

## Fuentes

1. Media Rating Council, [Invalid Data-Center Traffic](https://www.mediaratingcouncil.org/sites/default/files/News/General-Announcements/RP020817_Invalid%20Data-Center%20Traffic.pdf)
2. Revisión "Browser Fingerprinting: A Survey" (cita a Eckersley 2010 y a FP-Stalker): [arXiv 1905.01051](https://arxiv.org/pdf/1905.01051)
3. Vastel et al., [FP-STALKER: Tracking Browser Fingerprint Evolutions](https://archive.cps-vo.org/node/60189) (IEEE S&P 2018)
4. Cloudflare, [Bot Management for Enterprise](https://developers.cloudflare.com/bots/plans/bm-subscription/)
5. Cloudflare, [Turnstile](https://developers.cloudflare.com/turnstile/)
6. AML Intelligence, [How BioCatch uses the way people type to detect scammers](https://www.amlintelligence.com/2026/10/insight-how-biocatch-uses-the-way-people-type-to-detect-scammers/) (oct. 2026)
7. Killourhy y Maxion, [Comparing Anomaly-Detection Algorithms for Keystroke Dynamics](https://www.cs.cmu.edu/~keystroke/KillourhyMaxion09.pdf) (DSN 2009)
8. Cao et al., [SybilRank, NSDI 2012](https://www.usenix.org/conference/nsdi12/technical-sessions/presentation/cao)
9. Xu et al., [Deep Entity Classification, USENIX Security 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/xu)
10. Stripe, [Transaction risk prevention (Radar)](https://docs.stripe.com/radar/transaction-risk-prevention)