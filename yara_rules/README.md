# Reglas YARA locales

`testing/` contiene solo un marcador inocuo creado para MAP. Una coincidencia
con esa regla demuestra integración, no malware. Para probar, configura
`YARA_RULES_DIR` con la ruta absoluta a `yara_rules/testing` y sube un archivo
de texto con `MAP_STATIC_ANALYSIS_INNOCUOUS_TEST_v1`.

`reviewed/` es el destino para reglas revisadas por un responsable. Está vacío
inicialmente: no se descargan reglas ni se activa un conjunto por defecto.
No apuntes a `yara_rules/` entero porque incluiría las reglas de prueba.

Antes de incorporar una regla: revisar procedencia/licencia, documentar autor,
versión y propósito en `meta`, revisar patrones y coste, probar muestras inocuas
y falsos positivos, y aprobarla en Git. Usar archivos UTF-8 autocontenidos: no
se permiten `include`. El directorio debe poder escribirlo solo el operador,
no los clientes ni el proceso que recibe archivos de cuarentena. Desplegar
revisiones de forma atómica, evitando editar varios archivos durante un scan.

El scanner calcula SHA-256 del manifiesto de nombres relativos y contenidos,
compila una instantánea y conserva hasta dos revisiones en memoria por proceso.
Un cambio de contenido invalida la caché incluso si conserva tamaño y mtime.
Se releen y limitan los archivos en cada llamada; no hay fallback a reglas viejas
si la revisión nueva es inválida. Cada archivo tiene su propio namespace.
La compilación está serializada entre threads y no se ejecuta en el arranque
del proceso padre de Celery; se carga perezosamente en cada worker.
