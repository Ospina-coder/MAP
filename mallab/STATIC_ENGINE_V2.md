# Auditoría e implementación del motor estático v2

Revisión: 29 de octubre de 2026. Basada en código, no únicamente en README.
No se cambia SQLite, el modelo de datos, autenticación ni almacenamiento privado.
No se añaden modelos de IA ni se ejecutan muestras.

## Diagnóstico inicial

| Componente revisado | Situación antes del cambio | Acción en esta fase |
| --- | --- | --- |
| `analyzer.py` | Hashes MD5/SHA-256, Shannon, firmas de formato, PE y YARA implementados. | Conservar funciones y añadir coordinación v2. |
| PE | Secciones/imports/timestamp; sin límites explícitos de extracción ni permisos/RVA en el JSON. | Acotar extracción y añadir metadata para indicadores explicables. |
| YARA | Recompilación por muestra; `None` omite; errores fallan el pipeline. | Separar módulo, caché por contenido, identidad de reglas y estado ERROR explícito. |
| ClamAV | Ausente. | Módulo independiente con socket Unix local, opt-in. |
| Heurística | Ausente. | Indicadores deterministas con evidencia y límites, sin puntuación. |
| Persistencia | `JSONField` con payload versión 1 y columnas existentes. | Payload v2 aditivo; sin migraciones. |
| API | DRF Basic/Token/sesión, `IsAuthenticated`, propietario estricto. | Mantener permisos; extender reportes v2 sin reescribir antiguos. |
| Cola | ID por Celery/Redis, despacho tras commit, límites suave/duro 110/120 s. | Conservar contratos y no continuar con otra herramienta tras un límite suave. |
| Almacenamiento | Privado, UUID, límite 64 MiB, limpieza al fallar alta SQL. | Conservar. |
| Pruebas iniciales | 24 pruebas aprobadas en el checkout. | Añadir pruebas por componente, integración y compatibilidad. |

Pendientes que esta fase no resuelve: configuración permisiva de desarrollo
(`ALLOWED_HOSTS=['*']` y orígenes HTTP), falta de cuotas, recuperación automática
de estados atascados, outbox, purga de binarios y una configuración de producción
con límites de memoria/CPU a nivel de sistema. `uploaded_by` sigue nullable en
el modelo por compatibilidad histórica, pero las vistas siempre exigen usuario.

## Etapas y archivos

1. `services/exceptions.py`, `services/yara_scanner.py`, `tests/test_yara_scanner.py`
   y `yara_rules/`: separación y validación YARA real con marcadores inocuos.
2. `services/clamav.py`, `tests/test_clamav.py`: protocolo local, opt-in y fallos.
3. `services/heuristics.py`, `tests/test_heuristics.py`: indicadores explicables.
4. `services/analyzer.py`, `views.py`, `config/settings.py`, pruebas API/pipeline:
   integración, recursos y persistencia/API v2.
5. Esta guía, `API.md`, `ANALYZER.md` y `README.md`: contratos y activación.

No se modifican modelos, migraciones, requirements ni la infraestructura de BD.
`scan_yara(...)` continúa exportándose desde `analyzer.py` y conserva su retorno
histórico de lista. El motor utiliza el resultado enriquecido del módulo nuevo.

## YARA: reglas, caché y semántica

- `yara_rules/testing/` incluye una regla local inocua con `purpose=testing_only`.
- `yara_rules/reviewed/` está vacío inicialmente; el operador debe revisar y
  aprobar reglas antes de habilitarlo. No hay descargas automáticas.
- No configurar el directorio padre para evitar mezclar pruebas y producción.
- El directorio de reglas debe ser de confianza y estar separado de cuarentena.
  Los clientes de la API no pueden elegir rutas ni aportar reglas.
- Se usan fuentes UTF-8, namespaces por archivo, includes deshabilitados y
  warnings de compilación tratados como errores.
- Se calcula un manifiesto SHA-256 de nombres relativos/contenidos. Se compilan
  exactamente esos bytes y se guarda ese identificador en el reporte.
- La caché LRU conserva dos compilaciones por proceso, bajo lock; carga perezosa
  por worker. No se comparten objetos compilados por Redis ni por archivos.
- Cada llamada relee las fuentes con límites; cambios de contenido invalidan
  aunque no cambien tamaño/mtime. Una revisión inválida falla, sin fallback.
- La compilación bajo lock evita duplicarla en el primer acceso concurrente.
  Desplegar reglas mediante revisiones atómicas de directorio y permisos mínimos.

| Resultado YARA | Interpretación |
| --- | --- |
| `COMPLETED`, `match_count=0` | Se ejecutó correctamente ese conjunto sin coincidencias. |
| `COMPLETED`, `match_count>0` | Coincidencias en `AnalysisReport.yara_matches`; no es un veredicto global. |
| `SKIPPED`, `rules_directory_not_configured` | El operador no configuró reglas. |
| `SKIPPED`, `not_reached` | Otra etapa abortó antes de intentar YARA. |
| `ERROR`, `timeout` | Matching agotó su tiempo. |
| `ERROR`, `scan_error` | Lectura, reglas inválidas, límites u otro fallo; detalle en logs privados. |
| `ERROR`, `stage_error` | Interrupción a nivel de etapa, por ejemplo límite suave de Celery. |

El límite de coincidencias aborta sin devolver un éxito parcial. No hay garantía
de seguridad por lista vacía, regla de prueba coincidente o escaneo omitido.
El timeout del matching no limita la compilación; la tarea Celery y los límites
del worker constituyen la siguiente frontera de recursos.

### Prueba inocua en Ubuntu

Ejecutar en el checkout/entorno del worker, sustituyendo la ruta de ejemplo:

```bash
export YARA_RULES_DIR=/ruta/MAP/yara_rules/testing
printf '%s' 'MAP_STATIC_ANALYSIS_INNOCUOUS_TEST_v1' > /tmp/map-yara-marker.txt
# Reiniciar el worker mediante su mecanismo habitual para cargar el entorno.
# Subir el texto con credenciales; el marcador no es un archivo malicioso.
curl --user "$USERNAME" -F 'file=@/tmp/map-yara-marker.txt' \
  http://127.0.0.1:8000/api/samples/
```

Tras la prueba, deshabilitar ese conjunto o sustituirlo por un directorio revisado.
Un directorio configurado pero vacío produce ERROR, no SKIPPED ni "limpio".

## ClamAV: interfaz local y estados

El módulo utiliza `AF_UNIX/SOCK_STREAM` y `zINSTREAM\0` con chunks de longitud
32-bit en orden de red y terminador de longitud cero. Recibe los mismos bytes
analizados por hashes/PE/YARA: no pasa nombres del usuario al daemon, no usa
shell, no ejecuta `clamscan`, no crea copias temporales ni abre sockets TCP.

| Resultado ClamAV | Interpretación |
| --- | --- |
| `SKIPPED`, `disabled` | Deshabilitado por configuración. No abre socket. |
| `SKIPPED`, `not_reached` | No se llegó a intentar esta etapa. |
| `DETECTED` | Respuesta `FOUND`; firma conservada en `signatures`. |
| `NO_DETECTION` | Respuesta exacta `stream: OK`; no certifica seguridad. |
| `UNAVAILABLE` | Socket ausente, sin permisos, conexión rechazada o plataforma sin AF_UNIX. |
| `ERROR` | Timeout, transporte fallido, respuesta inválida/incompleta, límite o error del daemon. |

El cliente INSTREAM conserva la identificación que devuelve el daemon, pero no
garantiza enumerar todas las firmas posibles. Las detecciones heurísticas o de
límites de ClamAV se conservan como identificaciones del motor; no se reinterpretan
como familias de malware confirmadas. No se captura una versión/fecha de firmas
del daemon en esta fase. Un OK no acredita actualidad de firmas ni cobertura
completa si el daemon omite tipos o aplica límites internos.

ClamAV se mantiene deshabilitado por defecto. Para activarlo en Ubuntu:

1. Instalar/configurar `clamd` y sus firmas mediante el procedimiento del operador.
   Esta implementación no instala paquetes ni descarga firmas.
2. Usar `LocalSocket`, por ejemplo `/run/clamav/clamd.ctl`, con permisos para
   el usuario del worker mediante grupo apropiado; no usar permisos universales.
3. No habilitar/exponer `TCPSocket` para este módulo. No enviar muestras a APIs externas.
4. Alinear `StreamMaxLength` con el límite de 64 MiB y configurar límites del
   daemon: `MaxScanTime`, `MaxScanSize`, `MaxFileSize`, `MaxRecursion`, `MaxFiles`,
   `MaxThreads` y `MaxQueue` según capacidad. No subirlos sin evaluar archivos
   comprimidos y consumo de recursos.
5. Exportar antes de iniciar/reiniciar el worker:

```bash
export CLAMAV_ENABLED=1
export CLAMAV_SOCKET_PATH=/run/clamav/clamd.ctl
```

El socket por defecto es una convención configurable, no una detección automática
de la ruta real. `CLAMAV_ENABLED=0` desactiva la etapa. No basta con editar el
entorno del proceso web: Celery también debe recibirlo.

El plazo del cliente incluye conexión, envío y lectura, no un timeout nuevo por
cada bloque. Cerrar la conexión por timeout no garantiza cancelar inmediatamente
el trabajo del daemon: sus límites propios son necesarios. Si ClamAV está
habilitado y no disponible o falla, el reporte global es `FAILED`, aun si otros
analizadores finalizaron. Deshabilitarlo expresamente permite completar el resto.

## Heurísticas explicables

No hay puntuación, probabilidad, aprendizaje ni veredicto. Cada hallazgo contiene
`id`, `description`, `evidence`, `technical_rationale` y `limitations`.
El resultado registra `engine_version=1`, parámetros usados, alcance PE y una
advertencia de interpretación. La evidencia proviene de la instantánea leída.

| Indicador | Criterio y límites de interpretación |
| --- | --- |
| `high_file_entropy` | Shannon >= umbral y tamaño mínimo; compresión/cifrado legítimos también disparan. |
| `high_section_entropy` | Mismo criterio con bytes de sección realmente observados; no prueba empaquetado. |
| `writable_executable_section` | Bits WRITE y EXECUTE juntos; también posibles en JIT/protectores legítimos. |
| `section_raw_out_of_bounds` | Offset + tamaño raw supera el archivo; puede ser truncamiento o corrupción. |
| `entry_point_outside_executable_section` | RVA no nulo fuera de secciones declaradas ejecutables; revisar PE inusual. |
| `remote_process_memory_api_combination` | Imports conjuntos VirtualAllocEx, WriteProcessMemory y CreateRemoteThread; también usados por depuradores. |
| `invalid_pe_structure` | MZ inválido/incompleto; no presupone intención maliciosa. |
| `pe_parser_warnings` | Advertencias del parser, limitadas en cantidad/tamaño; no son firmas. |

El umbral inicial 7.5 bits/byte y tamaño mínimo 4096 bytes son criterios
operativos de revisión, explícitos y ajustables; no están calibrados contra
un dataset ni representan una probabilidad. Ninguno de estos indicadores
demuestra ejecución de las funciones importadas ni comportamiento observado.

## Configuración y límites

| Setting | Valor predeterminado | Alcance |
| --- | --- | --- |
| `ANALYZER_MAX_FILE_BYTES` | 64 MiB | Instantánea de entrada. Se conserva el límite de subida. |
| `YARA_SCAN_TIMEOUT` | 30 s | Matching YARA, no compilación. |
| `YARA_MAX_RULE_FILES` | 256 | Archivos `.yar`/`.yara` en el conjunto. |
| `YARA_MAX_RULE_BYTES` | 4 MiB | Total de fuentes leídas/compiladas. |
| `YARA_MAX_MATCHES` | 1000 | Abortado explícito si se exceden matches. |
| `PE_MAX_SECTIONS` | 96 | Secciones parseadas, antes de extracción adicional. |
| `PE_MAX_IMPORTS` | 4096 | Límite de descriptores DLL y funciones importadas antes del JSON. |
| `HEURISTIC_ENTROPY_THRESHOLD` | 7.5 | Criterio observable de entropía. |
| `HEURISTIC_MIN_ENTROPY_BYTES` | 4096 | Evitar interpretar entropía de buffers pequeños. |
| `CLAMAV_ENABLED` | `False` | Se lee de entorno: solo `'1'` habilita. |
| `CLAMAV_SOCKET_PATH` | `/run/clamav/clamd.ctl` | Entorno; ruta local absoluta. |
| `CLAMAV_TIMEOUT` | 30 s | Plazo total de comunicación. |
| `CLAMAV_MAX_RESPONSE_BYTES` | 8192 | Respuesta acotada y validada. |

Las advertencias PE se limitan a 20 de 500 caracteres cada una. Se sigue leyendo
una instantánea de hasta 64 MiB en memoria; ese valor no limita la RAM total de
pefile, YARA o clamd. El parser puede gastar recursos antes de verificar los
imports extraídos. Los límites de tareas 110/120 s ya existentes se conservan;
en Ubuntu usar un pool que soporte esos límites y un servicio con límites de
CPU/RAM. Esta fase no modifica la infraestructura ni afirma haberla configurado.

## Persistencia y API compatibles

Se conserva `AnalysisReport.pe_headers` como contenedor, sin añadir columnas:

```text
schema_version = 2
file = {size, mime_type, hashes}
pe = {campos previos + entry_point_rva + metadata adicional de secciones}
yara = {status, reason? o ruleset_sha256/rule_file_count/match_count}
clamav = {status, reason?, signatures}
heuristics = {status, engine_version?, parameters?, findings, scope?, interpretation?}
error? = {stage, type, message genérico}
```

`entropy` y `yara_matches` conservan sus columnas. Los reportes antiguos no se
reescriben. `COMPLETED` sigue siendo idempotente: no se actualizan reportes viejos
automáticamente para añadir herramientas nuevas. Un reanálisis requiere un flujo
explícito después de comprobar que no hay un worker en ejecución.

La consulta conserva `results` y el resto de campos. Solo los reportes v2
terminales añaden `analysis={schema_version,yara,clamav,heuristics}`. En fallos
esta extensión permite distinguir cobertura parcial; no se añade `results`.
Si YARA terminó correctamente, `analysis.yara.matches` expone la lista de la
columna existente incluso cuando falla una herramienta posterior.
El primer error conserva la etapa general y los estados individuales muestran
fallos múltiples. Detalles internos quedan en logs, no en la respuesta pública.

`COMPLETED` significa que las etapas configuradas terminaron; una detección no
es un error de infraestructura y puede aparecer en un reporte `COMPLETED`.
`SKIPPED` no equivale a `NO_DETECTION`; `FAILED` tampoco equivale a malware.

## Pruebas y límites de la verificación

```bash
python manage.py check
python manage.py test mallab.tests --settings=mallab.tests.settings
python manage.py makemigrations --check --dry-run
```

Los tests aíslan `CLAMAV_ENABLED=False` de las variables del servidor salvo donde
lo habilitan explícitamente. Usan PE sintéticos, textos inocuos y YARA real;
no descargan muestras ni reglas externas.

Para el test opcional contra clamd real, únicamente en Unix:

```bash
MAP_TEST_CLAMAV_SOCKET=/run/clamav/clamd.ctl \
  python manage.py test mallab.tests.test_clamav.LiveClamAVTests \
  --settings=mallab.tests.settings
```

Sin esa variable se omite explícitamente. Los tests simulados verifican frames,
firmas, errores, límites, socket local y deadline, pero no prueban firmas reales,
permisos ni servicio instalado en Ubuntu. Esa validación operativa sigue siendo
necesaria antes de habilitarlo en el servidor. El worker de la suite usa broker
en memoria; no demuestra salud del Redis remoto.

Se cubren caché concurrente/acotada, invalidación aunque mtime/tamaño coincidan,
reglas inválidas sin fallback, falta de reglas, timeout, includes prohibidos,
límites de matches/archivos/bytes, escape de ruta resuelta, heurísticas positivas
y negativas, límites PE, resultados parciales y contratos históricos de API.
Los tests de autenticación, CSRF, propietario, publicación y almacenamiento
anteriores se mantienen.

### Resultado local observado el 29 de octubre de 2026

| Comprobación final | Resultado |
| --- | --- |
| `manage.py check` | Sin incidencias. |
| Suite completa | 64 casos: 63 aprobados, 1 omitido explícitamente. |
| Caso omitido | `LiveClamAVTests`, requiere Unix y socket de clamd real. |
| `makemigrations --check --dry-run` | Sin cambios de modelo pendientes. |
| `git diff --check` | Sin errores de whitespace; Git avisa de conversión LF/CRLF en Windows. |

La suite inicial tenía 24 casos. Las nuevas verificaciones se ejecutaron primero
por componente y después junto con todas las pruebas anteriores, usando
`PYTHONPATH=.test-deps` para las dependencias del entorno local. El resultado
no equivale a una validación del despliegue en Ubuntu, Redis remoto o clamd real.

## Referencias primarias consultadas

- [API de yara-python](https://yara.readthedocs.io/en/stable/yarapython.html):
  fuentes por namespace, callbacks, includes y timeout.
- [Protocolo oficial clamd](https://docs.clamav.net/manual/Usage/ClamdProtocol.html):
  framing, AF_UNIX, INSTREAM y respuestas.
- [Uso de ClamAV](https://docs.clamav.net/manual/Usage/Scanning.html):
  configuración del daemon y límites de cobertura.

Se consultaron documentos; no se transfirieron muestras ni se descargaron reglas.
