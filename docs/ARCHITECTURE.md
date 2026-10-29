# MAP — Arquitectura vigente

Actualizado: 29/10/2026. Código inspeccionado `main`, `f7460b7`.
Diseño implementado de STATIC ENGINE V2; no prueba de despliegue Ubuntu.
Resumen autónomo y evidencia en [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md).

## Componentes y fronteras

| Componente | Responsabilidad / interfaz |
| --- | --- |
| `config/settings.py` | Django, BD, Storage, Celery y controles de análisis. |
| `config/celery.py`, `config/__init__.py` | Celery('mallab'), carga namespace CELERY, autodiscovery y celery_app. |
| `mallab/views.py`, `urls.py` | API JSON funcional DRF, autenticación, validación y autorización. |
| `upload_handlers.py` | Contabilidad de bytes durante multipart, antes de Storage. |
| `models.py` / ORM | User, Sample, AnalysisReport y restricciones/índices. |
| Storage / FileField | Cuarentena privada y nombres UUID. |
| `tasks.py` | `analyze_sample_task(sample_id)`: adaptador Celery, límites 110/120 s. |
| `services/analyzer.py` | Extracción base y orquestación de estado/persistencia. |
| `services/yara_scanner.py` | Snapshot confiable de fuentes, caché compilada, matching y metadatos. |
| `services/clamav.py` | Scanner externo local por bytes, AF_UNIX/INSTREAM, sin Django ni ORM. |
| `services/heuristics.py` | Evalúa metadata, retorna indicadores explicables sin IO/ejecución. |
| `services/exceptions.py` | AnalysisInputError compartido; reexportado por analyzer por compatibilidad. |
| `admin.py` | Administración Django; distinta del acceso por propietario de la API. |

```text
Cliente autenticado
   │ POST multipart, campo file
   ▼
Django/DRF ───────────────► Storage privado: quarantine/<UUID>
   │ transacción SQLite
   ├─────────────────────► Sample + AnalysisReport(PENDING)
   │ on_commit
   ▼
Redis / cola analysis ───► Celery worker / sample_id
                            │
                            ▼
                     instantánea acotada
                            │
                     hashes/formato/entropía/PE
                            │
                     heurísticas → YARA → ClamAV
                            │
                            ▼
                     SQLite: COMPLETED/FAILED + payload v2
                            ▲
Cliente propietario ── GET /api/samples/<id>/report/
```

## Ingestión y persistencia

El handler usa el mínimo de SAMPLE_MAX_UPLOAD_BYTES y ANALYZER_MAX_FILE_BYTES;
la vista comprueba nombre, cantidad, tamaño y SHA-256 por chunks. Usa
non_atomic_requests para controlar una transacción explícita, incluso si se
habilitara ATOMIC_REQUESTS. Guarda Sample/reporte en atomic y publica tras commit.
Storage no es transaccional: si falla el alta SQL se intenta borrar el archivo
ya escrito. No hay transacción distribuida con Redis ni garantía outbox.

No se abren transacciones largas durante PE/YARA/ClamAV. Los bytes analizados
se leen por FileField.open y se limitan; la ruta física no deriva del nombre
del cliente. La API no devuelve una descarga ni publica MEDIA_ROOT.

## Datos y relaciones

```text
User 1 ── N Sample 1 ── 0..1 AnalysisReport
             │
             └── FileField → Storage privado
```

User extiende AbstractUser, PK user_id; Sample usa id y FK uploaded_by; reporte
usa id_analysis y OneToOne sample. Las relaciones usan CASCADE SQL. Existen
restricciones de rol, estado, entropía y tamaños no negativos, e índices de hash,
fecha, usuario/fecha y estado. Los JSON usan default factories independientes.

Históricamente uploaded_by pasó a nullable en 0003. El contrato HTTP actual
siempre asigna usuario autenticado. La nullable no es permiso de anonimato.
No hay servicio/signal propio que elimine binarios al borrar modelos. Los datos
históricos no se migran ni se reanalizan al consultar. SQLite sigue siendo la BD.

## Estado y fallos

```text
PENDING ── UPDATE condicional ──► PROCESSING ── éxito ──► COMPLETED
                                    └──────── fallo ──► FAILED
FAILED ── reintento explícito ──► PROCESSING
COMPLETED ── otra invocación ──► mismo reporte (idempotencia)
```

No reclamar PROCESSING dos veces. `AnalysisInProgress` evita trabajo duplicado;
no acredita una garantía exactly-once. Una muestra eliminada produce DELETED
como retorno de tarea, sin crear un estado SQL nuevo.

El orden V2 es lectura, metadata, entropía, PE, heurísticas, YARA y ClamAV.
YARA omitido es SKIPPED; un error ordinario queda ERROR y permite intentar ClamAV.
El límite suave de Celery interrumpe y marca fallo sin iniciar otro scanner.
ClamAV deshabilitado es SKIPPED; habilitado y UNAVAILABLE/ERROR hace fallar el
reporte global. Coincidencias o DETECTED no son fallos de ejecución.
El primer error conserva su etapa y los bloques individuales exponen los fallos.
Una terminación dura/caída de BD puede dejar PROCESSING; no hay recuperación automática.

## Interfaces y versionado

| Interfaz | Contrato vigente |
| --- | --- |
| HTTP upload | POST /api/samples/, multipart; 202 + sample_id, report_id, status, report_url y Location. |
| HTTP report | GET /api/samples/<id>/report/, propietario; 200 con estado; Retry-After 3 si no terminal. |
| Celery | Nombre mallab.tasks.analyze_sample_task, argumento ID, cola analysis, JSON, ignore_result. |
| Servicio pipeline | process_sample(id) devuelve AnalysisReport incluso en fallos de análisis; BD/ausencia/concurrencia tienen excepciones. |
| YARA histórico | scan_yara(bytes, rules_directory, timeout=30) devuelve lista; disponible desde analyzer. |
| YARA enriquecido | scan_yara_result devuelve status, ruleset_sha256, rule_file_count y matches; excepciones si no termina. |
| ClamAV | scan_clamav(bytes, enabled, socket_path, timeout, límites) devuelve status/signatures/reason opcional. |
| Heurísticas | evaluate_heuristics(file_size=..., entropy=..., pe=..., ...) devuelve findings, versión, alcance y límites de interpretación. |

`AnalysisReport.pe_headers` v2 conserva file/pe/yara y añade clamav/heuristics.
Mantiene columnas entropy y yara_matches. La API conserva results en COMPLETED;
añade analysis en raíz para v2 terminales, también FAILED. Si YARA completó,
analysis.yara.matches usa la columna existente. No hay results completo para FAILED.
Los reportes sin versión/v1 no reciben esa extensión ni se reescriben.

## Autenticación y privacidad

IsAuthenticated; Basic → Token DRF → sesión, usuarios activos. POST con sesión
requiere CSRF interno DRF; Basic/Token no. La exención de middleware no invalida
la comprobación de SessionAuthentication. Las rutas de reporte filtran por PK y
propietario, incluso para staff. Role del modelo no concede acceso extra.
api_key personalizada no participa en estos autenticadores. No hay JWT ni endpoint
de emisión de tokens en mallab; DRF proporciona comando administrativo.

No guardar mensajes arbitrarios de herramientas en respuestas. Errores generales
de análisis son genéricos; detalle en logs privados. Los resultados pueden incluir
nombres/secciones/imports/metadatos de reglas, no bytes coincidentes ni binarios.

## Controles de herramientas

YARA: fuentes locales confiables, includes deshabilitados, warnings como errores,
snapshot y hash de los mismos bytes compilados. LRU de dos revisiones por proceso;
lock de compilación y sin fallback a revisiones viejas ante reglas inválidas.
Límites de fuentes y matches; timeout solo del matching. Revisiones multiarchivo
deben desplegarse atómicamente y estar fuera del control de clientes.

ClamAV: solo socket Unix absoluto; frames INSTREAM de hasta 64 KiB, deadline total,
respuesta acotada y parsing estricto. Sin shell, TCP o temporales del cliente.
El daemon necesita sus propios límites y actualización de firmas; el cliente no
puede garantizar cancelación remota ni cobertura de todas las firmas.

PE: controles de secciones/imports y salida acotada de warnings; los imports se
limitan después del parsing. El worker puede consumir más memoria que la entrada.
Heurísticas: observaciones con criterios declarados, no decisiones por capas.

## Decisiones y límites vigentes

- Separar HTTP, tarea y servicio; estado en BD, Storage privado y mensajes por ID.
- JSON v2 aditivo para no romper reportes antiguos; sin migraciones V2.
- Mantener SQLite hasta tarea separada; no alterar datos como parte de refactors.
- Técnicas tradicionales estáticas, sin muestras ejecutadas, IA o envío externo.
- ClamAV opt-in y reglas revisadas opt-in; ausencia de detección no prueba seguridad.
- No hay outbox, cuotas, retención, autosanación de tareas ni despliegue productivo
  reproducible. El motor de decisiones por capas aún no existe.

Detalle histórico y operativo: [STATIC_ENGINE_V2.md](../mallab/STATIC_ENGINE_V2.md),
[API.md](../mallab/API.md), [ANALYZER.md](../mallab/ANALYZER.md) y
[DEPLOYMENT.md](DEPLOYMENT.md). Cambios en estas interfaces requieren actualizar
también el contexto consolidado y pruebas relevantes.
