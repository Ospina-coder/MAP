# MAP — Contexto consolidado para transferencia a otra IA

Documento principal autónomo. Se puede compartir este archivo completo sin el
historial de conversación ni los documentos enlazados. Los enlaces amplían los
procedimientos, pero las decisiones y el estado esencial están descritos aquí.

## 1. Nombre, propósito y alcance

**MAP — Malware Lab Analysis Platform**, denominado también MalLab Analyzer en
el código, es un backend para recibir archivos de usuarios autenticados y
analizarlos estáticamente en segundo plano. Calcula hashes, entropía, formato,
estructura PE, coincidencias YARA, resultados opcionales ClamAV e indicadores
heurísticos explicables. Persiste resultados y los sirve solo al propietario.

La etapa actual es **STATIC ENGINE V2**. No hay ejecución de muestras, análisis
dinámico, CAPE, modelos de IA/ML, motor de decisiones por capas ni veredicto
probabilístico. Existe administrador Django; no un frontend propio de producto.

## 2. Referencia, fecha y reglas de evidencia

- Actualizado: **29 de octubre de 2026**, fecha de trabajo America/Bogota.
- Rama observada: **`main`**.
- Commit de referencia del código: **`f7460b7e66edd3a76e2a845095d4c909fc8ad5d2`**
  (`f7460b7`, mensaje `Avance`, 29/10/2026).
- Esta organización documental es un cambio local posterior a ese commit,
  todavía sin commit propio. No se realizó commit ni push en esta iteración.
- Existía previamente como archivo local sin seguimiento
  `mallab/DEPLOY_STATIC_ENGINE_V2_UBUNTU.md`; se conserva y enlaza.
- GitHub y el contenido desplegado en Ubuntu **no se verificaron por red**.

| Etiqueta | Significado y estado global actual |
| --- | --- |
| Implementado en código | Existe en los archivos inspeccionados; V2 sí cumple este nivel. |
| Validado mediante pruebas | Hay ejecución y resultado pertinente; suite local repetida, 63 aprobados y 1 omitido. |
| Desplegado y verificado en Ubuntu | Requiere evidencia del servidor/revisión/servicios/E2E; **no acreditado para V2**. |
| Pendiente de implementación | No existe la capacidad completa; figura en pendientes y roadmap. |
| Información del usuario sin verificar | Hardware y servicios previos comunicados; no sustituye una inspección remota. |

La fuente del comportamiento es el código contrastado con pruebas. Un plan,
ejemplo, test simulado o versión de dependencia permitida no acredita despliegue.

## 3. Tecnologías, versiones verificadas y dependencias

Versiones observadas el 29/10/2026 con Python y `importlib.metadata`, usando
`PYTHONPATH=.test-deps` en el entorno local Windows. No son versiones Ubuntu.

| Tecnología | Restricción del proyecto | Versión observada localmente |
| --- | --- | --- |
| Python | Compatibilidad documentada 3.10+; no hay versión de intérprete fijada | 3.10.10, plataforma `win32` |
| Django | `>=5.2.12,<5.3` | 5.2.12 |
| Django REST Framework | `>=3.16,<4` | 3.18.3 |
| Celery | `celery[redis]>=5.5,<6` | 5.6.3 |
| Redis, cliente Python | Dependencia transitiva del extra Redis | 6.4.0; **no es versión del servidor Redis** |
| pefile | `>=2024.8.26,<2025` | 2024.8.26 |
| yara-python | `>=4.5.0,<5` | 4.5.4, también runtime YARA observado |
| SQLite | Motor de BD incluido con Python | Runtime local 3.39.4 |
| ClamAV/clamd/FreshClam | Componentes externos del SO, no requirements Python | Versión/instalación remota sin verificar |

Se utilizan `hashlib`, `math`, `Counter`, `pathlib`, `datetime`, `uuid`, `secrets`,
`logging`, `socket`, `struct`, `time`, locks y utilidades estándar de pruebas.
No se necesita un cliente Python ClamAV externo: MAP implementa INSTREAM local.
Hay Git, puntos de entrada WSGI/ASGI y clientes cURL/REST. No hay lockfile de
dependencias, Dockerfile ni servidor WSGI de producción configurado en el repo.

## 4. Estructura del repositorio

```text
AGENTS.md                         Instrucciones permanentes de trabajo
docs/PROJECT_CONTEXT.md           Este archivo: transferencia autónoma
docs/CHANGELOG_DEV.md             Historia y evidencia por iteración
docs/ROADMAP.md                   Capacidades y siguientes actividades
docs/ARCHITECTURE.md              Diseño e interfaces vigentes
docs/DEPLOYMENT.md                Entornos, configuración y validación
manage.py / requirements.txt / README.md
config/                          Proyecto Django; app de dominio: mallab
  settings.py / urls.py / celery.py / __init__.py / wsgi.py / asgi.py
mallab/
  models.py / admin.py / urls.py / views.py / upload_handlers.py / tasks.py
  services/analyzer.py            Orquestación y extracción estática
  services/yara_scanner.py        Reglas locales, snapshots y caché
  services/clamav.py              Cliente clamd Unix
  services/heuristics.py          Indicadores deterministas
  services/exceptions.py          Error de entrada compartido
  migrations/                    0001, 0002 y 0003 históricas
  tests/                         Extracción, API, V2, YARA, ClamAV y heurísticas
  API.md / ANALYZER.md / STATIC_ENGINE_V2.md
  DEPLOY_STATIC_ENGINE_V2_UBUNTU.md
yara_rules/testing/               Fixture de regla inocua; sin copiarla aquí
yara_rules/reviewed/              Vacío inicialmente, salvo .gitkeep
yara_rules/README.md
CONTEXTO_PROYECTO_IA.md            Snapshot histórico previo a V2, conservado
```

`db.sqlite3`, `private-media/`, `.env`, venvs, `.test-deps/` y cachés están
excluidos de Git. `.test-deps/` es apoyo local de validación, no un despliegue.

## 5. Arquitectura real del backend

```text
HTTP autenticado
  → Django/DRF valida multipart, propietario y límite; SHA-256 por chunks
  → Storage privado + transacción SQLite: Sample y AnalysisReport(PENDING)
  → on_commit: publicar sample_id en Redis/cola analysis
  → worker Celery separado
  → leer instantánea acotada → hashes/formato/entropía/PE/heurísticas/YARA/ClamAV
  → SQLite: payload v2 y estado COMPLETED o FAILED
  → GET autenticado por propietario devuelve reporte, sin el binario
```

La vista usa `non_atomic_requests`, transacción explícita y limpieza compensatoria
del archivo si falla el alta SQL. El Storage no participa en la transacción.
El trabajo costoso no ocurre dentro de una transacción abierta. La cola transporta
IDs, nunca archivos ni instancias ORM. La API lee la BD, no `AsyncResult`.

## 6. Modelos y esquema de BD

**User:** hereda `AbstractUser`; `AUTH_USER_MODEL='mallab.User'`. PK `user_id`
(SQL `user_Id`), username heredado, email único, `name`, `role` (`USER`, `ANALYST`,
`ADMIN`), `last_ip`, `daily_uploads` y `api_key`. Roles son metadatos, no conceden
permisos Django por sí mismos. `daily_uploads` no implementa cuotas ni reinicio.
La `api_key` personalizada almacena un hash y tiene métodos de rotación/verificación,
pero no autentica esta API; no confundirla con tokens DRF.

**Sample:** PK `id` (SQL `Id`), nombre original, `FileField`, tamaño, hash,
tipo, fecha y FK `uploaded_by` con `CASCADE`. Se almacena con UUID bajo
`quarantine/`, sin usar la ruta original del cliente. Hash indexado, no único;
validador admite MD5/SHA-256; la ingestión actual genera SHA-256. Índices por
fecha y usuario/fecha. Archivo y usuario permiten valores opcionales por historia
del esquema, pero la API actual exige archivo y usuario autenticado.

**AnalysisReport:** PK `id_analysis` (SQL `Id_analysis`), relación uno a uno
con muestra (SQL `Id`), `entropy` nullable 0–8, JSON `yara_matches`, JSON
`pe_headers` y `status` indexado. Estados válidos SQL: `PENDING`, `PROCESSING`,
`COMPLETED`, `FAILED`. `pe_headers` es un contenedor histórico de todo el payload.

Migraciones: `0001_initial` crea entidades/restricciones/índices;
`0002_sample_file` incorpora archivo; `0003_alter_sample_uploaded_by` deja la FK
nullable durante antiguas pruebas anónimas. No se elimina esa migración aunque
las vistas ya cerraron el anonimato. DRF mantiene sus tablas de tokens.
V2 no cambia modelos ni necesita una migración adicional. No se inspeccionaron
registros privados ni las migraciones aplicadas en Ubuntu.

Borrar modelos tiene cascadas SQL; no hay limpieza automática propia de binarios
al borrar una muestra. `save()` no ejecuta `full_clean()` automáticamente.

## 7. Endpoints, autenticación y autorización

| Ruta | Contrato |
| --- | --- |
| `POST /api/samples/` | Exactamente un archivo multipart en `file`; crea muestra/reporte y publica tarea; HTTP 202 con IDs, estado, report_url y cabecera Location. |
| `GET /api/samples/<sample_id>/report/` | Solo muestra del solicitante; estado/metadatos y, al completar, resultados. |
| `/admin/` | Administrador nativo Django de usuarios, muestras y reportes. |

Ambas vistas DRF exigen `IsAuthenticated`. Orden: BasicAuthentication,
TokenAuthentication y SessionAuthentication; usuarios activos. El usuario
autenticado siempre es `uploaded_by`. No hay fallback al primer usuario.
Una muestra ajena devuelve 404 incluso para staff que use la API. No hay
endpoints propios de emisión de token, registro, listado, descarga o borrado.

Basic y `Authorization: Token <marcador>` funcionan sin CSRF. POST por sesión
exige CSRF por validación interna DRF pese a `@csrf_exempt` del middleware.
Errores DRF suelen tener `detail`; errores de negocio, `error`. HTTP: 400
entrada inválida, 401 autenticación, 403 CSRF, 404 inexistencia/propiedad,
405 método, 413 tamaño, 415 tipo de contenido, 503 publicación no confirmada.

GET devuelve HTTP 200 incluso si el análisis terminó FAILED; `status` expresa
ese fallo. En PENDING/PROCESSING: Retry-After 3. En COMPLETED: `results` con
entropy, hashes, file_size, file_type, pe_headers, yara_matches y yara.
Reportes v2 terminales añaden `analysis` con schema_version, yara, clamav y
heuristics. YARA completado incluye matches aun si falla después otra etapa.
Reportes sin versión o v1 conservan su JSON anterior; no se reescriben al leer.

## 8. Motor estático y semántica de resultados

`process_sample(sample_id)` reclama mediante UPDATE condicional de PENDING o
FAILED a PROCESSING. COMPLETED es idempotente; PROCESSING ya reclamado produce
`AnalysisInProgress`. Lee una instantánea de hasta 64 MiB para todas las etapas.

- **Hashes/formato/entropía:** MD5 identificador, SHA-256; Shannon 0–8; firmas
  PE/DOS, ELF, PDF, ZIP, gzip y PNG; desconocido como octet-stream.
- **PE:** pefile, timestamp declarado/UTC, RVA entry point, secciones con tamaños,
  offsets, direcciones, características, bytes observados y entropía; imports por
  DLL, nombre/ordinal/IAT y warnings. El timestamp no es prueba de fecha real.
- **YARA:** fuentes UTF-8 locales, sin includes, warnings como errores; namespaces
  por archivo, manifiesto SHA-256 y caché LRU de dos revisiones por proceso bajo
  lock. Relee/hasha antes de reutilizar: cambios aun con igual mtime invalidan;
  no usa revisión vieja si la nueva falla. Estados COMPLETED (0 o más matches),
  SKIPPED (sin configurar/no alcanzada), ERROR. Directorio revisado vacío no es
  escaneo limpio. Regla de testing separada, no activa por defecto.
- **ClamAV:** cliente independiente AF_UNIX/INSTREAM sobre los mismos bytes,
  opt-in, sin shell/TCP/temporales del cliente. SKIPPED, DETECTED con firmas,
  NO_DETECTION, UNAVAILABLE o ERROR. Solo conserva firmas devueltas; no garantiza
  enumerar todas ni registra versión/edad de firmas en el payload actual.
- **Heurísticas:** engine_version 1, parámetros y findings con id, descripción,
  evidencia, justificación técnica y limitaciones. Observa entropía elevada,
  sección W+X, raw fuera del archivo, entry point fuera de secciones ejecutables,
  combinación de imports de memoria/thread remoto, PE inválido y warnings.
  No hay score, probabilidad o clasificación. Umbral 7.5 y mínimo 4096 bytes son
  criterios operativos no calibrados, con posibles explicaciones legítimas.

Payload nuevo en `pe_headers`: schema_version 2; file, pe, yara, clamav,
heuristics y error opcional. Entropía y matches conservan columnas anteriores.
Los errores conservan resultados parciales; detalles internos en logs privados.
Un error YARA ordinario permite intentar ClamAV; un límite suave Celery no.
Si una herramienta habilitada falla o ClamAV no está disponible, el reporte
global es FAILED. Deshabilitar una etapa queda SKIPPED y permite completar las
restantes. COMPLETED significa ejecución, no ausencia de malware; DETECTED no
es un fallo del pipeline y NO_DETECTION no garantiza seguridad.

## 9. Redis, Celery y límites/configuración

`Celery('mallab')` en `config/celery.py`, settings namespace CELERY,
autodiscovery y exportación como celery_app desde `config/__init__.py`.
Comando del worker `celery -A config worker`; cola `analysis`.

Broker por defecto Redis loopback 6379/0, modificable por `CELERY_BROKER_URL`.
Backend configurado al mismo Redis, pero resultados Celery ignorados globalmente
y por tarea. Serializadores/accept JSON; eager False, prefetch 1, reintento de
publicación desactivado, conexión/socket 3 s. Tarea `analyze_sample_task` con
límites suave/duro 110/120 s. DELETED es retorno auxiliar, no estado de reporte.
Una publicación ambigua devuelve 503 con IDs guardados y solo marca FAILED si
seguía PENDING. No reintentar subidas automáticamente ni purgar la cola.

| Ajuste | Valor predeterminado |
| --- | --- |
| Entrada | 64 MiB; handler y vista comprueban tamaño, worker relee límite real. |
| YARA | 30 s matching, 256 archivos, 4 MiB fuentes, 1000 coincidencias. |
| PE | 96 secciones, 4096 descriptores/funciones importadas; 20 warnings de 500 caracteres. |
| Heurísticas | Entropía >=7.5 con mínimo 4096 bytes observados. |
| ClamAV | Deshabilitado, socket local configurable, 30 s plazo total, respuesta 8192 bytes. |

Variables realmente leídas: DJANGO_SECRET_KEY, DJANGO_DEBUG (default activo),
DJANGO_SETTINGS_MODULE, CELERY_BROKER_URL, YARA_RULES_DIR, CLAMAV_ENABLED (solo
`1` activa), CLAMAV_SOCKET_PATH. No hay carga automática de `.env`.
MEDIA_ROOT/SQLite/límites/backend de resultados se fijan en settings, no por
variables homónimas. ALLOWED_HOSTS permite todos los hosts y hay tres orígenes
CSRF HTTP de desarrollo; DJANGO_ALLOWED_HOSTS ya no se lee. TIME_ZONE es UTC.
Web y worker deben usar el mismo código, venv, configuración, BD y Storage.

## 10. Infraestructura conocida del ThinkPad

**Proporcionado por el usuario, sin inspección remota actual:** ThinkPad E14,
Intel 11.ª generación, 16 GB RAM; Ubuntu, proyecto `~/MAP`; Django/Redis/Celery
funcionaban previamente, Redis había respondido PONG; SQLite con registros y
cuarentena que deben preservarse; acceso SSH/Tailscale; Docker instalado sin
uso actual para CAPE. No se ha validado versión Ubuntu/Redis/clamd, recursos
libres, usuarios/unidades, ruta venv, firmas, permisos ni commit desplegado.

La guía propone empezar la validación con un proceso Celery prefork y medir;
esto no es la configuración observada ni un benchmark del equipo. Los ejemplos
de entorno systemd, socket y reglas en `/etc/map` son propuestas hasta aplicarlos.

## 11. Implementado y validado: matriz de estado

| Capacidad | Código | Evidencia local | Ubuntu V2 |
| --- | --- | --- | --- |
| Ingestión, límites, permisos, reportes | Implementado | Tests Django/DRF, BD temporal y Storage temporal | No acreditado |
| Hashes, entropía y PE | Implementado | Cálculos conocidos y PE sintéticos reales | No acreditado |
| YARA con caché/límites | Implementado | yara-python real, marcador inocuo, no-match, concurrencia y errores | No acreditado |
| Cliente ClamAV | Implementado | Socket/protocolo/detecciones simulados | Daemon/firmas/detección real pendientes |
| Heurísticas | Implementado | Indicadores positivos/negativos y evidencia persistida | No acreditado |
| Compatibilidad v1/v2 | Implementado | API legacy, v2 y fallos parciales | No acreditado |
| Celery | Implementado | Worker real con broker memory, no Redis remoto | Servicios previos reportados por usuario |
| Procedimiento de despliegue | Preparado | Lectura/sintaxis de comandos; no ejecución Ubuntu | Pendiente de ejecutar |

El test `LiveClamAVTests` no usa mocks, pero solo verifica texto sin detección.
Se omite fuera de Unix o sin MAP_TEST_CLAMAV_SOCKET. Para validar firmas reales
falta además una detección positiva inocua y un E2E contra el servidor.

## 12. Incompleto o pendiente

Prioridad inmediata: inventariar Ubuntu, respaldar datos, comprobar revisión,
dependencias/esquema, clamd/FreshClam/socket/grupos, reglas confiables, entorno
compartido y prueba HTTP→Redis→Celery→SQLite→GET con servicios reales.
La guía prevé texto sin detecciones, marcador YARA/entropía y prueba antivirus
estándar, sin copiar contenido de fixtures en este documento.

No implementados: decisiones por capas, recuperación automática de tareas
atascadas, outbox, reintentos de análisis programados, cuotas/rate limiting,
retención/purga de binarios, reanálisis administrado, frontend, API de listado/
descarga/borrado, endpoints de emisión de token/registro, JWT, CI y despliegue
reproducible completo. PostgreSQL/Supabase es trabajo independiente, no actual.
CAPE/análisis dinámico e IA no forman parte del alcance autorizado actual.

## 13. Última iteración

La iteración actual organiza exclusivamente documentación: crea este contexto,
historial, roadmap, arquitectura, despliegue e instrucciones raíz; añade enlaces
de entrada y marca el contexto anterior como histórico sin borrarlo. No cambia
el motor ni datos. Repite la suite para verificar el resumen previo.

La iteración funcional anterior, **STATIC ENGINE V2**, está en f7460b7: módulos
YARA/ClamAV/heurísticas/excepciones, límites, payload/API v2, reglas inocuas y
pruebas. La preparación posterior de despliegue es un documento local previo
a esta tarea, sin evidencia de ejecución remota. No equivale a despliegue.

## 14. Archivos y motivo de cambios

| Archivo de esta iteración | Motivo |
| --- | --- |
| `docs/PROJECT_CONTEXT.md` | Transferencia autónoma del estado real. |
| `docs/CHANGELOG_DEV.md` | Historia por fecha/commit/evidencia, sin inventar commits. |
| `docs/ROADMAP.md` | Separar capacidades implementadas, validación y futuros trabajos. |
| `docs/ARCHITECTURE.md` | Componentes, contratos, estados y decisiones vigentes. |
| `docs/DEPLOYMENT.md` | Separar local/Ubuntu y enlazar procedimiento administrativo. |
| `AGENTS.md` | Obligar a mantenimiento proporcional, seguridad y evidencia futura. |
| `README.md` | Índice de entrada a la documentación nueva y existente. |
| `CONTEXTO_PROYECTO_IA.md` | Aviso de snapshot histórico y enlace al consolidado actual. |

Archivos funcionales de V2: `config/settings.py`, `mallab/views.py`,
`mallab/services/{analyzer,yara_scanner,clamav,heuristics,exceptions}.py`,
`mallab/tests/{settings,test_analyzer,test_api,test_engine_v2,test_yara_scanner,
test_clamav,test_heuristics}.py`, `yara_rules/` y guías técnicas. No hay nuevas
migraciones ni dependencias directas en V2. El desglose histórico está en changelog.

## 15. Pruebas ejecutadas y resultados reales

Repetidas el 29/10/2026 durante la organización documental. PowerShell local:

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) '.test-deps'
python manage.py check
python manage.py test mallab.tests --settings=mallab.tests.settings
python manage.py makemigrations --check --dry-run
```

Resultados observados: check sin incidencias; **64 casos, 63 aprobados y 1
omitido**, `OK (skipped=1)`; sin cambios de modelo pendientes. El caso omitido
es el test real Unix/clamd. Se confirma así el resumen de la iteración anterior,
no por repetir su afirmación sino por una nueva ejecución.

Los tests usan SQLite en memoria/Storage temporal. Hay YARA/pefile reales y
simulaciones de fallos/ClamAV; el worker Celery del test usa memory. No se usan
los registros reales para la suite. `makemigrations --check --dry-run` no aplica
migraciones ni acredita el esquema del servidor. No se ejecutó E2E Ubuntu ni
se verificó GitHub. La documentación se revisa además por enlaces/coherencia;
no se añaden nuevas pruebas funcionales por esta organización de archivos.

## 16. Riesgos y problemas conocidos

- Configuración de desarrollo: wildcard de hosts, orígenes HTTP y DEBUG activo
  por defecto. Falta endurecimiento para exposición final y verificación HTTPS.
- ClamAV real, firmas vigentes y socket no acreditados; NO_DETECTION puede tener
  cobertura limitada. Client timeout no garantiza cancelar inmediatamente clamd.
- Compilación YARA y parser PE no tienen un aislamiento de memoria individual;
  algunos límites se comprueban tras parsear. El archivo limitado no limita toda RAM.
- SQLite puede sufrir contención con más escritores. No migrar por iniciativa propia.
- Caída entre commit/publicación deja PENDING; corte de worker puede dejar
  PROCESSING. No hay recuperación automática/outbox ni garantía de reintento.
- No hay cuotas/retención; `daily_uploads` sin lógica. Cascadas SQL no limpian Storage.
- Tokens DRF sin política propia de expiración/rotación; errores JSON de dos estilos.
- FK de propietario nullable por historia aunque API exige autenticación.
- Una copia de SQLite activa sin su protocolo correcto puede ser incoherente;
  backup y conservación de datos son prerrequisitos de despliegue.
- Rangos amplios sin lockfile; versiones instaladas en Ubuntu desconocidas.

## 17. Decisiones arquitectónicas vigentes

1. Análisis estático tradicional, sin ejecutar muestras ni usar IA.
2. Usuario obligatorio y acceso por propietario, incluso para staff en la API.
3. Storage privado con UUID; no descargar/publicar binarios por rutas existentes.
4. Ingestión separada del worker, mensajes JSON por ID y publicación tras commit.
5. BD como fuente de estado; JSON v2 aditivo, sin reescribir reportes históricos.
6. YARA solo con reglas confiables; test y reglas revisadas separados.
7. ClamAV opcional pero, habilitado, sus fallos impiden declarar análisis completo.
8. Hallazgos explicables, sin convertir indicadores en certezas ni probabilidades.
9. SQLite se conserva; cambios de infraestructura requieren otra tarea.
10. Código, tests y operación remota se documentan como evidencias distintas.

## 18. Próximas actividades recomendadas

Primero ejecutar el procedimiento Ubuntu con responsables y evidencias, sin
limpiar datos: revisión de servicios/rutas, backup, dependencias/esquema, firmas,
socket, reglas y entorno. Después validar herramientas reales, HTTP integral,
permisos, persistencia y conservación de filas, incluyendo consulta tras reinicio.
Registrar revisión/fecha/resultados del servidor antes de avanzar a decisiones
por capas. Si algo falla, mantenerlo como pendiente y conservar evidencia.
La prioridad siguiente se acuerda con el usuario; el roadmap no autoriza ejecutar
automáticamente todos sus puntos.

## 19. Instrucciones para otra IA y mapa documental

Leer este archivo como foto del estado fechado y comprobar referencia si llega
código más nuevo. No deducir producción desde tests o guías. No reintroducir
anonimato ni asignación al primer usuario, no confundir api_key con Token DRF,
no consultar AsyncResult como estado del reporte ni cambiar la cola por defecto.
Respetar datos existentes y el alcance antes de proponer cambios. Actualizar
contexto/evidencia después de modificaciones importantes siguiendo AGENTS.

Documentos ampliados (conservados):

- [Historial](CHANGELOG_DEV.md), [roadmap](ROADMAP.md),
  [arquitectura](ARCHITECTURE.md) y [despliegue](DEPLOYMENT.md).
- [Instrucciones permanentes](../AGENTS.md) y [entrada general](../README.md).
- [API](../mallab/API.md), [analizador](../mallab/ANALYZER.md),
  [auditoría e implementación V2](../mallab/STATIC_ENGINE_V2.md).
- [Procedimiento Ubuntu detallado](../mallab/DEPLOY_STATIC_ENGINE_V2_UBUNTU.md):
  comandos administrativos/automatizables, backups y aceptación E2E.
- [Reglas YARA](../yara_rules/README.md).
- [Snapshot previo a V2](../CONTEXTO_PROYECTO_IA.md), histórico, no contexto vigente.

Para el intercambio habitual con otra IA, compartir **este PROJECT_CONTEXT.md**.
