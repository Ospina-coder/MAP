# MalLab / MAP — Contexto técnico para una IA

> **Snapshot histórico previo a STATIC ENGINE V2.** Se conserva su contenido y
> referencia original. Para transferir el estado vigente a otra IA, usar
> [docs/PROJECT_CONTEXT.md](docs/PROJECT_CONTEXT.md), que incluye V2, pruebas y
> pendientes de validación Ubuntu. Este archivo no se mantiene como consolidado actual.

Fecha de revisión: 29 de octubre de 2026.
Código de referencia: rama local `main`, commit `129d84ad3a72ce04d4b2e92a79b349257ccffe5a`.
Repositorio configurado: https://github.com/Ospina-coder/MAP-Malware-Lab-Analysis-Platform-

Este documento describe la implementación encontrada en el código local. Se puede entregar completo a otra IA como contexto para continuar el desarrollo. Los nombres de archivos son relativos a la raíz del repositorio. No contiene contraseñas, tokens reales ni muestras. Las configuraciones de ejemplo usan marcadores de posición.

## 1. Resumen que debe conocer la IA

El proyecto se presenta en el repositorio como MAP — Malware Lab Analysis Platform y en el código como MalLab Analyzer. Es un backend de análisis estático de archivos construido con Python, Django y Django REST Framework. Un usuario autenticado sube una muestra mediante una API multipart; Django guarda el archivo en almacenamiento privado, registra sus metadatos y crea un reporte `PENDING`. Después del commit, se publica una tarea Celery en la cola `analysis`, usando Redis como broker. Un worker separado calcula hashes MD5/SHA-256, entropía Shannon, tipo de archivo por firmas, información PE y coincidencias YARA. Los estados y resultados se guardan en la base de datos y se consultan por una API que exige que la muestra pertenezca al usuario solicitante.

El proyecto NO ejecuta los archivos subidos. No incluye un sandbox de ejecución, un frontend propio, un clasificador de aprendizaje automático ni un veredicto automático de benigno/malicioso. El administrador nativo de Django sí está disponible.

El estado actual exige autenticación: Basic Auth, Token de DRF o sesión Django. Las pruebas anteriores con subida anónima fueron revertidas en las vistas. No se debe reintroducir `AllowAny` ni asignar muestras a `User.objects.first()` como si fueran el comportamiento vigente.

## 2. Alcance y procedencia de lo documentado

Fuentes principales revisadas: `requirements.txt`, `config/settings.py`, `config/celery.py`, rutas, modelos, vistas, tareas, servicio de análisis, upload handler, administrador, migraciones y pruebas. También se consultaron `README.md`, `mallab/API.md` y `mallab/ANALYZER.md`.

Se distinguen tres niveles de evidencia:

- **Implementado y observado en código:** comportamiento descrito en las secciones técnicas.
- **Contexto aportado por el usuario:** servidor Ubuntu, Redis instalado y respondiendo `PONG`, acceso de desarrollo mediante Tailscale en `100.65.59.31:8000` y clientes cURL/REST. Estos servicios no se inspeccionaron remotamente en esta revisión.
- **Pendiente o recomendado:** mejoras que todavía no están implementadas. No deben presentarse como funcionalidades existentes.

La revisión no confirma la versión desplegada en Ubuntu, sus migraciones aplicadas, la conectividad real con Redis ni el estado del worker remoto. El remoto Git está configurado, pero no se consultó por red para demostrar sincronización. Las referencias locales de Git no sustituyen esa comprobación.

## 3. Tecnologías utilizadas

| Tecnología | Versión o rango declarado | Uso real |
| --- | --- | --- |
| Python | Compatibilidad descrita: 3.10+ | Backend, análisis, scripts de gestión y workers. El proyecto usa anotaciones como `str \| Path`. |
| Django | `>=5.2.12,<5.3` | ORM, modelos, migraciones, autenticación, sesiones, administración, archivos, transacciones y configuración web. |
| Django REST Framework | `>=3.16,<4` | Vistas funcionales de API, autenticación Basic/Token/sesión, permiso `IsAuthenticated` y errores/renderizado JSON. |
| Celery con extra Redis | `celery[redis]>=5.5,<6` | Ejecución asíncrona del análisis en workers independientes. |
| Redis | Sin versión del servidor fijada en el repositorio | Broker de mensajes y backend de resultados configurado. El usuario informó que está operativo en Ubuntu. |
| SQLite | Backend incluido en Django | Base predeterminada en `db.sqlite3`; pruebas en memoria. |
| pefile | `>=2024.8.26,<2025` | Lectura estática de PE: timestamp declarado, secciones, imports y advertencias. |
| yara-python / YARA | `>=4.5.0,<5` para el paquete Python | Compilar y aplicar reglas locales `.yar` y `.yara`. |
| Biblioteca estándar Python | Incluida con Python | `hashlib`, `math`, `collections.Counter`, `datetime`, `pathlib`, `uuid`, `secrets`, `logging`; en pruebas, `unittest.mock`, `tempfile`, `struct`, `json`, `base64` y `threading`. |
| Django FileField / Storage | Integrado en Django | Guardar y leer muestras con nombres opacos en almacenamiento privado. |
| WSGI y ASGI | Puntos de entrada Django | `config/wsgi.py` y `config/asgi.py`; no hay servidor de producción específico configurado. |
| Git / GitHub | Repositorio y rama `main` | Control de versiones y remoto de sincronización. |
| Ubuntu | Versión no documentada | Entorno servidor indicado por el usuario. |
| Tailscale | Sin configuración del agente en el repo | Acceso de red privado indicado por el usuario; la IP aparece en orígenes CSRF. |
| cURL / clientes REST | Sin dependencia de ejecución del backend | Consumir la API desde clientes externos. |

Los rangos de `requirements.txt` expresan dependencias permitidas; no constituyen un lockfile ni prueban las versiones instaladas en el servidor. PostgreSQL, nginx, Docker, Gunicorn y un gestor de procesos no están implementados/configurados en el repositorio examinado, aunque algunos aparezcan como recomendaciones en la documentación.

## 4. Organización del repositorio

```text
MAP/
├── manage.py                         # Comandos de gestión Django
├── requirements.txt                  # Dependencias directas
├── README.md                         # Guía general
├── .gitignore                        # Excluye secretos locales, BD y binarios
├── config/                           # Paquete del proyecto Django
│   ├── __init__.py                    # Expone celery_app al importar el paquete
│   ├── settings.py                    # Configuración Django, Celery y análisis
│   ├── celery.py                      # Instancia Celery("mallab")
│   ├── urls.py                        # /admin/ y /api/
│   ├── wsgi.py
│   └── asgi.py
└── mallab/                           # App de dominio
    ├── apps.py
    ├── models.py                      # User, Sample, AnalysisReport
    ├── admin.py                       # Administración de las tres entidades
    ├── urls.py                        # Subida y consulta de reportes
    ├── views.py                       # Validación HTTP, autorización y despacho
    ├── tasks.py                       # Wrapper Celery del analizador
    ├── upload_handlers.py             # Límite durante la recepción multipart
    ├── services/analyzer.py           # Extracción estática y pipeline persistente
    ├── migrations/                    # Esquema inicial, archivo y usuario nullable
    ├── tests/settings.py              # Configuración aislada
    ├── tests/test_analyzer.py         # Extracción y pipeline
    ├── tests/test_api.py              # API, permisos y worker
    ├── API.md
    └── ANALYZER.md
```

`db.sqlite3`, `private-media/`, `.test-deps/`, `.env`, entornos virtuales y cachés de Python están excluidos de Git. `.test-deps/` se usó como directorio local de dependencias para verificar el proyecto; no es una arquitectura de despliegue. No se observa carga automática de `.env`: `settings.py` utiliza `os.environ`, por lo que las variables deben exportarse o inyectarse por el entorno de ejecución.

## 5. Arquitectura y responsabilidades

```text
Cliente cURL / REST / sesión Django
        │ POST multipart + credenciales
        ▼
API Django + DRF ─────► almacenamiento privado (archivo)
        │
        ├────────────► SQLite: Sample + AnalysisReport(PENDING)
        │ después de confirmar la transacción
        ▼
Redis: cola analysis
        ▼
Worker Celery: analyze_sample_task(sample_id)
        ▼
process_sample → hashes → entropía → PE → YARA
        │
        ▼
Base de datos: metadatos actualizados + reporte COMPLETED / FAILED
        ▲
GET /api/samples/<id>/report/ con autenticación y control de propietario
```

La vista hace la identificación SHA-256 inicial por bloques, pero no invoca el análisis pesado de forma síncrona. Solo se transporta el ID de la muestra por la cola: no se envían bytes ni instancias del ORM a Celery. La base de datos es la fuente consultada por la API para conocer el resultado.

## 6. Modelo de datos

### 6.1. `User`

Hereda de `AbstractUser` y se configura con `AUTH_USER_MODEL = 'mallab.User'`.

- PK `user_id`, columna SQL `user_Id`.
- Campos heredados: `username`, password con hash, nombres, `is_active`, `is_staff`, `is_superuser`, fechas, grupos y permisos.
- `name`: nombre visible, hasta 150 caracteres.
- `email`: único.
- `role`: `USER`, `ANALYST` o `ADMIN`, con restricción de base de datos.
- `last_ip`: IP opcional.
- `daily_uploads`: entero no negativo, por defecto 0.
- `api_key`: hash opcional no editable desde formularios normales.

`rotate_api_key()` genera una clave aleatoria, persiste su hash y devuelve el secreto una vez. `check_api_key()` lo comprueba para un usuario activo ya identificado. **Este campo no es el token de DRF y no hay una clase de autenticación que lo utilice en las vistas.** Los tokens HTTP vigentes pertenecen a `rest_framework.authtoken`.

El campo `role` no concede permisos Django automáticamente. Tampoco se implementan cuotas usando `daily_uploads`, actualización de `last_ip` ni reinicio diario del contador.

### 6.2. `Sample`

- PK `id`, columna SQL `Id`.
- `file_name`: nombre original, máximo 255 caracteres.
- `file`: `FileField`, opcional para compatibilidad con registros anteriores.
- `file_size`: tamaño no negativo en bytes.
- `hash`: hasta 64 caracteres; validador de MD5 o SHA-256 hexadecimal; índice, sin unicidad.
- `file_type`: clasificación del archivo.
- `creation_date`: fecha con zona horaria.
- `uploaded_by`: FK a `User`, `CASCADE`, relación inversa `samples`.

El código actual del modelo admite `null=True, blank=True` en `uploaded_by` debido a la migración de las pruebas anónimas. **La API actual, sin embargo, exige autenticación y siempre guarda `uploaded_by=request.user`.** No confundir una columna nullable con un permiso de acceso anónimo.

Los archivos se nombran `quarantine/<uuid4 hexadecimal>`, sin usar la ruta ni extensión del cliente. El nombre original queda como metadato y no se utiliza para resolver la ubicación física. Hay índices por fecha descendente y por usuario/fecha.

### 6.3. `AnalysisReport`

- PK `id_analysis`, columna SQL `Id_analysis`.
- `sample`: relación uno a uno con `Sample`, columna SQL `Id`, `CASCADE`, inversa `analysis_report`.
- `yara_matches`: `JSONField`, lista nueva por registro.
- `pe_headers`: `JSONField`, diccionario nuevo por registro. Su nombre histórico abarca más que cabeceras PE.
- `entropy`: nullable, rango 0–8.
- `status`: `PENDING`, `PROCESSING`, `COMPLETED` o `FAILED`; indexado y con restricción SQL.

Un usuario puede tener muchas muestras. Cada muestra admite como máximo un reporte. Borrar usuarios elimina sus muestras y reportes relacionados en la base de datos. La limpieza física de archivos al borrar modelos no tiene una señal o servicio propio implementado; no se debe asumir que `CASCADE` limpia automáticamente los binarios del Storage.

### 6.4. Migraciones

| Migración | Cambio |
| --- | --- |
| `0001_initial` | Crea usuario personalizado, muestras, reportes, restricciones e índices. |
| `0002_sample_file` | Añade `Sample.file`. Los registros previos requieren asociar un archivo antes de analizarlos. |
| `0003_alter_sample_uploaded_by` | Hace opcional la FK del usuario. Permanece en el historial aunque se cerró el acceso anónimo. |

DRF aporta además sus migraciones para tokens. Ejecutar `migrate` aplica también esas tablas. Cambiar `AUTH_USER_MODEL` en una base de datos que ya usaba otro usuario exige una estrategia de migración; no basta con editar el setting.

## 7. API, autenticación y CSRF

Ambas vistas son funciones decoradas con `@api_view`, `@permission_classes([IsAuthenticated])` y `@renderer_classes([JSONRenderer])`.

Orden de autenticadores en ambas: `BasicAuthentication`, `TokenAuthentication`, `SessionAuthentication`. Se exige un usuario activo. No hay JWT, OAuth ni endpoint propio de login/registro/token en las rutas de `mallab`.

- Basic: `Authorization: Basic <base64(username:password)>`; cURL puede generarlo con `--user`.
- Token: `Authorization: Token <clave>`; se genera para un usuario existente con `drf_create_token`.
- Sesión: cookies Django, obtenibles por el login del administrador para usuarios con acceso a él.

La subida conserva `@csrf_exempt` para el middleware Django. Esto no desactiva la validación interna de `SessionAuthentication` de DRF: POST con sesión exige CSRF; Basic y Token permiten llamadas sin token CSRF. `CSRF_TRUSTED_ORIGINS` no sustituye un token CSRF ni autentica al cliente.

### 7.1. `POST /api/samples/`

Nombre de ruta: `mallab:upload-sample`.

Requiere `multipart/form-data` y exactamente un archivo bajo el campo `file`. Rechaza campos adicionales de archivo, varios archivos en `file`, nombre inválido y exceso de tamaño. Puede aceptar campos de texto adicionales porque la comprobación se hace sobre `request.FILES`. Los archivos vacíos no tienen una prohibición explícita.

Flujo:

1. DRF autentica y comprueba permisos antes de ejecutar la función de subida.
2. Se valida tipo de petición, archivo, nombre y límite de bytes.
3. Se calcula SHA-256 sobre los chunks y se rebobina el archivo.
4. Dentro de `transaction.atomic()` se guarda `Sample` y se crea el reporte `PENDING`.
5. Si falla la escritura SQL, se intenta eliminar del Storage el archivo ya guardado.
6. `transaction.on_commit()` ejecuta el despacho Celery con `retry=False`.
7. Se devuelve JSON y cabecera `Location` con la URL del reporte.

La función usa `transaction.non_atomic_requests` para controlar la transacción incluso si se habilita `ATOMIC_REQUESTS`.

Ejemplo ilustrativo de respuesta HTTP `202`:

```json
{
  "sample_id": 1,
  "report_id": 1,
  "status": "PENDING",
  "report_url": "/api/samples/1/report/"
}
```

El estado se vuelve a leer de la base de datos y podría ser `PROCESSING` o `COMPLETED` si el worker avanza rápidamente. Si no se confirma la publicación, el POST devuelve `503`, conserva IDs y URL y añade `error: "queue_unavailable"`. Marca el reporte `FAILED` solo si seguía `PENDING`, para no sobrescribir un estado ya tomado por un worker.

### 7.2. `GET /api/samples/<int:sample_id>/report/`

Nombre de ruta: `mallab:analysis-report`.

Busca la muestra por PK **y por `uploaded_by=request.user`**. Si no existe o pertenece a otro usuario, devuelve `404`. Esto también se aplica a staff/superusuarios que usan esta API; el administrador Django es una interfaz diferente.

Siempre incluye `sample_id`, `report_id`, `status` y `file_name` cuando existe el reporte autorizado. En `PENDING` o `PROCESSING`, añade `Retry-After: 3`. Solo en `COMPLETED` incluye:

```text
results.entropy
results.hashes.md5
results.hashes.sha256
results.file_size
results.file_type
results.pe_headers
results.yara_matches
results.yara
```

En `FAILED` devuelve un error genérico con etapa y mensaje, no el traceback. Un reporte fallido consultado correctamente usa HTTP `200`; el fallo se expresa en `status`. No se incluye el archivo ni una URL pública al binario.

### 7.3. Errores HTTP

| HTTP | Situación |
| --- | --- |
| `400` | Archivo ausente/múltiple, nombre inválido o error de parseo. |
| `401` | Credenciales ausentes, inválidas o usuario inactivo. |
| `403` | CSRF inválido al usar autenticación por sesión en POST. |
| `404` | Muestra inexistente/ajena o reporte inexistente. |
| `405` | Método no admitido. |
| `413` | Archivo excede el límite. |
| `415` | Contenido distinto de multipart en la subida. |
| `503` | Fallo al confirmar publicación en la cola. |

Los errores propios de la vista suelen usar `{"error": "codigo"}`; los errores de DRF, como autenticación o permisos, usan normalmente `{"detail": "mensaje"}`. No hay un formato único de errores global implementado.

## 8. Análisis estático y persistencia

`mallab/services/analyzer.py` contiene funciones reutilizables y el coordinador `process_sample(sample_id)`.

| Función | Comportamiento |
| --- | --- |
| `calculate_hashes(data)` | MD5 con `usedforsecurity=False` y SHA-256 del contenido. |
| `calculate_entropy(data)` | Shannon global en bits/byte, acotada a 0–8; vacío devuelve 0. |
| `detect_file_type(data)` | Firmas para PE/DOS, ELF, PDF, ZIP, gzip y PNG; resto `application/octet-stream`. |
| `analyze_pe(data)` | pefile con `fast_load=True`, directorio de imports, timestamp, secciones e imports. |
| `scan_yara(data, directory, timeout=30)` | Compila reglas recursivamente y devuelve coincidencias serializables. |
| `_read_sample(sample, max_bytes)` | Lee por Storage hasta `max_bytes + 1` para comprobar el límite real. |
| `process_sample(sample_id)` | Reclama el reporte, ejecuta etapas y persiste éxito/fallo. |

PE incluye timestamp original y representación UTC, secciones con nombre/tamaño virtual/tamaño raw/entropía, y DLLs importadas con funciones por nombre u ordinal y dirección IAT. Los warnings de pefile se conservan. Un archivo no PE o un PE inválido produce información de formato y puede continuar con el resto del análisis.

YARA usa `.yar` y `.yara`, namespaces `rules_<índice>`, `includes=False` y `error_on_warning=True`. Verifica que los archivos resueltos estén dentro del directorio configurado. No hay un conjunto de reglas YARA de producción incluido; las pruebas generan reglas temporales.

Si `YARA_RULES_DIR` es `None`, el escaneo queda `SKIPPED` con motivo explícito. Si se proporciona un directorio inexistente/vacío/incorrecto, reglas inválidas o un timeout, la etapa falla; no se presenta como escaneo limpio. Cada match guarda `rule`, `namespace`, `tags` y `meta`, sin copiar bytes coincidentes.

### Estados y concurrencia

```text
PENDING ──reclamación condicional──► PROCESSING ──éxito──► COMPLETED
                                      │
                                      └──error──► FAILED
FAILED ──reintento explícito──► PROCESSING
```

La reclamación se hace con un `UPDATE` condicionado a `PENDING` o `FAILED`, para evitar que dos workers analicen el mismo reporte. `COMPLETED` es idempotente y se devuelve sin releer el archivo. Si otro proceso ya está en `PROCESSING`, se lanza `AnalysisInProgress`.

El pipeline lee una instantánea limitada en memoria: hashes, entropía, PE y YARA corresponden a esos mismos bytes. No hay transacción larga durante el trabajo costoso. En éxito, una transacción actualiza SHA-256/tamaño/tipo de `Sample` y el resultado `COMPLETED`.

`pe_headers` contiene un payload con `schema_version: 1`, bloques `file`, `pe`, `yara` y, si falla, `error`. Las etapas registradas son `read_file`, `file_metadata`, `entropy`, `pe` y `yara`. Un fallo conserva resultados parciales y registra el detalle en logs; la API muestra un mensaje genérico. Los errores de base de datos pueden propagarse y dejar estados que requieran recuperación.

Una entropía alta, un timestamp PE o una coincidencia YARA son evidencias técnicas, no un veredicto definitivo de malware. El código no calcula una puntuación de riesgo ni combina estas señales en una clasificación.

## 9. Celery, Redis y recuperación

`config/celery.py` fija por defecto `DJANGO_SETTINGS_MODULE=config.settings`, crea `Celery("mallab")`, carga settings con namespace `CELERY` y autodetecta tareas. `config/__init__.py` importa `app as celery_app`.

La tarea `mallab.tasks.analyze_sample_task(sample_id)` tiene `ignore_result=True`, límite suave de 110 segundos y límite duro de 120. Si la muestra ya se eliminó, devuelve estado auxiliar `DELETED`; si ya está en proceso, devuelve `PROCESSING`. `DELETED` no es un estado persistente permitido en `AnalysisReport`.

La configuración global también ignora resultados. Aunque existe `CELERY_RESULT_BACKEND` en Redis, el contrato de la API consulta `AnalysisReport`, no `AsyncResult`. Un resultado de tarea Celery no debe usarse como sustituto del estado de negocio; por ejemplo, el pipeline puede devolver un reporte `FAILED` sin lanzar una excepción a Celery.

No hay reintentos automáticos del pipeline, Celery Beat, outbox transaccional ni recuperación por antigüedad. Una caída entre commit y publicación puede dejar `PENDING`. Una terminación abrupta del worker puede dejar `PROCESSING`. Antes de restablecer a `FAILED` y reencolar, se debe comprobar que no sigue activo el análisis original.

## 10. Configuración vigente

### Django y red de desarrollo

```python
ALLOWED_HOSTS = ['*']
CSRF_TRUSTED_ORIGINS = ['http://100.65.59.31:8000', 'http://localhost:8000', 'http://127.0.0.1:8000']
AUTH_USER_MODEL = 'mallab.User'
TIME_ZONE = 'UTC'
USE_TZ = True
LANGUAGE_CODE = 'en-us'
```

El wildcard y los orígenes HTTP son ajustes pedidos para desarrollo. No habilitan CORS, no conceden acceso anónimo y no hacen que Django escuche en interfaces externas: el bind del servidor es otra configuración. No hay middleware CORS instalado. La zona horaria de la aplicación es UTC aunque la conversación del proyecto se haya realizado en America/Bogota.

### Archivos y análisis

```python
MEDIA_ROOT = BASE_DIR / 'private-media'
ANALYZER_MAX_FILE_BYTES = 64 * 1024 * 1024
SAMPLE_MAX_UPLOAD_BYTES = ANALYZER_MAX_FILE_BYTES
YARA_RULES_DIR = os.environ.get('YARA_RULES_DIR') or None
YARA_SCAN_TIMEOUT = 30
```

El límite equivale a 67.108.864 bytes (64 MiB). `SampleSizeUploadHandler` precede a los handlers nativos de memoria y archivo temporal, acumula bytes, marca `sample_upload_too_large` y detiene la recepción si se excede el mínimo de los dos límites. La vista vuelve a comprobar el tamaño declarado y el recorrido por chunks; el analizador comprueba los bytes realmente leídos.

El timeout YARA limita el matching, no la compilación de reglas ni todo el parser PE. El archivo completo acotado queda en memoria en el worker; el límite por archivo no es un límite total de memoria del proceso.

### Celery

```python
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://127.0.0.1:6379/0')
CELERY_RESULT_BACKEND = 'redis://127.0.0.1:6379/0'
CELERY_BROKER_CONNECTION_TIMEOUT = 3
CELERY_BROKER_TRANSPORT_OPTIONS = {'socket_connect_timeout': 3, 'socket_timeout': 3}
CELERY_TASK_PUBLISH_RETRY = False
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TASK_IGNORE_RESULT = True
CELERY_TASK_DEFAULT_QUEUE = 'analysis'
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_ALWAYS_EAGER = False
```

Solo la URL del broker tiene override por variable de entorno en el código actual; la del backend está escrita directamente en settings.

### Variables de entorno realmente leídas

| Variable | Efecto |
| --- | --- |
| `DJANGO_SECRET_KEY` | Secreto Django; obligatorio si se desactiva DEBUG. Hay un fallback explícitamente de desarrollo. |
| `DJANGO_DEBUG` | DEBUG está activo por defecto; solo el valor `'1'` lo activa. |
| `YARA_RULES_DIR` | Directorio de reglas; vacío/ausente omite YARA. |
| `CELERY_BROKER_URL` | Cambia el broker Redis. |
| `DJANGO_SETTINGS_MODULE` | Entry points fijan `config.settings` por defecto; pruebas usan settings aislados. |

`DJANGO_ALLOWED_HOSTS` dejó de leerse al fijar `ALLOWED_HOSTS=['*']`. Una mención antigua en `mallab/API.md` no cambia el comportamiento efectivo del código. El proyecto no configura por sí solo HTTPS, cookies seguras, proxy o una base de datos de producción.

## 11. Inicio y uso práctico

Comandos de referencia para Ubuntu, dentro del entorno Python del proyecto:

```bash
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py check
python manage.py createsuperuser
python manage.py drf_create_token <username>
```

No se incluye un endpoint público para emitir tokens. El comando anterior genera/muestra un token y su salida debe tratarse como credencial. Si `yara-python` debe compilarse en Ubuntu, la guía del repositorio menciona `build-essential`, `python3-dev` y `libssl-dev`; la necesidad concreta depende del entorno.

Procesos separados para desarrollo:

```bash
redis-cli ping
# Debe responder PONG en el servidor que tenga Redis.

python manage.py runserver 0.0.0.0:8000

# En otra terminal o servicio con el mismo entorno, BD y almacenamiento:
celery -A config worker --loglevel=INFO --queues=analysis --concurrency=2
```

La API y el worker deben compartir los archivos y la misma base de datos efectiva. Si se usa SQLite, rutas distintas o despliegues separados pueden dar lugar a bases independientes aunque el broker sea el mismo. Para desarrollo local Windows, la guía contiene un ejemplo con `--pool=solo`; no hay un servicio Windows de Celery configurado.

Ejemplos de cliente Bash para el entorno de desarrollo indicado por el usuario:

```bash
# Basic: curl solicita la contraseña del usuario indicado.
curl -i --user "$USERNAME" \
  -F "file=@./muestra.exe" \
  http://100.65.59.31:8000/api/samples/

# Token de DRF, previamente guardado en API_TOKEN.
curl -i -H "Authorization: Token $API_TOKEN" \
  -F "file=@./muestra.exe" \
  http://100.65.59.31:8000/api/samples/

# Consultar usando el ID real devuelto por la subida.
curl -H "Authorization: Token $API_TOKEN" \
  http://100.65.59.31:8000/api/samples/1/report/
```

No establecer manualmente `Content-Type` al usar `-F`: cURL construye el boundary multipart. La API usa barra final en las rutas. Los ejemplos HTTP reflejan el entorno de desarrollo; para enviar credenciales en un despliegue final debe configurarse HTTPS. `runserver` es el servidor usado en los ejemplos de desarrollo, no una configuración de producción entregada.

## 12. Administración y almacenamiento

`/admin/` registra usuarios, muestras y reportes. Los usuarios conservan los formularios de contraseña seguros de Django; muestras y reportes tienen búsquedas, filtros y relaciones autocompletadas. `api_key` no se expone en el administrador personalizado.

No hay rutas que publiquen `MEDIA_ROOT`. La privacidad del almacenamiento depende también de no servirlo accidentalmente desde infraestructura externa. El código utiliza la interfaz `FileField.open`, por lo que puede adaptarse a un Storage remoto, pero actualmente no hay uno configurado.

Hay limpieza compensatoria del archivo cuando falla el alta SQL. No hay políticas implementadas de retención, purga periódica, cuotas de disco ni descarga autorizada de muestras. El administrador permite modificar modelos, pero no incorpora un flujo específico de reencolado o protección frente a reemplazar archivos durante un análisis.

## 13. Pruebas y verificación realizada

Comando estándar:

```bash
python manage.py test mallab.tests --settings=mallab.tests.settings
```

La configuración de pruebas hereda middleware y rutas reales, utiliza SQLite en memoria, Storage temporal, clave solo para pruebas, hasher MD5 de contraseñas solo para acelerar tests y YARA deshabilitado salvo pruebas específicas.

Cobertura funcional observada:

- Hashes conocidos y casos de entropía.
- PE sintético, archivo no PE e imports por nombre/ordinal.
- Matching real YARA, ausencia de matches, reglas inválidas y timeout simulado.
- Persistencia de metadatos, resultados parciales, fallos por límite/archivo ausente.
- Idempotencia, reporte ya en proceso y muestra inexistente.
- Commit anterior al despacho, sin invocar análisis pesado desde HTTP.
- Basic Auth y Token sin CSRF; rechazo de anónimos y credenciales inválidas/inactivas.
- CSRF para POST con sesión, propiedad de reportes y errores HTTP de validación.
- Límite de subida, limpieza al fallar la BD y fallo del broker.
- Worker Celery real con transporte `memory://`, ejecutado con pool `solo` durante el test.

Resultados de la revisión del 29 de octubre de 2026:

| Comprobación | Resultado |
| --- | --- |
| `python manage.py check` | Sin incidencias. |
| Suite completa | 24 pruebas aprobadas. |
| `python manage.py makemigrations --check --dry-run` | Sin cambios pendientes de modelo. |

Se ejecutaron con las dependencias locales de `.test-deps/` mediante `PYTHONPATH`. La base de datos temporal de tests no acredita las migraciones aplicadas en Ubuntu. El test Celery en memoria no acredita la conexión Redis remota, y el test YARA no acredita la existencia de un conjunto real de reglas en producción.

## 14. Historial relevante y decisiones vigentes

Durante el desarrollo se habilitaron temporalmente subidas anónimas, primero permitiendo `uploaded_by=None` y después asignando el primer usuario para acomodar una base que aún exigía `NOT NULL`. Eso explica la migración nullable y el error histórico `IntegrityError: NOT NULL constraint failed: mallab_sample.uploaded_by_id` cuando código y esquema no coincidían.

La decisión posterior fue revertir el acceso anónimo. El código actual incorpora DRF, exige `IsAuthenticated`, admite credenciales en cada petición y asigna exclusivamente el usuario autenticado. El fallback al primer usuario ya no existe.

También se pidió habilitar conexiones de desarrollo externas: el resultado vigente es `ALLOWED_HOSTS=['*']` y los tres orígenes CSRF HTTP listados en la sección de configuración.

Hubo intentos de push bloqueados por revisión automática de permisos durante la conversación. Esta revisión documenta el contenido local y no afirma que el servidor Ubuntu o GitHub estén actualizados. No confundir un commit local, una referencia remota almacenada localmente y una versión desplegada.

## 15. Limitaciones y pendientes reales

Estos puntos describen trabajo no realizado; no deben darse por resueltos al continuar:

1. Confirmar en Ubuntu dependencias, migraciones, conectividad Redis, permisos de archivos, reglas YARA y versión de código.
2. Preparar configuración de producción: hosts concretos, secreto privado, DEBUG desactivado, HTTPS, cookies y servidor/gestor de procesos. La actual es de desarrollo.
3. Evaluar una base más adecuada para concurrencia si aumenta la carga; PostgreSQL no está configurado.
4. Implementar recuperación de `PENDING`/`PROCESSING` atascados y, si se necesita garantía de entrega, un patrón outbox o equivalente. La cola actual no ofrece atomicidad con la transacción SQL.
5. Añadir límites operativos de CPU, RAM, almacenamiento y tasa de peticiones. Las cuotas de usuarios y `daily_uploads` todavía no se usan.
6. Definir retención y limpieza de binarios, incluidos archivos huérfanos tras eliminación de modelos.
7. Definir ciclo de vida de tokens, expiración/rotación y cualquier endpoint de autenticación adicional si hace falta. No hay JWT ni expiración automática propia implementada.
8. Documentar y versionar una política de reglas YARA de confianza. Actualmente se compilan por cada análisis, sin caché propia.
9. Evitar reemplazar bytes de una muestra ya analizada: `COMPLETED` devuelve el reporte existente. Para contenido nuevo se debe crear otra muestra.
10. Decidir si el esquema debe volver a exigir `uploaded_by NOT NULL`, después de revisar registros históricos; la API ya lo garantiza, el modelo todavía no.
11. Corregir referencias documentales antiguas: `README.md` habla de ausencia de backend para la `api_key` personalizada, no de ausencia de Basic/Token; `mallab/API.md` aún menciona `DJANGO_ALLOWED_HOSTS`, que settings ya no lee.
12. No hay frontend de producto, listado/paginación de muestras, API de borrado/descarga, OpenAPI propio, pipeline CI, Docker ni despliegue reproducible completo en el código revisado.

## 16. Instrucciones de continuidad para la IA receptora

Usa este documento como contexto de la versión indicada y verifica el código si recibes una revisión posterior. Para futuras modificaciones:

- Mantén la separación entre ingestión HTTP, tarea Celery y servicio de análisis.
- Conserva autenticación obligatoria y control por propietario en subida/consulta.
- No equipares `User.api_key`, token DRF y credenciales Basic: son mecanismos distintos.
- Respeta los nombres reales: paquete Django `config`, app `mallab`, instancia Celery llamada `mallab`, comando del worker `-A config`, cola `analysis`.
- Conserva JSON, IDs en la cola, despacho tras commit y limpieza compensatoria del Storage.
- No ejecutes muestras ni publiques su almacenamiento. No interpretes indicadores estáticos como pruebas definitivas de malware.
- Distingue el estado persistente del análisis, el estado de una tarea Celery y el código HTTP de una petición.
- Si cambias modelos, entrega migraciones y considera datos/esquemas existentes; no edites solo la vista para ocultar una incoherencia de base de datos.
- Ejecuta pruebas relevantes, especialmente autenticación/CSRF, propietario, concurrencia, errores de broker y límites.
- Distingue funcionalidad existente, recomendaciones y entorno realmente comprobado. No afirmes un despliegue o push sin evidencia.

Este es un backend funcional de análisis estático asíncrono en etapa de desarrollo. Su siguiente evolución debe partir de los permisos actuales y del estado real de su base de datos, archivos y workers.
