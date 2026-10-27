# Subida y consulta de reportes

## Inicio local y worker

El repositorio incluye ahora el proyecto Django `config`, con las rutas y Celery
configurados. Instala las dependencias en un entorno virtual y prepara la base:

```console
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

En Ubuntu, instala e inicia Redis si no tienes ya un broker disponible:

```console
sudo apt-get install redis-server
sudo systemctl enable --now redis-server
celery -A config worker --loglevel=INFO --queues=analysis --concurrency=2
```

Configura `CELERY_BROKER_URL` en el entorno para usar otro Redis. Su valor local
por defecto es `redis://127.0.0.1:6379/0`. El worker y Django deben compartir base
de datos y almacenamiento privado. En Windows, para desarrollo, usa
`celery -A config worker --pool=solo --loglevel=INFO --queues=analysis` con Redis
en WSL, Docker o un servidor; Celery no ofrece soporte oficial para Windows.

`CELERY_TASK_ALWAYS_EAGER=False` conserva el análisis fuera de HTTP. El estado se
guarda en `AnalysisReport`; no hace falta un backend de resultados de Celery.
`YARA_RULES_DIR` puede configurarse mediante variable de entorno; si falta, el
reporte indica que YARA se omitió. Ver [guía del analizador](ANALYZER.md).

Para producción, establece `DJANGO_DEBUG=0`, una `DJANGO_SECRET_KEY` privada y
`DJANGO_ALLOWED_HOSTS`. La configuración incluida usa SQLite para desarrollo;
configura PostgreSQL, HTTPS y las cookies seguras en el despliegue. No publiques
`private-media` ni los archivos de cuarentena como contenido web.

## Contrato HTTP

Durante las pruebas, la subida admite peticiones anónimas y está exenta de CSRF.
Ejecuta `python manage.py migrate` para aplicar la migración que permite guardar
`uploaded_by=NULL`. Si hay una sesión activa, la muestra conserva ese propietario.
La consulta de reportes requiere sesión Django y propiedad de la muestra, incluso
para usuarios staff. Los reportes de muestras anónimas no están disponibles por
este endpoint. No se implementa autenticación mediante API key.

| Método y ruta | Resultado |
| --- | --- |
| `POST /api/samples/` | Un archivo multipart en el campo `file`; devuelve `202`, IDs, estado y `report_url`. |
| `GET /api/samples/<sample_id>/report/` | Estado y nombre del archivo; `results` solo al completar. |

Ejemplo de respuesta de subida:

```json
{
  "sample_id": 1,
  "report_id": 1,
  "status": "PENDING",
  "report_url": "/api/samples/1/report/"
}
```

La respuesta lleva `Location` con la misma URL. Una tarea rápida puede haber
pasado ya a `PROCESSING` o `COMPLETED`. Mientras esté pendiente o procesándose,
el GET incluye `Retry-After: 3`. En `COMPLETED`, `results` contiene `entropy`,
`hashes` (MD5 y SHA-256), `file_size`, `file_type`, `pe_headers` (secciones e
imports), `yara_matches` y el estado del escaneo `yara`.

Errores: `400` por archivo ausente o múltiple, `401` por sesión ausente/inactiva al consultar reportes,
`404` por muestra ajena/inexistente o reporte inexistente,
`413` por tamaño y `415` por contenido distinto de multipart. Un reporte `FAILED`
se consulta con HTTP `200`, con su estado y un error genérico.

Si el broker rechaza la publicación, el POST devuelve `503` con los IDs y la URL
de la muestra guardada; el reporte pasa a `FAILED` si seguía en `PENDING`.
No vuelvas a subir automáticamente el mismo archivo: consulta el reporte y,
cuando el broker se recupere, un operador puede reencolar el ID existente con
`analyze_sample_task.delay(sample_id)`. Una publicación ambigua puede haber llegado
al worker; no se sobrescriben estados ya reclamados por este.

## Ejemplo curl

La subida no requiere cookies ni token CSRF. En Bash:

```bash
curl -i http://127.0.0.1:8000/api/samples/ \
  -F "file=@./muestra.exe"

# Para consultar una muestra subida con sesión, usa la cookie de su propietario:
curl http://127.0.0.1:8000/api/samples/1/report/ \
  -b "sessionid=$SESSION_ID"
```

En PowerShell usa `curl.exe` y el carácter de continuación propio de PowerShell,
o ejecuta el comando en una sola línea.

## Límites, commits y recuperación

`SAMPLE_MAX_UPLOAD_BYTES` limita la suma de archivos recibidos; nunca supera
`ANALYZER_MAX_FILE_BYTES` (64 MiB por defecto). El handler se ejecuta antes de los
handlers nativos para evitar escribir archivos que exceden el límite; la vista
verifica de nuevo el tamaño declarado y el real. `FILE_UPLOAD_MAX_MEMORY_SIZE`
solo decide cuándo Django pasa de memoria a disco. Configura también un límite
de petición en el proxy, con margen para el envoltorio multipart.

La ingestión calcula SHA-256 por bloques para no guardar un identificador ficticio;
el análisis PE, entropía y YARA se realizan únicamente en Celery. Se crea el reporte
`PENDING` en la misma transacción que la muestra. `transaction.on_commit` publica
después de guardar y confirmar ambos. La vista usa `non_atomic_requests` para
controlar esa transacción incluso con `ATOMIC_REQUESTS`. Si una escritura SQL
falla, se intenta eliminar el archivo guardado para evitar archivos huérfanos.

Una caída del proceso entre commit y publicación puede dejar `PENDING`; un worker
terminado abruptamente puede dejar `PROCESSING`. Esta versión no añade un outbox
ni recuperación automática. Antes de restablecer un reporte a `FAILED` y reenviarlo,
confirma que no existe un worker activo para él. El pipeline evita reclamaciones
simultáneas y devuelve el reporte existente cuando ya está `COMPLETED`.

## Pruebas

```console
python manage.py test mallab.tests --settings=mallab.tests.settings
```

Incluyen autenticación de reportes, subida anónima sin token CSRF, permisos por propietario, tamaño, limpieza en rollback,
publicación tras commit, fallos del broker, resultados y consumo por un worker
Celery real con transporte en memoria. Redis debe comprobarse en el despliegue.

Referencias: [Celery con Django](https://docs.celeryq.dev/en/v5.5.3/django/first-steps-with-django.html)
y [recepción de archivos en Django](https://docs.djangoproject.com/en/5.2/topics/http/file-uploads/).
