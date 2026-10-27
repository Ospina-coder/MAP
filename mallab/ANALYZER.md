# Servicio de análisis estático

## Instalación y configuración

```console
python -m pip install -r requirements.txt
python manage.py migrate
```

La migración `0002_sample_file` añade `Sample.file`. Los registros anteriores
permanecen válidos, pero deben recibir su archivo antes del análisis. No se
resuelven rutas a partir de `file_name`, porque proviene del cliente.

Configuración de ejemplo en `settings.py`:

```python
MEDIA_ROOT = BASE_DIR / "private-media"
ANALYZER_MAX_FILE_BYTES = 64 * 1024 * 1024
YARA_RULES_DIR = BASE_DIR / "yara_rules"  # None para omitir YARA explícitamente
YARA_SCAN_TIMEOUT = 30  # segundos, entero positivo
```

El almacenamiento de muestras debe ser privado. No publiques `MEDIA_ROOT` con
URLs, nginx ni `static(settings.MEDIA_URL, ...)`. El servicio usa `FileField.open`,
por lo que también permite un Storage remoto. Los archivos se guardan con UUID
sin extensión bajo `quarantine/`; `file_name` conserva el nombre original.

YARA carga recursivamente archivos `.yar` y `.yara`, cada uno en su namespace,
con `includes` deshabilitados y warnings de compilación tratados como errores.
Usa reglas autocontenidas de confianza. Si se configura un directorio vacío,
inexistente o inválido, el análisis falla: no se presenta como escaneo limpio.

Si pip necesita compilar `yara-python` en Ubuntu, instala antes los requisitos
de compilación del sistema (`build-essential`, `python3-dev` y `libssl-dev`).
`math`, `hashlib` y las demás utilidades estándar no se instalan con pip.

## Invocación desde una vista (ejemplo síncrono)

```python
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_POST

from mallab.models import Sample
from mallab.services.analyzer import AnalysisInProgress, process_sample


@login_required
@require_POST
def analyze_sample(request, sample_id):
    sample = get_object_or_404(Sample, pk=sample_id, uploaded_by=request.user)
    try:
        report = process_sample(sample.id)
    except AnalysisInProgress:
        return JsonResponse({"status": "PROCESSING"}, status=409)
    return JsonResponse(
        {"report_id": report.pk, "status": report.status},
        status=422 if report.status == "FAILED" else 200,
    )
```

La carga debe asociar el `UploadedFile` al campo `file`, por ejemplo
`Sample.objects.create(file=request.FILES['file'], uploaded_by=request.user, ...)`.
Los metadatos obligatorios deben validarse o calcularse durante la ingestión.
El servicio vuelve a calcular tamaño, tipo y SHA-256 sobre los bytes analizados.

## Tarea en segundo plano (Celery)

El proyecto incluye `mallab/tasks.py`, la configuración Celery y una API de subida
que despacha después del commit. Consulta [la guía de API](API.md) para iniciar el
broker y el worker. Desde otro punto de integración, después de comprobar la
propiedad de la muestra:

```python
from django.db import transaction
from mallab.tasks import analyze_sample_task

transaction.on_commit(lambda: analyze_sample_task.delay(sample.id))
```

Usa `on_commit` para que el worker encuentre la muestra ya persistida. No llames
al análisis síncrono dentro de una transacción larga ni de `ATOMIC_REQUESTS`;
si esa opción está habilitada, despacha la tarea después del commit.

## Resultado y errores

`process_sample(sample.id)` devuelve el `AnalysisReport`, también si termina
en `FAILED`. Lanza `Sample.DoesNotExist` para un ID inexistente y
`AnalysisInProgress` si otro worker ya reclamó el análisis. Errores de base de
datos se propagan. `COMPLETED` es idempotente y `FAILED` permite reintentos.
La reclamación usa una actualización condicional en la base de datos.

Se mantienen los campos del reporte existentes:

- `pe_headers.file`: `hashes.md5`, `hashes.sha256`, `size` y `mime_type`.
- `pe_headers.pe`: indicador `is_pe`, timestamp declarado, secciones e imports
  (nombre u ordinal y dirección de la IAT), o explicación de formato no PE.
- `pe_headers.yara`: `COMPLETED` o `SKIPPED` con motivo.
- `pe_headers.error`: etapa, tipo y mensaje genérico cuando falla el pipeline.
- `entropy`: Shannon global, entre 0 y 8 bits por byte.
- `yara_matches`: reglas, namespaces, tags y metadatos, sin los bytes coincidentes.

Un archivo no PE o un PE inválido produce un JSON descriptivo sin impedir los
demás análisis. Los warnings de pefile se conservan para identificar resultados
parciales. La detección de tipo usa firmas y devuelve `application/octet-stream`
para formatos desconocidos. Una entropía alta puede acompañar compresión o
cifrado: no prueba por sí sola que una muestra sea malware o esté empaquetada.
El timestamp puede estar manipulado. Una lista YARA vacía no certifica inocuidad.

El pipeline lee una instantánea acotada del archivo para que hashes, entropía,
PE y YARA correspondan al mismo contenido. No reemplaces el archivo de una
muestra durante un análisis. Para analizar otros bytes, crea una nueva muestra.
Los resultados parciales se conservan si falla una etapa posterior.

Ejecuta el worker con permisos mínimos y límites de memoria/CPU, sin servir ni
ejecutar las muestras. El timeout YARA limita el escaneo; no limita su compilación
ni el parser PE. Un cierre abrupto del worker o una caída de la base puede dejar
`PROCESSING`: confirma que el worker terminó antes de restablecer ese reporte a
`FAILED` y reintentarlo. No se implementa recuperación automática por antigüedad.

## Pruebas

```console
python -m django test mallab.tests --settings=mallab.tests.settings
```

Se usan archivos inocuos, un PE sintético, reglas YARA locales y una base SQLite
temporal. La extracción PE y los matches YARA se prueban con sus librerías reales;
los imports por ordinal y el timeout también tienen pruebas controladas.

Referencias: [pefile](https://pefile.readthedocs.io/en/latest/usage/UsageExamples.html)
y [yara-python](https://yara.readthedocs.io/en/stable/yarapython.html).
