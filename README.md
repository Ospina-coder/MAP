# MalLab Analyzer

Proyecto Django compatible con Django 5.2 y Python 3.10+, con la app `mallab`, API JSON y procesamiento estático mediante Celery.

## Documentación vigente y transferencia de contexto

El archivo para compartir con otra IA es [docs/PROJECT_CONTEXT.md](docs/PROJECT_CONTEXT.md).
Consolida estado real, cambios recientes, evidencia local y pendientes Ubuntu
sin depender del historial del chat. Ver también:

- [Historial de desarrollo](docs/CHANGELOG_DEV.md).
- [Roadmap por estado de evidencia](docs/ROADMAP.md).
- [Arquitectura vigente](docs/ARCHITECTURE.md).
- [Entornos y despliegue](docs/DEPLOYMENT.md).
- [Instrucciones permanentes para agentes](AGENTS.md).

Se conservan las guías especializadas de [API](mallab/API.md),
[analizador](mallab/ANALYZER.md), [STATIC ENGINE V2](mallab/STATIC_ENGINE_V2.md)
y [validación Ubuntu](mallab/DEPLOY_STATIC_ENGINE_V2_UBUNTU.md).
La existencia de código o procedimientos no acredita el despliegue real.
El [contexto anterior](CONTEXTO_PROYECTO_IA.md) permanece como snapshot histórico.

## Integración y migraciones

El proyecto incluido ya configura estos ajustes. Para integrar la app en otro proyecto, agrega en `settings.py`, conservando las apps nativas:

```python
INSTALLED_APPS = [
    # ... django.contrib.admin, auth, contenttypes, sessions, messages, staticfiles
    "mallab.apps.MallabConfig",
]
AUTH_USER_MODEL = "mallab.User"
USE_TZ = True
```

Para iniciar el proyecto incluido:

```console
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py check
python manage.py createsuperuser
```

Configura `AUTH_USER_MODEL` antes de la primera migración del proyecto. El usuario personalizado debe aparecer en `mallab/0001_initial.py`. Si la base de datos ya usa otro usuario, se necesita planificar una migración de datos y relaciones; cambiar solamente el ajuste no es suficiente. Versiona las migraciones generadas y ejecuta `migrate` en Ubuntu al desplegar.

Documentación oficial: https://docs.djangoproject.com/en/5.2/topics/auth/customizing/#using-a-custom-user-model-when-starting-a-project

## Decisiones del modelo

- `User.user_id`, `Sample.id`, `AnalysisReport.id_analysis` y `AnalysisReport.sample` usan respectivamente las columnas `user_Id`, `Id`, `Id_analysis` e `Id`. La relación del reporte es `OneToOneField`: cada reporte exige una muestra y cada muestra admite como máximo un reporte. Una muestra puede estar temporalmente sin reporte.
- `AbstractUser` aporta `password`, `is_active` y `date_joined`, además de `username`, campos de nombres nativos y permisos. El acceso sigue usando `username`. `name` es el nombre visible de MalLab. `role` no concede permisos Django; los controlan grupos, permisos, `is_staff` e `is_superuser`.
- Crea usuarios con `User.objects.create_user(...)` y cambia contraseñas con `set_password()`; nunca asignes contraseñas en texto plano a `password`.
- `api_key` almacena un hash de Django, no el secreto. `user.rotate_api_key()` persiste el hash y devuelve la clave para mostrarla una sola vez. `user.check_api_key(secret)` la verifica para un usuario previamente identificado. No se incluye un backend de autenticación para este campo personalizado; Basic Auth y Token de DRF sí están configurados y son mecanismos distintos. La clave personalizada no se expone en el administrador.
- El hash de muestra admite MD5 o SHA-256 hexadecimales. No es único porque varios usuarios pueden subir la misma muestra. Usa una convención de minúsculas en la ingestión; MD5 sirve como identificador heredado, SHA-256 es preferible para muestras nuevas.
- `JSONField` usa fábricas `list` y `dict` para evitar valores mutables compartidos. La entropía es nula hasta calcularse; se asume Shannon por byte entre 0 y 8.
- La PK, el correo único, la FK y el OneToOne ya tienen índices implícitos. Se agregan índices para hash, fecha, historial por usuario y estado; no se duplican índices únicos.
- La validación de campos se ejecuta en los formularios del administrador. `save()` y `objects.create()` no llaman automáticamente a `full_clean()`: la API/capa de ingestión debe validar los datos antes de guardarlos. Las restricciones de estado, rol, tamaño no negativo y entropía también se aplican en la base de datos.
- `daily_uploads` es un contador persistente: la capa de servicio debe incrementarlo atómicamente con `F()` y reiniciarlo mediante una tarea diaria. El modelo no aplica cuotas por sí solo.
- Borrar un usuario elimina sus muestras y reportes en cascada; borrar una muestra elimina su reporte. Esto cumple las relaciones solicitadas y debe considerarse al otorgar permisos de eliminación.

El despliegue debe usar su propia configuración de secretos, `DEBUG=False`, hosts permitidos, HTTPS y base de datos. La app incluye una referencia al archivo en almacenamiento privado y análisis estático; no ejecuta muestras.

## Análisis estático

Consulta [la guía del analizador](mallab/ANALYZER.md) para configurar el almacenamiento,
las reglas YARA e invocar `process_sample(sample.id)` desde una vista o un worker.
La migración `0002_sample_file` añade la referencia al archivo para las muestras.

## API y cola de procesamiento

Consulta [la guía de API](mallab/API.md) para iniciar Redis y Celery, subir archivos
con `curl` y consultar sus reportes. Las rutas están registradas bajo `/api/`;
la subida y la consulta requieren `IsAuthenticated`, con Basic Auth, Token o
sesión Django. Cada muestra se asigna al usuario autenticado. Instala las
dependencias actualizadas y ejecuta `python manage.py migrate` para habilitar
los tokens de Django REST Framework.

El [motor estático v2](mallab/STATIC_ENGINE_V2.md) incorpora caché YARA por
contenido, integración opcional con ClamAV local e indicadores heurísticos
explicables. Conserva la consulta de reportes históricos y SQLite. Las reglas
inocuas están en `yara_rules/testing/`; no se activa ningún scanner nuevo ni
se descarga un conjunto de firmas automáticamente.
