# MAP — Entornos, configuración y despliegue

Actualizado: 29/10/2026. Código local inspeccionado `main`, `f7460b7`.
**V2 implementado y probado localmente; Ubuntu V2 sin aceptación acreditada.**
Este archivo es el índice operativo vigente. El procedimiento detallado está en
[DEPLOY_STATIC_ENGINE_V2_UBUNTU.md](../mallab/DEPLOY_STATIC_ENGINE_V2_UBUNTU.md),
que se conserva íntegro; existe localmente, todavía sin commit propio conocido.
No confundir comandos preparados con comandos ejecutados.

## Entorno local observado

Windows, Python 3.10.10, SQLite runtime 3.39.4; dependencias de validación disponibles
en `.test-deps/` (ignorado por Git). Django 5.2.12, DRF 3.18.3, Celery 5.6.3,
cliente Redis 6.4.0, pefile 2024.8.26 y yara-python 4.5.4 verificados por metadata.
Esto no fija versiones del servidor. `requirements.txt` conserva rangos; no lockfile.

Comandos ejecutados en PowerShell el 29/10/2026 para confirmar la evidencia:

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) '.test-deps'
python manage.py check
python manage.py test mallab.tests --settings=mallab.tests.settings
python manage.py makemigrations --check --dry-run
```

Resultados: sin incidencias; 64 casos, 63 aprobados y 1 omitido; sin cambios de
modelo. La suite usa SQLite en memoria y medios temporales, ClamAV desactivado
por defecto y un caso opcional real. No demuestra Redis/clamd de Ubuntu.
No se aplicaron migraciones ni se tocó la cuarentena existente en esta tarea.

Para una instalación local nueva de desarrollo se puede usar venv y requirements.
La preparación de una BD nueva es distinta de actualizar una existente: en esta
fase no se crea/reinicializa una BD para resolver problemas del servidor.

## Servidor comunicado por el usuario, aún sin verificar

| Dato comunicado | Evidencia operativa disponible en esta revisión |
| --- | --- |
| ThinkPad E14, Intel 11.ª generación, 16 GB RAM | Sin inspección de hardware/recursos. |
| Ubuntu, proyecto ~/MAP | Versión del SO y ruta efectiva sin comprobar. |
| Django, Redis y Celery funcionaban previamente; Redis respondió PONG | Informe del usuario, sin nueva sonda remota. |
| SQLite y private-media contienen datos que conservar | No se inspeccionaron ni modificaron sus registros. |
| SSH/Tailscale | Alias, identidad de servicio y acceso efectivo sin confirmar. |
| Docker instalado, sin uso actual para CAPE | No implica despliegue Docker de MAP. |

No se abrió sesión SSH ni se instaló software en Ubuntu durante la organización
documental. Unidad web/worker, venv, grupos, socket, firmas y revisión desplegada
siguen pendientes. No hay archivos systemd definitivos en el repo; los snippets
del procedimiento son propuestas que requieren adaptar rutas/servicios reales.

## Configuración efectiva del código

| Variable leída del entorno | Web | Worker | Observación |
| --- | --- | --- | --- |
| DJANGO_SETTINGS_MODULE | Sí | Sí | config.settings; nunca settings de tests en servicios. |
| DJANGO_SECRET_KEY | Sí | Sí | Privada; exigida con DEBUG desactivado; conservar clave vigente. |
| DJANGO_DEBUG | Sí | Sí | Solo texto 1 activa; por defecto activo en código. |
| CELERY_BROKER_URL | Publica | Consume | Default Redis loopback 6379/0; misma instancia/DB/cola. |
| YARA_RULES_DIR | Comprobación consistente | Escaneo | Ausente: SKIPPED; directorio vacío configurado: ERROR. |
| CLAMAV_ENABLED | Comprobación consistente | Escaneo | Solo texto 1 activa, default desactivado. |
| CLAMAV_SOCKET_PATH | Comprobación consistente | Escaneo | Default socket Unix local; confirmar ruta real. |
| MAP_TEST_CLAMAV_SOCKET | Solo runner de prueba | No configura producción | Habilita test real opcional en Unix. |

No hay carga automática de `.env`. El archivo privado común propuesto en
`/etc/map/map.env` y su vinculación a ambos servicios todavía no están acreditados.
Nunca guardar su contenido real en documentación/Git. Hacer coincidir código,
venv, BD, Storage, settings y broker; reiniciar procesos para cargar cambios.

ALLOWED_HOSTS actualmente permite todos los hosts; hay tres orígenes CSRF HTTP
de desarrollo. DJANGO_ALLOWED_HOSTS no se lee. Son ajustes vigentes de desarrollo,
no endurecimiento de producción. SQLite apunta a BASE_DIR/db.sqlite3 y Storage
a BASE_DIR/private-media; exportar variables homónimas no cambia esas rutas.
TIME_ZONE=UTC; esto es independiente de America/Bogota usado al documentar.

Límites efectivos: entrada 64 MiB; YARA 30 s, 256 fuentes/4 MiB/1000 matches;
PE 96 secciones y 4096 descriptores/funciones; heurística 7.5 bits/byte y 4096 bytes;
ClamAV deadline total 30 s/respuesta 8192 bytes. Celery tarea suave/duro 110/120 s,
prefetch 1, eager False, JSON, resultados ignorados. El backend Redis de resultados
está configurado, pero el estado de negocio se consulta en SQLite.

## Orden obligatorio de validación del despliegue

| Etapa | Puede ejecutar usuario del proyecto | Administración requerida |
| --- | --- | --- |
| Inventario | Leer Git, versiones, rutas y estado | Identificar unidades/usuarios si faltan permisos. |
| Protección de datos | Backup SQLite por API y archivo privado con identidad autorizada | Mantenimiento, drenar escritores/trabajo y permisos del backup. |
| Actualización | Avance rápido revisado y dependencias del venv | Resolver divergencias o configuración de servicios. |
| Esquema | showmigrations/plan, migrate --check, makemigrations --check --dry-run | Revisar cualquier migración histórica pendiente antes de aplicarla. |
| ClamAV | Sondas locales con identidad del worker | Paquetes, FreshClam, daemon, socket/grupos y límites. |
| YARA | Compilar/validar conjunto aprobado con texto inocuo | Aprobar reglas, desplegar revisión legible y de escritura restringida. |
| Procesos | Comprobar Redis, tarea registrada, cola y entorno efectivo | Entorno común, arranque/reinicio de unidades reales. |
| Aceptación E2E | Subida HTTP, polling, propiedad y persistencia | Acceso a logs/evidencia de servicios según permisos. |

Seguir los comandos exactos, marcadores y condiciones del
[procedimiento Ubuntu](../mallab/DEPLOY_STATIC_ENGINE_V2_UBUNTU.md). No iniciar
dos stacks que consuman la misma cola con revisiones distintas. La concurrencia
inicial de un proceso prefork es propuesta de validación, no un valor desplegado.
Medir RAM/swap y tiempos antes de aumentarla en el ThinkPad.

## Criterios de aceptación real

1. Identificar revisión, procesos y rutas compartidas; descartar eager o broker memory.
2. Backup coherente e íntegro de BD/cuarentena; inventario de filas previas conservado.
3. Clamd real activo, AF_UNIX restringido, firmas actualizadas por FreshClam y
   negativas/positivas inocuas ejecutadas como el usuario efectivo del worker.
4. YARA real con manifiesto consistente, match y no-match del conjunto de validación
   o expectativas documentadas del conjunto revisado. No apuntar al padre testing/reviewed.
5. HTTP autenticado crea muestras nuevas; Celery consume desde Redis real, con logs.
6. JSON v2 incluye YARA, ClamAV y heurísticas esperados; hashes/bytes/ORM coinciden.
7. Anónimo rechazado, otro propietario devuelve 404; históricos siguen consultables.
8. BD y cuarentena siguen intactas; consultas persisten tras reinicio controlado.
9. Guardar fecha, revisión, comandos/resultados y responsables sin secretos.

El test real existente solo prueba texto sin detección y puede omitirse. La guía
añade una detección antivirus positiva inocua y tres casos HTTP. Ni mocks ni
un HTTP 202 aislado bastan para declarar aceptación. Registrar fallos sin borrarlos
o falsear resultados para completar el checklist.

## Preservación y límites de alcance

No borrar db.sqlite3/private-media, purgar Redis/Celery, resetear migraciones,
restaurar un backup encima de nuevas filas ni modificar registros históricos
para las pruebas. V2 no requiere migraciones nuevas. Si el servidor está atrasado,
revisar las previas con backup y autorización, sin fake ni reinicialización.
No instalar CAPE, ejecutar muestras, enviar muestras a servicios externos ni
migrar a PostgreSQL/Supabase. La validación de servicios y la cobertura antivirus
no son un certificado de seguridad ni de exposición pública del backend.

## Registro del despliegue

Estado actual: **pendiente de verificar**. Cuando se ejecute, registrar en
CHANGELOG_DEV/contexto: fecha, revisión desplegada, SO/paquetes, versión/fecha de
firmas, reglas/manifiesto, usuario y unidades, resultados reales, IDs de prueba
no sensibles y comprobación de conservación. Guardar logs privados fuera de Git.
No completar esos campos con los valores propuestos por esta guía.
