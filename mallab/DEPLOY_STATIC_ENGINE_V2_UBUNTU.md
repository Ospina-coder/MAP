# MAP — Procedimiento de despliegue y validación real de STATIC ENGINE V2

Preparado el 29 de octubre de 2026, revisando el código del commit local
`f7460b7e66edd3a76e2a845095d4c909fc8ad5d2` y `STATIC_ENGINE_V2.md`.

**Estado de este documento: procedimiento preparado; servidor aún no validado.**
No se ha abierto una sesión SSH ni instalado/configurado nada en Ubuntu durante
esta revisión. No se han proporcionado el alias SSH, usuario de servicio, nombres
de unidades ni ruta real del entorno Python. Esos datos se obtienen en el paso 1.
Los comandos siguientes están destinados a Bash en Ubuntu, no a PowerShell.

Objetivo: validar la versión actual en el ThinkPad E14 con 16 GB de RAM,
conservando `~/MAP/db.sqlite3`, `~/MAP/private-media` y todos los registros.
No se instala CAPE, no se usa Docker para este procedimiento y no se cambia de BD.
No se ejecuta ningún archivo de prueba ni se envían muestras fuera del servidor.

## Estado confirmado antes del despliegue

| Funcionalidad | Implementada en el código revisado | Requiere Ubuntu/servicio real |
| --- | --- | --- |
| Hashes, entropía, formato y PE | Sí; extracción y límites probados localmente. | Dependencias Python y recursos del worker. |
| YARA | Sí; caché por contenido, límites y marcador inocuo probado con yara-python real. | Directorio confiable legible, revisión de reglas y entorno del worker. |
| ClamAV | Cliente AF_UNIX/INSTREAM implementado; protocolo y detecciones simuladas en tests. | Instalar/configurar daemon, firmas, socket, grupos y validar resultados reales. |
| Heurísticas | Sí; evidencia, justificación y limitaciones sin puntuaciones. | No necesita otro daemon; sí código/configuración correctos en Celery. |
| Persistencia/API v2 | Sí; compatibilidad y permisos probados con SQLite temporal. | Confirmar BD/cuarentena existentes y versión compartida en web/worker. |
| Celery/Redis | Integración implementada; test con broker en memoria. | Confirmar Redis real, consumidores, revisión y entorno de procesos vivos. |

Verificación local repetida durante esta preparación: `manage.py check` sin
incidencias; 64 casos de test, 63 aprobados y 1 omitido (ClamAV real); sin cambios
de modelo pendientes. Se comprobó además la fixture de entropía/YARA con las
librerías reales en local. Ninguno de estos resultados acredita Ubuntu.

## 0. Responsables, orden y criterios

**A — Automatizable por el usuario de aplicación**, una vez resueltos nombres,
rutas y entorno: inventario, verificaciones de código, backup autorizado,
pruebas locales, sondas de herramientas y test HTTP. Automatizable no significa
que ya se haya ejecutado ni que sea de solo lectura: se señala cada escritura.

**B — Intervención administrativa en Ubuntu:** ventana de mantenimiento,
instalación de paquetes, permisos/grupos, configuraciones de clamd/systemd,
gestión del entorno privado y reinicio de servicios. No copiar estos pasos a
una automatización desatendida sin revisar el sistema real.

| Orden | Acción | Tipo | Condición para continuar |
| --- | --- | --- | --- |
| 1 | Inventariar rutas, unidades y versión | A, lectura | Identidades y procesos identificados. |
| 2 | Detener entradas, drenar trabajo y respaldar | B + A, escrituras privadas | Backup íntegro de SQLite y cuarentena. |
| 3 | Actualizar código/dependencias y comprobar esquema | A, modifica checkout/venv | Revisión aprobada; esquema existente compatible. |
| 4 | Configurar clamd y firmas oficiales | B | Servicio local operativo, firmas vigentes y socket restringido. |
| 5 | Preparar reglas revisadas y entorno común | B | Rutas legibles por worker; misma configuración en ambos procesos. |
| 6 | Probar herramientas reales como usuario del worker | A | YARA match/no-match y ClamAV OK/FOUND reales. |
| 7 | Arrancar y comprobar Django, Redis y worker | B + A | Sin procesos viejos ni consumidores inesperados. |
| 8 | Test HTTP integral y persistencia | A, crea muestras de prueba | Resultados reales, propietario y registros previos conservados. |
| 9 | Guardar evidencia y emitir aceptación | A + revisión | Todas las comprobaciones relevantes aprobadas. |

No usar `git reset --hard`, `git clean`, `flush`, eliminación de migraciones,
`migrate ... zero`, borrado de SQLite/cuarentena, `celery purge`, `FLUSHDB` ni
`FLUSHALL`. No borrar/reencolar registros históricos para hacer pasar pruebas.
No enviar señales de terminación forzada a un worker que esté analizando.

## 1. Inventario y parámetros reales — A, solo lectura

Conectar con el alias SSH/Tailscale existente del operador. No se adivinan
credenciales ni se abren nuevos puertos. Ya dentro de Ubuntu:

```bash
cd "$HOME/MAP"
pwd -P
cat /etc/os-release
uname -a
free -h
df -h .
git status --short
git log -1 --oneline
git remote -v
test -f db.sqlite3
test -d private-media
ls -ld db.sqlite3 private-media
systemctl list-units --type=service --all
ps -eo user,pid,ppid,args | grep -E '[c]elery|[g]unicorn|[u]vicorn|[m]anage.py'
```

Revisar las salidas localmente; no publicar listas de procesos si contienen
credenciales introducidas anteriormente en argumentos. Confirmar si se usa
systemd, Supervisor o terminales. No arrancar un segundo stack encima del actual.
El resto de los pasos systemd solo aplica si se identificaron unidades reales.

Completar los valores siguientes **antes** de ejecutar comandos que los usen:

```bash
export MAP_ROOT="$(pwd -P)"
export MAP_USER='USUARIO_UNIX_REAL_DEL_WORKER'
export MAP_WEB_UNIT='UNIDAD_WEB_REAL.service'
export MAP_WORKER_UNIT='UNIDAD_CELERY_REAL.service'
export MAP_PY='/RUTA/ABSOLUTA/DEL/VENV/bin/python'
export MAP_CELERY='/RUTA/ABSOLUTA/DEL/VENV/bin/celery'
```

`MAP_USER` es una identidad Unix, no el usuario de la API. Confirmar los valores:

```bash
id "$MAP_USER"
systemctl show "$MAP_WEB_UNIT" "$MAP_WORKER_UNIT" \
  -p User -p Group -p WorkingDirectory -p ExecStart -p MainPID
test -x "$MAP_PY"
test -x "$MAP_CELERY"
"$MAP_PY" --version
```

El proyecto, intérprete y dependencias deben ser los mismos para Django y Celery.
No crear otro venv ni otra copia de SQLite para resolver un error de ruta.
Identificar también dos usuarios Django activos con credenciales autorizadas para
probar propiedad. Si el administrador debe crear una cuenta de validación,
hacerlo antes del manifiesto de registros del paso 2 y registrar esa intervención.
Si web y worker tienen usuarios distintos, el administrador debe definir un
grupo compartido de aplicación para entorno, BD y almacenamiento; no aplicar
`chmod 777` ni un `chown -R` indiscriminado sobre el proyecto.

Preparar una carpeta nueva para evidencia, fuera del repo, con permisos privados:

```bash
umask 077
export MAP_EVIDENCE="$(mktemp -d "$HOME/map-v2-evidence-XXXXXXXX")"
git rev-parse HEAD > "$MAP_EVIDENCE/revision-before.txt"
```

## 2. Protección de los registros — B y A, mantenimiento controlado

El administrador bloquea temporalmente nuevas subidas/paradas del servicio web
con su mecanismo habitual. Antes de parar Celery, con su entorno actual cargado:

```bash
cd "$MAP_ROOT"
"$MAP_CELERY" -A config inspect active --timeout=10
"$MAP_CELERY" -A config inspect reserved --timeout=10
"$MAP_CELERY" -A config inspect scheduled --timeout=10
```

**No continuar con una copia supuestamente estable mientras haya escritores o
trabajo que vaya a cambiar registros durante ella.** Esperar la finalización de
las tareas activas y acordar cómo preservar cualquier trabajo pendiente. No
purgarlo. Parar Celery mediante cierre normal; revisar primero que su unidad
no mate hijos activos prematuramente por `KillMode`/`TimeoutStopSec`.

```bash
# B: solo con las unidades reales identificadas y el trabajo drenado.
sudo systemctl stop "$MAP_WEB_UNIT"
sudo systemctl stop "$MAP_WORKER_UNIT"
systemctl is-active "$MAP_WEB_UNIT" "$MAP_WORKER_UNIT"
```

Es normal que `is-active` devuelva código distinto de cero al estar detenidos.
Si los procesos se manejan en terminal, el operador cierra Django y hace cierre
normal de Celery; no usar patrones de `pkill` que puedan afectar otros proyectos.
Evitar escrituras administrativas concurrentes durante la copia.

### Copia coherente — A como dueño de los datos, con permiso administrativo

No copiar únicamente `db.sqlite3` mientras está activo: puede haber WAL/journal.
Usar la API de backup SQLite, sin abrir una base nueva accidentalmente:

```bash
cd "$MAP_ROOT"
export MAP_BACKUP="$(mktemp -d "$HOME/map-v2-backup-XXXXXXXX")"
"$MAP_PY" - <<'PY'
import os, sqlite3
from pathlib import Path
root = Path(os.environ['MAP_ROOT']).resolve()
database = root / 'db.sqlite3'
target = Path(os.environ['MAP_BACKUP']) / 'db.sqlite3'
assert database.is_file(), 'Falta la BD existente: detener, no crear una nueva'
assert (root / 'private-media').is_dir(), 'Falta cuarentena: revisar ruta'
assert not target.exists()
with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as source:
    assert source.execute('PRAGMA quick_check').fetchall() == [('ok',)]
    with sqlite3.connect(target) as destination:
        source.backup(destination)
        assert destination.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
print('Backup SQLite íntegro:', target)
PY
tar --acls --xattrs -cpf "$MAP_BACKUP/private-media.tar" -C "$MAP_ROOT" private-media
tar -tf "$MAP_BACKUP/private-media.tar" > "$MAP_BACKUP/private-media-inventory.txt"
sha256sum "$MAP_BACKUP/db.sqlite3" "$MAP_BACKUP/private-media.tar" \
  > "$MAP_BACKUP/SHA256SUMS"
sha256sum -c "$MAP_BACKUP/SHA256SUMS"
```

Si tar no tiene permisos o no hay espacio, resolverlo antes de continuar. El
archivo de backup contiene material de cuarentena y la BD contiene credenciales
almacenadas: mantener permisos privados y no adjuntarlos a incidencias públicas.
Registrar también revisión de código, versiones y configuración privada por el
procedimiento de backup del administrador, fuera de Git.

### Referencia de registros previos — A, lectura de la BD

Con el entorno Django anterior válido, guardar un manifiesto de filas. Solo
guarda IDs y hashes; no publica contraseñas ni contenidos de muestras:

```bash
"$MAP_PY" - <<'PY'
import os, json, hashlib
from pathlib import Path
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()
from django.conf import settings
from mallab.models import User, Sample, AnalysisReport
assert Path(settings.DATABASES['default']['NAME']).resolve() == Path(os.environ['MAP_ROOT']) / 'db.sqlite3'
assert Path(settings.MEDIA_ROOT).resolve() == Path(os.environ['MAP_ROOT']) / 'private-media'
models = [(User, ['pk','username','email','role','is_active','is_staff','is_superuser']),
          (Sample, None), (AnalysisReport, None)]
baseline = {}
for model, fields in models:
    rows = model.objects.order_by('pk').values(*fields) if fields else model.objects.order_by('pk').values()
    pk_name = 'pk' if fields else model._meta.pk.name
    baseline[model.__name__] = {
        str(row[pk_name]): hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()
        for row in rows
    }
path = Path(os.environ['MAP_EVIDENCE']) / 'records-before.json'
path.write_text(json.dumps(baseline, indent=2), encoding='utf-8')
print({name: len(rows) for name, rows in baseline.items()})
PY
```

Si esta importación falla por dependencias anteriores, conservar el backup y
resolver el entorno; no cambiar modelos o borrar tablas para sortearlo.

## 3. Código, dependencias y esquema — A, checkout/venv

```bash
cd "$MAP_ROOT"
git status --short
git fetch origin
git log -5 --oneline origin/main
git diff --stat HEAD..origin/main
```

El operador revisa la revisión que va a desplegar. Si hay cambios locales o la
rama diverge, detener la actualización: no sobrescribirlos. Con `main` limpio y
la revisión remota aprobada, usar únicamente avance rápido:

```bash
test "$(git branch --show-current)" = main
test -z "$(git status --porcelain)"
git merge --ff-only origin/main
git rev-parse HEAD | tee "$MAP_EVIDENCE/revision-deployed.txt"
test -f mallab/services/clamav.py
test -f mallab/services/yara_scanner.py
test -f mallab/services/heuristics.py
"$MAP_PY" -m pip freeze > "$MAP_EVIDENCE/python-packages-before.txt"
"$MAP_PY" -m pip install -r requirements.txt
"$MAP_PY" -m pip check
"$MAP_PY" -m pip freeze > "$MAP_EVIDENCE/python-packages-after.txt"
"$MAP_PY" manage.py check
"$MAP_PY" manage.py showmigrations --plan
"$MAP_PY" manage.py migrate --check
"$MAP_PY" manage.py makemigrations --check --dry-run
```

V2 no necesita migraciones propias. `migrate --check` no aplica cambios. Si
existen migraciones previas sin aplicar, detener este procedimiento y revisar
el plan y backup con el administrador; no ejecutar migraciones a ciegas,
`--fake` ni un nuevo `startproject`. Los registros existentes se conservan.

Ejecutar la suite aislada, nunca `flush` sobre la BD real:

```bash
"$MAP_PY" manage.py test mallab.tests --settings=mallab.tests.settings
```

La suite usa SQLite en memoria y medios temporales. `tests/settings.py` desactiva
ClamAV salvo tests explícitos. Hasta esta revisión hay 64 casos, con uno omitido
si no se habilita el socket real; confirmar la cifra de la revisión desplegada.

## 4. ClamAV real — B, administración Ubuntu

### 4.1. Paquetes y servicio de firmas

Verificar versión Ubuntu/paquetes disponibles; no mezclar paquetes de varias
distribuciones o una instalación compilada en `/usr/local` con apt:

```bash
apt-cache policy clamav clamav-daemon clamav-freshclam
command -v clamd || true
command -v freshclam || true
sudo apt-get update
sudo apt-get install clamav clamav-daemon clamav-freshclam
clamscan --version
freshclam --version
systemctl cat clamav-daemon.service
systemctl cat clamav-daemon.socket
systemctl cat clamav-freshclam.service
```

La unidad `.socket` puede no existir en alguna versión; documentar ese caso y
omitir únicamente sus pasos específicos. Los paquetes pueden intentar arrancar
automáticamente: comprobar su estado, sin asumir que un arranque fallido previo
a cargar firmas significa un error del cliente Django.

Hacer backup de `/etc/clamav/clamd.conf` y `/etc/clamav/freshclam.conf` con el
mecanismo privado del administrador antes de editarlos. Ambos deben usar la
misma `DatabaseDirectory`, normalmente `/var/lib/clamav` en paquetes Ubuntu.
No instalar firmas de terceros ni reglas no revisadas.

Si hace falta una actualización manual inicial, detener primero el actualizador
automático para no competir por su lock:

```bash
sudo systemctl stop clamav-freshclam.service
if sudo freshclam --verbose; then
  sudo systemctl enable --now clamav-freshclam.service
else
  sudo systemctl start clamav-freshclam.service
  printf '%s\n' 'Actualización fallida: detener validación y revisar el log.'
  # No seguir al paso siguiente si entró en esta rama.
fi
sudo journalctl -u clamav-freshclam.service -n 80 --no-pager
```

Guardar evidencia de la actualización y edad de firmas; respetar cualquier
cooldown del proveedor, sin bucles de reintento agresivos. FreshClam descarga
firmas oficiales; no sube muestras. Un fallo DNS, proxy, reloj/TLS o disco debe
resolverse antes de afirmar cobertura actualizada. No ejecutar dos freshclam.

### 4.2. clamd.conf, límites y socket

Editar mediante `sudoedit /etc/clamav/clamd.conf`, conservando el resto de la
configuración del paquete. No añadir directivas duplicadas. Valores iniciales
para validar este laboratorio, sujetos a medir consumo y tiempos:

```text
LocalSocket /run/clamav/clamd.ctl
LocalSocketGroup clamav
LocalSocketMode 660
User clamav
StreamMaxLength 64M
MaxFileSize 64M
MaxScanSize 128M
MaxScanTime 20000
MaxRecursion 16
MaxFiles 1000
MaxThreads 2
MaxQueue 4
```

`MaxScanTime` está en milisegundos; es menor que el plazo cliente de 30 s para
dejar margen de comunicación. No es una garantía ante carga elevada.
`MaxScanSize` limita también expansión de contenedores; no significa cobertura
ilimitada de archivos comprimidos. Revisar `AlertExceedsMax yes` para hacer
visibles límites como identificaciones heurísticas, sin tratarlas como malware
confirmado. Confirmar las opciones en `man clamd.conf` de la versión instalada.

No debe haber `TCPSocket`/`TCPAddr` activos ni acciones `VirusEvent` personalizadas.
No habilitar monitorización on-access ni borrado/movimiento de muestras.
No habilitar firmas bytecode sin confianza. Mantener la gestión temporal normal
del daemon; el cliente MAP no crea archivos temporales para INSTREAM.

Si existe socket activation systemd, sus permisos pueden prevalecer. Revisar
la unidad y, si es necesario, ejecutar `sudo systemctl edit clamav-daemon.socket`
con este override (ruta consistente con `LocalSocket`):

```ini
[Socket]
ListenStream=
ListenStream=/run/clamav/clamd.ctl
SocketUser=clamav
SocketGroup=clamav
SocketMode=0660
```

Añadir solo al usuario real del worker el acceso al socket:

```bash
sudo usermod -aG clamav "$MAP_USER"
sudo systemctl daemon-reload
# Si existe clamav-daemon.socket, durante mantenimiento:
sudo systemctl stop clamav-daemon.service
sudo systemctl restart clamav-daemon.socket
sudo systemctl start clamav-daemon.service
# Si NO existe .socket, usar en su lugar: sudo systemctl restart clamav-daemon.service
sudo systemctl enable clamav-daemon.service
sudo systemctl enable clamav-freshclam.service
```

Si hay una unidad `.socket`, revisar también su habilitación para el arranque
según el paquete. No ejecutar simultáneamente un `clamd` manual.
No conceder a clamav acceso completo a `private-media`: MAP envía bytes por
INSTREAM. La nueva pertenencia a grupo necesita procesos nuevos: reiniciar el
worker y abrir nueva sesión del usuario para las sondas de consola.

```bash
systemctl is-active clamav-daemon.service clamav-freshclam.service
sudo journalctl -u clamav-daemon.service -n 100 --no-pager
stat -c '%U %G %a %n' /run/clamav/clamd.ctl
namei -l /run/clamav/clamd.ctl
sudo ss -lxnp
sudo ss -ltnp
free -h
```

Esperado: socket Unix con grupo `clamav`, modo `660`, directorios transitables,
servicio activo tras cargar firmas y ningún listener TCP clamd. Revisar AppArmor
y sandbox systemd si el usuario pertenece al grupo pero sigue sin acceder; no
desactivar todas las protecciones como solución genérica. Un test como root no
prueba que el worker pueda conectarse.

Con 16 GB, empezar con un proceso Celery de análisis y medir RAM, swap y duración.
La recarga de firmas puede aumentar temporalmente memoria de clamd. No hay un
benchmark de este equipo: no dar por seguros límites de RAM o concurrencia altos.

## 5. Reglas YARA y entorno compartido — B

### Reglas confiables

La carpeta `yara_rules/reviewed/` del repo está vacía. Apuntarla sin poblarla
produce ERROR. Para validación se puede aprobar expresamente la regla inocua
MAP existente, tras leer su código, y desplegarla como conjunto **de validación**:

```bash
cat "$MAP_ROOT/yara_rules/testing/map_smoke_test.yar"
export MAP_GROUP="$(id -gn "$MAP_USER")"
sudo install -d -o root -g "$MAP_GROUP" -m 0750 /etc/map /etc/map/yara
sudo install -d -o root -g "$MAP_GROUP" -m 0750 /etc/map/yara/validation-v1
sudo install -o root -g "$MAP_GROUP" -m 0640 \
  "$MAP_ROOT/yara_rules/testing/map_smoke_test.yar" \
  /etc/map/yara/validation-v1/map_smoke_test.yar
sha256sum "$MAP_ROOT/yara_rules/testing/map_smoke_test.yar"
sudo sha256sum /etc/map/yara/validation-v1/map_smoke_test.yar
```

Si `validation-v1` ya existe con contenido distinto, no reemplazarlo silenciosamente:
crear otra revisión y documentarla. Root administra estas carpetas; el worker
solo lee. Esta regla tiene `purpose=testing_only` y no detecta familias reales.
No apuntar a todo `yara_rules/` ni mezclar testing con conjuntos de cobertura.

Para reglas de detección reales: revisar procedencia/licencia, metadata, patrones,
includes (prohibidos), coste, falsos positivos y pruebas; aprobarlas en Git y
desplegar un directorio versionado separado, por ejemplo `reviewed-<revision>`.
No descargar un repositorio externo de reglas automáticamente. Para pasar del
conjunto de validación al revisado, cambiar ambos entornos, reiniciar worker y
repetir las pruebas con expectativas explícitas para ese conjunto.

### Archivo común de entorno

Crear/editar **fuera de Git** `/etc/map/map.env` con `sudoedit`. Preservar la
clave Django vigente y cualquier configuración privada existente; no generar
otra clave silenciosamente. Si ya existe, hacer backup privado antes de editar.

```text
DJANGO_SETTINGS_MODULE=config.settings
DJANGO_DEBUG=0
DJANGO_SECRET_KEY='<CONSERVAR_CLAVE_PRIVADA_VIGENTE>'
CELERY_BROKER_URL=redis://127.0.0.1:6379/0
YARA_RULES_DIR=/etc/map/yara/validation-v1
CLAMAV_ENABLED=1
CLAMAV_SOCKET_PATH=/run/clamav/clamd.ctl
```

Reemplazar el marcador de clave antes de cargarlo. Usar asignaciones simples con
comillas literales correctas, sin `export`, comandos, sustituciones o expansiones
de shell. systemd no expande `$HOME` en EnvironmentFile. Si un secreto necesita
escapes especiales, el administrador debe verificar la sintaxis compatible con
ambos consumidores; no imprimirlo en terminal/log ni copiarlo al repositorio.

```bash
sudo chown root:"$MAP_GROUP" /etc/map/map.env
sudo chmod 0640 /etc/map/map.env
```

| Variable | Web Django | Worker Celery | Observación del código real |
| --- | --- | --- | --- |
| `DJANGO_SETTINGS_MODULE` | Sí | Sí | `config.settings`, nunca settings de tests. |
| `DJANGO_SECRET_KEY` | Sí | Sí | Privada; mantener consistente. |
| `DJANGO_DEBUG` | Sí | Sí | Producción usa `0`; el código exige clave. |
| `CELERY_BROKER_URL` | Sí, publica | Sí, consume | Misma instancia, DB Redis y cola. |
| `YARA_RULES_DIR` | Para comprobaciones | Sí, analiza | Misma revisión de reglas en ambos. |
| `CLAMAV_ENABLED` | Para comprobaciones | Sí, analiza | Solo texto `1` activa. |
| `CLAMAV_SOCKET_PATH` | Para comprobaciones | Sí, analiza | Ruta local absoluta. |
| `MAP_TEST_CLAMAV_SOCKET` | No | No | Solo test real; no controla el scanner en producción. |

`BASE_DIR`, ruta SQLite, `MEDIA_ROOT`, límites de análisis, umbrales y
`CELERY_RESULT_BACKEND` están fijados en settings; exportar variables de esos
nombres no los modifica automáticamente. `.env` tampoco se carga por sí solo.
`DJANGO_ALLOWED_HOSTS` no se lee. Los hosts wildcard/orígenes HTTP de desarrollo
siguen en el código; esta guía no implica que la exposición pública sea segura.
La validación HTTP se realizará en loopback dentro de la sesión SSH.

### Vinculación con servicios reales

Administrativamente, añadir a **ambas** unidades existentes, con
`sudo systemctl edit "$MAP_WEB_UNIT"` y `sudo systemctl edit "$MAP_WORKER_UNIT"`:

```ini
[Service]
WorkingDirectory=/home/USUARIO_REAL/MAP
EnvironmentFile=/etc/map/map.env
```

Sustituir la ruta por `MAP_ROOT` real, no copiar el marcador. En el worker:

```ini
[Service]
SupplementaryGroups=clamav
```

Revisar que otros `EnvironmentFile`, opciones `Environment=` o scripts de arranque
no sobreescriban valores. Conservar el servidor web actual y su venv. Para el
worker, si se necesita sustituir `ExecStart`, hacerlo tras revisar la unidad:

```ini
[Service]
ExecStart=
ExecStart=/RUTA/REAL/VENV/bin/celery -A config worker --loglevel=INFO --pool=prefork --concurrency=1 --queues=analysis
```

No usar `solo` en esta validación Ubuntu: se necesitan procesos separados y los
límites de tiempo de la tarea. No crear una segunda unidad para competir con
consumidores antiguos. Revisar `ProtectHome`, rutas permitidas de escritura y
`RestrictAddressFamilies` para que puedan usar proyecto, SQLite, cuarentena,
Redis y AF_UNIX sin desactivar indiscriminadamente el sandbox.

Si el stack es manual, el operador usa el mismo archivo en ambas terminales:

```bash
set -a
. /etc/map/map.env
set +a
cd "$MAP_ROOT"
```

Hacerlo solo con un archivo administrado y legible; no `source` de archivos que
pueda escribir un cliente. Si el stack es Supervisor, usar su mecanismo de entorno
con los mismos valores y no ejecutar además los pasos de arranque systemd.

## 6. Sondas reales como usuario del worker — A

Abrir sesión nueva como `MAP_USER` o pedir al administrador que ejecute con esa
identidad y sus grupos actualizados. Cargar el archivo común, venv/rutas reales
y mantener `MAP_EVIDENCE`. Confirmar identidad antes de las pruebas:

```bash
test "$(id -un)" = "$MAP_USER"
id
test -r /etc/map/map.env
test -S /run/clamav/clamd.ctl
```

### Configuración efectiva sin divulgar secretos

```bash
cd "$MAP_ROOT"
"$MAP_PY" - <<'PY'
import os, json
from pathlib import Path
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()
from django.conf import settings as s
assert Path(s.DATABASES['default']['NAME']).resolve() == Path(os.environ['MAP_ROOT']) / 'db.sqlite3'
assert Path(s.MEDIA_ROOT).resolve() == Path(os.environ['MAP_ROOT']) / 'private-media'
assert Path(s.DATABASES['default']['NAME']).is_file()
assert s.CLAMAV_ENABLED is True
assert s.YARA_RULES_DIR
assert s.CELERY_TASK_ALWAYS_EAGER is False
assert s.SECRET_KEY and not s.SECRET_KEY.startswith('<')
print(json.dumps({
    'settings': os.environ['DJANGO_SETTINGS_MODULE'], 'debug': s.DEBUG,
    'database': str(s.DATABASES['default']['NAME']), 'media': str(s.MEDIA_ROOT),
    'yara_directory': str(s.YARA_RULES_DIR), 'clamav_enabled': s.CLAMAV_ENABLED,
    'clamav_socket': s.CLAMAV_SOCKET_PATH, 'queue': s.CELERY_TASK_DEFAULT_QUEUE,
    'eager': s.CELERY_TASK_ALWAYS_EAGER,
}, indent=2))
PY
```

Esta sonda prueba la consola configurada, no por sí sola el entorno de procesos
que ya estaban arrancados. En el paso 7 se revisan las unidades/PIDs y se reinician.

### YARA real: coincidencia y ausencia de coincidencia

```bash
"$MAP_PY" - <<'PY'
import os, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()
from django.conf import settings as s
from mallab.services.yara_scanner import scan_yara_result
options = dict(timeout=s.YARA_SCAN_TIMEOUT, max_files=s.YARA_MAX_RULE_FILES,
               max_bytes=s.YARA_MAX_RULE_BYTES, max_matches=s.YARA_MAX_MATCHES)
match = scan_yara_result(b'MAP_STATIC_ANALYSIS_INNOCUOUS_TEST_v1', s.YARA_RULES_DIR, **options)
empty = scan_yara_result(b'MAP plain text without marker', s.YARA_RULES_DIR, **options)
assert match['status'] == empty['status'] == 'COMPLETED'
assert any(x['rule'] == 'MAP_Innocuous_Smoke_Test' for x in match['matches'])
assert empty['matches'] == []
assert match['ruleset_sha256'] == empty['ruleset_sha256']
print(json.dumps({'marker': match, 'without_marker': empty}, indent=2))
PY
```

Las aserciones anteriores corresponden al conjunto `validation-v1`. Guardar el
hash del manifiesto para compararlo con el reporte generado por Celery.

### ClamAV real: PING, VERSION y detección positiva inocua

El EICAR es un patrón estandarizado de prueba antivirus, no una muestra de malware.
Se construye en memoria, no se ejecuta ni se descarga. Puede generar alertas
esperadas en las herramientas de seguridad del equipo. El operador debe conocer
la prueba; no desactivar el antivirus para hacerla pasar.

```bash
"$MAP_PY" - <<'PY'
import os, json, socket, base64
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()
from django.conf import settings as s
from mallab.services.clamav import scan_clamav
assert s.CLAMAV_ENABLED is True
def command(name):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
        c.settimeout(10)
        c.connect(s.CLAMAV_SOCKET_PATH)
        c.sendall(b'z' + name + b'\0')
        data = bytearray()
        while b'\0' not in data:
            block = c.recv(1024)
            assert block, 'Respuesta incompleta'
            data.extend(block)
            assert len(data) <= 8192
        return bytes(data).rstrip(b'\0').decode()
ping, version = command(b'PING'), command(b'VERSION')
assert ping == 'PONG'
options = dict(enabled=s.CLAMAV_ENABLED, socket_path=s.CLAMAV_SOCKET_PATH,
               timeout=s.CLAMAV_TIMEOUT, max_bytes=s.ANALYZER_MAX_FILE_BYTES,
               max_response_bytes=s.CLAMAV_MAX_RESPONSE_BYTES)
eicar = base64.b64decode('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')
assert len(eicar) == 68
negative = scan_clamav(b'MAP innocuous local check', **options)
positive = scan_clamav(eicar, **options)
assert negative['status'] == 'NO_DETECTION', negative
assert positive['status'] == 'DETECTED' and positive['signatures'], positive
print(json.dumps({'ping': ping, 'engine_and_database': version,
                  'negative': negative, 'eicar': positive}, indent=2))
PY
```

Registrar `VERSION`, fecha de la base cargada y log FreshClam; comprobarlos contra
la actualización real. `clamscan --version` por sí solo no prueba qué base está
usando el daemon. Si `VERSION` está deshabilitado, el administrador debe obtener
la versión/base cargada por logs o habilitar esa consulta local durante validación.
No fijar una firma exacta como `Eicar-Test-Signature`: su nombre puede variar.

Ejecutar también el único test ClamAV real del repo:

```bash
MAP_TEST_CLAMAV_SOCKET="$CLAMAV_SOCKET_PATH" \
  "$MAP_PY" manage.py test mallab.tests.test_clamav.LiveClamAVTests \
  --settings=mallab.tests.settings --verbosity=2
```

Debe aparecer **aprobado, no omitido**. No hay `patch` en esa clase. Solo valida
un caso sin detección; la sonda EICAR añade la prueba positiva real que falta.
Las otras clases ClamAV y algunos casos del pipeline sí usan mocks y no cuentan
como evidencia del servicio Ubuntu. El worker de tests usa `memory://`; tampoco
demuestra el Redis real.

## 7. Arranque y consistencia de los procesos — B + A

```bash
# B, una vez aprobadas las sondas y configuradas las unidades:
sudo systemctl daemon-reload
sudo systemctl start "$MAP_WORKER_UNIT"
sudo systemctl start "$MAP_WEB_UNIT"
systemctl is-active "$MAP_WORKER_UNIT" "$MAP_WEB_UNIT"
systemctl show "$MAP_WORKER_UNIT" "$MAP_WEB_UNIT" -p MainPID -p User -p WorkingDirectory
sudo journalctl -u "$MAP_WORKER_UNIT" -n 100 --no-pager
```

Para unidades ya arrancadas que recibieron un cambio de entorno/grupo, usar
reinicio controlado en la ventana de mantenimiento, no solamente `daemon-reload`.
Inspeccionar los PIDs reales para confirmar usuario, grupos, ejecutable y ruta:

```bash
ps -eo user,pid,ppid,args | grep -E '[c]elery|[g]unicorn|[u]vicorn|[m]anage.py'
redis-cli -h 127.0.0.1 -p 6379 -n 0 ping
"$MAP_CELERY" -A config inspect ping --timeout=10
"$MAP_CELERY" -A config inspect registered --timeout=10
"$MAP_CELERY" -A config inspect active_queues --timeout=10
```

Si Redis necesita autenticación, usar el método privado configurado; no poner
contraseñas en argumentos ni cambiar Redis para acomodar esta guía. Si el broker
real es otro, la sonda Redis debe corresponder a su URL efectiva.

Esperado: Redis `PONG`, worker accesible, tarea `mallab.tasks.analyze_sample_task`
registrada, cola `analysis`, broker real y `CELERY_TASK_ALWAYS_EAGER=False`.
No asumir que `inspect ping` prueba ClamAV/YARA: solo prueba control del worker.

**B, comprobación del entorno de los procesos vivos:** no ejecutar `cat` ni
publicar `/proc/<PID>/environ`. Este bloque compara solo variables seleccionadas
y no imprime secreto ni URL del broker. El PID de una unidad wrapper podría
no ser el de Python: en ese caso identificar los procesos hijos correctos antes
de ejecutar la comparación. No dar por aprobada una unidad que solo lanza otros
procesos con un entorno diferente.

```bash
MAP_WEB_PID="$(systemctl show "$MAP_WEB_UNIT" -p MainPID --value)"
MAP_WORKER_PID="$(systemctl show "$MAP_WORKER_UNIT" -p MainPID --value)"
sudo /usr/bin/python3 - "$MAP_WEB_PID" "$MAP_WORKER_PID" "$MAP_ROOT" <<'PY'
import sys, grp
from pathlib import Path
pids = [int(x) for x in sys.argv[1:3]]
assert all(pid > 1 for pid in pids), 'Falta un proceso activo'
def environment(pid):
    return dict(entry.split(b'=', 1) for entry in Path(f'/proc/{pid}/environ').read_bytes().split(b'\0') if b'=' in entry)
web, worker = map(environment, pids)
keys = ('DJANGO_SETTINGS_MODULE', 'DJANGO_DEBUG', 'DJANGO_SECRET_KEY',
        'CELERY_BROKER_URL', 'YARA_RULES_DIR', 'CLAMAV_ENABLED', 'CLAMAV_SOCKET_PATH')
for key in keys:
    value = key.encode()
    assert web.get(value) and web.get(value) == worker.get(value), f'Variable ausente/diferente: {key}'
    print(key, 'presente e igual')
assert worker[b'CLAMAV_ENABLED'] == b'1'
assert worker[b'DJANGO_SETTINGS_MODULE'] == b'config.settings'
for pid in pids:
    assert Path(f'/proc/{pid}/cwd').resolve() == Path(sys.argv[3]).resolve(), 'WorkingDirectory diferente'
status = Path(f'/proc/{pids[1]}/status').read_text().splitlines()
groups = next(line for line in status if line.startswith('Groups:')).split()[1:]
primary = next(line for line in status if line.startswith('Gid:')).split()[1]
assert str(grp.getgrnam('clamav').gr_gid) in groups + [primary], 'Worker sin grupo clamav'
print('CWD y grupo del worker verificados; secretos no impresos')
PY
```

Revisar también que el proceso web principal herede hacia sus workers y que el
ejecutable/ExecStart de ambos apunte al venv aprobado. Las sondas de consola no
sustituyen estas comprobaciones de procesos vivos.

## 8. Prueba integral real por HTTP — A, crea tres muestras nuevas

Precondiciones: servicios arrancados, entorno común cargado, reglas `validation-v1`,
credenciales de **dos usuarios Django activos ya existentes y diferentes**. No
usar el usuario Unix como si fuera automáticamente un usuario Django. Si faltan
credenciales/segundo usuario, el administrador debe preparar un usuario de
validación antes de capturar el manifiesto del paso 2; no modificar cuentas
ajenas ni copiar tokens al repositorio.

Ejecutar dentro de SSH contra `127.0.0.1:8000`; ajustar el puerto solo si el
servidor real está en otro. Para validar acceso Tailscale desde otro cliente,
usar después una conexión autorizada o túnel SSH. No enviar Basic sobre Internet.

El siguiente bloque usa stdlib, credenciales solicitadas una vez y solo memoria
para fixtures. No hace llamadas directas a `process_sample`/`.run`/`.apply`,
no levanta un worker en memoria y no usa mocks. Se conservan los registros de
prueba y su cuarentena como evidencia; no se borran al terminar.

```bash
cd "$MAP_ROOT"
"$MAP_PY" - <<'PY'
import os, json, time, uuid, base64, hashlib, getpass
from pathlib import Path
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
from urllib.error import HTTPError

base = 'http://127.0.0.1:8000'
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # No reenviar credenciales a otro destino.
opener = build_opener(ProxyHandler({}), NoRedirect())  # Ignorar proxies del entorno.
def prompt(message):
    with open('/dev/tty', 'r') as terminal:
        print(message, end='', flush=True)
        return terminal.readline().strip()
owner = prompt('Usuario Django propietario: ')
password = getpass.getpass('Contraseña: ')
other = prompt('Segundo usuario Django activo: ')
other_password = getpass.getpass('Contraseña del segundo usuario: ')
assert owner and other and owner != other
def credentials(user, secret):
    return 'Basic ' + base64.b64encode(f'{user}:{secret}'.encode()).decode()
auth, other_auth = credentials(owner, password), credentials(other, other_password)
def http(path, method='GET', data=None, content_type=None, authorization=None):
    assert path.startswith('/api/') and not path.startswith('//')
    headers = {'Accept': 'application/json'}
    if authorization:
        headers['Authorization'] = authorization
    if content_type:
        headers['Content-Type'] = content_type
    req = Request(base + path, data=data, method=method, headers=headers)
    try:
        response = opener.open(req, timeout=15)
    except HTTPError as exc:
        response = exc
    with response:
        raw = response.read(1024 * 1024 + 1)
        assert len(raw) <= 1024 * 1024
        body = json.loads(raw)
        return response.code, body
def upload(filename, data):
    boundary = uuid.uuid4().hex
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            'Content-Type: application/octet-stream\r\n\r\n').encode()
    body += data + f'\r\n--{boundary}--\r\n'.encode()
    status, result = http('/api/samples/', 'POST', body,
                          f'multipart/form-data; boundary={boundary}', auth)
    assert status == 202, (status, result)
    return result

status, _ = http('/api/samples/', 'POST', b'', 'multipart/form-data; boundary=test')
assert status == 401, 'Una petición anónima no debe crear registros'
eicar = base64.b64decode('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')
fixtures = [
    ('map-clean.txt', b'MAP plain text without marker', 'NO_DETECTION', False, False),
    ('map-yara-entropy.bin', bytes(range(256)) * 32 + b'MAP_STATIC_ANALYSIS_INNOCUOUS_TEST_v1',
     'NO_DETECTION', True, True),
    ('map-eicar.txt', eicar, 'DETECTED', False, False),
]
evidence = {'owner': owner, 'other': other, 'reports': []}
output = Path(os.environ['MAP_EVIDENCE']) / 'e2e-results.json'
assert not output.exists(), 'No sobrescribir evidencia anterior'
for name, data, clam_status, expect_yara, expect_entropy in fixtures:
    created = upload(name, data)
    deadline = time.monotonic() + 150
    while True:
        code, report = http(created['report_url'], authorization=auth)
        assert code == 200, (code, report)
        if report['status'] in {'COMPLETED', 'FAILED'}:
            break
        assert time.monotonic() < deadline, ('No terminó', created)
        time.sleep(2)
    # Guardar el reporte incluso si alguna aserción posterior falla.
    evidence['reports'].append({'fixture': name, 'expected_sha256': hashlib.sha256(data).hexdigest(),
                                'expected_size': len(data), 'report': report})
    output.write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    assert report['status'] == 'COMPLETED', report
    assert report['sample_id'] == created['sample_id']
    assert report['report_id'] == created['report_id']
    analysis, result = report['analysis'], report['results']
    assert analysis['schema_version'] == 2
    assert result['hashes']['sha256'] == hashlib.sha256(data).hexdigest()
    assert result['file_size'] == len(data)
    assert analysis['yara']['status'] == 'COMPLETED'
    hits = analysis['yara']['matches']
    assert bool(hits) == expect_yara, hits
    assert analysis['yara']['ruleset_sha256']
    if expect_yara:
        assert any(hit['rule'] == 'MAP_Innocuous_Smoke_Test' for hit in hits)
    assert analysis['clamav']['status'] == clam_status, analysis['clamav']
    if clam_status == 'DETECTED':
        assert analysis['clamav']['signatures']
    assert analysis['heuristics']['status'] == 'COMPLETED'
    findings = analysis['heuristics']['findings']
    assert any(x['id'] == 'high_file_entropy' for x in findings) == expect_entropy
    for finding in findings:
        assert all(finding.get(key) for key in ('description','evidence','technical_rationale','limitations'))
    assert http(created['report_url'])[0] == 401
    assert http(created['report_url'], authorization=other_auth)[0] == 404
    print(name, 'sample_id=', report['sample_id'], 'status=', report['status'],
          'clamav=', analysis['clamav']['status'], 'yara_matches=', len(hits))
print('Evidencia sin credenciales:', output)
PY
```

No usar Python `-O` con estos bloques: las aserciones son criterios de aceptación.
Si un patrón inocuo recibe otra firma ClamAV, detener, conservar evidencia y
revisar; no falsear el resultado esperado. La prueba EICAR comprueba detección
de prueba, no capacidad de detectar todas las amenazas. Las fixtures de entropía
son bytes de datos, no programas; no invocarlas como ejecutables.

### Demostrar consumo por el Celery real

```bash
sudo journalctl -u "$MAP_WORKER_UNIT" --since '15 minutes ago' --no-pager
"$MAP_CELERY" -A config inspect active --timeout=10
"$MAP_CELERY" -A config inspect reserved --timeout=10
```

Relacionar la ventana de las tres subidas con entradas `Task ... received` y
`... succeeded` del worker arrancado con la revisión aprobada. Los logs Celery
no necesariamente incluyen sample_id al ignorar resultados: no inventar esa
correlación. Ejecutar en ventana aislada de otras subidas y guardar IDs de tarea
visibles, IDs de muestra de la prueba y timestamps. Una transición muy rápida
puede saltar `PENDING/PROCESSING` entre polls; eso no invalida el resultado.

Requerir conjuntamente: eager deshabilitado en los procesos, cola real Redis,
worker registrado y logs de recepción/fin, más resultados persistidos. Una
llamada directa `.run()` o una respuesta 202 por sí sola no acreditan esto.

### Demostrar SQLite, bytes guardados y conservación — A, solo lectura

```bash
"$MAP_PY" - <<'PY'
import os, json, hashlib, sqlite3
from pathlib import Path
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()
from django.conf import settings
from mallab.models import User, Sample, AnalysisReport
folder = Path(os.environ['MAP_EVIDENCE'])
baseline = json.loads((folder / 'records-before.json').read_text())
e2e = json.loads((folder / 'e2e-results.json').read_text())
assert len(e2e['reports']) == 3, 'Prueba incompleta'
database = Path(settings.DATABASES['default']['NAME']).resolve()
assert database == Path(os.environ['MAP_ROOT']) / 'db.sqlite3'
with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
    assert connection.execute('PRAGMA quick_check').fetchall() == [('ok',)]
for entry in e2e['reports']:
    body = entry['report']
    sample = Sample.objects.get(pk=body['sample_id'])
    report = AnalysisReport.objects.get(pk=body['report_id'], sample=sample)
    assert sample.uploaded_by.username == e2e['owner']
    assert report.status == 'COMPLETED' and report.pe_headers['schema_version'] == 2
    assert report.pe_headers['clamav'] == body['analysis']['clamav']
    assert report.pe_headers['heuristics'] == body['analysis']['heuristics']
    assert report.pe_headers['yara']['ruleset_sha256'] == body['analysis']['yara']['ruleset_sha256']
    assert report.yara_matches == body['analysis']['yara']['matches']
    assert sample.hash == entry['expected_sha256']
    assert sample.file_size == entry['expected_size']
    assert sample.file.name.startswith('quarantine/')
    with sample.file.open('rb') as stream:
        data = stream.read(1024 * 1024)
    assert len(data) == entry['expected_size']
    assert hashlib.sha256(data).hexdigest() == entry['expected_sha256']
models = [(User, ['pk','username','email','role','is_active','is_staff','is_superuser']),
          (Sample, None), (AnalysisReport, None)]
for model, fields in models:
    previous = baseline[model.__name__]
    rows = model.objects.order_by('pk').values(*fields) if fields else model.objects.order_by('pk').values()
    pk_name = 'pk' if fields else model._meta.pk.name
    current = {str(row[pk_name]): hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()
               for row in rows}
    assert all(current.get(pk) == digest for pk, digest in previous.items()), model.__name__
    expected_added = 3 if model in (Sample, AnalysisReport) else 0
    assert len(current) == len(previous) + expected_added, (model.__name__, len(current), len(previous))
print('BD original íntegra, tres muestras persistidas y filas previas conservadas')
PY
```

Los conteos exactos presuponen la ventana sin otras subidas/altas de usuarios.
Si hay trabajo legítimo concurrente o registros de pruebas creados antes,
documentar los IDs adicionales y repetir en aislamiento; no borrar datos para
igualar el conteo. El manifiesto también detecta modificaciones de filas previas.

Consultar además con credenciales del propietario un reporte histórico conocido
y confirmar que su forma anterior no cambió. Tras otro reinicio controlado de
web/worker, consultar de nuevo los tres IDs y repetir la lectura de persistencia
sin volver a subirlos. Un reporte `COMPLETED` no se reanaliza automáticamente.

## 9. Evidencia de aceptación y resolución de fallos

Registrar en la carpeta privada de evidencia:

- revisión del servidor, Python/dependencias y versión Ubuntu;
- backup validado de SQLite/cuarentena y manifiesto anterior;
- identidades/unidades/rutas/venv, sin secretos;
- estado Redis, cola, worker, grupos y socket local;
- actualización FreshClam, VERSION del daemon y sondas real negativa/positiva;
- manifiesto YARA usado por consola y por Celery, con hashes coincidentes;
- salida del test real ClamAV **sin skip** y suite automatizada;
- los tres IDs, JSON final, evidencia Celery y comparación ORM/bytes;
- comprobación de propietario y reportes históricos/persistencia tras reinicio.

| Fallo | Acción antes de repetir |
| --- | --- |
| `UNAVAILABLE/permission_denied` | Grupo efectivo del worker, modo del socket, directorios, AppArmor/systemd. |
| `UNAVAILABLE/connection_unavailable` | Estado/carga de firmas de clamd, ruta LocalSocket y socket activation. |
| `ERROR/timeout` | CPU/RAM/carga, plazo clamd/cliente, expansión de archivos; no ampliar sin medir. |
| YARA `scan_error` | Conjunto vacío, fuentes inválidas, permisos o límites; revisar log privado. |
| Reporte sin bloque `analysis` | Registro histórico, versión vieja del worker o error de cola anterior a v2. |
| `PENDING` prolongado | Cola real, consumidor correcto, tareas registradas y entorno/BD compartida. |
| `PROCESSING` atascado | Investigar terminación/BD; no restablecer/reencolar sin comprobar que no sigue activo. |
| `database is locked` | Otros escritores o concurrencia; medir y reducir carga, sin cambiar infraestructura. |
| `401/403` | Credenciales, usuario activo o CSRF con sesión; no habilitar acceso anónimo. |
| `503 queue_unavailable` | Broker no confirmado; consultar el ID guardado, no volver a subir automáticamente. |
| DB/manifiesto no coincide | Detener aceptación, revisar rutas/esquema/escritores; no crear una BD vacía. |

Si el despliegue falla, pausar nuevas entradas y conservar BD, cuarentena y
evidencia. Recuperar servicios/configuración anterior por el procedimiento
administrativo; no restaurar una copia sobre la BD actual automáticamente,
porque podría perder nuevas filas. Restaurar datos requiere revisión separada.
Cambiar ClamAV a deshabilitado puede recuperar análisis parcial, pero **no es
una aceptación de ClamAV** y debe quedar explícito en el estado operativo.

Solo después de superar las sondas reales, test HTTP integral, prueba de permisos,
persistencia y conservación se puede afirmar: "V2 validado en este servidor,
con esta revisión, conjunto YARA y firmas ClamAV". No es un certificado de
seguridad de archivos ni una validación general de exposición pública.

## Fuentes primarias para el operador

- [Instalación por paquetes ClamAV](https://docs.clamav.net/manual/Installing/Packages.html).
- [Configuración ClamAV](https://docs.clamav.net/manual/Usage/Configuration.html).
- [FreshClam y firmas oficiales](https://docs.clamav.net/manual/Usage/SignatureManagement.html).
- [Manual Ubuntu clamd.conf](https://manpages.ubuntu.com/manpages/noble/man5/clamd.conf.5.html);
  verificar también `man clamd.conf` en la versión instalada.
- [Protocolo clamd](https://docs.clamav.net/manual/Usage/ClamdProtocol.html).
- [EnvironmentFile y grupos systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
- [Archivo de prueba EICAR](https://www.eicar.org/download-anti-malware-testfile/).

Los valores de recursos son una propuesta inicial para validar, no un benchmark
del ThinkPad. Las decisiones administrativas dependen del inventario real.
