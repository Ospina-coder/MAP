# MAP — Historial de desarrollo

Actualizado: 29/10/2026. Orden cronológico inverso (lo más reciente primero).
Fecha de commits según Git con offset -05:00; fecha de trabajos sin commit según
la sesión. Una referencia es evidencia local de Git, no de publicación/despliegue.

## 2026-10-29 — Organización documental permanente

**Referencia de código:** rama `main`, `f7460b7e66edd3a76e2a845095d4c909fc8ad5d2`.
**Commit de esta iteración:** no creado; cambios documentales locales.

- Crea `docs/PROJECT_CONTEXT.md` como contexto autónomo para otra IA.
- Crea `docs/ARCHITECTURE.md`, `docs/DEPLOYMENT.md` y `docs/ROADMAP.md` con
  responsabilidades diferenciadas, evidencias y pendientes.
- Crea este historial y `AGENTS.md` con actualización proporcional de documentación.
- Añade índice al README y aviso histórico al contexto previo a V2.
- Conserva API.md, ANALYZER.md, STATIC_ENGINE_V2.md, reglas y procedimiento Ubuntu.
- No cambia código funcional, modelos, SQLite, cuarentena ni dependencias.

**Verificación repetida:** `manage.py check` correcto; suite de 64 casos,
63 aprobados y 1 omitido; `makemigrations --check --dry-run`: sin cambios.
El omitido es `LiveClamAVTests`, no aplicable al entorno Windows sin clamd Unix.
Versiones locales contrastadas con metadata, diferenciadas del servidor.
Revisión documental de enlaces relativos, referencia y estados de evidencia.

**Pendiente:** commit/publicación de documentos y validación Ubuntu. No se afirma
sincronización GitHub ni disponibilidad remota por tener referencias locales.

## 2026-10-29 — Preparación del despliegue y validación V2

**Archivo previo a la iteración documental actual:**
`mallab/DEPLOY_STATIC_ENGINE_V2_UBUNTU.md`, local sin seguimiento al iniciar
esta tarea. **Sin commit propio conocido.** Base inspeccionada: f7460b7.

Procedimiento con responsables A/B, inventario, backup coherente SQLite/cuarentena,
ClamAV/FreshClam/socket/grupos, reglas confiables, entorno común y test HTTP integral.
Define tres casos inocuos de prueba y verificación de filas históricas/persistencia.
No ejecutado por SSH. La revisión previa comprobó sintaxis de ocho fragmentos
Python y fixture local YARA/entropía; esto no prueba comandos administrativos.

El resultado local comunicado fue 63 aprobados/1 omitido; se confirmó nuevamente
en la organización documental. No consta ejecución del test ClamAV real o E2E
en Ubuntu. La guía es preparación, no cambio operativo aplicado.

## 2026-10-29 — STATIC ENGINE V2

**Commit existente:** `f7460b7` — `Avance`.

| Archivos | Cambio funcional/documental del commit |
| --- | --- |
| `mallab/services/yara_scanner.py`, `exceptions.py` | Scanner separado, snapshot/hash, caché LRU/lock y límites; excepción compartida. |
| `mallab/services/clamav.py` | Cliente clamd local AF_UNIX/INSTREAM, opt-in, estados y respuestas acotadas. |
| `mallab/services/heuristics.py` | Indicadores con evidencia/justificación/limitaciones, sin puntuación. |
| `mallab/services/analyzer.py` | Coordinación v2, metadata PE adicional, límites y resultados parciales. |
| `config/settings.py` | Configuración ClamAV y límites/umbrales YARA/PE/heurísticas. |
| `mallab/views.py` | Extensión `analysis` para reportes v2, compatible con lectura histórica. |
| `mallab/tests/test_{analyzer,api,engine_v2,yara_scanner,clamav,heuristics}.py`, `tests/settings.py` | Nuevos escenarios y aislamiento de ClamAV. |
| `yara_rules/` | Regla inocua separada de carpeta reviewed vacía y proceso de revisión. |
| `mallab/STATIC_ENGINE_V2.md`, API.md, ANALYZER.md, README.md | Auditoría, contratos y configuración actualizada. |
| `CONTEXTO_PROYECTO_IA.md` | Snapshot previo a V2 incorporado al commit; referencia histórica interna 129d84a. |

La evidencia documentada de cierre fue 64 casos, 63 aprobados y 1 omitido,
check sin incidencias y sin migraciones nuevas. Esa cifra se reprodujo durante
la organización documental. ClamAV real quedó explícitamente sin validar.
No hay cambio de infraestructura de BD ni ejecución dinámica de muestras.

## 2026-10-27 — Red y CSRF de desarrollo

- `129d84a` — `Configure development hosts and trusted CSRF origins`:
  wildcard en ALLOWED_HOSTS y tres orígenes CSRF HTTP para desarrollo.
- `03addcf` — `Allow Tailscale and all hosts during development`:
  ajuste anterior de hosts, sustituido después por el valor del commit siguiente.

Son configuraciones de desarrollo, no un despliegue de producción validado.
No hay evidencia nueva de pruebas remotas asociada a estas referencias.

## 2026-10-27 — Autenticación obligatoria y pruebas temporales de anonimato

- `92c0bca` — `Require authenticated API uploads with Basic and Token auth`:
  DRF, Basic/Token/sesión, IsAuthenticated y cierre de acceso anónimo.
- `2813da0` — `Assign anonymous uploads to an existing user`: fallback temporal
  al primer usuario para compatibilidad con NOT NULL; **ya revertido en vistas**.
- `3e0d414` — `Allow anonymous sample uploads during testing`: pruebas temporales
  y migración nullable de uploaded_by, que se conserva en el esquema histórico.
- `871fc40` — `Exempt sample upload API from CSRF checks`: exención de middleware
  de subida; DRF SessionAuthentication exige después su propio CSRF.

La suite actual verifica autenticación y rechazo de anónimos. No se atribuyen a
cada commit histórico cantidades exactas de tests sin una ejecución archivada.

## 2026-10-27 — Base del repositorio

`990e244` — `All new`, base histórica anterior a las iteraciones detalladas.
Los componentes de esa base deben leerse en su revisión; el estado funcional
vigente está consolidado en [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md).

## Cómo añadir entradas

Registrar fecha, referencia real o ausencia de commit, problema/respuesta,
archivos afectados, pruebas ejecutadas/resultados, limitaciones y pendientes.
No sustituir una entrada histórica por el estado más nuevo ni llamar desplegado
a un commit local. El commit de referencia del código y el commit que contiene
documentación pueden ser distintos; no crear una cadena de hashes autorreferenciales.
