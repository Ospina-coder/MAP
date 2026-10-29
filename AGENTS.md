# MAP — Instrucciones permanentes para agentes

Estas instrucciones aplican a todo el repositorio. Mantén el trabajo dentro de
la solicitud del usuario y del estado real del código.

## Antes de trabajar

1. Lee `docs/PROJECT_CONTEXT.md` y la documentación relevante de `docs/` antes
   de proponer cambios. Consulta `README.md`, `mallab/API.md`, `mallab/ANALYZER.md`
   y las guías V2 cuando afecten a la tarea.
2. Inspecciona código, `git status`, rama y commit. La documentación es contexto,
   no prueba suficiente de que una función siga existiendo o esté desplegada.
3. Conserva cambios ajenos y documentación existente. Distingue cambios de esta
   iteración de archivos pendientes de iteraciones anteriores.

## Arquitectura y seguridad

- MAP es un backend de análisis estático: Django/DRF → SQLite/Storage privado →
  Celery/Redis → servicios de análisis → reporte persistido y API por propietario.
- Conserva `IsAuthenticated`, usuarios activos, autorización por propietario,
  JSON, límites y almacenamiento privado. Una FK nullable no habilita anonimato.
- Mantén tareas por ID y despacho tras commit. No metas el análisis costoso en
  la petición HTTP ni transportes binarios/modelos por la cola.
- No ejecutes archivos sospechosos. Nunca ejecutarlos fuera de un laboratorio
  aislado; este backend actualmente no tiene ejecución dinámica autorizada.
  No instales CAPE ni incorpores análisis dinámico salvo solicitud específica.
- No envíes muestras a servicios externos ni publiques cuarentena.
- No borres, reinicialices, restaures ni modifiques datos existentes de SQLite
  o archivos de cuarentena sin autorización del usuario. Una autorización para
  cambiar código no autoriza limpieza de datos. Usa datos temporales en tests.
- No cambies de infraestructura de BD ni elimines/reinterpretes migraciones
  históricas para resolver un error sin una solicitud y estrategia explícitas.
- No introduzcas IA/ML, puntuaciones probabilísticas, secretos ni funciones ajenas
  al alcance. Los indicadores explicables no son certezas de malware.
- No escribas contraseñas, tokens, claves, datos sensibles o contenido de muestras
  en documentación, logs de entrega ni Git. Usa marcadores de posición y referencias
  a fixtures inocuas existentes, sin copiar contenido de muestras reales.

## Verificación

- Tras cambios de código, ejecuta las pruebas relevantes. Amplía al conjunto
  completo cuando se afecten pipeline, autenticación, API, persistencia o tareas.
- Comandos de referencia, desde la raíz y con las dependencias instaladas:

  ```bash
  python manage.py check
  python manage.py test mallab.tests --settings=mallab.tests.settings
  python manage.py makemigrations --check --dry-run
  ```

- La suite usa SQLite en memoria y medios temporales. No ejecutar `flush`,
  purgas Redis/Celery o pruebas destructivas sobre datos del servidor.
- Para cambios solo documentales, verifica exactitud, enlaces y coherencia;
  no repitas toda la suite por una errata. Si la tarea exige confirmar resultados
  actuales, ejecútala y registra el resultado observado.
- Separa tests reales, simulaciones y casos omitidos. Un test ClamAV con mocks,
  el broker `memory://` o una guía de despliegue no validan los servicios Ubuntu.
- Documenta fallos, limitaciones, pruebas no ejecutadas y sus motivos. No declares
  una capacidad validada ni una versión desplegada sin evidencia pertinente.

## Mantenimiento documental al cerrar una iteración

`docs/PROJECT_CONTEXT.md` es el único archivo autónomo que se entrega a otra IA.
Debe bastar para entender estado, cambios recientes, evidencia y pendientes sin
el historial del chat. Los documentos especializados amplían sus detalles.

| Cambio | Actualización proporcional requerida |
| --- | --- |
| Implementación, corrección, refactor o cambio importante | Contexto consolidado, entrada en `CHANGELOG_DEV.md` y documentos afectados. |
| Componentes, flujo, interfaces, persistencia o decisiones | `ARCHITECTURE.md` y resumen correspondiente del contexto. |
| Configuración, dependencias, variables, servicios o despliegue | `DEPLOYMENT.md` y procedimientos afectados. |
| Cambio de estado/prioridad de una funcionalidad | `ROADMAP.md` y contexto si cambia el estado global. |
| Errata, formato o ajuste documental trivial | Solo los archivos afectados; no reescribir todo ni inventar una iteración funcional. |

En una actualización importante:

1. Registrar fecha, alcance, archivos/motivos, pruebas/resultados, riesgos y siguiente
   paso. Mantener las versiones observadas separadas de rangos de requirements.
2. Identificar explícitamente: implementado en código, validado por pruebas,
   desplegado/verificado en Ubuntu, pendiente e información del usuario sin verificar.
3. Usar fecha de la sesión y rama/commit realmente leídos. El commit es la referencia
   del código inspeccionado; si la documentación está sin commit, decirlo. No buscar
   un hash autorreferencial ni inventar el commit que contendrá el documento.
4. Añadir una entrada cronológica sin borrar el historial. Cuando exista un commit
   real, citarlo; si no, indicar «sin commit» o «cambios locales».
5. Corregir contradicciones con el código y conservar documentos históricos con
   referencia temporal y enlace al contexto vigente. No borrar documentación previa.
6. No presentar `git status`, una referencia `origin/main` local, un commit o un
   intento de push como prueba de sincronización GitHub o despliegue remoto.
7. En la entrega, enlazar el contexto principal, resumir cambios y verificaciones
   pendientes. No crear commits, pushes o despliegues por la sola obligación documental;
   respetar el alcance y la autorización de la tarea.

## Pendientes que condicionan el trabajo actual

STATIC ENGINE V2 existe y tiene pruebas locales. La validación real Ubuntu de
ClamAV/YARA/Celery/Redis y el test HTTP integral no están acreditados. Consultar
`docs/DEPLOYMENT.md`. El motor de decisiones por capas es una actividad futura;
no confundir las heurísticas actuales con ese componente.
