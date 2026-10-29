# MAP — Roadmap por estado de evidencia

Actualizado: 29/10/2026. Rama de referencia `main`, código `f7460b7`.
Documentación reorganizada localmente, sin commit nuevo. No hay fechas futuras
comprometidas ni autorización implícita para ejecutar todos los puntos.

## Implementado y probado localmente

| Capacidad | Evidencia | Límite |
| --- | --- | --- |
| API autenticada y propiedad de muestras/reportes | Tests DRF Basic/Token/sesión, CSRF y aislamiento | Sin aceptación Ubuntu V2. |
| Ingestión privada, tamaño, transacciones/despacho | Tests con Storage temporal y callbacks | No hay outbox ni retención. |
| Hashes, Shannon, formato y PE | Cálculos, pefile real y PE sintéticos | Detección por firmas no valida completamente todos los formatos. |
| YARA, caché, límites y regla inocua | yara-python real, no-match, cambios de contenido, concurrencia y errores | reviewed vacío, reglas de cobertura por aprobar. |
| Cliente ClamAV local | Pruebas simuladas del protocolo y fallos | Daemon/firmas/detección real pendientes. |
| Heurísticas explicables | Tests de evidencia positiva/negativa e integración PE | No es motor de decisiones ni score calibrado. |
| Payload/API v2 compatible | Tests legacy y resultados parciales | No reanaliza reportes completados automáticamente. |
| Celery | Worker de test real con broker en memoria | No acredita Redis ni worker Ubuntu. |
| Documentación permanente | Contexto, historial, arquitectura, despliegue, roadmap y AGENTS | Cambios locales; sin publicación verificada. |

Suite repetida en esta revisión: **63 aprobados, 1 omitido, 64 casos**.

## Preparado / trabajo activo de validación

**Prioridad P0: aceptación operativa de V2 en Ubuntu.** Existe procedimiento,
pero no consta ejecución remota de sus etapas:

1. Inventariar revisión, servicios, identidades, venv, SQLite y cuarentena.
2. Respaldar coherentemente y registrar inventario/manifiesto de filas históricas.
3. Instalar/configurar ClamAV/FreshClam, firmas y socket de permisos mínimos.
4. Aprobar conjunto YARA y mantenerlo legible, separado de las reglas de prueba.
5. Unificar entorno web/worker, comprobar Redis/cola y procesos nuevos.
6. Ejecutar prueba ClamAV real negativa/positiva y HTTP E2E por Celery real.
7. Verificar propiedad, datos/bytes persistidos, registros anteriores y reinicio.
8. Documentar evidencia por revisión/fecha antes de declarar aceptación.

No se está implementando actualmente una nueva capa funcional del motor. La
preparación de un procedimiento no equivale a que su ejecución esté en curso.
Ver [DEPLOYMENT.md](DEPLOYMENT.md).

## Pendiente de implementación o decisión de alcance

| Prioridad orientativa | Actividad | Condición/dependencia |
| --- | --- | --- |
| P1 | Diseñar motor de decisiones por capas | Después de aceptar V2 y acordar criterios explicables con el usuario. No existe aún. |
| P1 | Endurecimiento de despliegue y recursos | Inventario real; hosts/HTTPS/DEBUG, permisos, CPU/RAM y mediciones. |
| P1 | Recuperación de PENDING/PROCESSING atascados | Definir propiedad de ejecución, antigüedad y reintentos seguros. |
| P1 | Entrega robusta entre commit y broker | Evaluar outbox o equivalente; no prometer exactamente una ejecución. |
| P2 | Cuotas, rate limiting y retención/purga | Política de producto y autorización sobre datos; daily_uploads no basta. |
| P2 | Ciclo de vida de credenciales/tokens | Decidir expiración/rotación y endpoints; no confundir api_key personalizada. |
| P2 | Reanálisis, historial/listados/descarga autorizada | Definir contratos y política antes de ampliar la API. |
| P2 | Dependencias reproducibles, CI y evidencia operativa | Seleccionar herramientas sin introducir infraestructura ajena a la solicitud. |
| Separada | PostgreSQL/Supabase | Migración independiente con estrategia de preservación; no autorizada en esta fase. |

## Fuera del alcance actual

IA/ML, probabilidades sin validación, ejecución dinámica, instalación de CAPE,
exposición de cuarentena y envío a servicios externos. Docker comunicado por el
usuario no significa que exista un despliegue Docker de MAP o CAPE.

## Criterio para cambiar estados

Una implementación requiere archivos y pruebas pertinentes. Una validación remota
requiere revisión desplegada, servicios reales y evidencia E2E. Registrar el
cambio en [CHANGELOG_DEV.md](CHANGELOG_DEV.md) y en el contexto consolidado.
No marcar un pendiente como completado por tener solo diseño, mocks o comandos.
