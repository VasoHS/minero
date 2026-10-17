# Reporte de seguridad

_Generado: 2026-10-17T12:39:00+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


## Crítica/alta

No se reportan hallazgos de estas severidades en la evidencia recibida.

## Media

No se reportan hallazgos de severidad media en la evidencia recibida.

## Baja/informativa

### Artefactos generados versionados — misma regla

- **Observado:** `results-sbom.json`, `results-vuln.json` y `results.json` están versionados como artefactos generados; no se aporta evidencia sobre su contenido ni sobre si deben permanecer en el repositorio [TR-001][TR-002][TR-003].
- **Por qué importa:** podrían contener datos sensibles o generar exposición innecesaria si no existe una justificación para versionarlos; esto no está confirmado por los hallazgos [TR-001][TR-002][TR-003].
- **Mitigación:** revisar el contenido y decidir si cada archivo debe formar parte del repositorio. Si no es necesario, dejar de versionarlo y añadir los patrones correspondientes a `.gitignore` [TR-001][TR-002][TR-003].

Los hallazgos no describen posibles secretos, por lo que no hay base en ellos para recomendar la revocación de credenciales [TR-001][TR-002][TR-003].

## Cobertura del análisis

| Verificación | Estado |
|---|---|
| secretos (archivos no ignorados por git) | ejecutado (0 hallazgos) |
| workflows | ejecutado (0 hallazgos) |
| docker (Dockerfile y .devcontainer/Dockerfile) | ejecutado (0 hallazgos) |
| higiene (.gitignore) | ejecutado (0 hallazgos) |
| archivos versionados | ejecutado (3 hallazgos) |
| lockfile | ejecutado (0 hallazgos) |
| dependencias (Syft+Grype) | ejecutado (69 componentes, 0 vulnerabilidades en total) |

## Apéndice: evidencia

| ID | Severidad | Archivo | Línea | Regla | Evidencia |
|---|---|---|---|---|---|
| TR-001 | info | `results-sbom.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-002 | info | `results-vuln.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-003 | info | `results.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
