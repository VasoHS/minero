# Reporte de seguridad

_Generado: 2026-10-13T16:41:40+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


## Crítica/alta

No se reportan hallazgos de severidad crítica o alta en la evidencia proporcionada.

## Media

No se reportan hallazgos de severidad media en la evidencia proporcionada.

## Baja/informativa

### Artefactos generados versionados

Se detectaron tres artefactos generados que están versionados en el repositorio: `results-sbom.json`, `results-vuln.json` y `results.json` [TR-001][TR-002][TR-003].

Esto importa porque dichos archivos podrían contener datos sensibles o resultados de análisis que no deberían formar parte del repositorio; sin embargo, la evidencia disponible no confirma que contengan información sensible [TR-001][TR-002][TR-003].

**Mitigación concreta:** revisar el contenido de los tres archivos y determinar si deben permanecer versionados. Si no son necesarios, eliminarlos del repositorio, añadir sus rutas al `.gitignore` y evitar que se vuelvan a generar dentro del árbol versionado [TR-001][TR-002][TR-003].

La cobertura reporta que la verificación de secretos en archivos no ignorados por Git no encontró hallazgos; por tanto, no hay base en este análisis para recomendar la revocación de credenciales [TR-001][TR-002][TR-003].

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
