# Reporte de seguridad

_Generado: 2026-10-09T15:44:48+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


# Crítica/alta

No se registraron hallazgos de severidad crítica o alta en la evidencia proporcionada. [TR-001][TR-002][TR-003]

# Media

No se registraron hallazgos de severidad media. [TR-001][TR-002][TR-003]

# Baja/informativa

## Artefactos generados versionados

Se observaron tres artefactos generados versionados: `results-sbom.json`, `results-vuln.json` y `results.json`. [TR-001][TR-002][TR-003]

Esto importa porque dichos archivos podrían contener datos sensibles o resultados de análisis que no deberían mantenerse en el repositorio; sin embargo, el JSON no demuestra que contengan información sensible. [TR-001][TR-002][TR-003]

Mitigación concreta: revisar el contenido de los tres archivos y confirmar si deben formar parte del repositorio; si no son necesarios, eliminarlos del control de versiones y añadir patrones apropiados al `.gitignore`. [TR-001][TR-002][TR-003]

## Cobertura adicional

La búsqueda de secretos en archivos no ignorados por Git se ejecutó y reportó cero hallazgos; por tanto, no hay evidencia en este análisis para recomendar la revocación de credenciales. [TR-001][TR-002][TR-003]

También se reportaron cero hallazgos en workflows, Dockerfiles, `.gitignore` y lockfiles, así como cero vulnerabilidades entre 69 componentes analizados mediante Syft+Grype. [TR-001][TR-002][TR-003]

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
