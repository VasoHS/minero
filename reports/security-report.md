# Reporte de seguridad

_Generado: 2026-10-10T14:58:26+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


# Crítica/alta

No se registraron hallazgos de severidad crítica o alta en la evidencia proporcionada. [TR-001][TR-002][TR-003]

# Media

No se registraron hallazgos de severidad media en la evidencia proporcionada. [TR-001][TR-002][TR-003]

# Baja/informativa

## Artefactos generados versionados

Los archivos `results-sbom.json`, `results-vuln.json` y `results.json` aparecen como artefactos generados que están versionados en el repositorio. [TR-001][TR-002][TR-003]

Esto importa porque dichos artefactos podrían contener datos sensibles o generar ruido y mantenimiento innecesario en el repositorio; el JSON no confirma que contengan información sensible. [TR-001][TR-002][TR-003]

**Mitigación:** revisar el contenido de los tres archivos y determinar si deben permanecer en el repositorio. Si no son necesarios, eliminarlos del control de versiones y añadir sus rutas a `.gitignore`; si deben conservarse, validar que no expongan datos sensibles. [TR-001][TR-002][TR-003]

La comprobación de secretos en archivos no ignorados por Git reportó cero hallazgos, por lo que no hay evidencia en este análisis para recomendar la revocación de credenciales. [TR-001][TR-002][TR-003]

La cobertura reporta cero hallazgos en workflows, Docker, `.gitignore` y lockfiles, y cero vulnerabilidades entre los componentes analizados; estas conclusiones se limitan a las verificaciones ejecutadas y no sustituyen la revisión del contenido de los artefactos versionados. [TR-001][TR-002][TR-003]

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
