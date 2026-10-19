# Reporte de seguridad

_Generado: 2026-10-19T16:06:28+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


# Crítica/alta

No se reportan hallazgos de severidad crítica o alta en el JSON recibido. [TR-001] [TR-002] [TR-003]

# Media

No se reportan hallazgos de severidad media en el JSON recibido. [TR-001] [TR-002] [TR-003]

# Baja/informativa

## Artefactos generados versionados

Se observaron tres artefactos generados versionados: `results-sbom.json` [TR-001], `results-vuln.json` [TR-002] y `results.json` [TR-003].

Esto importa porque podrían contener datos sensibles o resultados internos, aunque la evidencia disponible no confirma que los contengan. [TR-001] [TR-002] [TR-003]

**Mitigación concreta:** revisar el contenido de los tres archivos y decidir explícitamente si deben permanecer en el repositorio; si no son necesarios, eliminarlos del control de versiones y añadirlos a `.gitignore`. [TR-001] [TR-002] [TR-003]

No hay evidencia suficiente para recomendar la revocación de credenciales: los hallazgos solo indican que son artefactos generados versionados y no posibles secretos confirmados o detectados. [TR-001] [TR-002] [TR-003]

La cobertura indica que la verificación de secretos en archivos no ignorados por Git se ejecutó sin hallazgos, pero la revisión del contenido y necesidad de conservar estos artefactos sigue siendo aplicable. [TR-001] [TR-002] [TR-003]

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
