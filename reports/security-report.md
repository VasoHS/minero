# Reporte de seguridad

_Generado: 2026-10-09T00:19:03+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


## Crítica/alta

No se reportan hallazgos de severidad crítica o alta en la evidencia proporcionada. [TR-001] [TR-002] [TR-003]

## Media

No se reportan hallazgos de severidad media en la evidencia proporcionada. [TR-001] [TR-002] [TR-003]

## Baja/informativa

### Artefactos generados versionados

Los archivos `results-sbom.json`, `results-vuln.json` y `results.json` están versionados pese a ser artefactos generados. [TR-001] [TR-002] [TR-003]

Esto puede introducir ruido en el repositorio y conservar resultados generados que quizá deban producirse durante el proceso de CI/CD; además, la evidencia disponible no permite determinar si contienen datos sensibles. [TR-001] [TR-002] [TR-003]

Como mitigación, revisa el contenido de los tres archivos y confirma si deben formar parte del repositorio; si no son necesarios, elimínalos del control de versiones y añade sus rutas al `.gitignore`. [TR-001] [TR-002] [TR-003]

No hay evidencia suficiente en estos hallazgos para recomendar la revocación de credenciales. [TR-001] [TR-002] [TR-003]

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
