# Reporte de seguridad

_Generado: 2026-10-16T13:42:40+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


## Crítica / alta

No se reportan hallazgos de severidad crítica o alta en la evidencia recibida. [TR-001] [TR-002] [TR-003]

## Media

No se reportan hallazgos de severidad media. [TR-001] [TR-002] [TR-003]

## Baja / informativa

### Artefactos generados versionados

Se observaron tres artefactos generados dentro del repositorio:

- `results-sbom.json` [TR-001]
- `results-vuln.json` [TR-002]
- `results.json` [TR-003]

Estos archivos están versionados y deben revisarse para determinar si contienen datos sensibles o si realmente deben formar parte del repositorio. [TR-001] [TR-002] [TR-003]

Esto importa porque los resultados generados pueden introducir información innecesaria o potencialmente sensible en el historial del repositorio; sin embargo, la evidencia disponible no confirma que estos archivos contengan datos sensibles ni que deban eliminarse. [TR-001] [TR-002] [TR-003]

**Mitigación concreta:** inspeccionar el contenido de los tres archivos, confirmar si son necesarios para el proyecto y, si no lo son, eliminarlos del control de versiones y añadir sus rutas a `.gitignore`. Si contienen información sensible, debe evaluarse su exposición y aplicar el procedimiento correspondiente de saneamiento. [TR-001] [TR-002] [TR-003]

La verificación de secretos en archivos no ignorados por Git se ejecutó sin hallazgos, por lo que no hay base en este análisis para recomendar la revocación de credenciales. [TR-001] [TR-002] [TR-003]

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
