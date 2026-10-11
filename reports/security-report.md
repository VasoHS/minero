# Reporte de seguridad

_Generado: 2026-10-11T15:16:09+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


## Crítica/alta

No se reportan hallazgos de severidad crítica o alta en la evidencia recibida [TR-001][TR-002][TR-003].

## Media

No se reportan hallazgos de severidad media en la evidencia recibida [TR-001][TR-002][TR-003].

## Baja/informativa

### Artefactos generados versionados

Se observaron tres artefactos generados que están versionados en el repositorio: `results-sbom.json`, `results-vuln.json` y `results.json` [TR-001][TR-002][TR-003].

- **Qué importa:** al estar versionados, estos archivos pueden introducir ruido en el historial, aumentar el tamaño del repositorio o exponer datos sensibles si los contienen; sin embargo, la evidencia disponible no confirma que contengan información sensible [TR-001][TR-002][TR-003].
- **Mitigación:** revisar el contenido de los tres archivos y determinar si deben formar parte del repositorio. Si son salidas temporales, eliminarlos del control de versiones y añadir sus rutas a `.gitignore`; si deben conservarse, documentar su propósito y verificar que no incluyan datos sensibles [TR-001][TR-002][TR-003].
- **Limitación:** no hay evidencia suficiente para recomendar la revocación de credenciales, porque estos hallazgos no identifican posibles secretos [TR-001][TR-002][TR-003].

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
