# Reporte de seguridad

_Generado: 2026-10-15T13:52:29+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


## Crítica/alta

No se reportan hallazgos de severidad crítica o alta en la evidencia proporcionada. [TR-001][TR-002][TR-003]

## Media

No se reportan hallazgos de severidad media en la evidencia proporcionada. [TR-001][TR-002][TR-003]

## Baja/informativa

### Artefactos generados versionados

Se observaron tres artefactos generados que están versionados en el repositorio: `results-sbom.json`, `results-vuln.json` y `results.json`. [TR-001][TR-002][TR-003]

Esto importa porque la evidencia disponible no permite determinar si esos archivos contienen datos sensibles ni si deben formar parte del repositorio. [TR-001][TR-002][TR-003]

Mitigación concreta:

- Revisar el contenido de los tres archivos para confirmar que no incluyan datos sensibles o información innecesaria. [TR-001][TR-002][TR-003]
- Si son resultados temporales o generados durante CI, eliminarlos del repositorio y añadirlos al `.gitignore`, generándolos bajo demanda. [TR-001][TR-002][TR-003]
- Si deben permanecer versionados, documentar su necesidad y validar que su contenido sea apropiado para el repositorio. [TR-001][TR-002][TR-003]

No hay evidencia suficiente para recomendar la revocación de credenciales, ya que estos hallazgos no identifican posibles secretos. [TR-001][TR-002][TR-003]

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
