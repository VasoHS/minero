# Reporte de seguridad

_Generado: 2026-10-20T14:03:00+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


## Crítica/alta

No se reportaron hallazgos de severidad crítica o alta.

## Media

No se reportaron hallazgos de severidad media.

## Baja/informativa

### Artefactos generados versionados

Se observaron tres artefactos generados versionados: `results-sbom.json`, `results-vuln.json` y `results.json` [TR-001] [TR-002] [TR-003].

Esto importa porque esos archivos podrían contener datos sensibles o resultados que no deberían formar parte del repositorio; el JSON no aporta evidencia suficiente para confirmar que contengan información sensible [TR-001] [TR-002] [TR-003].

Mitigación concreta:

- Revisar el contenido de los tres archivos y confirmar si deben permanecer en el repositorio [TR-001] [TR-002] [TR-003].
- Si no son necesarios, eliminarlos del control de versiones y añadir sus patrones al `.gitignore` [TR-001] [TR-002] [TR-003].
- Si deben mantenerse, documentar su propósito y verificar que no incluyan datos sensibles [TR-001] [TR-002] [TR-003].

La revisión de secretos en archivos no ignorados por Git no reportó hallazgos, por lo que no hay base para recomendar la revocación de credenciales a partir de estos hallazgos [TR-001] [TR-002] [TR-003].

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
