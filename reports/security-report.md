# Reporte de seguridad

_Generado: 2026-10-14T14:17:06+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


# Hallazgos de severidad crítica/alta

No se reportan hallazgos con severidad crítica o alta en el JSON recibido [TR-001][TR-002][TR-003].

# Hallazgos de severidad media

No se reportan hallazgos con severidad media en el JSON recibido [TR-001][TR-002][TR-003].

# Hallazgos de severidad baja/informativa

## Artefactos generados versionados

Se observaron tres artefactos generados versionados: `results-sbom.json` [TR-001], `results-vuln.json` [TR-002] y `results.json` [TR-003].

- **Qué importa:** el JSON no permite determinar si contienen datos sensibles ni si deben formar parte del repositorio; por tanto, no hay evidencia suficiente para afirmar que exista una exposición. Mantener resultados generados bajo control de versiones puede introducir datos innecesarios o facilitar la publicación accidental de información interna [TR-001][TR-002][TR-003].
- **Mitigación:** revisar el contenido de los tres archivos y confirmar si su versionado es necesario. Si no lo es, eliminarlos del repositorio, añadir sus patrones al `.gitignore` y generar los resultados únicamente en CI o durante las revisiones locales [TR-001][TR-002][TR-003].
- **Credenciales:** no se recomienda revocar credenciales basándose en estos hallazgos, porque solo indican que son artefactos generados versionados y no identifican un posible secreto [TR-001][TR-002][TR-003].

## Cobertura

La cobertura indica que se ejecutaron las verificaciones de secretos en archivos no ignorados por Git, workflows, Dockerfiles, `.gitignore`, archivos versionados, lockfile y dependencias; el único resultado registrado fueron estos tres artefactos versionados [TR-001][TR-002][TR-003]. No hay verificaciones omitidas o inconcluyentes indicadas en el JSON.

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
