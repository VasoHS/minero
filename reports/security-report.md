# Reporte de seguridad

_Generado: 2026-10-18T12:56:37+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


## Crítica/alta

No se registran hallazgos de severidad crítica o alta en la evidencia proporcionada. [TR-001] [TR-002] [TR-003]

## Media

No se registran hallazgos de severidad media. [TR-001] [TR-002] [TR-003]

## Baja/informativa

### Artefactos generados versionados

- **Qué se observó:** `results-sbom.json`, `results-vuln.json` y `results.json` están versionados aunque son artefactos generados. [TR-001] [TR-002] [TR-003]
- **Por qué importa:** No hay evidencia en el JSON sobre su contenido. Por tanto, no puede confirmarse si contienen datos sensibles ni si deben permanecer en el repositorio; conservar artefactos generados innecesarios puede aumentar el tamaño del repositorio y exponer información que no debería versionarse. [TR-001] [TR-002] [TR-003]
- **Mitigación concreta:** Revisar el contenido de los tres archivos y decidir si deben formar parte del repositorio. Si no son necesarios, eliminarlos del control de versiones y añadirlos a `.gitignore`; si contienen información sensible, retirarla y aplicar los controles correspondientes. [TR-001] [TR-002] [TR-003]

La verificación de secretos en archivos no ignorados por Git reportó cero hallazgos; con la evidencia disponible no hay base para recomendar la revocación de credenciales. [TR-001] [TR-002] [TR-003]

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
