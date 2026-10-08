# Reporte de seguridad

_Generado: 2026-10-08T16:02:50+00:00_  
_Hallazgos detectados: 3 (con modelo de lenguaje)_


# Hallazgos de Seguridad

## Baja/Informativa

### Artefactos Generados Versionados
Se han identificado varios artefactos generados que están versionados en el repositorio. Estos son:
- [TR-001]: `results-sbom.json`
- [TR-002]: `results-vuln.json`
- [TR-003]: `results.json`

**Observación:** Estos archivos son artefactos generados y podrían contener datos sensibles.  
**Importancia:** Es crucial revisar estos archivos para asegurarse de que no contengan información sensible que no deba estar expuesta en el repositorio.  
**Mitigación:** Realizar una revisión de contenido de estos archivos y, si es necesario, considerar su eliminación del repositorio o su exclusión mediante `.gitignore` si no deben ser versionados.

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
