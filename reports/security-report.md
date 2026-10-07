# Reporte de seguridad

_Generado: 2026-10-07T23:58:51+00:00_  
_Hallazgos detectados: 11 (con modelo de lenguaje)_


# Hallazgos de Seguridad

## Severidad Media
- **Hallazgos relacionados con scripts remotos ejecutados sin verificar integridad**:
  - Se observó que se están ejecutando scripts remotos desde URLs sin verificar su integridad [WF-003], [WF-004]. Esto es importante porque ejecutar scripts de fuentes no verificadas puede introducir vulnerabilidades en el sistema, permitiendo la ejecución de código malicioso.
  - **Mitigación**: Se recomienda verificar la integridad de los scripts descargados utilizando hashes o firmas digitales antes de su ejecución.

- **Hallazgo relacionado con dependencias no fijadas**:
  - Se observó que no hay un lockfile ni un archivo de requirements con versiones resueltas en `pyproject.toml` [DEP-001]. Esto es relevante porque las dependencias no fijadas pueden resultar en builds no reproducibles y un escaneo de CVEs limitado.
  - **Mitigación**: Se sugiere crear un lockfile y especificar versiones de dependencias en el archivo de configuración para asegurar la reproducibilidad y facilitar el escaneo de vulnerabilidades.

## Severidad Baja
- **Hallazgos relacionados con acciones no fijadas a un SHA de commit**:
  - Se observó que varias acciones en el archivo `.github/workflows/security-report.yml` no están fijadas a un SHA de commit [WF-001], [WF-002], [WF-005]. Esto es importante porque usar versiones de acciones sin fijar puede llevar a la ejecución de código no intencionado si la acción se actualiza.
  - **Mitigación**: Se recomienda fijar las acciones a un SHA de commit específico para evitar cambios inesperados en el comportamiento de las mismas.

## Informativa
- **Hallazgos relacionados con artefactos generados versionados**:
  - Se observó que varios artefactos generados están versionados, incluyendo `results-sbom.json`, `results-vuln.json`, `resultsTensorFlow.json`, `resultsTensorFlow2.json` y `sboms1.zip` [TR-001], [TR-002], [TR-003], [TR-004], [TR-005]. Es importante revisar estos artefactos para asegurarse de que no contengan datos sensibles y determinar si deben estar en el repositorio.
  - **Mitigación**: Se sugiere realizar una revisión de contenido de estos artefactos para asegurar que no contengan información sensible y evaluar su necesidad en el repositorio.

## Cobertura del análisis

| Verificación | Estado |
|---|---|
| secretos (archivos no ignorados por git) | ejecutado (0 hallazgos) |
| workflows | ejecutado (5 hallazgos) |
| docker (solo Dockerfile de la raíz) | ejecutado (0 hallazgos) |
| higiene (.gitignore) | ejecutado (0 hallazgos) |
| archivos versionados | ejecutado (5 hallazgos) |
| lockfile | ejecutado (1 hallazgos) |
| dependencias (Syft+Grype) | ejecutado (4 componentes, 0 vulnerabilidades en total) |

## Apéndice: evidencia

| ID | Severidad | Archivo | Línea | Regla | Evidencia |
|---|---|---|---|---|---|
| WF-001 | low | `.github/workflows/security-report.yml` | 15 | acción no fijada a un SHA de commit | - uses: actions/checkout@v4 |
| WF-002 | low | `.github/workflows/security-report.yml` | 17 | acción no fijada a un SHA de commit | - uses: actions/setup-python@v5 |
| WF-003 | medium | `.github/workflows/security-report.yml` | 24 | script remoto ejecutado sin verificar integridad | curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin v1.51.0 |
| WF-004 | medium | `.github/workflows/security-report.yml` | 25 | script remoto ejecutado sin verificar integridad | curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin v0.120.0 |
| WF-005 | low | `.github/workflows/security-report.yml` | 38 | acción no fijada a un SHA de commit | - uses: actions/upload-artifact@v4 |
| TR-001 | info | `results-sbom.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-002 | info | `results-vuln.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-003 | info | `resultsTensorFlow.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-004 | info | `resultsTensorFlow2.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-005 | info | `sboms1.zip` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| DEP-001 | medium | `pyproject.toml` | - | las dependencias no están fijadas: builds no reproducibles y escaneo de CVEs limitado | no hay lockfile ni requirements con versiones resueltas |
