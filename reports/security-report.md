# Reporte de seguridad

_Generado: 2026-10-21T14:19:12+00:00_  
_Hallazgos detectados: 11 (con modelo de lenguaje)_


## Crítica

### Dependencia `certifi`

- **Qué se observó:** El SBOM reporta la vulnerabilidad **GHSA-6q48-6c7w-9gw2** en `certifi` **2026.7.22`; la corrección indicada es `2026.10.19` [VUL-001].
- **Por qué importa:** Se trata de una vulnerabilidad conocida con severidad crítica en una dependencia incluida en el repositorio [VUL-001].
- **Mitigación:** Actualizar `certifi` al menos a `2026.10.19`, regenerar el SBOM y repetir el análisis de dependencias para confirmar la corrección [VUL-001].

### Dependencia `pillow`

- **Qué se observó:** El SBOM reporta **GHSA-8g5g-8vmr-9782** en `pillow` **12.3.0`; la corrección indicada es `13.0.0` [VUL-002].
- **Por qué importa:** La dependencia contiene una vulnerabilidad conocida con severidad crítica [VUL-002].
- **Mitigación:** Actualizar `pillow` al menos a `13.0.0`, validar la compatibilidad de la aplicación y repetir el análisis de dependencias [VUL-002].

## Alta

### Vulnerabilidades adicionales en `pillow`

- **Qué se observó:** El SBOM reporta las vulnerabilidades **GHSA-58r4-6rv3-gfh8**, **GHSA-65qm-jvmh-6pqg**, **GHSA-c6hw-5grf-ff96**, **GHSA-p4wg-p73j-c528**, **GHSA-pchr-8j38-3x4p** y **GHSA-q45j-58j2-45rg** en `pillow` **12.3.0`; para todas se indica como versión corregida `13.0.0` [VUL-003] [VUL-004] [VUL-005] [VUL-006] [VUL-007] [VUL-008].
- **Por qué importa:** Estas vulnerabilidades conocidas tienen severidad alta y afectan a la misma versión de `pillow` [VUL-003] [VUL-004] [VUL-005] [VUL-006] [VUL-007] [VUL-008].
- **Mitigación:** Actualizar `pillow` a `13.0.0` o posterior, realizar pruebas funcionales y repetir el escaneo para verificar que no permanezcan estos identificadores [VUL-003] [VUL-004] [VUL-005] [VUL-006] [VUL-007] [VUL-008].

## Media

No se registran hallazgos de severidad media en la evidencia proporcionada [VUL-001] [VUL-002] [VUL-003] [VUL-004] [VUL-005] [VUL-006] [VUL-007] [VUL-008].

## Baja / Informativa

### Artefactos generados versionados

- **Qué se observó:** `results-sbom.json`, `results-vuln.json` y `results.json` aparecen como artefactos generados versionados [TR-001] [TR-002] [TR-003].
- **Por qué importa:** El hallazgo requiere revisar si esos artefactos deben permanecer en el repositorio y si contienen datos sensibles; el JSON no aporta evidencia suficiente para confirmar que contengan información sensible [TR-001] [TR-002] [TR-003].
- **Mitigación:** Inspeccionar el contenido de los tres archivos, confirmar si su versionado es necesario y, si no lo es, eliminarlos del repositorio y añadirlos a `.gitignore`; si deben conservarse, limitar su contenido a información no sensible [TR-001] [TR-002] [TR-003].

No se recomienda revocar credenciales, porque estos hallazgos no identifican un posible secreto en un archivo no ignorado por Git [TR-001] [TR-002] [TR-003].

## Cobertura del análisis

| Verificación | Estado |
|---|---|
| secretos (archivos no ignorados por git) | ejecutado (0 hallazgos) |
| workflows | ejecutado (0 hallazgos) |
| docker (Dockerfile y .devcontainer/Dockerfile) | ejecutado (0 hallazgos) |
| higiene (.gitignore) | ejecutado (0 hallazgos) |
| archivos versionados | ejecutado (3 hallazgos) |
| lockfile | ejecutado (0 hallazgos) |
| dependencias (Syft+Grype) | ejecutado (69 componentes, 10 vulnerabilidades en total) |

## Apéndice: evidencia

| ID | Severidad | Archivo | Línea | Regla | Evidencia |
|---|---|---|---|---|---|
| TR-001 | info | `results-sbom.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-002 | info | `results-vuln.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-003 | info | `results.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| VUL-001 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-6q48-6c7w-9gw2 en certifi 2026.7.22; corregido en 2026.10.19 |
| VUL-002 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-8g5g-8vmr-9782 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-003 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-58r4-6rv3-gfh8 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-004 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-65qm-jvmh-6pqg en pillow 12.3.0; corregido en 13.0.0 |
| VUL-005 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-c6hw-5grf-ff96 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-006 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-p4wg-p73j-c528 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-007 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-pchr-8j38-3x4p en pillow 12.3.0; corregido en 13.0.0 |
| VUL-008 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-q45j-58j2-45rg en pillow 12.3.0; corregido en 13.0.0 |
