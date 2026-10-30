# Reporte de seguridad

_Generado: 2026-10-30T15:29:51+00:00_  
_Hallazgos detectados: 23 (con modelo de lenguaje)_


## Crítica

### Vulnerabilidad en `certifi`

- **Qué se observó:** Se detectó la vulnerabilidad **GHSA-6q48-6c7w-9gw2** en `certifi` **2026.7.22`; la corrección indicada está disponible en `2026.10.18` [VUL-001].
- **Por qué importa:** La dependencia contiene una vulnerabilidad conocida identificada por Grype y debe considerarse un riesgo crítico hasta su actualización [VUL-001].
- **Mitigación:** Actualizar `certifi` a `2026.10.18` o posterior, regenerar el SBOM y volver a ejecutar el análisis de dependencias [VUL-001].

### Vulnerabilidades en `pillow`

- **Qué se observó:** `pillow` **12.3.0** presenta cinco vulnerabilidades críticas: **GHSA-332p-7hrc-92wf**, **GHSA-5x8w-8jj5-q52h**, **GHSA-8g5g-8vmr-9782**, **GHSA-v9pv-5gc8-w2m6** y **GHSA-w889-685w-c8fh** [VUL-002][VUL-003][VUL-004][VUL-005][VUL-006].
- **Por qué importa:** Se trata de vulnerabilidades conocidas en una dependencia actualmente incluida en el SBOM; su presencia justifica una remediación prioritaria [VUL-002][VUL-003][VUL-004][VUL-005][VUL-006].
- **Mitigación:** Actualizar `pillow` a **13.0.0** o posterior, validar la compatibilidad de la aplicación y repetir el análisis de dependencias [VUL-002][VUL-003][VUL-004][VUL-005][VUL-006].

## Alta

### Vulnerabilidades adicionales en `pillow`

- **Qué se observó:** `pillow` **12.3.0** presenta las vulnerabilidades de alta severidad **GHSA-22hg-r758-rrw9**, **GHSA-27h8-gf7j-v5hc**, **GHSA-3j72-p6qg-6xp7**, **GHSA-58r4-6rv3-gfh8**, **GHSA-5xm2-6676-qcp9**, **GHSA-65qm-jvmh-6pqg**, **GHSA-78g4-xqwv-q3g8**, **GHSA-7mwm-ghpf-9vrm**, **GHSA-9v9v-9qvf-h2hj**, **GHSA-c6hw-5grf-ff96**, **GHSA-cp9v-662q-vvx9**, **GHSA-f2g6-542v-9j58**, **GHSA-g4qv-2jxx-769h** y **GHSA-g7cr-3p24-7wf7** [VUL-007][VUL-008][VUL-009][VUL-010][VUL-011][VUL-012][VUL-013][VUL-014][VUL-015][VUL-016][VUL-017][VUL-018][VUL-019][VUL-020].
- **Por qué importa:** La misma versión de `pillow` concentra múltiples vulnerabilidades conocidas de alta severidad, por lo que mantenerla aumenta la superficie de riesgo del proyecto [VUL-007][VUL-008][VUL-009][VUL-010][VUL-011][VUL-012][VUL-013][VUL-014][VUL-015][VUL-016][VUL-017][VUL-018][VUL-019][VUL-020].
- **Mitigación:** Actualizar `pillow` a **13.0.0** o posterior; si la actualización no es inmediatamente viable, evaluar una alternativa soportada y documentar una excepción temporal con controles compensatorios [VUL-007][VUL-008][VUL-009][VUL-010][VUL-011][VUL-012][VUL-013][VUL-014][VUL-015][VUL-016][VUL-017][VUL-018][VUL-019][VUL-020].

## Media

No hay hallazgos de severidad media en la evidencia proporcionada.

## Baja / informativa

### Artefactos generados versionados

- **Qué se observó:** Los artefactos generados `results-sbom.json`, `results-vuln.json` y `results.json` están versionados en el repositorio [TR-001][TR-002][TR-003].
- **Por qué importa:** El hallazgo requiere revisar si esos artefactos contienen datos sensibles y si su permanencia en el repositorio es necesaria; el JSON no aporta evidencia suficiente para confirmar que contengan información sensible [TR-001][TR-002][TR-003].
- **Mitigación:** Inspeccionar el contenido de los tres archivos, retirar cualquier dato sensible si existe y decidir si deben permanecer versionados; si son resultados reproducibles, valorar excluirlos mediante `.gitignore` y conservarlos únicamente como artefactos de CI [TR-001][TR-002][TR-003].

No se recomienda revocar credenciales por estos hallazgos, ya que no se identificó un posible secreto en un archivo no ignorado por Git [TR-001][TR-002][TR-003].

## Cobertura del análisis

| Verificación | Estado |
|---|---|
| secretos (archivos no ignorados por git) | ejecutado (0 hallazgos) |
| workflows | ejecutado (0 hallazgos) |
| docker (Dockerfile y .devcontainer/Dockerfile) | ejecutado (0 hallazgos) |
| higiene (.gitignore) | ejecutado (0 hallazgos) |
| archivos versionados | ejecutado (3 hallazgos) |
| lockfile | ejecutado (0 hallazgos) |
| dependencias (Syft+Grype) | ejecutado (69 componentes, 45 vulnerabilidades en total); se listan 20 de 29 Critical/High |

## Apéndice: evidencia

| ID | Severidad | Archivo | Línea | Regla | Evidencia |
|---|---|---|---|---|---|
| TR-001 | info | `results-sbom.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-002 | info | `results-vuln.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-003 | info | `results.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| VUL-001 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-6q48-6c7w-9gw2 en certifi 2026.7.22; corregido en 2026.10.18 |
| VUL-002 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-332p-7hrc-92wf en pillow 12.3.0; corregido en 13.0.0 |
| VUL-003 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-5x8w-8jj5-q52h en pillow 12.3.0; corregido en 13.0.0 |
| VUL-004 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-8g5g-8vmr-9782 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-005 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-v9pv-5gc8-w2m6 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-006 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-w889-685w-c8fh en pillow 12.3.0; corregido en 13.0.0 |
| VUL-007 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-22hg-r758-rrw9 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-008 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-27h8-gf7j-v5hc en pillow 12.3.0; corregido en 13.0.0 |
| VUL-009 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-3j72-p6qg-6xp7 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-010 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-58r4-6rv3-gfh8 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-011 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-5xm2-6676-qcp9 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-012 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-65qm-jvmh-6pqg en pillow 12.3.0; corregido en 13.0.0 |
| VUL-013 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-78g4-xqwv-q3g8 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-014 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-7mwm-ghpf-9vrm en pillow 12.3.0; corregido en 13.0.0 |
| VUL-015 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-9v9v-9qvf-h2hj en pillow 12.3.0; corregido en 13.0.0 |
| VUL-016 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-c6hw-5grf-ff96 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-017 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-cp9v-662q-vvx9 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-018 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-f2g6-542v-9j58 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-019 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-g4qv-2jxx-769h en pillow 12.3.0; corregido en 13.0.0 |
| VUL-020 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-g7cr-3p24-7wf7 en pillow 12.3.0; corregido en 13.0.0 |
