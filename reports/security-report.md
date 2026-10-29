# Reporte de seguridad

_Generado: 2026-10-29T15:48:14+00:00_  
_Hallazgos detectados: 23 (con modelo de lenguaje)_


# Hallazgos

## Crítica/alta

### Vulnerabilidades críticas en dependencias

- **Certifi 2026.7.22:** el SBOM reporta la vulnerabilidad **GHSA-6q48-6c7w-9gw2**, corregida en **2026.10.18** [VUL-001]. Esto importa porque la dependencia instalada está asociada a una vulnerabilidad conocida. **Mitigación:** actualizar `certifi` a la versión **2026.10.18** o posterior compatible y volver a ejecutar el análisis [VUL-001].

- **Pillow 12.3.0:** el SBOM reporta las vulnerabilidades **GHSA-332p-7hrc-92wf**, **GHSA-5x8w-8jj5-q52h**, **GHSA-8g5g-8vmr-9782**, **GHSA-v9pv-5gc8-w2m6** y **GHSA-w889-685w-c8fh**, todas corregidas en **13.0.0** [VUL-002] [VUL-003] [VUL-004] [VUL-005] [VUL-006]. Esto importa porque una misma versión de una dependencia concentra varias vulnerabilidades conocidas. **Mitigación:** actualizar `Pillow` a **13.0.0** o posterior compatible, validar la aplicación y regenerar el SBOM [VUL-002] [VUL-003] [VUL-004] [VUL-005] [VUL-006].

### Vulnerabilidades altas en Pillow

- **Pillow 12.3.0:** el SBOM reporta las vulnerabilidades **GHSA-22hg-r758-rrw9**, **GHSA-27h8-gf7j-v5hc**, **GHSA-3j72-p6qg-6xp7**, **GHSA-58r4-6rv3-gfh8**, **GHSA-5xm2-6676-qcp9**, **GHSA-65qm-jvmh-6pqg**, **GHSA-78g4-xqwv-q3g8**, **GHSA-7mwm-ghpf-9vrm**, **GHSA-9v9v-9qvf-h2hj**, **GHSA-c6hw-5grf-ff96**, **GHSA-cp9v-662q-vvx9**, **GHSA-f2g6-542v-9j58**, **GHSA-g4qv-2jxx-769h** y **GHSA-g7cr-3p24-7wf7**, corregidas en **13.0.0** [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019] [VUL-020]. Esto importa porque la dependencia mantiene múltiples vulnerabilidades de severidad alta. **Mitigación:** actualizar `Pillow` a **13.0.0** o posterior compatible y verificar regresiones funcionales [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019] [VUL-020].

- La cobertura indica que el análisis de dependencias encontró **45 vulnerabilidades en total** y que solo se listan **20 de 29 vulnerabilidades críticas/altas**; por tanto, las vulnerabilidades críticas/altas restantes no pueden evaluarse con el detalle disponible en este JSON [VUL-001] [VUL-002] [VUL-003] [VUL-004] [VUL-005] [VUL-006] [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019] [VUL-020].

## Media

No se reportan hallazgos de severidad media en el JSON recibido.

## Baja/informativa

### Artefactos generados versionados

- Se observaron como versionados los artefactos generados `results-sbom.json`, `results-vuln.json` y `results.json` [TR-001] [TR-002] [TR-003]. Esto importa porque el JSON no confirma si contienen datos sensibles ni si deben formar parte permanente del repositorio; por tanto, no hay evidencia suficiente para afirmar que exista una exposición de datos [TR-001] [TR-002] [TR-003]. **Mitigación:** revisar manualmente su contenido y necesidad de versionado; si no deben estar en el repositorio, eliminarlos del control de versiones y añadir las rutas correspondientes a `.gitignore` [TR-001] [TR-002] [TR-003].

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
