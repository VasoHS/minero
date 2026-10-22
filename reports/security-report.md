# Reporte de seguridad

_Generado: 2026-10-22T14:18:17+00:00_  
_Hallazgos detectados: 23 (con modelo de lenguaje)_


> **Nota:** el modelo no comentó estos hallazgos (ver apéndice): ['VUL-020'].

# Informe de hallazgos

## Crítica / alta

### Vulnerabilidades críticas en dependencias

- Se identificó una vulnerabilidad crítica **GHSA-6q48-6c7w-9gw2** en `certifi` versión `2026.7.22`; la corrección indicada está disponible en `2026.10.19` [VUL-001]. Esto puede exponer al repositorio o a sus consumidores a riesgos asociados con una dependencia vulnerable. **Mitigación:** actualizar `certifi` al menos a `2026.10.19` y regenerar el SBOM para verificar el resultado [VUL-001].
- Se identificaron tres vulnerabilidades críticas en `pillow` versión `12.3.0`: **GHSA-332p-7hrc-92wf**, **GHSA-8g5g-8vmr-9782** y **GHSA-w889-685w-c8fh**; la corrección indicada es `13.0.0` [VUL-002] [VUL-003] [VUL-004]. La permanencia de esa versión mantiene expuesta la dependencia a vulnerabilidades conocidas. **Mitigación:** actualizar `pillow` al menos a `13.0.0`, revisar compatibilidad de la aplicación y regenerar el SBOM [VUL-002] [VUL-003] [VUL-004].

### Vulnerabilidades altas en `pillow`

- Se identificaron vulnerabilidades altas en `pillow` versión `12.3.0`, correspondientes a **GHSA-22hg-r758-rrw9**, **GHSA-27h8-gf7j-v5hc**, **GHSA-58r4-6rv3-gfh8**, **GHSA-5xm2-6676-qcp9**, **GHSA-65qm-jvmh-6pqg**, **GHSA-7mwm-ghpf-9vrm**, **GHSA-c6hw-5grf-ff96**, **GHSA-cp9v-662q-vvx9**, **GHSA-f2g6-542v-9j58**, **GHSA-gg2r-wvfm-q9rx**, **GHSA-j4m9-6w36-pw47**, **GHSA-jg86-v3jv-hrpm**, **GHSA-p4wg-p73j-c528**, **GHSA-pchr-8j38-3x4p**, **GHSA-q45j-58j2-45rg** y **GHSA-xvh5-g6gv-559v** [VUL-005] [VUL-006] [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019].
- La versión corregida indicada para todos esos avisos es `pillow 13.0.0`; mantener `12.3.0` conserva múltiples vulnerabilidades conocidas en la misma dependencia [VUL-005] [VUL-006] [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019].
- **Mitigación:** actualizar `pillow` a `13.0.0` o posterior, ejecutar las pruebas de compatibilidad y volver a generar el análisis de dependencias [VUL-005] [VUL-006] [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019].

## Media

No se reportan hallazgos de severidad media en la evidencia recibida [VUL-001] [VUL-005].

## Baja / informativa

### Artefactos generados versionados

- `results-sbom.json`, `results-vuln.json` y `results.json` aparecen como artefactos generados versionados [TR-001] [TR-002] [TR-003].
- Esto importa porque el JSON únicamente demuestra que están versionados y no permite determinar si contienen datos sensibles ni si deben permanecer en el repositorio; por tanto, no hay evidencia suficiente para confirmar exposición de información sensible [TR-001] [TR-002] [TR-003].
- **Mitigación:** revisar el contenido de los tres archivos y decidir explícitamente si deben versionarse; si no son necesarios, eliminarlos del repositorio y añadirlos a `.gitignore` o al mecanismo equivalente de exclusión [TR-001] [TR-002] [TR-003].
- No se recomienda revocar credenciales basándose en estos hallazgos, porque no se identificó un posible secreto; la evidencia solo indica que son artefactos generados versionados [TR-001] [TR-002] [TR-003].

## Cobertura del análisis

| Verificación | Estado |
|---|---|
| secretos (archivos no ignorados por git) | ejecutado (0 hallazgos) |
| workflows | ejecutado (0 hallazgos) |
| docker (Dockerfile y .devcontainer/Dockerfile) | ejecutado (0 hallazgos) |
| higiene (.gitignore) | ejecutado (0 hallazgos) |
| archivos versionados | ejecutado (3 hallazgos) |
| lockfile | ejecutado (0 hallazgos) |
| dependencias (Syft+Grype) | ejecutado (69 componentes, 29 vulnerabilidades en total) |

## Apéndice: evidencia

| ID | Severidad | Archivo | Línea | Regla | Evidencia |
|---|---|---|---|---|---|
| TR-001 | info | `results-sbom.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-002 | info | `results-vuln.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-003 | info | `results.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| VUL-001 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-6q48-6c7w-9gw2 en certifi 2026.7.22; corregido en 2026.10.19 |
| VUL-002 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-332p-7hrc-92wf en pillow 12.3.0; corregido en 13.0.0 |
| VUL-003 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-8g5g-8vmr-9782 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-004 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-w889-685w-c8fh en pillow 12.3.0; corregido en 13.0.0 |
| VUL-005 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-22hg-r758-rrw9 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-006 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-27h8-gf7j-v5hc en pillow 12.3.0; corregido en 13.0.0 |
| VUL-007 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-58r4-6rv3-gfh8 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-008 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-5xm2-6676-qcp9 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-009 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-65qm-jvmh-6pqg en pillow 12.3.0; corregido en 13.0.0 |
| VUL-010 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-7mwm-ghpf-9vrm en pillow 12.3.0; corregido en 13.0.0 |
| VUL-011 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-c6hw-5grf-ff96 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-012 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-cp9v-662q-vvx9 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-013 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-f2g6-542v-9j58 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-014 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-gg2r-wvfm-q9rx en pillow 12.3.0; corregido en 13.0.0 |
| VUL-015 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-j4m9-6w36-pw47 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-016 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-jg86-v3jv-hrpm en pillow 12.3.0; corregido en 13.0.0 |
| VUL-017 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-p4wg-p73j-c528 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-018 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-pchr-8j38-3x4p en pillow 12.3.0; corregido en 13.0.0 |
| VUL-019 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-q45j-58j2-45rg en pillow 12.3.0; corregido en 13.0.0 |
| VUL-020 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-xvh5-g6gv-559v en pillow 12.3.0; corregido en 13.0.0 |
