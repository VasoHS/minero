# Reporte de seguridad

_Generado: 2026-10-28T15:42:06+00:00_  
_Hallazgos detectados: 23 (con modelo de lenguaje)_


# Hallazgos de severidad crítica/alta

## Dependencias vulnerables

- **Certifi 2026.7.22 — severidad crítica [VUL-001]**
  - **Qué se observó:** El SBOM identifica la vulnerabilidad **GHSA-6q48-6c7w-9gw2** en `certifi` 2026.7.22; la corrección indicada es la versión 2026.10.18 [VUL-001].
  - **Por qué importa:** La dependencia contiene una vulnerabilidad conocida y la versión instalada no es la versión corregida indicada [VUL-001].
  - **Mitigación:** Actualizar `certifi` a 2026.10.18 o posterior compatible, regenerar el lockfile y repetir el análisis de dependencias [VUL-001].

- **Pillow 12.3.0 — vulnerabilidades críticas [VUL-002], [VUL-003], [VUL-004], [VUL-005], [VUL-006]**
  - **Qué se observó:** Se identificaron cinco vulnerabilidades GHSA en `pillow` 12.3.0, todas con corrección indicada en Pillow 13.0.0 [VUL-002] [VUL-003] [VUL-004] [VUL-005] [VUL-006].
  - **Por qué importa:** El uso de una versión afectada expone al software a vulnerabilidades conocidas de severidad crítica [VUL-002] [VUL-003] [VUL-004] [VUL-005] [VUL-006].
  - **Mitigación:** Actualizar Pillow a 13.0.0 o posterior, validar compatibilidad de la aplicación y repetir el escaneo [VUL-002] [VUL-003] [VUL-004] [VUL-005] [VUL-006].

- **Pillow 12.3.0 — vulnerabilidades altas [VUL-007]–[VUL-020]**
  - **Qué se observó:** Se identificaron vulnerabilidades GHSA de severidad alta en Pillow 12.3.0; para todas las incluidas en el análisis, la corrección indicada es Pillow 13.0.0 [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019] [VUL-020].
  - **Por qué importa:** La versión utilizada contiene múltiples vulnerabilidades conocidas de severidad alta [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019] [VUL-020].
  - **Mitigación:** Actualizar Pillow a 13.0.0 o posterior y verificar que no queden restricciones de dependencia que mantengan la versión 12.3.0 [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019] [VUL-020].

La cobertura indica que el análisis de dependencias encontró **42 vulnerabilidades en total** y que solo se listan **20 de 29 vulnerabilidades críticas/altas**; por tanto, las vulnerabilidades críticas/altas restantes no pudieron evaluarse individualmente con la evidencia proporcionada [VUL-001] [VUL-020].

# Hallazgos de severidad media

No hay hallazgos de severidad media en la evidencia proporcionada.

# Hallazgos de severidad baja/informativa

## Artefactos generados versionados

- **`results-sbom.json`, `results-vuln.json` y `results.json` [TR-001] [TR-002] [TR-003]**
  - **Qué se observó:** Los tres archivos son artefactos generados y están versionados en el repositorio [TR-001] [TR-002] [TR-003].
  - **Por qué importa:** La evidencia no confirma que contengan datos sensibles, pero deben revisarse para determinar si su contenido debe permanecer en el repositorio y evitar exposición accidental o ruido de artefactos generados [TR-001] [TR-002] [TR-003].
  - **Mitigación:** Inspeccionar el contenido, confirmar que no incluya datos sensibles y decidir si deben mantenerse versionados; si no son necesarios, eliminarlos del repositorio y añadirlos al `.gitignore` [TR-001] [TR-002] [TR-003].

No se recomienda revocar credenciales por estos hallazgos: la evidencia solo identifica artefactos generados versionados y no un posible secreto [TR-001] [TR-002] [TR-003].

## Cobertura del análisis

| Verificación | Estado |
|---|---|
| secretos (archivos no ignorados por git) | ejecutado (0 hallazgos) |
| workflows | ejecutado (0 hallazgos) |
| docker (Dockerfile y .devcontainer/Dockerfile) | ejecutado (0 hallazgos) |
| higiene (.gitignore) | ejecutado (0 hallazgos) |
| archivos versionados | ejecutado (3 hallazgos) |
| lockfile | ejecutado (0 hallazgos) |
| dependencias (Syft+Grype) | ejecutado (69 componentes, 42 vulnerabilidades en total); se listan 20 de 29 Critical/High |

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
