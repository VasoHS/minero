# Reporte de seguridad

_Generado: 2026-10-27T15:05:44+00:00_  
_Hallazgos detectados: 23 (con modelo de lenguaje)_


# Hallazgos de severidad crítica/alta

## Vulnerabilidades en dependencias

Se detectaron vulnerabilidades conocidas mediante Grype en dependencias incluidas en el SBOM:

- **`certifi 2026.7.22`** presenta la vulnerabilidad **GHSA-6q48-6c7w-9gw2**, corregida en `2026.10.18` [VUL-001].
- **`pillow 12.3.0`** presenta cinco vulnerabilidades críticas, corregidas en `13.0.0` [VUL-002] [VUL-003] [VUL-004] [VUL-005] [VUL-006].
- **`pillow 12.3.0`** presenta catorce vulnerabilidades de severidad alta, corregidas en `13.0.0` [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019] [VUL-020].

Esto importa porque las versiones identificadas están asociadas a vulnerabilidades conocidas y permanecen por debajo de las versiones indicadas como corregidas [VUL-001] [VUL-002] [VUL-003] [VUL-004] [VUL-005] [VUL-006] [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019] [VUL-020].

**Mitigación concreta:**

1. Actualizar `certifi` al menos a `2026.10.18` [VUL-001].
2. Actualizar `pillow` al menos a `13.0.0` [VUL-002] [VUL-003] [VUL-004] [VUL-005] [VUL-006] [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019] [VUL-020].
3. Regenerar el lockfile o manifiesto de dependencias y volver a ejecutar el análisis de dependencias para confirmar que las vulnerabilidades fueron resueltas [VUL-001] [VUL-002] [VUL-003] [VUL-004] [VUL-005] [VUL-006] [VUL-007] [VUL-008] [VUL-009] [VUL-010] [VUL-011] [VUL-012] [VUL-013] [VUL-014] [VUL-015] [VUL-016] [VUL-017] [VUL-018] [VUL-019] [VUL-020].

La cobertura indica que se encontraron 42 vulnerabilidades en total y que solo se listan 20 de las 29 vulnerabilidades críticas/altas; por tanto, las restantes vulnerabilidades críticas/altas no están detalladas en los hallazgos proporcionados y no pudieron evaluarse individualmente [VUL-001] [VUL-020].

# Hallazgos de severidad media

No se reportan hallazgos de severidad media en el JSON proporcionado [TR-001].

# Hallazgos de severidad baja/informativa

## Artefactos generados versionados

Se identificaron tres artefactos generados que están versionados en el repositorio: `results-sbom.json`, `results-vuln.json` y `results.json` [TR-001] [TR-002] [TR-003].

Esto importa porque la evidencia disponible no confirma si contienen datos sensibles ni si deben formar parte del repositorio; mantener resultados generados versionados puede introducir información no destinada a distribución o generar ruido en el control de cambios [TR-001] [TR-002] [TR-003].

**Mitigación concreta:**

- Revisar el contenido de los tres archivos para determinar si contienen datos sensibles y confirmar si su versionado es necesario [TR-001] [TR-002] [TR-003].
- Si no deben versionarse, eliminarlos del repositorio y añadir sus rutas a `.gitignore` [TR-001] [TR-002] [TR-003].
- Si deben conservarse, documentar su propósito y limitar su contenido a la información estrictamente necesaria [TR-001] [TR-002] [TR-003].

No hay evidencia en estos hallazgos de un secreto confirmado o posible en un archivo no ignorado por Git; por ello, no se recomienda revocar credenciales basándose en estos tres hallazgos [TR-001] [TR-002] [TR-003].

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
