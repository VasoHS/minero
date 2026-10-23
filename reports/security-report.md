# Reporte de seguridad

_Generado: 2026-10-23T14:01:17+00:00_  
_Hallazgos detectados: 23 (con modelo de lenguaje)_


## Crítica / alta

### Vulnerabilidades conocidas en dependencias

- Se detectó una vulnerabilidad crítica **GHSA-6q48-6c7w-9gw2** en `certifi` **2026.7.22`; la evidencia indica que está corregida en **2026.10.19** [VUL-001]. Esto puede exponer al componente a la condición de seguridad asociada a esa vulnerabilidad. Mitigación: actualizar `certifi` a **2026.10.19** o una versión posterior compatible y volver a ejecutar el análisis [VUL-001].

- Se detectaron cuatro vulnerabilidades críticas en `pillow` **12.3.0**: **GHSA-332p-7hrc-92wf**, **GHSA-8g5g-8vmr-9782**, **GHSA-v9pv-5gc8-w2m6** y **GHSA-w889-685w-c8fh**; la evidencia indica que se corrigen en `pillow` **13.0.0** [VUL-002][VUL-003][VUL-004][VUL-005]. Mitigación: actualizar `pillow` a **13.0.0** o posterior, validar compatibilidad de la aplicación y repetir el escaneo [VUL-002][VUL-003][VUL-004][VUL-005].

- Se detectaron quince vulnerabilidades de severidad alta en `pillow` **12.3.0**, identificadas como **GHSA-22hg-r758-rrw9**, **GHSA-27h8-gf7j-v5hc**, **GHSA-3j72-p6qg-6xp7**, **GHSA-58r4-6rv3-gfh8**, **GHSA-5xm2-6676-qcp9**, **GHSA-65qm-jvmh-6pqg**, **GHSA-78g4-xqwv-q3g8**, **GHSA-7mwm-ghpf-9vrm**, **GHSA-9v9v-9qvf-h2hj**, **GHSA-c6hw-5grf-ff96**, **GHSA-cp9v-662q-vvx9**, **GHSA-f2g6-542v-9j58**, **GHSA-g4qv-2jxx-769h**, **GHSA-g7cr-3p24-7wf7** y **GHSA-g842-9rc4-69pw** [VUL-006][VUL-007][VUL-008][VUL-009][VUL-010][VUL-011][VUL-012][VUL-013][VUL-014][VUL-015][VUL-016][VUL-017][VUL-018][VUL-019][VUL-020]. La evidencia indica que todas se corrigen en `pillow` **13.0.0** [VUL-006][VUL-007][VUL-008][VUL-009][VUL-010][VUL-011][VUL-012][VUL-013][VUL-014][VUL-015][VUL-016][VUL-017][VUL-018][VUL-019][VUL-020]. Mitigación: actualizar `pillow` a **13.0.0** o posterior, realizar pruebas de regresión y confirmar que las vulnerabilidades desaparecen del SBOM [VUL-006][VUL-007][VUL-008][VUL-009][VUL-010][VUL-011][VUL-012][VUL-013][VUL-014][VUL-015][VUL-016][VUL-017][VUL-018][VUL-019][VUL-020].

- La cobertura de dependencias indica **40 vulnerabilidades en total** y que solo se listan **20 de 28** vulnerabilidades críticas/altas [VUL-001][VUL-002][VUL-003][VUL-004][VUL-005][VUL-006][VUL-007][VUL-008][VUL-009][VUL-010][VUL-011][VUL-012][VUL-013][VUL-014][VUL-015][VUL-016][VUL-017][VUL-018][VUL-019][VUL-020]. Por tanto, no se pudo verificar mediante los detalles proporcionados cuáles son las otras ocho vulnerabilidades críticas o altas ni sus versiones afectadas. Mitigación: revisar el informe completo de Grype y priorizar también esas ocho vulnerabilidades [VUL-001][VUL-020].

## Media

- No se registraron hallazgos de severidad media en la evidencia proporcionada [VUL-001][VUL-020].

## Baja / informativa

### Artefactos generados versionados

- `results-sbom.json`, `results-vuln.json` y `results.json` aparecen como artefactos generados versionados [TR-001][TR-002][TR-003]. Esto importa porque dichos archivos podrían contener datos sensibles o resultados internos, aunque la evidencia disponible **no es suficiente para confirmar** que contengan información sensible [TR-001][TR-002][TR-003]. Mitigación: revisar su contenido y necesidad de permanencia en el repositorio; si no deben versionarse, eliminarlos del control de versiones, añadirlos a `.gitignore` y evitar que vuelvan a generarse como cambios versionados [TR-001][TR-002][TR-003].

- La verificación de secretos en archivos no ignorados por Git terminó con **0 hallazgos**, por lo que no hay evidencia en este análisis de un posible secreto que requiera recomendar revocación de credenciales [TR-001][TR-002][TR-003]. Esto no confirma que el contenido de los artefactos versionados sea apropiado ni sustituye la revisión manual indicada [TR-001][TR-002][TR-003].

## Cobertura del análisis

| Verificación | Estado |
|---|---|
| secretos (archivos no ignorados por git) | ejecutado (0 hallazgos) |
| workflows | ejecutado (0 hallazgos) |
| docker (Dockerfile y .devcontainer/Dockerfile) | ejecutado (0 hallazgos) |
| higiene (.gitignore) | ejecutado (0 hallazgos) |
| archivos versionados | ejecutado (3 hallazgos) |
| lockfile | ejecutado (0 hallazgos) |
| dependencias (Syft+Grype) | ejecutado (69 componentes, 40 vulnerabilidades en total); se listan 20 de 28 Critical/High |

## Apéndice: evidencia

| ID | Severidad | Archivo | Línea | Regla | Evidencia |
|---|---|---|---|---|---|
| TR-001 | info | `results-sbom.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-002 | info | `results-vuln.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| TR-003 | info | `results.json` | - | revisar que no contenga datos sensibles y si debe estar en el repo | artefacto generado versionado |
| VUL-001 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-6q48-6c7w-9gw2 en certifi 2026.7.22; corregido en 2026.10.19 |
| VUL-002 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-332p-7hrc-92wf en pillow 12.3.0; corregido en 13.0.0 |
| VUL-003 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-8g5g-8vmr-9782 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-004 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-v9pv-5gc8-w2m6 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-005 | critical | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-w889-685w-c8fh en pillow 12.3.0; corregido en 13.0.0 |
| VUL-006 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-22hg-r758-rrw9 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-007 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-27h8-gf7j-v5hc en pillow 12.3.0; corregido en 13.0.0 |
| VUL-008 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-3j72-p6qg-6xp7 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-009 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-58r4-6rv3-gfh8 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-010 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-5xm2-6676-qcp9 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-011 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-65qm-jvmh-6pqg en pillow 12.3.0; corregido en 13.0.0 |
| VUL-012 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-78g4-xqwv-q3g8 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-013 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-7mwm-ghpf-9vrm en pillow 12.3.0; corregido en 13.0.0 |
| VUL-014 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-9v9v-9qvf-h2hj en pillow 12.3.0; corregido en 13.0.0 |
| VUL-015 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-c6hw-5grf-ff96 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-016 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-cp9v-662q-vvx9 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-017 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-f2g6-542v-9j58 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-018 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-g4qv-2jxx-769h en pillow 12.3.0; corregido en 13.0.0 |
| VUL-019 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-g7cr-3p24-7wf7 en pillow 12.3.0; corregido en 13.0.0 |
| VUL-020 | high | `(SBOM del repositorio)` | - | vulnerabilidad conocida en dependencia (Grype) | GHSA-g842-9rc4-69pw en pillow 12.3.0; corregido en 13.0.0 |
