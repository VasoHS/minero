# Métricas del Analyzer

Este documento describe las métricas implementadas en `analysis/metrics.py`.
Todas las funciones son **puras y deterministas** (solo librería estándar, sin
`pandas`) y consumen las tablas planas de `analysis.loader.to_records` y el
reporte normalizado `analysis.loader.MinerReport`.

## Convenciones

- **Denominadores.** Los conteos de vulnerabilidades usan la lista plana
  `records["vulnerabilities"]` (una fila por vulnerabilidad), no el campo
  `vuln_total`. Así `top_cves`, `top_packages`, `concentration` y
  `repository_distribution` comparten denominador.
- **Orden canónico de severidad.** `Critical`, `High`, `Medium`, `Low`,
  `Negligible`, `Unknown` (de más a menos grave). "Peor severidad" = la de
  menor índice.
- **Redondeo.** Las fracciones e índices se redondean a 4 decimales; `-0.0` se
  normaliza a `0.0`.
- **Orden de salida.** Las listas se ordenan por conteo descendente y luego por
  clave ascendente (desempate estable); los diccionarios de estado, por clave.

---

## 1. Cobertura — `compute_coverage(report)`

| Campo | Pregunta que responde | Fórmula / denominador | Interpretación |
| --- | --- | --- | --- |
| `repositories_total` | ¿Cuántos repositorios trae el reporte? | `len(report.repositories)` | Base de todos los porcentajes por repositorio. |
| `by_repo_status` | ¿Cómo se distribuyen los estados de repositorio? | Conteo de `repo.status`, claves ordenadas | Muestra fallos de clonado/análisis (`clone_failed`, `db_failed`, …). |
| `by_vuln_status` | ¿Cuántos repos completaron Grype? | Conteo de `repo.vuln_status` | `scanned`/`no_vulnerabilities` = éxito; `failed`/`skipped` reducen cobertura. |
| `by_sbom_status` | ¿Cuántos repos generaron SBOM? | Conteo de `repo.sbom_status` | `generated`/`no_components` = éxito. |
| `unsupported` | ¿Cuántos repos quedaron fuera por no soportados? | Conteo de `status == "unsupported"` | Sesga a la baja los totales. |
| `vuln_failed` | ¿Cuántos fallaron en Grype? | Conteo de `vuln_status == "failed"` | Sus vulnerabilidades no están representadas. |
| `sbom_failed` | ¿Cuántos fallaron al generar SBOM? | Conteo de `sbom_status == "failed"` | Inventario de componentes incompleto. |
| `coverage_ratio` | ¿Qué fracción tiene al menos un análisis exitoso? | `cubiertos / repositories_total` | Éxito si `status == "analyzed"` **o** `vuln_status ∈ {scanned, no_vulnerabilities}` **o** `sbom_status ∈ {generated, no_components}`. `0.0` si no hay repos. |
| `warnings` | ¿Qué advertencias aplican? | `report.warnings` + avisos por `unsupported`/`vuln_failed`/`sbom_failed` | Lista de strings lista para mostrar. |

---

## 2. Severidad global — `compute_severity_distribution(records)`

| Campo | Pregunta | Fórmula / denominador | Interpretación |
| --- | --- | --- | --- |
| `[{severity, count}]` | ¿Cómo se reparte la gravedad? | Conteo por `vulnerability.severity` / total de vulnerabilidades | Incluye las 6 severidades canónicas con ceros, en orden canónico. Permite calcular el peso de High+Critical. |

---

## 3. Frecuencia por tipo

### 3.1 Top reglas CodeQL — `compute_top_rules(records, limit=20)`

| Campo | Pregunta | Fórmula / denominador | Interpretación |
| --- | --- | --- | --- |
| `rule_id` | ¿Qué regla aparece más? | Agrupación por `finding.rule_id` | Identifica patrones de código recurrentes. |
| `count` | ¿Cuántos hallazgos? | Nº de filas del grupo / total de hallazgos | Volumen de la regla. |
| `repos_affected` | ¿En cuántos repos? | Nº de `repo` distintos del grupo | Alcance organizacional de la regla. |

### 3.2 Top CVEs/GHSA — `compute_top_cves(records, limit=20)`

| Campo | Pregunta | Fórmula / denominador | Interpretación |
| --- | --- | --- | --- |
| `id` | ¿Qué identificador se repite más? | Agrupación por `vulnerability.id` | Un mismo CVE puede aparecer en varios paquetes/repos. |
| `severity` | ¿Qué gravedad tiene? | Peor severidad observada del `id` | Orden canónico. |
| `count` | ¿Cuántas apariciones? | Nº de filas del grupo | Frecuencia. |
| `repos_affected` | ¿En cuántos repos? | Nº de `repo` distintos | Propagación del CVE. |

### 3.3 Top paquetes — `compute_top_packages(records, limit=20)`

| Campo | Pregunta | Fórmula / denominador | Interpretación |
| --- | --- | --- | --- |
| `package` | ¿Qué dependencia acumula más vulnerabilidades? | Agrupación por `vulnerability.package` | Candidata a actualización prioritaria. |
| `count` | ¿Cuántas vulnerabilidades? | Nº de filas del grupo | Volumen. |
| `repos_affected` | ¿En cuántos repos? | Nº de `repo` distintos | Reutilización del paquete. |
| `worst_severity` | ¿Cuál es el peor caso? | Peor severidad del grupo | Prioriza paquetes con Critical/High. |

---

## 4. Distribución por repositorio — `compute_repository_distribution(report)`

| Campo | Pregunta | Fórmula / denominador | Interpretación |
| --- | --- | --- | --- |
| `repo` | ¿Qué repositorio? | Nombre | Orden alfabético. |
| `vulnerabilities` | ¿Cuántas vulnerabilidades tiene? | `len(repo.vulnerabilities)` | Cuadra con la tabla plana. |
| `findings` | ¿Cuántos hallazgos CodeQL tiene? | `len(repo.findings)` | — |
| `components` | ¿Cuántos componentes aporta su SBOM? | `repo.sbom_components` | 0 si SBOM omitido o fallido. |
| `status` | ¿En qué estado terminó? | `repo.status` | Contextualiza los ceros. |

---

## 5. Concentración — `compute_concentration(records, top_n=3)`

| Campo | Pregunta | Fórmula / denominador | Interpretación |
| --- | --- | --- | --- |
| `repositories_with_vulns` | ¿Cuántos repos tienen vulnerabilidades? | Nº de repos con ≥1 fila | Base del decil. |
| `top_n` | — | Parámetro `top_n` | Reproducibilidad. |
| `top_n_share` | ¿Cuánto acumulan los N repos más afectados? | `sum(top_n counts) / total` (0..1) | Cerca de 1 ⇒ alta concentración. |
| `top_10pct_share` | ¿Cuánto acumula el decil superior? | `sum(top k counts) / total`, con `k = max(1, ceil(n·0.10))` | Concentración robusta al tamaño. |
| `hhi` | ¿Cómo de repartidas están? | `Σ (count_i / total)²` (0..1) | 1.0 con un solo repo; tiende a 0 al repartirse. |

`top_n_share`, `top_10pct_share` y `hhi` valen `0.0` si no hay vulnerabilidades.

---

## 6. Relaciones — `compute_relations(report, records)`

| Campo | Pregunta | Fórmula / denominador | Interpretación |
| --- | --- | --- | --- |
| `components_vs_vulnerabilities.pearson` | ¿A más componentes, más vulnerabilidades? | Pearson poblacional entre `sbom_components` y `vuln_total` por repo | `null` si `n < 2` o alguna varianza es 0. **Correlación ≠ causalidad.** |
| `components_vs_vulnerabilities.n` | ¿Con cuántos repos se calculó? | Nº de repositorios | Tamaño de muestra. |
| `fixed_version_available_share` | ¿Hay corrección disponible? | Vulnerabilidades con `fixed_version` no vacío / total | Alto ⇒ fácil de remediar. |
| `severity_by_package_type` | ¿La gravedad depende del ecosistema? | Conteo por `(type, severity)` | Compara tipos de paquete; `type` nulo ⇒ `"unknown"`. |
| `findings_by_language` | ¿Qué lenguajes concentran reglas? | Conteo por `(language, rule_id)`; **cada lenguaje del repo cuenta una vez por hallazgo** | Repos multi-lenguaje duplican el hallazgo por lenguaje. |

---

## 7. Observaciones — `build_observations(report, coverage, datasets)`

Lista de dicts `{"id", "title", "statement", "metric", "evidence"}`. Cada
observación cita cifras concretas en `evidence` tomadas de `coverage` y
`datasets`. Solo se emiten las dimensiones con datos:

1. Cobertura del análisis.
2. Sesgo por estados fallidos (solo si existen).
3. Severidad y peso de High/Critical.
4. Distribución entre repositorios (con/sin vulnerabilidades).
5. Concentración top-N / decil / HHI.
6. Paquetes más afectados.
7. Identificadores (CVE/GHSA) más frecuentes.
8. Reglas CodeQL más frecuentes.
9. Disponibilidad de versión corregida.
10. Correlación componentes ↔ vulnerabilidades (solo si es calculable).
11. Hallazgos por lenguaje.
12. Severidad por tipo de paquete.

---

## 8. Limitaciones — `build_limitations(report, coverage)`

Lista de strings que siempre declara:

- **Secciones ausentes** (cuando aplica): sin `findings`, sin
  `vulnerabilities`, sin SBOM con componentes.
- **Estados fallidos / no soportados** y cobertura < 100 %.
- **Inconsistencias de conteo**: filas de detalle vs `vuln_total` vs `summary`.
- **Advertencias del cargador** (`report.warnings`).
- **Correlación ≠ causalidad** (siempre).
- **Muestras pequeñas** (`repositories_total < 30`): alta incertidumbre.

---

## Limitaciones generales

- **Cobertura parcial.** Un `coverage_ratio` < 1 significa que los totales no
  describen a toda la organización; los repos `unsupported`, `clone_failed`,
  `db_failed` y los fallos de SBOM/Grype sesgan los resultados a la baja.
- **Correlación no implica causalidad.** La relación entre número de
  componentes y vulnerabilidades puede estar confundida por el tamaño o el
  ecosistema del repositorio.
- **Muestras pequeñas.** Con pocos repositorios, las proporciones, el HHI y las
  correlaciones tienen alta incertidumbre y no deben generalizarse.
- **Secciones opcionales.** Un reporte de `miner vuln` no trae `findings` ni
  SBOM; uno de `miner sbom` no trae vulnerabilidades. Las métricas de cada
  dimensión solo existen si la sección correspondiente está presente.
- **Atribución por lenguaje.** `findings_by_language` cuenta cada hallazgo una
  vez por cada lenguaje declarado en el repositorio; los repos sin lenguajes
  declarados no atribuyen sus hallazgos.
