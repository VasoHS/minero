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
- **Pesos de severidad.** La nota 1-10 y los agregados de gravedad usan pesos
  fijos: `Critical=10`, `High=7`, `Medium=4`, `Low=2`, `Negligible=1`,
  `Unknown=0`. Son una decisión metodológica explícita, no una medida oficial de
  explotabilidad.
- **Redondeo.** Las fracciones e índices se redondean a 4 decimales; la nota
  1-10 y `mean_repository_score`, a 1 decimal. `-0.0` se normaliza a `0.0`.
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
| `repo_failed` | ¿Cuántos fallaron en fases previas? | Conteo de `status ∈ FAILED_STATUSES` (`clone_failed`, `db_failed`, `analyze_failed`, `invalid_name`) | Sin análisis de código; sus hallazgos no están representados. |
| `vuln_failed` | ¿Cuántos fallaron en Grype? | Conteo de `vuln_status == "failed"` | Sus vulnerabilidades no están representadas. |
| `sbom_failed` | ¿Cuántos fallaron al generar SBOM? | Conteo de `sbom_status == "failed"` | Inventario de componentes incompleto. |
| `coverage_ratio` | ¿Qué fracción tiene **al menos un** análisis exitoso? | `cubiertos / repositories_total` | Éxito si `status == "analyzed"` **o** `vuln_status ∈ VULN_OK_STATUSES` **o** `sbom_status ∈ SBOM_OK_STATUSES`. No significa cobertura de las tres dimensiones. `0.0` si no hay repos. |
| `code_coverage_ratio` | ¿Qué fracción tiene análisis de código? | Nº de `status == "analyzed"` / total | Ratio por dimensión; desambigua `coverage_ratio`. |
| `sbom_coverage_ratio` | ¿Qué fracción generó SBOM? | Nº de `sbom_status ∈ SBOM_OK_STATUSES` / total | Ratio por dimensión. |
| `vuln_coverage_ratio` | ¿Qué fracción completó Grype? | Nº de `vuln_status ∈ VULN_OK_STATUSES` / total | Ratio por dimensión. |
| `warnings` | ¿Qué advertencias aplican? | `report.warnings` + avisos por `unsupported`/`repo_failed`/`vuln_failed`/`sbom_failed` | Lista de strings lista para mostrar; los fallos de fase previa detallan el estado. |

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

## 5. Riesgo por repositorio — `compute_repository_risk(report)`

Una fila por repositorio, **también los que no tienen vulnerabilidades**
(quedan con `score = 1.0`). Ordenado por `score` descendente, luego por
`severity_weighted_average` descendente y por `repo` ascendente.

### 5.1 Nota de vulnerabilidad 1-10

La nota resume la **gravedad media** de las vulnerabilidades, no su volumen. Se
calcula en dos pasos:

1. **Peso por severidad** (0..10), según la tabla fija de `SEVERITY_WEIGHTS`.
2. **Reescalado lineal a `[1, 10]`**: con media de pesos `avg` (0..10),
   `score = 1 + 9 · (avg / 10)`, redondeado a 1 decimal. Así una media de 10
   (todas `Critical`) da `10.0`, y una media de 0 (todas `Unknown` o sin
   vulnerabilidades) da `1.0`.

| Severidad | Peso |
| --- | --- |
| `Critical` | 10 |
| `High` | 7 |
| `Medium` | 4 |
| `Low` | 2 |
| `Negligible` | 1 |
| `Unknown` (o inválida) | 0 |

| Campo | Pregunta que responde | Fórmula / denominador | Interpretación |
| --- | --- | --- | --- |
| `repo` | ¿Qué repositorio? | Nombre | Ordenado por gravedad, no alfabéticamente. |
| `status` | ¿En qué estado terminó? | `repo.status` | Contextualiza los ceros (`unsupported`, `clone_failed`, …). |
| `languages` | ¿Qué lenguajes declara? | `list(repo.languages)` | Base de `severity_by_language`. |
| `vulnerabilities` | ¿Cuántas vulnerabilidades tiene? | `len(repo.vulnerabilities)` | Cuadra con la tabla plana. |
| `findings` | ¿Cuántos hallazgos CodeQL tiene? | `len(repo.findings)` | Vale `0` si CodeQL no se ejecutó (`status != "analyzed"`): significa **"no evaluado"**, no "limpio". |
| `components` | ¿Cuántos componentes aporta su SBOM? | `repo.sbom_components` | 0 si el SBOM se omitió o falló. |
| `critical` | ¿Cuántas Critical? | Nº de vulnerabilidades `Critical` | Hotspot si `> 0`. |
| `high` | ¿Cuántas High? | Nº de vulnerabilidades `High` | — |
| `worst_severity` | ¿Cuál es el peor caso? | Peor severidad del repositorio | `Unknown` si no hay vulnerabilidades. |
| `severity_weighted_average` | ¿Qué gravedad media tiene? | Media de los pesos (0..10), 4 decimales | `0.0` sin vulnerabilidades. |
| `severity_median` | ¿Y la mediana? | Mediana de los pesos (0..10), 4 decimales | `0.0` sin vulnerabilidades. |
| `score` | ¿Qué nota 1-10 obtiene? | `1 + 9 · (severity_weighted_average / 10)`, 1 decimal | **Obligatorio**, rango `[1, 10]`; `1.0` sin vulnerabilidades. Mide gravedad media, no volumen. |
| `vulns_per_component` | ¿Cuántas vulnerabilidades por componente? | `vulnerabilities / components`, 4 decimales; `null` si `components == 0` | Densidad comparable entre repos de distinto tamaño. |
| `findings_per_component` | ¿Y hallazgos por componente? | `findings / components`, 4 decimales; `null` si `components == 0` | Vale `0.0` si CodeQL no se ejecutó: **"no evaluado"**, no "limpio". |
| `fixed_version_share` | ¿Qué fracción tiene corrección? | Vulnerabilidades con `fixed_version` no vacío / `vulnerabilities`, 4 decimales; `null` si no hay vulnerabilidades | Cerca de 1 ⇒ más fácil de remediar. |

---

## 6. Resumen global de riesgo — `compute_risk_summary(report, repository_risk)`

Objeto que agrega el riesgo de toda la organización a partir del ranking por
repositorio. A diferencia de `repository_risk.score` (siempre en `[1, 10]`), los
campos numéricos de `risk_summary` están en `[0, 10]` y pueden ser `0.0` cuando
no hay repositorios puntuados.

| Campo | Pregunta que responde | Fórmula / denominador | Interpretación |
| --- | --- | --- | --- |
| `score` | ¿Qué nota 1-10 global tiene la organización? | Misma fórmula 1-10 sobre **todas** las vulnerabilidades | **Ponderado por volumen**: un repo con muchas Critical pesa más. Puede diferir de `mean_repository_score`. |
| `severity_weighted_average` | ¿Qué gravedad media global hay? | Media de los pesos de todas las vulnerabilidades (0..10) | `0.0` sin vulnerabilidades. |
| `severity_median` | ¿Y la mediana global? | Mediana de los pesos de todas las vulnerabilidades (0..10) | `0.0` sin vulnerabilidades. |
| `total_vulnerabilities` | ¿Cuántas vulnerabilidades hay? | `len` de todas las filas de detalle | Denominador de los agregados. |
| `repositories_scored` | ¿Cuántos repos entran en la nota media? | Nº de repos con ≥ 1 vulnerabilidad | Excluye los repos sin vulnerabilidades. |
| `repositories_with_critical` | ¿Cuántos repos tienen Critical? | Nº de repos con `critical > 0` | Hotspots de máxima gravedad. |
| `repositories_with_high_or_critical` | ¿Y High o Critical? | Nº de repos con `critical + high > 0` | — |
| `mean_repository_score` | ¿Cuál es la nota media por repo? | Media de los `score` de repos **con** vulnerabilidades, 1 decimal; `0.0` si no hay ninguno | No ponderada por volumen. |
| `max_repository_score` | ¿Cuál es la peor nota por repo? | Máximo de los `score` de repos con vulnerabilidades; `0.0` si no hay ninguno | Repositorio más grave. |
| `critical_hotspots` | ¿Qué repos son hotspots Critical? | Nombres de repos con `critical > 0`, ordenados alfabéticamente | Lista (posiblemente vacía). |
| `worst_severity` | ¿Cuál es la peor severidad global? | Peor severidad de todas las vulnerabilidades | `Unknown` sin vulnerabilidades. |

---

## 7. Concentración — `compute_concentration(records, top_n=3)`

| Campo | Pregunta | Fórmula / denominador | Interpretación |
| --- | --- | --- | --- |
| `repositories_with_vulns` | ¿Cuántos repos tienen vulnerabilidades? | Nº de repos con ≥1 fila | Base del decil. |
| `top_n` | ¿Sobre cuántos repos se calculó el top? | `min(top_n_solicitado, repositories_with_vulns)` | Valor **efectivo**; evita contar repos inexistentes. |
| `top_n_share` | ¿Cuánto acumulan los N repos más afectados? | `sum(top_n counts) / total` (0..1) | Cerca de 1 ⇒ alta concentración. |
| `top_10pct_share` | ¿Cuánto acumula el decil superior? | `sum(top k counts) / total`, con `k = max(1, ceil(n·0.10))` | Concentración robusta al tamaño. |
| `hhi` | ¿Cómo de repartidas están? | `Σ (count_i / total)²` (0..1) | 1.0 con un solo repo; tiende a 0 al repartirse. |

`top_n_share`, `top_10pct_share` y `hhi` valen `0.0` si no hay vulnerabilidades
(y entonces `top_n` es `0`). Con pocos repositorios afectados (< 5) el top-N y
el decil son poco informativos; se emite una limitación específica.

---

## 8. Relaciones — `compute_relations(report, records)`

| Campo | Pregunta | Fórmula / denominador | Interpretación |
| --- | --- | --- | --- |
| `components_vs_vulnerabilities.pearson` | ¿A más componentes, más vulnerabilidades? | Pearson poblacional entre `sbom_components` y `vuln_total` por repo | `null` si `n < 2` o alguna varianza es 0. **Correlación ≠ causalidad.** |
| `components_vs_vulnerabilities.n` | ¿Con cuántos repos se calculó? | Nº de repositorios | Tamaño de muestra. |
| `fixed_version_available_share` | ¿Hay corrección disponible? | Vulnerabilidades con `fixed_version` no vacío / total | Alto ⇒ fácil de remediar. |
| `severity_by_package_type` | ¿La gravedad depende del ecosistema? | Conteo por `(type, severity)` | Compara tipos de paquete; `type` nulo ⇒ `"unknown"`. |
| `findings_by_language` | ¿Qué lenguajes concentran reglas? | Conteo por `(language, rule_id)`; **cada lenguaje del repo cuenta una vez por hallazgo** | Ordenado por lenguaje, luego `count` desc y regla. Está **desagregado**: para elegir el lenguaje con más hallazgos hay que sumar los `count` por lenguaje. Repos multi-lenguaje duplican el hallazgo por lenguaje. |
| `severity_by_language` | ¿Qué severidades se asocian a cada lenguaje? | Conteo por `(language, severity)`; **cada lenguaje del repo cuenta la vulnerabilidad una vez** | Ordenado por lenguaje y severidad canónica. Los repos multi-lenguaje **duplican** la vulnerabilidad por lenguaje, por lo que los conteos por lenguaje **no suman** el total global. |

---

## 9. Observaciones — `build_observations(report, coverage, datasets)`

Lista de dicts `{"id", "title", "statement", "metric", "evidence"}`. Cada
observación cita cifras concretas en `evidence` tomadas de `coverage` y
`datasets`. Solo se emiten las dimensiones con datos:

1. **Cobertura del análisis.** Declara explícitamente "al menos un análisis
   exitoso" e incluye `code_coverage_ratio`, `sbom_coverage_ratio` y
   `vuln_coverage_ratio` en `evidence`.
2. **Sesgo por estados fallidos** (solo si existen): `unsupported`,
   `repo_failed`, `vuln_failed` y `sbom_failed`.
3. **Severidad y peso de High/Critical.**
4. **Distribución entre repositorios** (con/sin vulnerabilidades).
5. **Concentración top-N / decil / HHI** (con el `top_n` efectivo acotado).
6. **Paquetes más afectados.** Indica "top `limit` de `N` paquetes distintos",
   no el total implícito.
7. **Identificadores (CVE/GHSA) más frecuentes.** "top `limit` de `N`
   identificadores distintos" (`N` en `evidence`).
8. **Reglas CodeQL más frecuentes.** "top `limit` de `N` reglas distintas".
9. **Disponibilidad de versión corregida.** El conteo se calcula directamente
   sumando filas con `fixed_version` (no redondeando la fracción).
10. **Correlación componentes ↔ vulnerabilidades** (solo si es calculable).
11. **Hallazgos por lenguaje.** El líder se elige por la **suma** de `count`
    por lenguaje (desempate alfabético), no por el primer elemento del dataset.
12. **Severidad por tipo de paquete.**
13. **Nota global de vulnerabilidad (gravedad media).** Cita
    `datasets.risk_summary` (nota, media ponderada, peor severidad y
    `mean_repository_score`). Solo se emite si hay vulnerabilidades.
14. **Repositorios con mayor gravedad media.** Ranking de
    `datasets.repository_risk`; encabeza el de mayor `score` (gravedad media, no
    volumen) y declara cuántos de los repositorios tienen vulnerabilidades.
15. **Densidad de vulnerabilidades.** Líder por `vulns_per_component` entre los
    repos **con vulnerabilidades** y componentes
    (`datasets.repository_risk.vulns_per_component`).
16. **Repositorios con vulnerabilidades Critical.** Hotspots de
    `datasets.risk_summary.critical_hotspots` y cuántos tienen High o Critical.
17. **Severidad de vulnerabilidades por lenguaje.** Combinaciones
    `(lenguaje, severidad)` de `relations.severity_by_language`.

Las observaciones se numeran `OBS-01`, `OBS-02`, … en orden de emisión; con
datos completos las cinco nuevas ocupan las posiciones 13-17.

---

## 10. Limitaciones — `build_limitations(report, coverage)`

Lista de strings que siempre declara:

- **Secciones ausentes** (cuando aplica): sin `findings`, sin
  `vulnerabilities`, sin SBOM con componentes.
- **Estados fallidos / no soportados** y cobertura < 100 %: `unsupported`,
  `repo_failed` (con detalle de los estados de `FAILED_STATUSES` presentes en
  `by_repo_status`), `vuln_failed` y `sbom_failed`.
- **Inconsistencias de conteo**: filas de detalle vs `vuln_total`, `by_severity`
  vs filas de detalle, y `summary` vs filas de detalle.
- **Concentración degenerada**: con menos de 5 repositorios con
  vulnerabilidades, el top-N y el decil son poco informativos.
- **Nota 1-10 con pesos fijos**: la nota, la media ponderada y la mediana de
  severidad resumen la gravedad media, no el volumen ni la explotabilidad real,
  y **no sustituyen** una priorización basada en CVSS, EPSS o KEV.
- **Densidad no calculable**: los repos con vulnerabilidades pero sin
  componentes de SBOM quedan fuera del ranking de `vulns_per_component`.
- **Atribución múltiple por lenguaje**: los repos multi-lenguaje duplican cada
  vulnerabilidad en `severity_by_language`, por lo que sus conteos no suman el
  total global.
- **Sin lenguajes declarados**: si ningún repositorio declara lenguajes, no puede
  calcularse la severidad de vulnerabilidades por lenguaje.
- **Hallazgos no evaluados**: `findings` y `findings_per_component` valen `0`
  cuando CodeQL no se ejecutó (`status != "analyzed"`), lo que significa "no
  evaluado", no "limpio".
- **Advertencias del cargador** (`report.warnings`).
- **Correlación ≠ causalidad** (siempre).
- **Muestras pequeñas** (`repositories_total < 30`): alta incertidumbre.

---

## Limitaciones generales

- **Cobertura parcial.** Un `coverage_ratio` < 1 significa que los totales no
  describen a toda la organización. Como `coverage_ratio` cuenta "al menos una
  dimensión con éxito", conviene mirar `code_coverage_ratio`,
  `sbom_coverage_ratio` y `vuln_coverage_ratio` por separado; los repos
  `unsupported`, los de `FAILED_STATUSES` (`clone_failed`, `db_failed`,
  `analyze_failed`, `invalid_name`) y los fallos de SBOM/Grype sesgan los
  resultados a la baja.
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
  declarados no atribuyen sus hallazgos. Del mismo modo, `severity_by_language`
  cuenta cada vulnerabilidad una vez por lenguaje, así que los conteos por
  lenguaje no suman el total global.
- **Gravedad frente a explotabilidad.** La nota 1-10, `severity_weighted_average`
  y `severity_median` usan pesos fijos por severidad y miden **gravedad media**,
  no volumen ni explotabilidad; no sustituyen CVSS, EPSS o KEV.
- **Densidad dependiente del SBOM.** `vulns_per_component` y
  `findings_per_component` son `null` cuando el repositorio no tiene componentes
  de SBOM, por lo que esos repos quedan fuera del ranking de densidad.
