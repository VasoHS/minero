# Analyzer

El **Analyzer** transforma la evidencia cruda que produce el Miner en información
lista para el **Visualizer**. No vuelve a ejecutar CodeQL, Syft ni Grype: consume
los reportes JSON que ya generó la CLI, **los fusiona por repositorio** y los
convierte en métricas, observaciones y un documento estructurado, versionado y
autocontenido.

## Propósito y relación con el Miner y el Visualizer

```
Miner (CLI)                          Analyzer                             Visualizer
────────────                         ────────                             ──────────
miner scan ─► results.json ────┐
miner sbom ─► results-sbom.json ┼─► load_report(s) → merge_reports ─┐
miner vuln ─► results-vuln.json ┘   (fusión por repositorio)        │
                                                                     ▼
                     to_records → metrics → contract ─► analysis/outputs/analyzer_output.json
                                                        (datasets, observaciones, limitaciones,
                                                         CSV y figuras)
```

- El **Miner** genera tres tipos de reporte: `results.json` (`scan`),
  `results-vuln.json` (`vuln`) y `results-sbom.json` (`sbom`).
- El **Analyzer** acepta **uno o varios** reportes. Cuando recibe varios, los
  fusiona por nombre de repositorio con `merge_reports`: combina los componentes
  del SBOM con las vulnerabilidades de Grype, deduplica hallazgos y
  vulnerabilidades, conserva el mejor estado de SBOM/Grype y recalcula el
  resumen. Así, fusionar `results-sbom.json` con `results-vuln.json` permite
  calcular la correlación componentes↔vulnerabilidades sobre datos reales. El
  documento resultante queda con `source_kind` `merged`.
- El **Visualizer** consume ese documento (y no el código de los notebooks ni
  `metrics.py`). El contrato se detalla en
  [`contracts/README.md`](contracts/README.md).

## Instalación

El núcleo del Analyzer (`loader`, `metrics`, `contract`, `pipeline`) solo usa la
librería estándar y funciona con la instalación base del Miner. Para ejecutar los
notebooks y exportar CSV/figuras hace falta el extra `[analyzer]`:

```bash
pip install -e .[analyzer]
```

El extra añade `pandas`, `matplotlib`, `nbformat`, `nbclient` e `ipykernel`
(definido en `pyproject.toml`).

## Arquitectura

El flujo es siempre el mismo: `load_report(s) → merge_reports → to_records →
metrics → contract`. La lógica vive en módulos, de modo que se puede invocar
desde los notebooks, desde `pytest` o desde la CLI sin depender de Jupyter.

| Módulo | Responsabilidad |
| --- | --- |
| `analysis/loader.py` | Carga y normalización tolerante de los reportes del Miner (`load_report`, `to_records`) y fusión por repositorio (`merge_reports`). Solo librería estándar. |
| `analysis/metrics.py` | Métricas puras y deterministas: cobertura, severidad, topes, concentración, relaciones, observaciones y limitaciones. |
| `analysis/contract.py` | Ensamblado (`build_document`), validación (`validate_document`) y escritura (`write_document`) del documento de salida. |
| `analysis/pipeline.py` | Punto de entrada `run_analysis(input_paths, output_path)`; acepta una ruta o una lista y encadena todo el pipeline. |
| `analysis/contracts/` | JSON Schema (`analyzer_output.schema.json`), ejemplo válido y guía del contrato. |
| `analysis/METRICAS.md` | Referencia detallada de cada métrica, su fórmula y su interpretación. |
| `analysis/outputs/` | Salidas generadas (JSON, CSV y figuras); ignoradas por git. |

## Notebooks

Los notebooks documentan y verifican el pipeline paso a paso. Se ejecutan en
orden con:

```bash
python notebooks/execute.py
```

`notebooks/execute.py` recorre todos los `notebooks/*.ipynb` en orden
alfabético, usa el kernel `python3`, fija el directorio de trabajo en la raíz del
repositorio y devuelve un código de salida distinto de `0` si algún notebook
falla. Ejecuta primero el entorno virtual (`source .venv/bin/activate`) para que
el kernel use el intérprete correcto.

| Notebook | Qué hace | Escribe en disco |
| --- | --- | --- |
| `01_carga_y_calidad.ipynb` | Carga los reportes y los fusiona por repositorio, describe la organización y el origen, mide la cobertura y audita la calidad/coherencia de los datos. | No |
| `02_analisis_vulnerabilidades.ipynb` | Analiza severidad, CVE/GHSA, paquetes, distribución por repositorio, concentración y relaciones; muestra figuras inline. | No |
| `03_sintesis_visualizer.ipynb` | Ejecuta `run_analysis`, valida el contrato y exporta el documento, los CSV y las figuras. | Sí |

Cada notebook resuelve su `INPUT_PATHS` (lista) con esta regla: si existe
`results.json` (`scan`) usa solo ese; en caso contrario, fusiona los que existan
de `[results-sbom.json, results-vuln.json]`, en ese orden. `03` permite fijar
`meta.generated_at` con la variable de entorno `GENERATED_AT`; si no se define,
usa la hora real de ejecución:

```bash
GENERATED_AT="2026-01-01T00:00:00+00:00" .venv/bin/python notebooks/execute.py
```

## Entrada soportada

El Analyzer acepta uno o varios reportes del Miner y **no asume** que todas las
secciones estén presentes:

| Reporte(s) | Origen (`source_kind`) | Trae hallazgos CodeQL | Trae SBOM | Trae vulnerabilidades |
| --- | --- | --- | --- | --- |
| `results.json` | `scan` | Sí | Sí | Sí |
| `results-vuln.json` | `vuln` | No | No | Sí |
| `results-sbom.json` | `sbom` | No | Sí | No |
| Varios (p. ej. `results-sbom.json` + `results-vuln.json`) | `merged` | Según los reportes | Sí | Sí |

Comportamiento tolerante:

- Al pasar **varios** reportes se fusionan por repositorio (`merge_reports`):
  lenguajes, hallazgos y vulnerabilidades se unen con deduplicación; se conserva
  el mejor estado de SBOM y de Grype; y se recalculan `by_severity`,
  `vuln_total` y el `summary`. Un solo reporte se devuelve tal cual, sin
  recalcular.
- Un reporte sin `findings`, sin `vulnerabilities` o sin `sbom` se carga igual:
  las secciones ausentes quedan vacías y las métricas que dependen de ellas no se
  emiten.
- Las incoherencias de datos no se corrigen en silencio: se registran como
  advertencias en `meta.warnings` y como limitaciones.
- Si el archivo no existe, `load_report` lanza `FileNotFoundError`; si no es un
  objeto JSON válido, lanza `ValueError`. `run_analysis` exige al menos una ruta.

## Salida

Al ejecutar el notebook `03` (o `run_analysis` con `output_path`) se escribe:

```
analysis/outputs/
├── analyzer_output.json      # contrato validado (schema_version 1.1)
├── csv/                      # un CSV por dataset tabular + concentration/risk_summary/relations
└── figures/                  # figuras PNG de severidad, paquetes, CVE, repos y riesgo
```

Los nombres de los CSV coinciden con las claves de `datasets`; `concentration`,
`risk_summary` y `relations` (incluida `severity_by_language`) se aplanan en
archivos propios. Las figuras se omiten cuando no hay datos. Todo
`analysis/outputs/` está ignorado por git.

### Resumen del contrato

Documento de nivel superior (contrato completo en
[`contracts/README.md`](contracts/README.md) y en
`contracts/analyzer_output.schema.json`):

| Clave | Contenido |
| --- | --- |
| `schema_version` | Versión del contrato; actualmente `"1.1"` (1.1 es un cambio **aditivo** sobre 1.0: añade los datasets `repository_risk` y `risk_summary` y la relación `severity_by_language`). |
| `meta` | `organization`, `source`, `source_kind` (`scan`/`vuln`/`sbom`/`merged`/`unknown`), `generated_at`, `repositories`, `warnings`. Con varios reportes, `source` une los nombres (`results-sbom.json + results-vuln.json`). |
| `summary` | Bloque `summary` del Miner; con varios reportes se recalcula a partir de la fusión. |
| `coverage` | `repositories_total` (obligatoria) y `by_repo_status`, `by_vuln_status`, `by_sbom_status`, `unsupported`, `repo_failed`, `vuln_failed`, `sbom_failed`, `coverage_ratio`, `code_coverage_ratio`, `sbom_coverage_ratio`, `vuln_coverage_ratio`, `warnings`. |
| `datasets` | Datasets tabulares y objetos de apoyo (ver abajo). |
| `observations` | Lista de `{id, title, statement, metric, evidence}`; cada afirmación cita cifras verificables. |
| `limitations` | Lista de limitaciones que condicionan las conclusiones. |

Invariantes que valida `validate_document`:

- `schema_version == "1.1"`.
- `meta.repositories == len(datasets["repositories"])`.
- `coverage.repositories_total == meta.repositories`.
- Todos los datasets presentes y con los tipos esperados; severidades dentro de
  `Critical, High, Medium, Low, Negligible, Unknown`; conteos `>= 0`.
- Cada observación tiene sus 5 claves y un `id` único.

Catálogo de datasets:

| Dataset | Granularidad (fila =) | Columnas clave |
| --- | --- | --- |
| `repositories` | un repositorio | `repo`, `full_name`, `url`, `commit`, `status`, `languages`, `sbom_status`, `sbom_components`, `vuln_status`, `vuln_total`, `findings_total` |
| `findings` | un hallazgo de CodeQL | `repo`, `rule_id`, `severity` (nivel SARIF), `file`, `start_line` |
| `vulnerabilities` | una vulnerabilidad de Grype | `repo`, `id`, `severity`, `package`, `version`, `type`, `fixed_version`, `namespace` |
| `severity_distribution` | una severidad (global) | `severity`, `count` |
| `severity_by_repo` | un par (repo, severidad) | `repo`, `severity`, `count` |
| `top_rules` | una regla de CodeQL | `rule_id`, `count`, `repos_affected` |
| `top_cves` | un identificador CVE/GHSA | `id`, `severity`, `count`, `repos_affected` |
| `top_packages` | un paquete afectado | `package`, `count`, `repos_affected`, `worst_severity` |
| `repository_distribution` | un repositorio | `repo`, `vulnerabilities`, `findings`, `components`, `status` |
| `repository_risk` | un repositorio | `repo`, `status`, `languages`, `vulnerabilities`, `findings`, `components`, `critical`, `high`, `worst_severity`, `severity_weighted_average`, `severity_median`, `score` (obligatorio, 1-10), `vulns_per_component`, `findings_per_component`, `fixed_version_share` |
| `concentration` | objeto (no tabular) | `repositories_with_vulns`, `top_n`, `top_n_share`, `top_10pct_share`, `hhi` |
| `risk_summary` | objeto (no tabular) | `score`, `severity_weighted_average`, `severity_median`, `total_vulnerabilities`, `repositories_scored`, `repositories_with_critical`, `repositories_with_high_or_critical`, `mean_repository_score`, `max_repository_score`, `critical_hotspots`, `worst_severity` |
| `relations` | objeto (no tabular) | `components_vs_vulnerabilities`, `fixed_version_available_share`, `severity_by_package_type`, `findings_by_language`, `severity_by_language` |

### Uso programático

```python
from analysis.pipeline import run_analysis

# Una ruta: analiza ese reporte. Varias: se fusionan por repositorio.
document = run_analysis(
    ["results-sbom.json", "results-vuln.json"],
    "analysis/outputs/analyzer_output.json",
)
```

`run_analysis` acepta una ruta o una lista de rutas. Con varias, fusiona la
evidencia por repositorio antes de analizar (`source_kind` queda como `merged`).
Devuelve el documento validado y, si se indica `output_path`, lo escribe en UTF-8
con JSON indentado. Acepta `generated_at` para fijar la marca temporal en
ejecuciones reproducibles.

## Métricas

El Analyzer calcula, entre otras: cobertura global (`coverage_ratio`) y por
dimensión (`code_coverage_ratio`, `sbom_coverage_ratio`, `vuln_coverage_ratio`),
el recuento de repos fallidos en fases previas (`repo_failed`), distribución de
severidad, topes de reglas/CVE/paquetes, distribución y concentración por
repositorio (cuota top-N, decil superior, HHI), y relaciones (componentes vs
vulnerabilidades, disponibilidad de corrección, severidad por tipo de paquete,
hallazgos por lenguaje y severidad por lenguaje).

Además, desde la versión 1.1 del contrato incorpora el **riesgo por
repositorio** y la **nota de vulnerabilidad 1-10**: `repository_risk` puntúa cada
repositorio con una nota 1-10 (gravedad media con pesos fijos `Critical=10`,
`High=7`, `Medium=4`, `Low=2`, `Negligible=1`, `Unknown=0`), su densidad
(`vulns_per_component`, `findings_per_component`) y su reparabilidad
(`fixed_version_share`); `risk_summary` agrega la nota global (ponderada por
volumen), los hotspots Critical y las notas media y máxima por repositorio. La
referencia completa —fórmulas, denominadores e interpretación— está en
[`METRICAS.md`](METRICAS.md).

## Limitaciones y buenas prácticas

- **Determinismo.** Las métricas son puras y ordenan sus salidas de forma estable.
  El único valor no determinista es `meta.generated_at`; fíjalo con
  `generated_at` o `GENERATED_AT` si necesitas reproducibilidad byte a byte.
- **Correlación ≠ causalidad.** La correlación entre componentes del SBOM y
  vulnerabilidades puede estar confundida por el tamaño o el ecosistema del
  repositorio. No la interpretes como causa.
- **Muestras pequeñas.** Con pocos repositorios, las proporciones, el HHI y las
  correlaciones tienen alta incertidumbre y no deben generalizarse.
- **Cobertura parcial.** Un `coverage_ratio` menor que `1` significa que los
  totales no describen a toda la organización: los repos `unsupported`,
  `clone_failed`, `db_failed` y los fallos de SBOM/Grype sesgan los resultados a
  la baja. Revisa siempre `coverage` y `limitations`.
- **Secciones opcionales.** Un reporte de `miner vuln` no trae `findings` ni
  SBOM, y uno de `miner sbom` no trae vulnerabilidades; las métricas de cada
  dimensión solo existen si la sección correspondiente está presente.
