# Analyzer

El **Analyzer** transforma la evidencia cruda que produce el Miner en información
lista para el **Visualizer**. No vuelve a ejecutar CodeQL, Syft ni Grype: consume
los reportes JSON que ya generó la CLI y los convierte en métricas, observaciones
y un documento estructurado, versionado y autocontenido.

## Propósito y relación con el Miner y el Visualizer

```
Miner (CLI)                    Analyzer                        Visualizer
────────────                   ────────                        ──────────
miner scan  ──► results.json ─┐
miner vuln  ──► results-vuln.json ─┼─► loader → metrics → contract ─► analysis/outputs/analyzer_output.json
miner sbom  ──► results-sbom.json ─┘        (notebooks + pipeline)        (datasets, observaciones,
                                                                          limitaciones, CSV y figuras)
```

- El **Miner** genera tres tipos de reporte: `results.json` (`scan`),
  `results-vuln.json` (`vuln`) y `results-sbom.json` (`sbom`).
- El **Analyzer** los carga de forma tolerante, calcula métricas y emite el
  contrato de salida `schema_version` `1.0`.
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

El flujo es siempre el mismo: `load_report → to_records → metrics → contract`. La
lógica vive en módulos, de modo que se puede invocar desde los notebooks, desde
`pytest` o desde la CLI sin depender de Jupyter.

| Módulo | Responsabilidad |
| --- | --- |
| `analysis/loader.py` | Carga y normalización tolerante de los reportes del Miner; `load_report` y `to_records`. Solo librería estándar. |
| `analysis/metrics.py` | Métricas puras y deterministas: cobertura, severidad, topes, concentración, relaciones, observaciones y limitaciones. |
| `analysis/contract.py` | Ensamblado (`build_document`), validación (`validate_document`) y escritura (`write_document`) del documento de salida. |
| `analysis/pipeline.py` | Punto de entrada `run_analysis(input, output)` que encadena todo el pipeline. |
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
| `01_carga_y_calidad.ipynb` | Carga el reporte, describe la organización y el origen, mide la cobertura y audita la calidad/coherencia de los datos. | No |
| `02_analisis_vulnerabilidades.ipynb` | Analiza severidad, CVE/GHSA, paquetes, distribución por repositorio, concentración y relaciones; muestra figuras inline. | No |
| `03_sintesis_visualizer.ipynb` | Ejecuta `run_analysis`, valida el contrato y exporta el documento, los CSV y las figuras. | Sí |

Cada notebook resuelve su `INPUT_PATH` con esta regla: `results.json` si existe;
en caso contrario, `results-vuln.json`. `03` permite fijar `meta.generated_at`
con la variable `GENERATED_AT` (por defecto, la hora real de ejecución).

## Entrada soportada

El Analyzer acepta cualquiera de los tres reportes del Miner y **no asume** que
todas las secciones estén presentes:

| Reporte | Origen (`source_kind`) | Trae hallazgos CodeQL | Trae SBOM | Trae vulnerabilidades |
| --- | --- | --- | --- | --- |
| `results.json` | `scan` | Sí | Sí | Sí |
| `results-vuln.json` | `vuln` | No | No | Sí |
| `results-sbom.json` | `sbom` | No | Sí | No |

Comportamiento tolerante:

- Un reporte sin `findings`, sin `vulnerabilities` o sin `sbom` se carga igual:
  las secciones ausentes quedan vacías y las métricas que dependen de ellas no se
  emiten.
- Las incoherencias de datos no se corrigen en silencio: se registran como
  advertencias en `meta.warnings` y como limitaciones.
- Si el archivo no existe, `load_report` lanza `FileNotFoundError`; si no es un
  objeto JSON válido, lanza `ValueError`.

## Salida

Al ejecutar el notebook `03` (o `run_analysis` con `output_path`) se escribe:

```
analysis/outputs/
├── analyzer_output.json      # contrato validado (schema_version 1.0)
├── csv/                      # un CSV por dataset tabular + concentration/relations
└── figures/                  # figuras PNG de severidad, paquetes, CVE y repos
```

Los nombres de los CSV coinciden con las claves de `datasets`; `concentration` y
`relations` se aplanan en archivos propios. Las figuras se omiten cuando no hay
datos. Todo `analysis/outputs/` está ignorado por git.

### Resumen del contrato

Documento de nivel superior (contrato completo en
[`contracts/README.md`](contracts/README.md) y en
`contracts/analyzer_output.schema.json`):

| Clave | Contenido |
| --- | --- |
| `schema_version` | Versión del contrato; actualmente `"1.0"`. |
| `meta` | `organization`, `source`, `source_kind` (`scan`/`vuln`/`sbom`/`unknown`), `generated_at`, `repositories`, `warnings`. |
| `summary` | Bloque `summary` del reporte del Miner, tal cual. |
| `coverage` | `repositories_total` (obligatoria) y `by_repo_status`, `by_vuln_status`, `by_sbom_status`, `unsupported`, `vuln_failed`, `sbom_failed`, `coverage_ratio`, `warnings`. |
| `datasets` | Datasets tabulares y objetos de apoyo (ver abajo). |
| `observations` | Lista de `{id, title, statement, metric, evidence}`; cada afirmación cita cifras verificables. |
| `limitations` | Lista de limitaciones que condicionan las conclusiones. |

Invariantes que valida `validate_document`:

- `schema_version == "1.0"`.
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
| `concentration` | objeto (no tabular) | `repositories_with_vulns`, `top_n`, `top_n_share`, `top_10pct_share`, `hhi` |
| `relations` | objeto (no tabular) | `components_vs_vulnerabilities`, `fixed_version_available_share`, `severity_by_package_type`, `findings_by_language` |

### Uso programático

```python
from analysis.pipeline import run_analysis

document = run_analysis(
    "results-vuln.json",
    "analysis/outputs/analyzer_output.json",
)
```

`run_analysis` devuelve el documento validado y, si se indica `output_path`, lo
escribe en UTF-8 con JSON indentado. Acepta `generated_at` para fijar la marca
temporal en ejecuciones reproducibles.

## Métricas

El Analyzer calcula, entre otras: cobertura por estados, distribución de
severidad, topes de reglas/CVE/paquetes, distribución y concentración por
repositorio (cuota top-N, decil superior, HHI), y relaciones (componentes vs
vulnerabilidades, disponibilidad de corrección, severidad por tipo de paquete y
hallazgos por lenguaje). La referencia completa —fórmulas, denominadores e
interpretación— está en [`METRICAS.md`](METRICAS.md).

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
