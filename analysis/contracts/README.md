# Contrato de salida del Analyzer

Documento JSON versionado que el Analyzer entrega al **Visualizer**. El
Visualizer debe consumir este contrato y no depender de leer el código de los
notebooks ni de `metrics.py`.

## Archivos

| Archivo | Descripción |
| --- | --- |
| `contract.py` | Ensamblado, validación y escritura del documento (solo librería estándar). |
| `contracts/analyzer_output.schema.json` | JSON Schema draft 2020-12 del documento. |
| `contracts/example_analyzer_output.json` | Ejemplo mínimo válido (2 repos, 1 finding, 1 vulnerabilidad). |

## Estructura del documento

```jsonc
{
  "schema_version": "1.0",
  "meta": {
    "organization": "acme",
    "source": "results-vuln.json",
    "source_kind": "vuln",          // scan | vuln | sbom | merged | unknown
    "generated_at": "2026-10-05T12:00:00+00:00",
    "repositories": 6,
    "warnings": []
  },
  "summary": { /* bloque summary del Miner, tal cual */ },
  "coverage": { /* metrics.compute_coverage */ },
  "datasets": { /* ver catálogo */ },
  "observations": [{ "id", "title", "statement", "metric", "evidence" }],
  "limitations": ["..."]
}
```

Invariantes verificadas por `validate_document`:

- `schema_version == "1.0"`.
- `meta.repositories == len(datasets["repositories"])`.
- `coverage.repositories_total == meta.repositories`.
- `meta.organization` no vacío; `source_kind` dentro del enum.
- Todos los datasets presentes; severidades dentro de
  `Critical, High, Medium, Low, Negligible, Unknown`; conteos `>= 0`.
- Cada observación tiene las 5 claves y `id` únicos.

## Catálogo de datasets

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

Las columnas no listadas se permiten (`additionalProperties`), pero las
anteriores son el mínimo estable. La semántica de cada métrica está en
`analysis/METRICAS.md`.

## Uso

```python
from analysis.loader import load_report, to_records
from analysis import metrics
from analysis.contract import build_document, validate_document, write_document

report = load_report("results-vuln.json")
records = to_records(report)
datasets = metrics.compute_datasets(report, records)
coverage = metrics.compute_coverage(report)
observations = metrics.build_observations(report, coverage, datasets)
limitations = metrics.build_limitations(report, coverage)

document = build_document(report, datasets, coverage, observations, limitations)
errors = validate_document(document)
assert not errors, errors
write_document(document, "analysis/outputs/analyzer_output.json")
```

`build_document` acepta `generated_at` para reproducibilidad en tests. El orden
de las filas lo fija `metrics` (determinista); el contrato no reordena datos.

## Versionado

`schema_version` es `"1.0"`. Un cambio incompatible (renombrar/eliminar claves
obligatorias o cambiar tipos) requiere incrementar la versión y actualizar el
JSON Schema. Añadir columnas opcionales a un dataset no rompe el contrato.
