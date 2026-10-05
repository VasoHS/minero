"""Contrato de salida del Analyzer para el Visualizer.

Este módulo define la forma canónica, versionada y autocontenida del documento
que el Analyzer entrega al Visualizer. Solo usa la librería estándar y **no**
importa ``metrics`` en tiempo de importación: recibe sus resultados como
argumentos (``datasets``, ``coverage``, ``observations`` y ``limitations``).

Estructura del documento (``schema_version`` = ``"1.0"``)::

    {
      "schema_version": "1.0",
      "meta": {
        "organization": str,
        "source": str,
        "source_kind": str,        # scan | vuln | sbom | unknown
        "generated_at": str,       # ISO-8601 UTC
        "repositories": int,
        "warnings": [str]
      },
      "summary": { ...resumen del Miner tal cual... },
      "coverage": { ...resultado de compute_coverage... },
      "datasets": {
        "repositories": [...], "findings": [...], "vulnerabilities": [...],
        "severity_distribution": [...], "severity_by_repo": [...],
        "top_rules": [...], "top_cves": [...], "top_packages": [...],
        "repository_distribution": [...], "concentration": {...},
        "relations": {...}
      },
      "observations": [{"id", "title", "statement", "metric", "evidence"}],
      "limitations": [str]
    }

Decisiones de diseño relevantes:

- ``meta.repositories`` es la fuente de verdad del número de repositorios y
  debe coincidir con ``len(datasets["repositories"])`` y con
  ``coverage["repositories_total"]``.
- Las severidades de vulnerabilidades y de las distribuciones de severidad
  pertenecen al conjunto canónico ``SEVERITIES`` de Grype. Las severidades de
  los hallazgos de CodeQL son niveles SARIF (``error``/``warning``/``note``) y
  por eso **no** se restringen a ``SEVERITIES``.
- El orden de las filas es responsabilidad de ``metrics``: el contrato exige
  que sea determinista, pero este módulo no reordena datos.
- Los conteos deben ser enteros JSON nativos (``int``), no ``bool``. La
  validación acepta cualquier ``numbers.Integral`` (p. ej. escalares de
  NumPy) y ``write_document`` normaliza esos escalares a tipos nativos al
  serializar; no se altera ningún valor.
- No se corrige ningún dato de forma silenciosa: las incoherencias se
  devuelven como errores en ``validate_document``.
"""

from __future__ import annotations

import json
import numbers
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:  # Importación como paquete (``analysis.contract``).
    from .loader import SEVERITIES
except ImportError:  # pragma: no cover - ejecución como script suelto.
    from loader import SEVERITIES  # type: ignore

__all__ = [
    "SCHEMA_VERSION",
    "SOURCE_KINDS",
    "DATASET_KEYS",
    "LIST_DATASETS",
    "OBJECT_DATASETS",
    "build_document",
    "validate_document",
    "write_document",
]

#: Versión del contrato de salida. Cambia solo ante rupturas de compatibilidad.
SCHEMA_VERSION = "1.0"

#: Orígenes posibles de un reporte del Miner (mismo conjunto que ``loader``).
SOURCE_KINDS = ("scan", "vuln", "sbom", "merged", "unknown")

#: Datasets que debe contener todo documento, en orden canónico.
DATASET_KEYS = (
    "repositories",
    "findings",
    "vulnerabilities",
    "severity_distribution",
    "severity_by_repo",
    "top_rules",
    "top_cves",
    "top_packages",
    "repository_distribution",
    "concentration",
    "relations",
)

#: Datasets tabulares (lista de filas).
LIST_DATASETS = (
    "repositories",
    "findings",
    "vulnerabilities",
    "severity_distribution",
    "severity_by_repo",
    "top_rules",
    "top_cves",
    "top_packages",
    "repository_distribution",
)

#: Datasets de apoyo representados como objeto.
OBJECT_DATASETS = ("concentration", "relations")

#: Claves obligatorias del documento de nivel superior.
TOP_LEVEL_REQUIRED = (
    "schema_version",
    "meta",
    "summary",
    "coverage",
    "datasets",
    "observations",
    "limitations",
)

#: Claves obligatorias de ``meta``.
META_REQUIRED = (
    "organization",
    "source",
    "source_kind",
    "generated_at",
    "repositories",
    "warnings",
)

#: Claves obligatorias de ``coverage``. La salida real de
#: ``metrics.compute_coverage`` es: ``repositories_total``, ``by_repo_status``,
#: ``by_vuln_status``, ``by_sbom_status``, ``unsupported``, ``repo_failed``,
#: ``vuln_failed``, ``sbom_failed``, ``coverage_ratio``,
#: ``code_coverage_ratio``, ``sbom_coverage_ratio``, ``vuln_coverage_ratio`` y
#: ``warnings``.
COVERAGE_REQUIRED = ("repositories_total",)

#: Claves obligatorias de cada observación.
OBSERVATION_KEYS = ("id", "title", "statement", "metric", "evidence")


def _is_int(value: Any) -> bool:
    """``True`` si ``value`` es un entero (acepta escalares de NumPy)."""
    return isinstance(value, numbers.Integral) and not isinstance(value, bool)


def _is_non_negative_int(value: Any) -> bool:
    """``True`` si ``value`` es un entero mayor o igual que cero."""
    return _is_int(value) and value >= 0


def _is_non_empty_str(value: Any) -> bool:
    """``True`` si ``value`` es una cadena con contenido (no solo espacios)."""
    return isinstance(value, str) and bool(value.strip())


def _json_default(value: Any) -> Any:
    """Convierte escalares no nativos (p. ej. NumPy) a tipos JSON nativos.

    Solo se usa como ``default`` de ``json.dumps`` y no modifica el documento
    en memoria. Cualquier otro tipo no serializable produce ``TypeError``.
    """
    item = getattr(value, "item", None)
    if callable(item):
        return item()
    raise TypeError(f"Tipo no serializable en JSON: {type(value).__name__}")


def build_document(
    report: Any,
    datasets: Dict[str, Any],
    coverage: Dict[str, Any],
    observations: List[Dict[str, Any]],
    limitations: List[str],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Ensambla el documento de salida del Analyzer.

    Parámetros
    ----------
    report:
        ``MinerReport`` cargado con ``analysis.loader.load_report``. Se usa
        mediante acceso a atributos (duck typing), por lo que también sirve
        cualquier objeto con los mismos campos.
    datasets:
        Salida de ``metrics.compute_datasets``.
    coverage:
        Salida de ``metrics.compute_coverage``.
    observations:
        Salida de ``metrics.build_observations``.
    limitations:
        Salida de ``metrics.build_limitations``.
    generated_at:
        Marca temporal ISO-8601. Si es ``None`` se usa el instante actual en
        UTC; si se indica, se respeta tal cual (útil en tests deterministas).

    Devuelve un ``dict`` listo para ``json.dumps(..., ensure_ascii=False,
    indent=2)``. No valida: usa ``validate_document`` antes de escribirlo.
    """
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).isoformat()

    return {
        "schema_version": SCHEMA_VERSION,
        "meta": {
            "organization": report.organization,
            "source": report.source_path,
            "source_kind": report.source_kind,
            "generated_at": generated_at,
            "repositories": len(report.repositories),
            "warnings": list(report.warnings),
        },
        "summary": report.summary,
        "coverage": coverage,
        "datasets": datasets,
        "observations": observations,
        "limitations": limitations,
    }


def _validate_severity(row: Dict[str, Any], where: str, errors: List[str]) -> None:
    """Valida que ``row['severity']`` pertenezca al conjunto canónico."""
    if "severity" not in row:
        errors.append(f"Falta 'severity' en {where}.")
        return
    value = row["severity"]
    if value not in SEVERITIES:
        errors.append(
            f"{where}.severity={value!r} no pertenece a {list(SEVERITIES)}."
        )


def _validate_optional_severity(
    row: Dict[str, Any], where: str, errors: List[str]
) -> None:
    """Valida la severidad solo si la fila la incluye."""
    if "severity" in row and row["severity"] not in SEVERITIES:
        errors.append(
            f"{where}.severity={row['severity']!r} no pertenece a {list(SEVERITIES)}."
        )


def _validate_count_fields(
    row: Dict[str, Any], where: str, errors: List[str]
) -> None:
    """Comprueba que los campos de conteo presentes sean enteros >= 0."""
    for field in ("count", "total", "occurrences"):
        if field in row and not _is_non_negative_int(row[field]):
            errors.append(f"{where}.{field} debe ser un entero >= 0.")


def _validate_repository_rows(rows: List[Any], errors: List[str]) -> None:
    for index, row in enumerate(rows):
        where = f"datasets.repositories[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where} debe ser un objeto.")
            continue
        if not _is_non_empty_str(row.get("repo")):
            errors.append(f"{where}.repo debe ser una cadena no vacía.")
        for field in ("sbom_components", "vuln_total", "findings_total"):
            if field in row and not _is_non_negative_int(row[field]):
                errors.append(f"{where}.{field} debe ser un entero >= 0.")


def _validate_finding_rows(rows: List[Any], errors: List[str]) -> None:
    for index, row in enumerate(rows):
        where = f"datasets.findings[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where} debe ser un objeto.")
            continue
        if not _is_non_empty_str(row.get("repo")):
            errors.append(f"{where}.repo debe ser una cadena no vacía.")
        if not _is_non_empty_str(row.get("rule_id")):
            errors.append(f"{where}.rule_id debe ser una cadena no vacía.")
        # La severidad de CodeQL es un nivel SARIF (error/warning/note): solo
        # se comprueba el tipo, no el conjunto canónico de Grype.
        if "severity" in row and row["severity"] is not None and not isinstance(
            row["severity"], str
        ):
            errors.append(f"{where}.severity debe ser una cadena o null.")


def _validate_vulnerability_rows(rows: List[Any], errors: List[str]) -> None:
    for index, row in enumerate(rows):
        where = f"datasets.vulnerabilities[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where} debe ser un objeto.")
            continue
        for field in ("repo", "id", "package"):
            if not _is_non_empty_str(row.get(field)):
                errors.append(f"{where}.{field} debe ser una cadena no vacía.")
        _validate_severity(row, where, errors)


def _validate_severity_distribution(rows: List[Any], errors: List[str]) -> None:
    for index, row in enumerate(rows):
        where = f"datasets.severity_distribution[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where} debe ser un objeto.")
            continue
        _validate_severity(row, where, errors)
        if "count" not in row:
            errors.append(f"Falta 'count' en {where}.")
        else:
            _validate_count_fields(row, where, errors)


def _validate_severity_by_repo(rows: List[Any], errors: List[str]) -> None:
    for index, row in enumerate(rows):
        where = f"datasets.severity_by_repo[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where} debe ser un objeto.")
            continue
        if not _is_non_empty_str(row.get("repo")):
            errors.append(f"{where}.repo debe ser una cadena no vacía.")
        _validate_optional_severity(row, where, errors)
        _validate_count_fields(row, where, errors)


def _validate_top_rules(rows: List[Any], errors: List[str]) -> None:
    for index, row in enumerate(rows):
        where = f"datasets.top_rules[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where} debe ser un objeto.")
            continue
        if not _is_non_empty_str(row.get("rule_id")):
            errors.append(f"{where}.rule_id debe ser una cadena no vacía.")
        _validate_count_fields(row, where, errors)


def _validate_top_cves(rows: List[Any], errors: List[str]) -> None:
    for index, row in enumerate(rows):
        where = f"datasets.top_cves[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where} debe ser un objeto.")
            continue
        if not _is_non_empty_str(row.get("id")):
            errors.append(f"{where}.id debe ser una cadena no vacía.")
        _validate_optional_severity(row, where, errors)
        _validate_count_fields(row, where, errors)


def _validate_top_packages(rows: List[Any], errors: List[str]) -> None:
    for index, row in enumerate(rows):
        where = f"datasets.top_packages[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where} debe ser un objeto.")
            continue
        if not _is_non_empty_str(row.get("package")):
            errors.append(f"{where}.package debe ser una cadena no vacía.")
        _validate_count_fields(row, where, errors)


def _validate_repository_distribution(rows: List[Any], errors: List[str]) -> None:
    for index, row in enumerate(rows):
        where = f"datasets.repository_distribution[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where} debe ser un objeto.")
            continue
        if not _is_non_empty_str(row.get("repo")):
            errors.append(f"{where}.repo debe ser una cadena no vacía.")
        for field in (
            "vulnerabilities",
            "findings",
            "components",
            "count",
            "total",
        ):
            if field in row and not _is_non_negative_int(row[field]):
                errors.append(f"{where}.{field} debe ser un entero >= 0.")


def validate_document(document: Any) -> List[str]:
    """Valida el documento de salida en Python puro (sin ``jsonschema``).

    Devuelve una lista de errores legibles. Una lista vacía significa que el
    documento cumple el contrato ``1.0``.
    """
    errors: List[str] = []

    if not isinstance(document, dict):
        return ["El documento debe ser un objeto JSON (dict)."]

    # --- Claves de nivel superior -----------------------------------------
    for key in TOP_LEVEL_REQUIRED:
        if key not in document:
            errors.append(f"Falta la clave obligatoria '{key}'.")

    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version debe ser {SCHEMA_VERSION!r}, "
            f"se encontró {document.get('schema_version')!r}."
        )

    # --- meta --------------------------------------------------------------
    meta = document.get("meta")
    meta_repositories: Optional[int] = None
    if not isinstance(meta, dict):
        errors.append("'meta' debe ser un objeto.")
    else:
        for key in META_REQUIRED:
            if key not in meta:
                errors.append(f"Falta 'meta.{key}'.")
        if not _is_non_empty_str(meta.get("organization")):
            errors.append("meta.organization debe ser una cadena no vacía.")
        if not isinstance(meta.get("source"), str):
            errors.append("meta.source debe ser una cadena.")
        if meta.get("source_kind") not in SOURCE_KINDS:
            errors.append(
                f"meta.source_kind={meta.get('source_kind')!r} no pertenece a "
                f"{list(SOURCE_KINDS)}."
            )
        if not _is_non_empty_str(meta.get("generated_at")):
            errors.append("meta.generated_at debe ser una cadena no vacía.")
        if not _is_non_negative_int(meta.get("repositories")):
            errors.append("meta.repositories debe ser un entero >= 0.")
        else:
            meta_repositories = int(meta["repositories"])
        warnings = meta.get("warnings")
        if not isinstance(warnings, list) or any(
            not isinstance(item, str) for item in warnings
        ):
            errors.append("meta.warnings debe ser una lista de cadenas.")

    # --- summary -----------------------------------------------------------
    if not isinstance(document.get("summary"), dict):
        errors.append("'summary' debe ser un objeto (resumen del Miner).")

    # --- coverage ----------------------------------------------------------
    coverage = document.get("coverage")
    coverage_total: Optional[int] = None
    if not isinstance(coverage, dict):
        errors.append("'coverage' debe ser un objeto.")
    else:
        for key in COVERAGE_REQUIRED:
            if key not in coverage:
                errors.append(f"Falta 'coverage.{key}'.")
        if not _is_non_negative_int(coverage.get("repositories_total")):
            errors.append("coverage.repositories_total debe ser un entero >= 0.")
        else:
            coverage_total = int(coverage["repositories_total"])
        for key in ("unsupported", "repo_failed", "vuln_failed", "sbom_failed"):
            if key in coverage and not _is_non_negative_int(coverage[key]):
                errors.append(f"coverage.{key} debe ser un entero >= 0.")
        for key in ("by_repo_status", "by_vuln_status", "by_sbom_status"):
            if key in coverage and not isinstance(coverage[key], dict):
                errors.append(f"coverage.{key} debe ser un objeto.")
        for key in (
            "coverage_ratio",
            "code_coverage_ratio",
            "sbom_coverage_ratio",
            "vuln_coverage_ratio",
        ):
            ratio = coverage.get(key)
            if ratio is not None and not (
                isinstance(ratio, (int, float))
                and not isinstance(ratio, bool)
                and 0 <= ratio <= 1
            ):
                errors.append(f"coverage.{key} debe ser un número en [0, 1].")

    # --- datasets ----------------------------------------------------------
    datasets = document.get("datasets")
    if not isinstance(datasets, dict):
        errors.append("'datasets' debe ser un objeto.")
        datasets = {}
    else:
        for key in DATASET_KEYS:
            if key not in datasets:
                errors.append(f"Falta 'datasets.{key}'.")
        for key in LIST_DATASETS:
            if key in datasets and not isinstance(datasets[key], list):
                errors.append(f"datasets.{key} debe ser una lista.")
        for key in OBJECT_DATASETS:
            if key in datasets and not isinstance(datasets[key], dict):
                errors.append(f"datasets.{key} debe ser un objeto.")

        # Validación por fila de cada dataset tabular.
        row_validators = {
            "repositories": _validate_repository_rows,
            "findings": _validate_finding_rows,
            "vulnerabilities": _validate_vulnerability_rows,
            "severity_distribution": _validate_severity_distribution,
            "severity_by_repo": _validate_severity_by_repo,
            "top_rules": _validate_top_rules,
            "top_cves": _validate_top_cves,
            "top_packages": _validate_top_packages,
            "repository_distribution": _validate_repository_distribution,
        }
        for key, validator in row_validators.items():
            rows = datasets.get(key)
            if isinstance(rows, list):
                validator(rows, errors)

    # --- observations ------------------------------------------------------
    observations = document.get("observations")
    if not isinstance(observations, list):
        errors.append("'observations' debe ser una lista.")
    else:
        seen_ids = set()
        for index, observation in enumerate(observations):
            where = f"observations[{index}]"
            if not isinstance(observation, dict):
                errors.append(f"{where} debe ser un objeto.")
                continue
            for key in OBSERVATION_KEYS:
                if key not in observation:
                    errors.append(f"Falta '{key}' en {where}.")
            observation_id = observation.get("id")
            if not _is_non_empty_str(observation_id):
                errors.append(f"{where}.id debe ser una cadena no vacía.")
            elif observation_id in seen_ids:
                errors.append(f"{where}.id={observation_id!r} está duplicado.")
            else:
                seen_ids.add(observation_id)
            for key in ("title", "statement"):
                if not _is_non_empty_str(observation.get(key)):
                    errors.append(f"{where}.{key} debe ser una cadena no vacía.")

    # --- limitations -------------------------------------------------------
    limitations = document.get("limitations")
    if not isinstance(limitations, list) or any(
        not isinstance(item, str) for item in limitations
    ):
        errors.append("'limitations' debe ser una lista de cadenas.")

    # --- Coherencia entre secciones ---------------------------------------
    if meta_repositories is not None:
        repository_rows = datasets.get("repositories")
        if isinstance(repository_rows, list) and meta_repositories != len(
            repository_rows
        ):
            errors.append(
                f"meta.repositories={meta_repositories} no coincide con "
                f"len(datasets['repositories'])={len(repository_rows)}."
            )
        if coverage_total is not None and coverage_total != meta_repositories:
            errors.append(
                f"coverage.repositories_total={coverage_total} no coincide con "
                f"meta.repositories={meta_repositories}."
            )

    return errors


def write_document(document: Dict[str, Any], path: Union[str, Path]) -> None:
    """Valida y escribe el documento como JSON UTF-8.

    Lanza ``ValueError`` con la lista de errores si el documento no cumple el
    contrato. Crea el directorio padre si no existe. Los escalares no nativos
    (p. ej. NumPy) se convierten a tipos nativos al serializar, sin alterar su
    valor.
    """
    errors = validate_document(document)
    if errors:
        detalle = "\n".join(f"  - {error}" for error in errors)
        raise ValueError(f"Documento inválido; no se escribió:\n{detalle}")

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(
        document,
        ensure_ascii=False,
        indent=2,
        default=_json_default,
    )
    target.write_text(text + "\n", encoding="utf-8")
