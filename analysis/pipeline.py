"""Pipeline del Analyzer: de uno o varios reportes del Miner al Visualizer.

Une las piezas del Analyzer en un único punto de entrada reproducible:

    load_report(s) → merge_reports → to_records → metrics → contract

El resultado es el documento estructurado descrito en ``analysis/contract.py``,
listo para que lo consuma el Visualizer. Al vivir en código (y no solo en un
notebook) el pipeline puede ejecutarse desde los notebooks y desde ``pytest``
sin depender de Jupyter.

Acepta una ruta o una lista de rutas: cuando se pasan varios reportes (por
ejemplo ``results-sbom.json`` + ``results-vuln.json``) se fusionan por
repositorio, de modo que el análisis combine toda la evidencia disponible del
Miner en lugar de una sola dimensión.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Union

from analysis import contract, metrics
from analysis.loader import load_report, merge_reports, to_records

__all__ = ["run_analysis"]

PathLike = Union[str, Path]


def _as_paths(input_paths: Union[PathLike, Iterable[PathLike]]) -> list:
    """Normaliza la entrada a una lista de rutas (una o varias)."""
    if isinstance(input_paths, (str, Path)):
        return [input_paths]
    return list(input_paths)


def run_analysis(
    input_paths: Union[PathLike, Iterable[PathLike]],
    output_path: Optional[PathLike] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Analiza uno o varios reportes del Miner y devuelve el documento.

    Parámetros
    ----------
    input_paths:
        Ruta a un reporte JSON del Miner (``results.json``, ``results-vuln.json``
        o ``results-sbom.json``) o lista de rutas que se fusionan por
        repositorio antes de analizar.
    output_path:
        Si se indica, valida y escribe el documento en esa ruta (UTF-8, JSON
        indentado). Si es ``None``, solo se devuelve en memoria.
    generated_at:
        Marca temporal ISO-8601 para ``meta.generated_at``. Si es ``None`` se
        usa el instante actual en UTC; se puede fijar en tests.

    Devuelve
    -------
    El documento de contrato validado (``dict``). Lanza ``ValueError`` si el
    documento resultante no cumple el contrato.
    """
    paths = _as_paths(input_paths)
    if not paths:
        raise ValueError("Se requiere al menos un reporte de entrada.")

    report = merge_reports([load_report(path) for path in paths])
    records = to_records(report)
    datasets = metrics.compute_datasets(report, records)
    coverage = metrics.compute_coverage(report)
    observations = metrics.build_observations(report, coverage, datasets)
    limitations = metrics.build_limitations(report, coverage)

    document = contract.build_document(
        report,
        datasets,
        coverage,
        observations,
        limitations,
        generated_at=generated_at,
    )

    errors = contract.validate_document(document)
    if errors:
        raise ValueError(
            "El documento generado no cumple el contrato:\n"
            + "\n".join(f"  - {error}" for error in errors)
        )

    if output_path is not None:
        contract.write_document(document, output_path)

    return document
