"""Pipeline del Analyzer: de un reporte del Miner al documento del Visualizer.

Une las piezas del Analyzer en un único punto de entrada reproducible:

    load_report → to_records → metrics → contract

El resultado es el documento estructurado descrito en ``analysis/contract.py``,
listo para que lo consuma el Visualizer. Al vivir en código (y no solo en un
notebook) el pipeline puede ejecutarse desde la CLI, desde los notebooks y desde
``pytest`` sin depender de Jupyter.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Union

from analysis import contract, metrics
from analysis.loader import load_report, to_records

__all__ = ["run_analysis"]


def run_analysis(
    input_path: Union[str, Path],
    output_path: Optional[Union[str, Path]] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Analiza un reporte del Miner y devuelve el documento del Analyzer.

    Parámetros
    ----------
    input_path:
        Ruta al reporte JSON del Miner (``results.json``, ``results-vuln.json``
        o ``results-sbom.json``).
    output_path:
        Si se indica, valida y escribe el documento en esa ruta (UTF-8, JSON
        indentado). Si es ``None``, solo se devuelve en memoria.
    generated_at:
        Marca temporal ISO-8601 para ``meta.generated_at``. Si es ``None`` se
        usa el instante actual en UTC; se puede fijar en tests.

    Devuelve
    -------
    El documento de contrato validado (``dict``).
    """
    report = load_report(input_path)
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

    if output_path is not None:
        contract.write_document(document, output_path)

    return document
