import json
from pathlib import Path
from typing import List

from .models import Finding


def _as_str(value: object, default: str) -> str:
    """Devuelve el valor solo si es una cadena no vacía."""
    return value if isinstance(value, str) and value else default


def parse_sarif(sarif_path: Path) -> List[Finding]:
    """Convierte un SARIF de CodeQL en hallazgos.

    Es tolerante a documentos ausentes, vacíos, truncados o con estructura
    inesperada: en esos casos devuelve una lista vacía en lugar de lanzar una
    excepción, para no abortar el escaneo completo. Se recorren todos los
    ``runs`` del documento (un mismo SARIF puede contener varios).
    """
    if not sarif_path.exists():
        return []

    try:
        with open(sarif_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []

    if not isinstance(data, dict):
        return []

    runs = data.get("runs")
    if not isinstance(runs, list):
        return []

    findings: List[Finding] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            findings.append(_parse_result(result))
    return findings


def _parse_result(result: dict) -> Finding:
    """Extrae un hallazgo de un resultado SARIF validando cada campo."""
    rule_id = _as_str(result.get("ruleId"), "unknown")
    level = _as_str(result.get("level"), "warning")

    message_obj = result.get("message")
    message = ""
    if isinstance(message_obj, dict):
        message = _as_str(message_obj.get("text"), "")

    artifact = "unknown"
    start_line = None
    locations = result.get("locations")
    if isinstance(locations, list) and locations:
        first = locations[0]
        if isinstance(first, dict):
            physical = first.get("physicalLocation")
            if isinstance(physical, dict):
                artifact_location = physical.get("artifactLocation")
                if isinstance(artifact_location, dict):
                    artifact = _as_str(artifact_location.get("uri"), "unknown")
                region = physical.get("region")
                if isinstance(region, dict):
                    line = region.get("startLine")
                    if isinstance(line, int) and not isinstance(line, bool):
                        start_line = line

    return Finding(
        rule_id=rule_id,
        severity=level,
        message=message,
        file=artifact,
        start_line=start_line,
    )
