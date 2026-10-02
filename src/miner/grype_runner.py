import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .models import VulnResult, Vulnerability

# Severidades canónicas de Grype. La comparación ignora mayúsculas/espacios.
SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")

# Orden de prioridad para el ordenamiento determinista de los hallazgos.
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITIES)}

def get_grype_version() -> Optional[str]:
    """Obtiene la versión de Grype instalada, o None si no está disponible."""
    try:
        result = subprocess.run(
            ["grype", "version", "-o", "json"],
            check=True, capture_output=True, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return None
    version = data.get("version") if isinstance(data, dict) else None
    return version if isinstance(version, str) and version else None

def _normalize_severity(value: object) -> str:
    """Normaliza la severidad de Grype a una de las canónicas (o 'Unknown')."""
    if isinstance(value, str):
        candidate = value.strip().lower()
        for severity in SEVERITIES:
            if severity.lower() == candidate:
                return severity
    return "Unknown"

def _optional_str(value: object) -> Optional[str]:
    """Devuelve el valor solo si es una cadena (evita romper el modelo Pydantic)."""
    return value if isinstance(value, str) else None

def _first_fixed_version(fix: object) -> Optional[str]:
    """Extrae la primera versión con corrección del bloque 'fix' de Grype."""
    if not isinstance(fix, dict):
        return None
    versions = fix.get("versions")
    if isinstance(versions, list) and versions:
        first = versions[0]
        return first if isinstance(first, str) and first else None
    return None

def parse_matches(data: object) -> Optional[List[Vulnerability]]:
    """Convierte la salida JSON de Grype en una lista de vulnerabilidades.

    Devuelve None si el documento no es válido, para distinguir un JSON ilegible
    de una ejecución correcta sin coincidencias (lista vacía).
    """
    if not isinstance(data, dict):
        return None

    matches = data.get("matches")
    if matches is None:
        return []
    if not isinstance(matches, list):
        return None

    vulnerabilities: List[Vulnerability] = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        vuln = match.get("vulnerability")
        artifact = match.get("artifact")
        vuln = vuln if isinstance(vuln, dict) else {}
        artifact = artifact if isinstance(artifact, dict) else {}

        vulnerabilities.append(Vulnerability(
            id=str(vuln.get("id") or "unknown"),
            severity=_normalize_severity(vuln.get("severity")),
            package=str(artifact.get("name") or "unknown"),
            version=_optional_str(artifact.get("version")),
            type=_optional_str(artifact.get("type")),
            fixed_version=_first_fixed_version(vuln.get("fix")),
            namespace=_optional_str(vuln.get("namespace")),
        ))
    return vulnerabilities

def summarize_by_severity(vulnerabilities: List[Vulnerability]) -> dict:
    """Cuenta las vulnerabilidades por severidad, incluyendo los ceros."""
    by_severity = {severity: 0 for severity in SEVERITIES}
    for vulnerability in vulnerabilities:
        key = vulnerability.severity or "Unknown"
        by_severity[key] = by_severity.get(key, 0) + 1
    return by_severity

def _discard(path: Path) -> None:
    """Elimina un archivo best-effort (evita dejar reportes previos/parciales)."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass

def scan_vulnerabilities(source: str, output_file: Path,
                         grype_version: Optional[str] = None) -> VulnResult:
    """Escanea con Grype un SBOM o un directorio y devuelve el resultado.

    `source` es el objetivo tal como lo espera Grype, por ejemplo
    ``sbom:ruta/al/bom.cdx.json`` o ``dir:ruta/al/repositorio``.
    """
    generated_at = datetime.now(timezone.utc).isoformat()
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return VulnResult(status="failed", grype_version=grype_version,
                          generated_at=generated_at)

    # Evita que un reporte de una ejecución previa sobreviva si esta falla.
    _discard(output_file)

    try:
        subprocess.run(
            ["grype", str(source), "-o", "json", "--file", str(output_file)],
            check=True, capture_output=True, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        _discard(output_file)
        return VulnResult(status="failed", grype_version=grype_version,
                          generated_at=generated_at)

    try:
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        _discard(output_file)
        return VulnResult(status="failed", grype_version=grype_version,
                          generated_at=generated_at)

    vulnerabilities = parse_matches(data)
    if vulnerabilities is None:
        # Grype terminó "bien" pero el reporte no es legible: se considera fallo.
        _discard(output_file)
        return VulnResult(status="failed", grype_version=grype_version,
                          generated_at=generated_at)

    # Orden determinista: severidad, paquete, CVE y versión (desempate estable).
    vulnerabilities.sort(
        key=lambda v: (_SEVERITY_RANK.get(v.severity or "Unknown", len(SEVERITIES)),
                       v.package, v.id, v.version or "")
    )

    total = len(vulnerabilities)
    status = "scanned" if total > 0 else "no_vulnerabilities"
    return VulnResult(
        status=status,
        total=total,
        by_severity=summarize_by_severity(vulnerabilities),
        vulnerabilities=vulnerabilities,
        grype_version=grype_version,
        generated_at=generated_at,
        file=str(output_file)
    )
