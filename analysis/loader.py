"""Carga y normalización tolerante de los reportes del Miner.

El Analyzer consume los reportes JSON generados por la CLI (``miner scan``,
``miner sbom`` y ``miner vuln``). Este módulo no depende de pandas ni de
terceros: solo de la librería estándar, de modo que la carga pueda probarse con
``pytest`` sin instalar el extra ``[analyzer]``.

Un reporte puede venir de cualquiera de los tres comandos, por lo que algunas
secciones pueden faltar (por ejemplo, ``findings`` en ``results-vuln.json`` o
``vulnerabilities`` en ``results-sbom.json``). El cargador nunca asume su
presencia: rellena valores por defecto y acumula advertencias en
``MinerReport.warnings``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Severidades canónicas de Grype (mismo orden que ``miner.models``).
SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")

# Estados conocidos de repositorio (incluye los de los tres comandos).
REPO_STATUSES = (
    "analyzed",
    "clone_failed",
    "unsupported",
    "db_failed",
    "analyze_failed",
    "invalid_name",
    "cloned",
    "scanned",
    "pending",
)

# Origen detectado del reporte.
SOURCE_SCAN = "scan"
SOURCE_VULN = "vuln"
SOURCE_SBOM = "sbom"
SOURCE_UNKNOWN = "unknown"


@dataclass
class RepoData:
    """Vista normalizada de un repositorio del reporte."""

    name: str
    full_name: Optional[str] = None
    url: str = ""
    commit: Optional[str] = None
    status: str = "pending"
    languages: List[str] = field(default_factory=list)
    sbom_status: str = "skipped"
    sbom_components: int = 0
    vuln_status: str = "skipped"
    vuln_total: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class MinerReport:
    """Reporte del Miner cargado y normalizado."""

    organization: str
    source_path: str
    source_kind: str
    summary: Dict[str, Any]
    repositories: List[RepoData]
    warnings: List[str] = field(default_factory=list)


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_str(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


def normalize_severity(value: Any) -> str:
    """Normaliza una severidad a una de las canónicas (o ``Unknown``)."""
    if not isinstance(value, str):
        return "Unknown"
    lowered = value.strip().lower()
    for canonical in SEVERITIES:
        if canonical.lower() == lowered:
            return canonical
    return "Unknown"


def detect_source_kind(data: Dict[str, Any]) -> str:
    """Infiere el comando de origen a partir de las claves presentes."""
    repositories = _as_list(data.get("repositories"))
    has_vuln = False
    has_sbom = False
    for repo in repositories:
        repo = _as_dict(repo)
        vuln = _as_dict(repo.get("vulnerabilities"))
        sbom = _as_dict(repo.get("sbom"))
        if vuln and vuln.get("status", "skipped") != "skipped":
            has_vuln = True
        if sbom and sbom.get("status", "skipped") != "skipped":
            has_sbom = True
    if has_vuln and not has_sbom:
        return SOURCE_VULN
    if has_sbom and not has_vuln:
        return SOURCE_SBOM
    if has_sbom and has_vuln:
        return SOURCE_SCAN
    return SOURCE_UNKNOWN


def _parse_repo(raw: Dict[str, Any], index: int, warnings: List[str]) -> RepoData:
    raw = _as_dict(raw)
    name = _as_str(raw.get("name"))
    if not name:
        name = f"repo-{index}"
        warnings.append(f"Repositorio sin 'name' en la posición {index}; se usó '{name}'.")

    sbom = _as_dict(raw.get("sbom"))
    vuln = _as_dict(raw.get("vulnerabilities"))

    by_severity_raw = _as_dict(vuln.get("by_severity"))
    by_severity = {
        severity: _as_int(by_severity_raw.get(severity, 0)) for severity in SEVERITIES
    }

    findings = []
    for finding in _as_list(raw.get("findings")):
        finding = _as_dict(finding)
        findings.append(
            {
                "repo": name,
                "rule_id": _as_str(finding.get("rule_id"), "unknown"),
                "severity": _as_str(finding.get("severity"), "unknown"),
                "file": _as_str(finding.get("file")),
                "start_line": finding.get("start_line")
                if isinstance(finding.get("start_line"), int)
                else None,
            }
        )

    vulnerabilities = []
    for vuln_item in _as_list(vuln.get("vulnerabilities")):
        vuln_item = _as_dict(vuln_item)
        vulnerabilities.append(
            {
                "repo": name,
                "id": _as_str(vuln_item.get("id"), "unknown"),
                "severity": normalize_severity(vuln_item.get("severity")),
                "package": _as_str(vuln_item.get("package"), "unknown"),
                "version": vuln_item.get("version")
                if isinstance(vuln_item.get("version"), str)
                else None,
                "type": vuln_item.get("type")
                if isinstance(vuln_item.get("type"), str)
                else None,
                "fixed_version": vuln_item.get("fixed_version")
                if isinstance(vuln_item.get("fixed_version"), str)
                else None,
                "namespace": vuln_item.get("namespace")
                if isinstance(vuln_item.get("namespace"), str)
                else None,
            }
        )

    return RepoData(
        name=name,
        full_name=raw.get("full_name") if isinstance(raw.get("full_name"), str) else None,
        url=_as_str(raw.get("url")),
        commit=raw.get("commit") if isinstance(raw.get("commit"), str) else None,
        status=_as_str(raw.get("status"), "pending"),
        languages=[lang for lang in _as_list(raw.get("languages")) if isinstance(lang, str)],
        sbom_status=_as_str(sbom.get("status"), "skipped"),
        sbom_components=_as_int(sbom.get("components")),
        vuln_status=_as_str(vuln.get("status"), "skipped"),
        vuln_total=_as_int(vuln.get("total")),
        by_severity=by_severity,
        findings=findings,
        vulnerabilities=vulnerabilities,
    )


def load_report(path: Union[str, Path]) -> MinerReport:
    """Carga un reporte del Miner de forma tolerante.

    Lanza ``FileNotFoundError`` si la ruta no existe y ``ValueError`` si el
    contenido no es un objeto JSON válido.
    """
    source = Path(path)
    text = source.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"El archivo {source} no es JSON válido: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"El archivo {source} no contiene un objeto JSON de reporte.")

    warnings: List[str] = []
    organization = _as_str(data.get("organization"), "desconocida")
    repositories = [
        _parse_repo(raw, index, warnings)
        for index, raw in enumerate(_as_list(data.get("repositories")))
    ]

    return MinerReport(
        organization=organization,
        source_path=str(source),
        source_kind=detect_source_kind(data),
        summary=_as_dict(data.get("summary")),
        repositories=repositories,
        warnings=warnings,
    )


def to_records(report: MinerReport) -> Dict[str, List[Dict[str, Any]]]:
    """Convierte el reporte en tablas planas (listas de diccionarios).

    Estas tablas son la base tanto de las métricas como de los datasets que
    consume el Visualizer:

    - ``repositories``: una fila por repositorio.
    - ``findings``: una fila por hallazgo de CodeQL.
    - ``vulnerabilities``: una fila por vulnerabilidad de Grype.
    - ``severity_distribution``: una fila por (repo, severidad) con su conteo.
    """
    repositories: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    vulnerabilities: List[Dict[str, Any]] = []
    severity_distribution: List[Dict[str, Any]] = []

    for repo in report.repositories:
        repositories.append(
            {
                "repo": repo.name,
                "full_name": repo.full_name,
                "url": repo.url,
                "commit": repo.commit,
                "status": repo.status,
                "languages": list(repo.languages),
                "sbom_status": repo.sbom_status,
                "sbom_components": repo.sbom_components,
                "vuln_status": repo.vuln_status,
                "vuln_total": repo.vuln_total,
                "findings_total": len(repo.findings),
            }
        )
        findings.extend(repo.findings)
        vulnerabilities.extend(repo.vulnerabilities)
        for severity in SEVERITIES:
            count = repo.by_severity.get(severity, 0)
            if count:
                severity_distribution.append(
                    {"repo": repo.name, "severity": severity, "count": count}
                )

    return {
        "repositories": repositories,
        "findings": findings,
        "vulnerabilities": vulnerabilities,
        "severity_distribution": severity_distribution,
    }
