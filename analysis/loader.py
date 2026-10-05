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
# Origen combinado: varios reportes fusionados por repositorio.
SOURCE_MERGED = "merged"

# Estados que indican éxito de cada análisis.
VULN_OK_STATUSES = frozenset({"scanned", "no_vulnerabilities"})
SBOM_OK_STATUSES = frozenset({"generated", "no_components"})
FAILED_STATUSES = frozenset(
    {"clone_failed", "db_failed", "analyze_failed", "invalid_name"}
)

# Prioridad al fusionar el ``status`` de un repositorio presente en varios
# reportes: primero un resultado real de CodeQL, luego los fallos, después los
# estados exclusivos de ``sbom``/``vuln`` y por último ``pending``.
_STATUS_PRIORITY = (
    "analyzed",
    "unsupported",
    "db_failed",
    "analyze_failed",
    "clone_failed",
    "invalid_name",
    "scanned",
    "cloned",
    "pending",
)
_STATUS_RANK = {status: index for index, status in enumerate(_STATUS_PRIORITY)}


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


def _portable_path(source: Path) -> str:
    """Devuelve una ruta portable: relativa al cwd si está contenida en él."""
    try:
        resolved = source.resolve()
        cwd = Path.cwd().resolve()
        if resolved != cwd and cwd in resolved.parents:
            return str(resolved.relative_to(cwd))
    except (OSError, ValueError):
        pass
    return str(source)


def load_report(path: Union[str, Path]) -> MinerReport:
    """Carga un reporte del Miner de forma tolerante.

    Lanza ``FileNotFoundError`` si la ruta no existe y ``ValueError`` si el
    archivo no es UTF-8, no es JSON válido o no contiene un objeto de reporte.
    """
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"El archivo {source} no está codificado en UTF-8: {exc}") from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"El archivo {source} no es JSON válido: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"El archivo {source} no contiene un objeto JSON de reporte.")

    warnings: List[str] = []
    raw_repositories = data.get("repositories")
    if raw_repositories is not None and not isinstance(raw_repositories, list):
        warnings.append("El campo 'repositories' no es una lista; se ignoró su contenido.")
    organization = _as_str(data.get("organization"), "desconocida")
    repositories = [
        _parse_repo(raw, index, warnings)
        for index, raw in enumerate(_as_list(raw_repositories))
    ]

    return MinerReport(
        organization=organization,
        source_path=_portable_path(source),
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


# ---------------------------------------------------------------------------
# Fusión de reportes (SBOM + vulnerabilidades, scan + sbom, etc.)
# ---------------------------------------------------------------------------


def _copy_repo(repo: RepoData) -> RepoData:
    """Copia profunda de un ``RepoData`` para no mutar el reporte original."""
    return RepoData(
        name=repo.name,
        full_name=repo.full_name,
        url=repo.url,
        commit=repo.commit,
        status=repo.status,
        languages=list(repo.languages),
        sbom_status=repo.sbom_status,
        sbom_components=repo.sbom_components,
        vuln_status=repo.vuln_status,
        vuln_total=repo.vuln_total,
        by_severity=dict(repo.by_severity),
        findings=[dict(finding) for finding in repo.findings],
        vulnerabilities=[dict(vuln) for vuln in repo.vulnerabilities],
    )


def _merge_sbom_status(current: str, other: str) -> str:
    if current == "skipped":
        return other
    if other == "skipped" or current in SBOM_OK_STATUSES:
        return current
    return other if other in SBOM_OK_STATUSES else current


def _merge_vuln_status(current: str, other: str) -> str:
    if current == "skipped":
        return other
    if other == "skipped" or current in VULN_OK_STATUSES:
        return current
    return other if other in VULN_OK_STATUSES else current


def _pick_status(current: str, other: str) -> str:
    """Elige el estado más informativo según ``_STATUS_PRIORITY``."""
    return min(
        (current, other),
        key=lambda status: _STATUS_RANK.get(status, len(_STATUS_PRIORITY)),
    )


def _merge_repo_into(target: RepoData, other: RepoData) -> None:
    """Fusiona ``other`` dentro de ``target`` (mismo repositorio)."""
    if not target.full_name:
        target.full_name = other.full_name
    if not target.url:
        target.url = other.url
    if not target.commit:
        target.commit = other.commit

    for language in other.languages:
        if language not in target.languages:
            target.languages.append(language)

    seen_findings = {
        (f.get("rule_id"), f.get("file"), f.get("start_line")) for f in target.findings
    }
    for finding in other.findings:
        key = (finding.get("rule_id"), finding.get("file"), finding.get("start_line"))
        if key not in seen_findings:
            seen_findings.add(key)
            target.findings.append(dict(finding))

    seen_vulns = {
        (
            v.get("id"),
            v.get("package"),
            v.get("version"),
            v.get("type"),
            v.get("namespace"),
        )
        for v in target.vulnerabilities
    }
    for vuln in other.vulnerabilities:
        key = (
            vuln.get("id"),
            vuln.get("package"),
            vuln.get("version"),
            vuln.get("type"),
            vuln.get("namespace"),
        )
        if key not in seen_vulns:
            seen_vulns.add(key)
            target.vulnerabilities.append(dict(vuln))

    target.sbom_status = _merge_sbom_status(target.sbom_status, other.sbom_status)
    target.sbom_components = max(target.sbom_components, other.sbom_components)
    target.vuln_status = _merge_vuln_status(target.vuln_status, other.vuln_status)
    target.status = _pick_status(target.status, other.status)


def _recompute_repo_derived(repo: RepoData) -> None:
    """Recalcula ``by_severity`` y ``vuln_total`` desde las vulnerabilidades."""
    repo.vuln_total = len(repo.vulnerabilities)
    repo.by_severity = {severity: 0 for severity in SEVERITIES}
    for vuln in repo.vulnerabilities:
        repo.by_severity[normalize_severity(vuln.get("severity"))] += 1


def _recompute_summary(repositories: List[RepoData]) -> Dict[str, Any]:
    """Resume un conjunto de repositorios fusionados (mismo esquema del Miner)."""
    by_severity = {severity: 0 for severity in SEVERITIES}
    for repo in repositories:
        for severity, count in repo.by_severity.items():
            if severity in by_severity:
                by_severity[severity] += count

    return {
        "repositories": len(repositories),
        "analyzed": sum(1 for repo in repositories if repo.status == "analyzed"),
        "failed": sum(1 for repo in repositories if repo.status in FAILED_STATUSES),
        "unsupported": sum(1 for repo in repositories if repo.status == "unsupported"),
        "findings": sum(len(repo.findings) for repo in repositories),
        "sboms_generated": sum(
            1 for repo in repositories if repo.sbom_status in SBOM_OK_STATUSES
        ),
        "sboms_failed": sum(
            1 for repo in repositories if repo.sbom_status == "failed"
        ),
        "components": sum(repo.sbom_components for repo in repositories),
        "vulns_scanned": sum(
            1 for repo in repositories if repo.vuln_status in VULN_OK_STATUSES
        ),
        "vulns_failed": sum(
            1 for repo in repositories if repo.vuln_status == "failed"
        ),
        "vulnerabilities": sum(len(repo.vulnerabilities) for repo in repositories),
        "vulns_critical": by_severity["Critical"],
        "vulns_high": by_severity["High"],
        "vulns_medium": by_severity["Medium"],
        "vulns_low": by_severity["Low"],
    }


def _pick_organization(reports: List[MinerReport]) -> str:
    """Elige la organización más informativa entre varios reportes."""
    placeholders = {"", "desconocida", "local"}
    for report in reports:
        if report.organization and report.organization not in placeholders:
            return report.organization
    return reports[0].organization if reports else "desconocida"


def merge_reports(reports: List[MinerReport]) -> MinerReport:
    """Fusiona varios reportes del Miner por nombre de repositorio.

    Permite combinar la evidencia repartida entre comandos (por ejemplo
    ``results-sbom.json`` + ``results-vuln.json``) sin volver a ejecutar el
    Miner. Para cada repositorio se unen lenguajes, hallazgos y
    vulnerabilidades (con deduplicación), se conserva el mejor estado de SBOM y
    de Grype y se recalcula ``by_severity``, ``vuln_total`` y el resumen global.

    Con un solo reporte se devuelve tal cual (sin recalcular nada), de modo que
    el comportamiento de una única entrada no cambia.
    """
    if not reports:
        raise ValueError("Se requiere al menos un reporte para fusionar.")
    if len(reports) == 1:
        return reports[0]

    merged: Dict[str, RepoData] = {}
    for report in reports:
        for repo in report.repositories:
            if repo.name in merged:
                _merge_repo_into(merged[repo.name], repo)
            else:
                merged[repo.name] = _copy_repo(repo)

    repositories = sorted(merged.values(), key=lambda repo: repo.name.lower())
    for repo in repositories:
        _recompute_repo_derived(repo)

    warnings: List[str] = []
    for report in reports:
        warnings.extend(report.warnings)

    return MinerReport(
        organization=_pick_organization(reports),
        source_path=" + ".join(Path(report.source_path).name for report in reports),
        source_kind=SOURCE_MERGED,
        summary=_recompute_summary(repositories),
        repositories=repositories,
        warnings=warnings,
    )
