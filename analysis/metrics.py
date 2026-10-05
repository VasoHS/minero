"""Métricas y observaciones del Analyzer sobre los reportes del Miner.

Este módulo es **puro y determinista**: solo usa la librería estándar (sin
``pandas``) y todas las salidas se ordenan de forma estable. Consume las tablas
planas producidas por :func:`analysis.loader.to_records` y el reporte
normalizado :class:`analysis.loader.MinerReport`.

Decisiones de diseño relevantes:

- Los conteos de vulnerabilidades se calculan sobre la lista plana
  ``records["vulnerabilities"]`` (una fila por vulnerabilidad), no sobre el
  campo ``vuln_total`` del reporte. Así ``top_cves``, ``top_packages``,
  ``concentration`` y ``repository_distribution`` comparten el mismo
  denominador y son internamente consistentes. Si ambos difieren, se advierte
  en :func:`build_limitations`.
- La severidad "peor" de un identificador o paquete usa el orden canónico de
  :data:`analysis.loader.SEVERITIES` (``Critical`` es el índice 0).
- ``findings_by_language`` atribuye cada hallazgo a **cada** lenguaje declarado
  por el repositorio, tal como indica el contrato del Analyzer.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from analysis.loader import SEVERITIES, MinerReport

__all__ = [
    "compute_coverage",
    "compute_severity_distribution",
    "compute_top_rules",
    "compute_top_cves",
    "compute_top_packages",
    "compute_repository_distribution",
    "compute_concentration",
    "compute_relations",
    "compute_datasets",
    "build_observations",
    "build_limitations",
]

# Estados que indican que el análisis correspondiente terminó con éxito.
VULN_OK_STATUSES = frozenset({"scanned", "no_vulnerabilities"})
SBOM_OK_STATUSES = frozenset({"generated", "no_components"})

# Índice canónico de severidad (menor = más grave).
_SEVERITY_INDEX = {severity: index for index, severity in enumerate(SEVERITIES)}


# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------


def _round4(value: float) -> float:
    """Redondea a 4 decimales de forma estable (evita -0.0)."""
    rounded = round(float(value), 4)
    return 0.0 if rounded == 0 else rounded


def _norm_severity(value: Any) -> str:
    """Normaliza un valor a severidad canónica (o ``Unknown``)."""
    return value if value in _SEVERITY_INDEX else "Unknown"


def _severity_rank(severity: str) -> int:
    """Devuelve la posición canónica de una severidad (desconocidas al final)."""
    return _SEVERITY_INDEX.get(severity, len(SEVERITIES))


def _worst_severity(severities: Iterable[Any]) -> str:
    """Elige la severidad más grave según el orden canónico."""
    normalized = [_norm_severity(severity) for severity in severities]
    return min(normalized, key=_severity_rank) if normalized else "Unknown"


def _sorted_counter(counter: Counter) -> Dict[str, int]:
    """Convierte un ``Counter`` en un dict con claves ordenadas."""
    return {key: counter[key] for key in sorted(counter)}


def _repos_affected(rows: Iterable[Dict[str, Any]]) -> int:
    """Cuenta repositorios distintos en una colección de filas."""
    return len({row.get("repo") for row in rows})


def _pearson(xs: Sequence[float], ys: Sequence[float]) -> Optional[float]:
    """Correlación de Pearson (poblacional).

    Devuelve ``None`` si hay menos de 2 pares o si alguna de las dos series
    tiene varianza cero (correlación indefinida).
    """
    n = len(xs)
    if n < 2 or n != len(ys):
        return None
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    sxx = sum((x - mean_x) ** 2 for x in xs)
    syy = sum((y - mean_y) ** 2 for y in ys)
    if sxx == 0 or syy == 0:
        return None
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    return _round4(sxy / math.sqrt(sxx * syy))


# ---------------------------------------------------------------------------
# Cobertura
# ---------------------------------------------------------------------------


def compute_coverage(report: MinerReport) -> Dict[str, Any]:
    """Resume cuántos repositorios se analizaron con éxito y con qué estado.

    Pregunta que responde: *¿qué proporción de la organización tiene al menos
    un análisis exitoso y qué modos de fallo aparecen?*

    Un repositorio cuenta como "cubierto" si su estado es ``analyzed`` o si
    ``vuln_status`` ∈ {scanned, no_vulnerabilities} o ``sbom_status`` ∈
    {generated, no_components}. El denominador es el total de repositorios.
    """
    repositories = report.repositories
    total = len(repositories)

    by_repo_status: Counter = Counter(repo.status for repo in repositories)
    by_vuln_status: Counter = Counter(repo.vuln_status for repo in repositories)
    by_sbom_status: Counter = Counter(repo.sbom_status for repo in repositories)

    unsupported = by_repo_status.get("unsupported", 0)
    vuln_failed = by_vuln_status.get("failed", 0)
    sbom_failed = by_sbom_status.get("failed", 0)

    covered = sum(
        1
        for repo in repositories
        if repo.status == "analyzed"
        or repo.vuln_status in VULN_OK_STATUSES
        or repo.sbom_status in SBOM_OK_STATUSES
    )
    coverage_ratio = _round4(covered / total) if total else 0.0

    warnings: List[str] = list(report.warnings)
    if unsupported:
        warnings.append(
            f"{unsupported} repositorio(s) no soportado(s): sin análisis de código ni SBOM."
        )
    if vuln_failed:
        warnings.append(f"{vuln_failed} repositorio(s) fallaron en el escaneo de Grype.")
    if sbom_failed:
        warnings.append(f"{sbom_failed} repositorio(s) fallaron al generar el SBOM.")

    return {
        "repositories_total": total,
        "by_repo_status": _sorted_counter(by_repo_status),
        "by_vuln_status": _sorted_counter(by_vuln_status),
        "by_sbom_status": _sorted_counter(by_sbom_status),
        "unsupported": unsupported,
        "vuln_failed": vuln_failed,
        "sbom_failed": sbom_failed,
        "coverage_ratio": coverage_ratio,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Severidad global
# ---------------------------------------------------------------------------


def compute_severity_distribution(records: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Distribución global de severidades (agregado de todas las filas).

    Denominador: total de filas en ``records["vulnerabilities"]``. Incluye las
    seis severidades canónicas (con ceros) en orden canónico.
    """
    counter: Counter = Counter()
    for vuln in records.get("vulnerabilities", []):
        counter[_norm_severity(vuln.get("severity"))] += 1
    return [{"severity": severity, "count": counter.get(severity, 0)} for severity in SEVERITIES]


# ---------------------------------------------------------------------------
# Frecuencia por tipo
# ---------------------------------------------------------------------------


def compute_top_rules(
    records: Dict[str, List[Dict[str, Any]]], limit: int = 20
) -> List[Dict[str, Any]]:
    """Reglas de CodeQL más frecuentes.

    Devuelve ``[{rule_id, count, repos_affected}]`` ordenado por ``count``
    descendente y ``rule_id`` ascendente como desempate.
    """
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for finding in records.get("findings", []):
        grouped.setdefault(finding.get("rule_id", "unknown"), []).append(finding)

    rows = [
        {
            "rule_id": rule_id,
            "count": len(items),
            "repos_affected": _repos_affected(items),
        }
        for rule_id, items in grouped.items()
    ]
    rows.sort(key=lambda row: (-row["count"], row["rule_id"]))
    return rows[:limit]


def compute_top_cves(
    records: Dict[str, List[Dict[str, Any]]], limit: int = 20
) -> List[Dict[str, Any]]:
    """Identificadores de vulnerabilidad (CVE/GHSA) más frecuentes.

    Devuelve ``[{id, severity, count, repos_affected}]``. La severidad es la
    más grave observada para ese ``id``. Ordenado por ``count`` descendente y
    ``id`` ascendente.
    """
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for vuln in records.get("vulnerabilities", []):
        grouped.setdefault(vuln.get("id", "unknown"), []).append(vuln)

    rows = []
    for vuln_id, items in grouped.items():
        rows.append(
            {
                "id": vuln_id,
                "severity": _worst_severity(item.get("severity", "Unknown") for item in items),
                "count": len(items),
                "repos_affected": _repos_affected(items),
            }
        )
    rows.sort(key=lambda row: (-row["count"], row["id"]))
    return rows[:limit]


def compute_top_packages(
    records: Dict[str, List[Dict[str, Any]]], limit: int = 20
) -> List[Dict[str, Any]]:
    """Paquetes con más vulnerabilidades.

    Devuelve ``[{package, count, repos_affected, worst_severity}]`` ordenado
    por ``count`` descendente y ``package`` ascendente.
    """
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for vuln in records.get("vulnerabilities", []):
        grouped.setdefault(vuln.get("package", "unknown"), []).append(vuln)

    rows = []
    for package, items in grouped.items():
        rows.append(
            {
                "package": package,
                "count": len(items),
                "repos_affected": _repos_affected(items),
                "worst_severity": _worst_severity(
                    item.get("severity", "Unknown") for item in items
                ),
            }
        )
    rows.sort(key=lambda row: (-row["count"], row["package"]))
    return rows[:limit]


# ---------------------------------------------------------------------------
# Distribución por repositorio y concentración
# ---------------------------------------------------------------------------


def compute_repository_distribution(report: MinerReport) -> List[Dict[str, Any]]:
    """Una fila por repositorio con vulnerabilidades, hallazgos y componentes.

    ``vulnerabilities`` y ``findings`` son el número de filas de detalle
    (``len``), de modo que su suma cuadra con las tablas planas. Ordenado por
    nombre de repositorio ascendente.
    """
    rows = [
        {
            "repo": repo.name,
            "vulnerabilities": len(repo.vulnerabilities),
            "findings": len(repo.findings),
            "components": repo.sbom_components,
            "status": repo.status,
        }
        for repo in report.repositories
    ]
    rows.sort(key=lambda row: row["repo"])
    return rows


def compute_concentration(
    records: Dict[str, List[Dict[str, Any]]], top_n: int = 3
) -> Dict[str, Any]:
    """Concentración de vulnerabilidades entre repositorios.

    - ``top_n_share``: fracción de vulnerabilidades en los ``top_n`` repos con
      más hallazgos.
    - ``top_10pct_share``: fracción en el decil superior de repositorios con
      vulnerabilidades; el número de repos es ``max(1, ceil(n * 0.10))``.
    - ``hhi``: índice Herfindahl-Hirschman (suma de cuadrados de cuotas).
      Vale 1.0 con un solo repositorio afectado y se acerca a 0 al repartirse.

    Denominador: total de filas en ``records["vulnerabilities"]``.
    """
    counter: Counter = Counter()
    for vuln in records.get("vulnerabilities", []):
        counter[vuln.get("repo")] += 1

    counts = sorted(counter.values(), reverse=True)
    total = sum(counts)
    repositories_with_vulns = len(counts)

    if total == 0:
        return {
            "repositories_with_vulns": 0,
            "top_n": top_n,
            "top_n_share": 0.0,
            "top_10pct_share": 0.0,
            "hhi": 0.0,
        }

    effective_top_n = max(0, top_n)
    top_n_share = _round4(sum(counts[:effective_top_n]) / total)

    decile_size = max(1, math.ceil(repositories_with_vulns * 0.10))
    top_10pct_share = _round4(sum(counts[:decile_size]) / total)

    hhi = _round4(sum((count / total) ** 2 for count in counts))

    return {
        "repositories_with_vulns": repositories_with_vulns,
        "top_n": top_n,
        "top_n_share": top_n_share,
        "top_10pct_share": top_10pct_share,
        "hhi": hhi,
    }


# ---------------------------------------------------------------------------
# Relaciones
# ---------------------------------------------------------------------------


def compute_relations(
    report: MinerReport, records: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """Relaciones entre métricas: componentes, correcciones, tipos y lenguajes.

    - ``components_vs_vulnerabilities``: Pearson entre ``sbom_components`` y
      ``vuln_total`` por repositorio (``n`` = nº de repositorios). ``null`` si
      ``n < 2`` o alguna serie tiene varianza cero.
    - ``fixed_version_available_share``: fracción de vulnerabilidades con
      ``fixed_version`` no vacío.
    - ``severity_by_package_type``: conteo por (tipo de paquete, severidad).
    - ``findings_by_language``: conteo por (lenguaje, regla); cada lenguaje del
      repositorio cuenta una vez por hallazgo.
    """
    # Correlación componentes <-> vulnerabilidades.
    components = [repo.sbom_components for repo in report.repositories]
    vuln_totals = [repo.vuln_total for repo in report.repositories]
    pearson = _pearson(components, vuln_totals)

    # Disponibilidad de versión corregida.
    vulnerabilities = records.get("vulnerabilities", [])
    fixed = sum(1 for vuln in vulnerabilities if vuln.get("fixed_version"))
    fixed_share = _round4(fixed / len(vulnerabilities)) if vulnerabilities else 0.0

    # Severidad por tipo de paquete.
    type_sev: Counter = Counter()
    for vuln in vulnerabilities:
        type_sev[(vuln.get("type") or "unknown", _norm_severity(vuln.get("severity")))] += 1
    severity_by_package_type = [
        {"type": package_type, "severity": severity, "count": count}
        for (package_type, severity), count in sorted(
            type_sev.items(), key=lambda item: (item[0][0], _severity_rank(item[0][1]))
        )
    ]

    # Hallazgos por lenguaje (cada lenguaje del repositorio cuenta).
    lang_rule: Counter = Counter()
    for repo in report.repositories:
        for language in repo.languages:
            for finding in repo.findings:
                lang_rule[(language, finding.get("rule_id", "unknown"))] += 1
    findings_by_language = [
        {"language": language, "rule_id": rule_id, "count": count}
        for (language, rule_id), count in sorted(
            lang_rule.items(), key=lambda item: (item[0][0], -item[1], item[0][1])
        )
    ]

    return {
        "components_vs_vulnerabilities": {"pearson": pearson, "n": len(report.repositories)},
        "fixed_version_available_share": fixed_share,
        "severity_by_package_type": severity_by_package_type,
        "findings_by_language": findings_by_language,
    }


# ---------------------------------------------------------------------------
# Datasets
# ---------------------------------------------------------------------------


def compute_datasets(
    report: MinerReport, records: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """Empaqueta todas las tablas y agregados para el Visualizer.

    Mantiene las claves exactas acordadas con el contrato de salida.
    """
    severity_by_repo = sorted(
        records.get("severity_distribution", []),
        key=lambda row: (row.get("repo", ""), _severity_rank(row.get("severity", "Unknown"))),
    )

    return {
        "repositories": list(records.get("repositories", [])),
        "findings": list(records.get("findings", [])),
        "vulnerabilities": list(records.get("vulnerabilities", [])),
        "severity_distribution": compute_severity_distribution(records),
        "severity_by_repo": severity_by_repo,
        "top_rules": compute_top_rules(records),
        "top_cves": compute_top_cves(records),
        "top_packages": compute_top_packages(records),
        "repository_distribution": compute_repository_distribution(report),
        "concentration": compute_concentration(records),
        "relations": compute_relations(report, records),
    }


# ---------------------------------------------------------------------------
# Observaciones
# ---------------------------------------------------------------------------


def _pct(fraction: float) -> str:
    """Formatea una fracción 0..1 como porcentaje con un decimal."""
    return f"{fraction * 100:.1f}%"


def build_observations(
    report: MinerReport,
    coverage: Dict[str, Any],
    datasets: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Genera observaciones respaldadas por cifras de ``coverage``/``datasets``.

    Cada observación es ``{"id","title","statement","metric","evidence"}`` y
    solo se emite si la dimensión tiene datos. Las cifras citadas provienen
    directamente de los datasets, de modo que la afirmación siempre es
    verificable contra ellos.
    """
    observations: List[Dict[str, Any]] = []

    def add(title: str, statement: str, metric: str, evidence: Dict[str, Any]) -> None:
        observations.append(
            {
                "id": f"OBS-{len(observations) + 1:02d}",
                "title": title,
                "statement": statement,
                "metric": metric,
                "evidence": evidence,
            }
        )

    vulnerabilities = datasets.get("vulnerabilities", [])
    findings = datasets.get("findings", [])
    severity_distribution = datasets.get("severity_distribution", [])
    repository_distribution = datasets.get("repository_distribution", [])
    concentration = datasets.get("concentration", {})
    relations = datasets.get("relations", {})
    total_vulns = sum(row["count"] for row in severity_distribution)

    # 1. Cobertura general.
    if coverage["repositories_total"]:
        add(
            "Cobertura del análisis",
            (
                f"{coverage['repositories_total']} repositorios en el reporte; "
                f"la cobertura de análisis exitoso es {_pct(coverage['coverage_ratio'])}."
            ),
            "coverage.coverage_ratio",
            {
                "repositories_total": coverage["repositories_total"],
                "coverage_ratio": coverage["coverage_ratio"],
                "by_vuln_status": coverage["by_vuln_status"],
                "by_sbom_status": coverage["by_sbom_status"],
            },
        )

    # 2. Sesgo por estados fallidos / no soportados.
    if coverage["unsupported"] or coverage["vuln_failed"] or coverage["sbom_failed"]:
        add(
            "Sesgo por estados fallidos",
            (
                "Existen repositorios sin análisis completo "
                f"(unsupported={coverage['unsupported']}, "
                f"vuln_failed={coverage['vuln_failed']}, "
                f"sbom_failed={coverage['sbom_failed']}); "
                "las métricas subestiman su superficie real."
            ),
            "coverage.by_repo_status",
            {
                "unsupported": coverage["unsupported"],
                "vuln_failed": coverage["vuln_failed"],
                "sbom_failed": coverage["sbom_failed"],
                "by_repo_status": coverage["by_repo_status"],
            },
        )

    # 3. Distribución de severidad y peso de High/Critical.
    if total_vulns:
        by_severity = {row["severity"]: row["count"] for row in severity_distribution}
        high_critical = by_severity.get("Critical", 0) + by_severity.get("High", 0)
        share = high_critical / total_vulns
        add(
            "Severidad de las vulnerabilidades",
            (
                f"El {_pct(share)} de las vulnerabilidades son High o Critical "
                f"({high_critical} de {total_vulns}); "
                f"Critical={by_severity.get('Critical', 0)}, High={by_severity.get('High', 0)}."
            ),
            "datasets.severity_distribution",
            {
                "total": total_vulns,
                "high_or_critical": high_critical,
                "high_or_critical_share": _round4(share),
                "by_severity": by_severity,
            },
        )

    # 4. Distribución entre repositorios (con y sin vulnerabilidades).
    if total_vulns:
        affected = [row for row in repository_distribution if row["vulnerabilities"] > 0]
        clean = [row for row in repository_distribution if row["vulnerabilities"] == 0]
        add(
            "Distribución de vulnerabilidades por repositorio",
            (
                f"{len(affected)} de {len(repository_distribution)} repositorios "
                f"concentran las {total_vulns} vulnerabilidades; "
                f"{len(clean)} no presentan ninguna."
            ),
            "datasets.repository_distribution",
            {
                "repositories_total": len(repository_distribution),
                "repositories_with_vulns": len(affected),
                "repositories_without_vulns": len(clean),
                "total_vulnerabilities": total_vulns,
            },
        )

    # 5. Concentración top-N / HHI.
    if concentration.get("repositories_with_vulns"):
        add(
            "Concentración entre repositorios",
            (
                f"El top {concentration['top_n']} de repositorios acumula el "
                f"{_pct(concentration['top_n_share'])} de las vulnerabilidades y "
                f"el decil superior el {_pct(concentration['top_10pct_share'])} "
                f"(HHI={concentration['hhi']})."
            ),
            "datasets.concentration",
            {
                "repositories_with_vulns": concentration["repositories_with_vulns"],
                "top_n": concentration["top_n"],
                "top_n_share": concentration["top_n_share"],
                "top_10pct_share": concentration["top_10pct_share"],
                "hhi": concentration["hhi"],
            },
        )

    # 6. Paquetes más afectados.
    top_packages = datasets.get("top_packages", [])
    if top_packages:
        leader = top_packages[0]
        add(
            "Paquetes más afectados",
            (
                f"El paquete más afectado es '{leader['package']}' con "
                f"{leader['count']} vulnerabilidades (peor severidad "
                f"{leader['worst_severity']}) en {leader['repos_affected']} repositorio(s); "
                f"se identificaron {len(top_packages)} paquetes en el top."
            ),
            "datasets.top_packages",
            {"top_packages": top_packages},
        )

    # 7. CVEs/GHSA más frecuentes.
    top_cves = datasets.get("top_cves", [])
    if top_cves:
        leader = top_cves[0]
        add(
            "Identificadores de vulnerabilidad más frecuentes",
            (
                f"El identificador más repetido es {leader['id']} "
                f"(severidad {leader['severity']}) con {leader['count']} aparición(es) "
                f"en {leader['repos_affected']} repositorio(s); "
                f"hay {len(top_cves)} identificadores distintos en el top."
            ),
            "datasets.top_cves",
            {"top_cves": top_cves},
        )

    # 8. Reglas de CodeQL más frecuentes.
    top_rules = datasets.get("top_rules", [])
    if top_rules:
        leader = top_rules[0]
        add(
            "Reglas de CodeQL más frecuentes",
            (
                f"La regla más frecuente es {leader['rule_id']} con "
                f"{leader['count']} hallazgo(s) en {leader['repos_affected']} "
                f"repositorio(s); hay {len(findings)} hallazgos en total."
            ),
            "datasets.top_rules",
            {"top_rules": top_rules, "findings_total": len(findings)},
        )

    # 9. Disponibilidad de corrección.
    if vulnerabilities:
        share = relations.get("fixed_version_available_share", 0.0)
        available = round(share * len(vulnerabilities))
        add(
            "Disponibilidad de versión corregida",
            (
                f"El {_pct(share)} de las vulnerabilidades ({available} de "
                f"{len(vulnerabilities)}) tiene versión corregida publicada; "
                f"el resto carece de corrección conocida."
            ),
            "relations.fixed_version_available_share",
            {
                "total": len(vulnerabilities),
                "with_fixed_version": available,
                "fixed_version_available_share": share,
            },
        )

    # 10. Correlación componentes <-> vulnerabilidades.
    correlation = relations.get("components_vs_vulnerabilities", {})
    if correlation.get("pearson") is not None:
        add(
            "Componentes y vulnerabilidades",
            (
                f"Correlación de Pearson entre componentes del SBOM y "
                f"vulnerabilidades por repositorio: {correlation['pearson']} "
                f"(n={correlation['n']}); no implica causalidad."
            ),
            "relations.components_vs_vulnerabilities.pearson",
            {
                "pearson": correlation["pearson"],
                "n": correlation["n"],
            },
        )

    # 11. Hallazgos por lenguaje.
    findings_by_language = relations.get("findings_by_language", [])
    if findings_by_language:
        leader = findings_by_language[0]
        languages = sorted({row["language"] for row in findings_by_language})
        add(
            "Hallazgos por lenguaje",
            (
                f"El lenguaje con más hallazgos atribuidos es '{leader['language']}' "
                f"(regla {leader['rule_id']}, {leader['count']}); "
                f"se cubren {len(languages)} lenguaje(s)."
            ),
            "relations.findings_by_language",
            {"findings_by_language": findings_by_language},
        )

    # 12. Severidad por tipo de paquete.
    severity_by_type = relations.get("severity_by_package_type", [])
    if severity_by_type:
        types = sorted({row["type"] for row in severity_by_type})
        add(
            "Severidad por tipo de paquete",
            (
                f"Se observan {len(severity_by_type)} combinación(es) "
                f"(tipo, severidad) sobre {len(types)} tipo(s) de paquete: "
                f"{', '.join(types)}."
            ),
            "relations.severity_by_package_type",
            {"severity_by_package_type": severity_by_type},
        )

    return observations


# ---------------------------------------------------------------------------
# Limitaciones
# ---------------------------------------------------------------------------


def build_limitations(report: MinerReport, coverage: Dict[str, Any]) -> List[str]:
    """Declara limitaciones y sesgos que afectan la confiabilidad.

    Incluye las secciones ausentes, los estados fallidos, inconsistencias de
    conteo y la advertencia de que correlación no implica causalidad.
    """
    limitations: List[str] = []

    repositories = report.repositories

    # Secciones ausentes.
    if not any(repo.findings for repo in repositories):
        limitations.append(
            "El reporte no incluye hallazgos de CodeQL (findings vacío o ausente): "
            "no pueden calcularse métricas por regla ni por lenguaje."
        )
    if not any(repo.vulnerabilities for repo in repositories):
        limitations.append(
            "El reporte no incluye vulnerabilidades de Grype: no pueden calcularse "
            "métricas de severidad, paquetes ni correcciones."
        )
    if not any(
        repo.sbom_components > 0 or repo.sbom_status in SBOM_OK_STATUSES
        for repo in repositories
    ):
        limitations.append(
            "El reporte no incluye un SBOM con componentes: no puede evaluarse la "
            "relación entre componentes y vulnerabilidades."
        )

    # Estados fallidos.
    if coverage["unsupported"]:
        limitations.append(
            f"{coverage['unsupported']} repositorio(s) no soportado(s) quedan fuera "
            "del análisis y sesgan a la baja los totales."
        )
    if coverage["vuln_failed"]:
        limitations.append(
            f"{coverage['vuln_failed']} repositorio(s) fallaron en Grype: sus "
            "vulnerabilidades no están representadas."
        )
    if coverage["sbom_failed"]:
        limitations.append(
            f"{coverage['sbom_failed']} repositorio(s) fallaron al generar el SBOM: "
            "su inventario de componentes está incompleto."
        )
    if coverage["coverage_ratio"] < 1.0 and coverage["repositories_total"]:
        limitations.append(
            f"La cobertura de análisis exitoso es {_pct(coverage['coverage_ratio'])}: "
            "las conclusiones no describen a toda la organización."
        )

    # Consistencia de conteos.
    flat_vulns = sum(len(repo.vulnerabilities) for repo in repositories)
    reported_vulns = sum(repo.vuln_total for repo in repositories)
    if flat_vulns != reported_vulns:
        limitations.append(
            f"Discrepancia de conteo: {flat_vulns} vulnerabilidades en las filas de "
            f"detalle frente a {reported_vulns} en 'vuln_total'; los totales por "
            "repositorio pueden no coincidir con el resumen."
        )
    summary_vulns = report.summary.get("vulnerabilities")
    if isinstance(summary_vulns, int) and summary_vulns != flat_vulns:
        limitations.append(
            f"El resumen declara {summary_vulns} vulnerabilidades pero las filas de "
            f"detalle suman {flat_vulns}; revisar la integridad del reporte."
        )

    # Advertencias del cargador.
    limitations.extend(report.warnings)

    # Advertencias metodológicas siempre presentes.
    limitations.append(
        "La correlación entre variables (p. ej. componentes y vulnerabilidades) no "
        "implica causalidad; puede estar confundida por el tamaño o el ecosistema "
        "del repositorio."
    )
    if coverage["repositories_total"] < 30:
        limitations.append(
            f"La muestra es pequeña ({coverage['repositories_total']} repositorios): "
            "las proporciones y correlaciones tienen alta incertidumbre y no deben "
            "generalizarse."
        )

    return limitations
