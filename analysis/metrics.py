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

from analysis.loader import (
    FAILED_STATUSES,
    SBOM_OK_STATUSES,
    SEVERITIES,
    VULN_OK_STATUSES,
    MinerReport,
)

__all__ = [
    "SEVERITY_WEIGHTS",
    "compute_coverage",
    "compute_severity_distribution",
    "compute_top_rules",
    "compute_top_cves",
    "compute_top_packages",
    "compute_repository_distribution",
    "compute_repository_risk",
    "compute_risk_summary",
    "compute_concentration",
    "compute_relations",
    "compute_datasets",
    "build_observations",
    "build_limitations",
]

# ``VULN_OK_STATUSES``, ``SBOM_OK_STATUSES`` y ``FAILED_STATUSES`` se
# re-exportan desde ``analysis.loader`` para mantener una única fuente de
# verdad; se conservan como nombres de este módulo por compatibilidad.

# Índice canónico de severidad (menor = más grave).
_SEVERITY_INDEX = {severity: index for index, severity in enumerate(SEVERITIES)}

#: Peso de gravedad (0..10) por severidad canónica. Se usa para la nota 1-10,
#: la media ponderada de severidad y la mediana de severidad. Los pesos son una
#: decisión metodológica explícita, no una medida oficial de explotabilidad.
SEVERITY_WEIGHTS: Dict[str, float] = {
    "Critical": 10.0,
    "High": 7.0,
    "Medium": 4.0,
    "Low": 2.0,
    "Negligible": 1.0,
    "Unknown": 0.0,
}


# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------


def _round4(value: float) -> float:
    """Redondea a 4 decimales de forma estable (evita -0.0)."""
    rounded = round(float(value), 4)
    return 0.0 if rounded == 0 else rounded


def _round1(value: float) -> float:
    """Redondea a 1 decimal de forma estable (evita -0.0)."""
    rounded = round(float(value), 1)
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


def _severity_weight(severity: Any) -> float:
    """Peso de gravedad (0..10) de una severidad; ``Unknown``/inválida = 0."""
    return SEVERITY_WEIGHTS.get(_norm_severity(severity), 0.0)


def _median(values: Sequence[float]) -> float:
    """Mediana de una serie de números (``0.0`` si está vacía)."""
    ordered = sorted(values)
    count = len(ordered)
    if count == 0:
        return 0.0
    middle = count // 2
    if count % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _severity_score(weights: Sequence[float]) -> float:
    """Nota 1-10 a partir de los pesos de severidad (0..10).

    Es el promedio de los pesos reescalado linealmente a ``[1, 10]``: un
    promedio de 10 (todas Critical) da 10.0 y un promedio de 0 (todas Unknown o
    sin vulnerabilidades) da 1.0. Mide **gravedad media**, no volumen.
    """
    if not weights:
        return 1.0
    average = sum(weights) / len(weights)
    return _round1(1.0 + 9.0 * (average / 10.0))


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

    ``coverage_ratio`` cuenta un repositorio como cubierto si su estado es
    ``analyzed`` o si ``vuln_status`` ∈ :data:`VULN_OK_STATUSES` o
    ``sbom_status`` ∈ :data:`SBOM_OK_STATUSES` (es decir, **al menos** una de
    las tres dimensiones tuvo éxito). Para desambiguar esa lectura se exponen
    además ``code_coverage_ratio``, ``sbom_coverage_ratio`` y
    ``vuln_coverage_ratio``, cada uno con su propia dimensión como numerador.
    El denominador de todos los ratios es el total de repositorios.
    """
    repositories = report.repositories
    total = len(repositories)

    by_repo_status: Counter = Counter(repo.status for repo in repositories)
    by_vuln_status: Counter = Counter(repo.vuln_status for repo in repositories)
    by_sbom_status: Counter = Counter(repo.sbom_status for repo in repositories)

    unsupported = by_repo_status.get("unsupported", 0)
    vuln_failed = by_vuln_status.get("failed", 0)
    sbom_failed = by_sbom_status.get("failed", 0)
    repo_failed = sum(1 for repo in repositories if repo.status in FAILED_STATUSES)

    covered = sum(
        1
        for repo in repositories
        if repo.status == "analyzed"
        or repo.vuln_status in VULN_OK_STATUSES
        or repo.sbom_status in SBOM_OK_STATUSES
    )
    code_covered = by_repo_status.get("analyzed", 0)
    sbom_covered = sum(1 for repo in repositories if repo.sbom_status in SBOM_OK_STATUSES)
    vuln_covered = sum(1 for repo in repositories if repo.vuln_status in VULN_OK_STATUSES)

    def _ratio(count: int) -> float:
        return _round4(count / total) if total else 0.0

    coverage_ratio = _ratio(covered)
    code_coverage_ratio = _ratio(code_covered)
    sbom_coverage_ratio = _ratio(sbom_covered)
    vuln_coverage_ratio = _ratio(vuln_covered)

    warnings: List[str] = list(report.warnings)
    if unsupported:
        warnings.append(
            f"{unsupported} repositorio(s) no soportado(s): sin análisis de código ni SBOM."
        )
    if repo_failed:
        failed_detail = ", ".join(
            f"{status}={by_repo_status[status]}"
            for status in sorted(FAILED_STATUSES)
            if by_repo_status.get(status)
        )
        warnings.append(
            f"{repo_failed} repositorio(s) fallaron en fases previas "
            f"({failed_detail}); no tienen análisis de código."
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
        "repo_failed": repo_failed,
        "vuln_failed": vuln_failed,
        "sbom_failed": sbom_failed,
        "coverage_ratio": coverage_ratio,
        "code_coverage_ratio": code_coverage_ratio,
        "sbom_coverage_ratio": sbom_coverage_ratio,
        "vuln_coverage_ratio": vuln_coverage_ratio,
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


def compute_repository_risk(report: MinerReport) -> List[Dict[str, Any]]:
    """Riesgo por repositorio: nota 1-10, gravedad media, densidad y corrección.

    Una fila por repositorio (también los que no tienen vulnerabilidades, con
    ``score = 1.0``). Campos:

    - ``score``: nota 1-10 (promedio ponderado de severidad reescalado).
    - ``severity_weighted_average``: media de los pesos (0..10).
    - ``severity_median``: mediana de los pesos (0..10).
    - ``worst_severity``: severidad más grave observada.
    - ``critical``/``high``: conteos de esas severidades.
    - ``vulns_per_component``/``findings_per_component``: densidad (``null`` si
      no hay componentes de SBOM).
    - ``fixed_version_share``: fracción con corrección publicada (``null`` si no
      hay vulnerabilidades).

    Ordenado por ``score`` descendente, luego por ``severity_weighted_average``
    descendente y por ``repo`` ascendente (determinista).
    """
    rows: List[Dict[str, Any]] = []
    for repo in report.repositories:
        vulnerabilities = repo.vulnerabilities
        weights = [_severity_weight(vuln.get("severity")) for vuln in vulnerabilities]
        total = len(weights)
        components = repo.sbom_components
        findings = len(repo.findings)
        critical = sum(
            1 for vuln in vulnerabilities if _norm_severity(vuln.get("severity")) == "Critical"
        )
        high = sum(
            1 for vuln in vulnerabilities if _norm_severity(vuln.get("severity")) == "High"
        )
        fixed = sum(1 for vuln in vulnerabilities if vuln.get("fixed_version"))

        rows.append(
            {
                "repo": repo.name,
                "status": repo.status,
                "languages": list(repo.languages),
                "vulnerabilities": total,
                "findings": findings,
                "components": components,
                "critical": critical,
                "high": high,
                "worst_severity": _worst_severity(
                    vuln.get("severity") for vuln in vulnerabilities
                ),
                "severity_weighted_average": _round4(sum(weights) / total) if total else 0.0,
                "severity_median": _round4(_median(weights)) if total else 0.0,
                "score": _severity_score(weights),
                "vulns_per_component": _round4(total / components) if components > 0 else None,
                "findings_per_component": _round4(findings / components)
                if components > 0
                else None,
                "fixed_version_share": _round4(fixed / total) if total else None,
            }
        )

    rows.sort(
        key=lambda row: (-row["score"], -row["severity_weighted_average"], row["repo"])
    )
    return rows


def compute_risk_summary(
    report: MinerReport, repository_risk: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Resumen global de riesgo a partir del ranking por repositorio.

    - ``score``: nota 1-10 de la organización, calculada sobre **todas** las
      vulnerabilidades (ponderada por volumen).
    - ``severity_weighted_average``/``severity_median``: agregados globales.
    - ``mean_repository_score``/``max_repository_score``: media y máximo de las
      notas por repositorio **con vulnerabilidades** (sin ponderar por volumen).
    - ``repositories_scored``: repositorios con al menos una vulnerabilidad.
    - ``repositories_with_critical``/``repositories_with_high_or_critical``:
      hotspots.
    - ``critical_hotspots``: nombres ordenados de repos con al menos una
      vulnerabilidad ``Critical``.
    - ``worst_severity``: severidad más grave de la organización.
    """
    all_weights = [
        _severity_weight(vuln.get("severity"))
        for repo in report.repositories
        for vuln in repo.vulnerabilities
    ]
    total = len(all_weights)
    scored = [row for row in repository_risk if row["vulnerabilities"] > 0]
    scores = [row["score"] for row in scored]
    critical_hotspots = sorted(
        row["repo"] for row in repository_risk if row["critical"] > 0
    )

    return {
        "score": _severity_score(all_weights),
        "severity_weighted_average": _round4(sum(all_weights) / total) if total else 0.0,
        "severity_median": _round4(_median(all_weights)) if total else 0.0,
        "total_vulnerabilities": total,
        "repositories_scored": len(scored),
        "repositories_with_critical": len(critical_hotspots),
        "repositories_with_high_or_critical": sum(
            1 for row in repository_risk if row["critical"] + row["high"] > 0
        ),
        "mean_repository_score": _round1(sum(scores) / len(scores)) if scores else 0.0,
        "max_repository_score": max(scores) if scores else 0.0,
        "critical_hotspots": critical_hotspots,
        "worst_severity": _worst_severity(
            vuln.get("severity")
            for repo in report.repositories
            for vuln in repo.vulnerabilities
        ),
    }


def compute_concentration(
    records: Dict[str, List[Dict[str, Any]]], top_n: int = 3
) -> Dict[str, Any]:
    """Concentración de vulnerabilidades entre repositorios.

    - ``top_n_share``: fracción de vulnerabilidades en los ``top_n`` repos con
      más hallazgos. ``top_n`` se acota a ``min(top_n, repositories_with_vulns)``
      para no contar repositorios inexistentes; la respuesta devuelve ese valor
      efectivo.
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
    effective_top_n = min(max(0, top_n), repositories_with_vulns)

    if total == 0:
        return {
            "repositories_with_vulns": 0,
            "top_n": 0,
            "top_n_share": 0.0,
            "top_10pct_share": 0.0,
            "hhi": 0.0,
        }

    top_n_share = _round4(sum(counts[:effective_top_n]) / total)

    decile_size = max(1, math.ceil(repositories_with_vulns * 0.10))
    top_10pct_share = _round4(sum(counts[:decile_size]) / total)

    hhi = _round4(sum((count / total) ** 2 for count in counts))

    return {
        "repositories_with_vulns": repositories_with_vulns,
        "top_n": effective_top_n,
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
      repositorio cuenta una vez por hallazgo. Se ordena por lenguaje, luego
      por ``count`` descendente y luego por regla; **no** está agregado por
      lenguaje, así que para elegir el lenguaje con más hallazgos hay que sumar
      los ``count`` de cada lenguaje (lo hace :func:`build_observations`).
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

    # Severidad de vulnerabilidades por lenguaje del repositorio. Igual que
    # ``findings_by_language``, cada lenguaje declarado cuenta la vulnerabilidad
    # una vez, por lo que los conteos por lenguaje no suman el total global.
    lang_sev: Counter = Counter()
    for repo in report.repositories:
        for language in repo.languages:
            for vuln in repo.vulnerabilities:
                lang_sev[(language, _norm_severity(vuln.get("severity")))] += 1
    severity_by_language = [
        {"language": language, "severity": severity, "count": count}
        for (language, severity), count in sorted(
            lang_sev.items(), key=lambda item: (item[0][0], _severity_rank(item[0][1]))
        )
    ]

    return {
        "components_vs_vulnerabilities": {"pearson": pearson, "n": len(report.repositories)},
        "fixed_version_available_share": fixed_share,
        "severity_by_package_type": severity_by_package_type,
        "findings_by_language": findings_by_language,
        "severity_by_language": severity_by_language,
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
    repository_risk = compute_repository_risk(report)

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
        "repository_risk": repository_risk,
        "concentration": compute_concentration(records),
        "risk_summary": compute_risk_summary(report, repository_risk),
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
                f"al menos un análisis exitoso en "
                f"{_pct(coverage['coverage_ratio'])} de ellos "
                f"(código {_pct(coverage['code_coverage_ratio'])}, "
                f"SBOM {_pct(coverage['sbom_coverage_ratio'])}, "
                f"Grype {_pct(coverage['vuln_coverage_ratio'])})."
            ),
            "coverage.coverage_ratio",
            {
                "repositories_total": coverage["repositories_total"],
                "coverage_ratio": coverage["coverage_ratio"],
                "code_coverage_ratio": coverage["code_coverage_ratio"],
                "sbom_coverage_ratio": coverage["sbom_coverage_ratio"],
                "vuln_coverage_ratio": coverage["vuln_coverage_ratio"],
                "by_vuln_status": coverage["by_vuln_status"],
                "by_sbom_status": coverage["by_sbom_status"],
            },
        )

    # 2. Sesgo por estados fallidos / no soportados.
    if (
        coverage["unsupported"]
        or coverage["repo_failed"]
        or coverage["vuln_failed"]
        or coverage["sbom_failed"]
    ):
        add(
            "Sesgo por estados fallidos",
            (
                "Existen repositorios sin análisis completo "
                f"(unsupported={coverage['unsupported']}, "
                f"repo_failed={coverage['repo_failed']}, "
                f"vuln_failed={coverage['vuln_failed']}, "
                f"sbom_failed={coverage['sbom_failed']}); "
                "las métricas subestiman su superficie real."
            ),
            "coverage.by_repo_status",
            {
                "unsupported": coverage["unsupported"],
                "repo_failed": coverage["repo_failed"],
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
        packages_distinct = len({vuln.get("package") for vuln in vulnerabilities})
        add(
            "Paquetes más afectados",
            (
                f"El paquete más afectado es '{leader['package']}' con "
                f"{leader['count']} vulnerabilidades (peor severidad "
                f"{leader['worst_severity']}) en {leader['repos_affected']} repositorio(s); "
                f"el top {len(top_packages)} de {packages_distinct} paquetes distintos."
            ),
            "datasets.top_packages",
            {
                "top_packages": top_packages,
                "packages_distinct": packages_distinct,
            },
        )

    # 7. CVEs/GHSA más frecuentes.
    top_cves = datasets.get("top_cves", [])
    if top_cves:
        leader = top_cves[0]
        cves_distinct = len({vuln.get("id") for vuln in vulnerabilities})
        add(
            "Identificadores de vulnerabilidad más frecuentes",
            (
                f"El identificador más repetido es {leader['id']} "
                f"(severidad {leader['severity']}) con {leader['count']} aparición(es) "
                f"en {leader['repos_affected']} repositorio(s); "
                f"el top {len(top_cves)} de {cves_distinct} identificadores distintos."
            ),
            "datasets.top_cves",
            {"top_cves": top_cves, "cves_distinct": cves_distinct},
        )

    # 8. Reglas de CodeQL más frecuentes.
    top_rules = datasets.get("top_rules", [])
    if top_rules:
        leader = top_rules[0]
        rules_distinct = len({finding.get("rule_id") for finding in findings})
        add(
            "Reglas de CodeQL más frecuentes",
            (
                f"La regla más frecuente es {leader['rule_id']} con "
                f"{leader['count']} hallazgo(s) en {leader['repos_affected']} "
                f"repositorio(s); el top {len(top_rules)} de {rules_distinct} "
                f"reglas distintas sobre {len(findings)} hallazgos en total."
            ),
            "datasets.top_rules",
            {
                "top_rules": top_rules,
                "rules_distinct": rules_distinct,
                "findings_total": len(findings),
            },
        )

    # 9. Disponibilidad de corrección.
    if vulnerabilities:
        share = relations.get("fixed_version_available_share", 0.0)
        available = sum(1 for vuln in vulnerabilities if vuln.get("fixed_version"))
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
        # El dataset está desagregado por (lenguaje, regla); el líder se elige
        # por la suma de hallazgos por lenguaje, con desempate alfabético.
        language_totals: Dict[str, int] = {}
        for row in findings_by_language:
            language_totals[row["language"]] = (
                language_totals.get(row["language"], 0) + row["count"]
            )
        leader_language = min(
            language_totals, key=lambda language: (-language_totals[language], language)
        )
        leader_rows = [
            row for row in findings_by_language if row["language"] == leader_language
        ]
        leader_rule = min(
            leader_rows, key=lambda row: (-row["count"], row["rule_id"])
        )
        languages = sorted(language_totals)
        add(
            "Hallazgos por lenguaje",
            (
                f"El lenguaje con más hallazgos atribuidos es '{leader_language}' "
                f"({language_totals[leader_language]} hallazgos; regla más frecuente "
                f"{leader_rule['rule_id']} con {leader_rule['count']}); "
                f"se cubren {len(languages)} lenguaje(s)."
            ),
            "relations.findings_by_language",
            {
                "findings_by_language": findings_by_language,
                "language_totals": language_totals,
                "leader_language": leader_language,
                "leader_total": language_totals[leader_language],
                "leader_rule": leader_rule["rule_id"],
            },
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

    # 13. Nota global de vulnerabilidad (1-10).
    risk_summary = datasets.get("risk_summary", {})
    if risk_summary.get("total_vulnerabilities"):
        add(
            "Nota global de vulnerabilidad",
            (
                f"La organización obtiene una nota de {risk_summary['score']}/10 "
                f"(media ponderada de severidad "
                f"{risk_summary['severity_weighted_average']}/10, peor severidad "
                f"{risk_summary['worst_severity']}); la media de las notas por "
                f"repositorio es {risk_summary['mean_repository_score']}/10 sobre "
                f"{risk_summary['repositories_scored']} repositorio(s) con "
                f"vulnerabilidades."
            ),
            "datasets.risk_summary",
            {
                "score": risk_summary["score"],
                "severity_weighted_average": risk_summary["severity_weighted_average"],
                "severity_median": risk_summary["severity_median"],
                "mean_repository_score": risk_summary["mean_repository_score"],
                "max_repository_score": risk_summary["max_repository_score"],
                "repositories_scored": risk_summary["repositories_scored"],
                "worst_severity": risk_summary["worst_severity"],
                "total_vulnerabilities": risk_summary["total_vulnerabilities"],
            },
        )

    # 14. Ranking de repositorios por gravedad.
    repository_risk = datasets.get("repository_risk", [])
    ranked = [row for row in repository_risk if row["vulnerabilities"] > 0]
    if ranked:
        leader = ranked[0]
        add(
            "Repositorios con vulnerabilidades más graves",
            (
                f"'{leader['repo']}' encabeza el ranking con nota {leader['score']}/10 "
                f"(media ponderada {leader['severity_weighted_average']}/10, peor "
                f"severidad {leader['worst_severity']}, "
                f"{leader['vulnerabilities']} vulnerabilidad(es)); "
                f"{len(ranked)} de {len(repository_risk)} repositorio(s) tienen "
                f"vulnerabilidades."
            ),
            "datasets.repository_risk",
            {
                "repository_risk": ranked,
                "leader": leader["repo"],
                "leader_score": leader["score"],
                "repositories_scored": len(ranked),
                "repositories_total": len(repository_risk),
            },
        )

    # 15. Densidad de vulnerabilidades por componente.
    density_rows = [
        row for row in repository_risk if row["vulns_per_component"] is not None
    ]
    if density_rows:
        density_leader = min(
            density_rows, key=lambda row: (-row["vulns_per_component"], row["repo"])
        )
        add(
            "Densidad de vulnerabilidades",
            (
                f"'{density_leader['repo']}' tiene la mayor densidad: "
                f"{density_leader['vulns_per_component']} vulnerabilidades por "
                f"componente ({density_leader['vulnerabilities']} de "
                f"{density_leader['components']} componentes)."
            ),
            "datasets.repository_risk.vulns_per_component",
            {
                "leader": density_leader["repo"],
                "vulns_per_component": density_leader["vulns_per_component"],
                "repositories_with_density": len(density_rows),
            },
        )

    # 16. Hotspots de severidad Critical.
    if risk_summary.get("repositories_with_critical"):
        hotspots = risk_summary.get("critical_hotspots", [])
        add(
            "Repositorios con vulnerabilidades Critical",
            (
                f"{risk_summary['repositories_with_critical']} repositorio(s) tienen "
                f"al menos una vulnerabilidad Critical: {', '.join(hotspots)}; "
                f"{risk_summary['repositories_with_high_or_critical']} repositorio(s) "
                f"tienen High o Critical."
            ),
            "datasets.risk_summary.critical_hotspots",
            {
                "repositories_with_critical": risk_summary["repositories_with_critical"],
                "repositories_with_high_or_critical": risk_summary[
                    "repositories_with_high_or_critical"
                ],
                "critical_hotspots": hotspots,
            },
        )

    # 17. Severidad de vulnerabilidades por lenguaje.
    severity_by_language = relations.get("severity_by_language", [])
    if severity_by_language:
        languages = sorted({row["language"] for row in severity_by_language})
        add(
            "Severidad de vulnerabilidades por lenguaje",
            (
                f"Se observan {len(severity_by_language)} combinación(es) "
                f"(lenguaje, severidad) sobre {len(languages)} lenguaje(s): "
                f"{', '.join(languages)}."
            ),
            "relations.severity_by_language",
            {"severity_by_language": severity_by_language},
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
    if coverage["repo_failed"]:
        failed_detail = ", ".join(
            f"{status}={coverage['by_repo_status'][status]}"
            for status in sorted(FAILED_STATUSES)
            if coverage["by_repo_status"].get(status)
        )
        limitations.append(
            f"{coverage['repo_failed']} repositorio(s) fallaron en fases previas "
            f"({failed_detail}): sin análisis de código, sus hallazgos no están "
            "representados."
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
            f"La cobertura de análisis exitoso (al menos una de las tres "
            f"dimensiones) es {_pct(coverage['coverage_ratio'])}: las conclusiones "
            "no describen a toda la organización."
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
    by_severity_total = sum(
        sum(repo.by_severity.values()) for repo in repositories
    )
    if by_severity_total != flat_vulns:
        limitations.append(
            f"Los conteos de 'by_severity' ({by_severity_total}) no cuadran con las "
            f"filas de detalle de vulnerabilidades ({flat_vulns}): la distribución "
            "por repositorio y severidad puede estar incompleta."
        )
    summary_vulns = report.summary.get("vulnerabilities")
    if isinstance(summary_vulns, int) and summary_vulns != flat_vulns:
        limitations.append(
            f"El resumen declara {summary_vulns} vulnerabilidades pero las filas de "
            f"detalle suman {flat_vulns}; revisar la integridad del reporte."
        )

    # Advertencias del cargador.
    limitations.extend(report.warnings)

    # Concentración degenerada: con pocos repos afectados el top-N y el decil
    # no son informativos.
    repositories_with_vulns = sum(1 for repo in repositories if repo.vulnerabilities)
    if 0 < repositories_with_vulns < 5:
        limitations.append(
            f"Solo {repositories_with_vulns} repositorio(s) tienen vulnerabilidades: "
            "el top-N y el decil superior son poco informativos y las medidas de "
            "concentración (top_n_share, top_10pct_share, HHI) deben interpretarse "
            "con cautela."
        )

    # Nota 1-10: explicitar que es una decisión metodológica con pesos fijos.
    if any(repo.vulnerabilities for repo in repositories):
        limitations.append(
            "La nota 1-10, la media ponderada y la mediana de severidad usan pesos "
            "fijos (Critical=10, High=7, Medium=4, Low=2, Negligible=1, Unknown=0): "
            "resumen la gravedad media, no el volumen ni la explotabilidad real, y "
            "no sustituyen una priorización basada en CVSS, EPSS o KEV."
        )

    # Densidad no calculable por falta de SBOM.
    repos_without_components = sum(
        1 for repo in repositories if repo.vulnerabilities and repo.sbom_components <= 0
    )
    if repos_without_components:
        limitations.append(
            f"{repos_without_components} repositorio(s) con vulnerabilidades no tienen "
            "componentes de SBOM: su densidad de vulnerabilidades (vulns por "
            "componente) no es calculable y quedan fuera de ese ranking."
        )

    # Atribución múltiple en la severidad por lenguaje.
    multi_language = sum(
        1 for repo in repositories if repo.vulnerabilities and len(repo.languages) > 1
    )
    if multi_language:
        limitations.append(
            f"{multi_language} repositorio(s) con vulnerabilidades declaran varios "
            "lenguajes: la severidad por lenguaje atribuye cada vulnerabilidad a cada "
            "lenguaje, por lo que los conteos por lenguaje no suman el total global."
        )

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
