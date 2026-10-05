"""Tests de las métricas y observaciones del Analyzer (``analysis.metrics``).

Solo usan la librería estándar y ``pytest``: no requieren pandas. Se construyen
reportes sintéticos en ``tmp_path`` y se derivan las tablas con ``to_records``.
"""

import json

import pytest

from analysis.loader import SEVERITIES, load_report, to_records
from analysis.metrics import (
    build_limitations,
    build_observations,
    compute_concentration,
    compute_coverage,
    compute_datasets,
    compute_relations,
    compute_repository_distribution,
    compute_severity_distribution,
    compute_top_cves,
    compute_top_packages,
    compute_top_rules,
)


def write_json(tmp_path, data, name="report.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def rich_report_data():
    """Tres repositorios: dos con datos completos y uno con fallos."""
    return {
        "organization": "acme",
        "summary": {"vulnerabilities": 4, "findings": 3, "repositories": 3},
        "repositories": [
            {
                "name": "alpha",
                "status": "analyzed",
                "languages": ["python"],
                "sbom": {"status": "generated", "components": 10},
                "vulnerabilities": {
                    "status": "scanned",
                    "total": 3,
                    "by_severity": {
                        "Critical": 1,
                        "High": 1,
                        "Medium": 1,
                        "Low": 0,
                        "Negligible": 0,
                        "Unknown": 0,
                    },
                    "vulnerabilities": [
                        {
                            "id": "CVE-1",
                            "severity": "Critical",
                            "package": "openssl",
                            "version": "1",
                            "type": "deb",
                            "fixed_version": "2",
                            "namespace": "nvd",
                        },
                        {
                            "id": "CVE-2",
                            "severity": "High",
                            "package": "openssl",
                            "version": "1",
                            "type": "deb",
                            "fixed_version": None,
                            "namespace": "nvd",
                        },
                        {
                            "id": "CVE-1",
                            "severity": "High",
                            "package": "lodash",
                            "version": "1",
                            "type": "npm",
                            "fixed_version": "2",
                            "namespace": "nvd",
                        },
                    ],
                },
                "findings": [
                    {
                        "rule_id": "py/sqli",
                        "severity": "error",
                        "file": "a.py",
                        "start_line": 1,
                    },
                    {
                        "rule_id": "py/sqli",
                        "severity": "warning",
                        "file": "b.py",
                        "start_line": 2,
                    },
                ],
            },
            {
                "name": "beta",
                "status": "analyzed",
                "languages": ["python", "javascript"],
                "sbom": {"status": "generated", "components": 5},
                "vulnerabilities": {
                    "status": "scanned",
                    "total": 1,
                    "by_severity": {
                        "Critical": 0,
                        "High": 0,
                        "Medium": 1,
                        "Low": 0,
                        "Negligible": 0,
                        "Unknown": 0,
                    },
                    "vulnerabilities": [
                        {
                            "id": "CVE-3",
                            "severity": "Medium",
                            "package": "requests",
                            "version": "1",
                            "type": "python",
                            "fixed_version": "3",
                            "namespace": "nvd",
                        },
                    ],
                },
                "findings": [
                    {
                        "rule_id": "js/xss",
                        "severity": "error",
                        "file": "c.js",
                        "start_line": 3,
                    },
                ],
            },
            {
                "name": "gamma",
                "status": "unsupported",
                "languages": [],
                "sbom": {"status": "failed", "components": 0},
                "vulnerabilities": {"status": "failed", "total": 0},
            },
        ],
    }


def load_rich(tmp_path):
    report = load_report(write_json(tmp_path, rich_report_data()))
    return report, to_records(report)


# ---------------------------------------------------------------------------
# Severidad y frecuencia por tipo
# ---------------------------------------------------------------------------


def test_compute_severity_distribution_includes_six_and_sums(tmp_path):
    _, records = load_rich(tmp_path)

    distribution = compute_severity_distribution(records)

    assert [row["severity"] for row in distribution] == list(SEVERITIES)
    assert sum(row["count"] for row in distribution) == len(
        records["vulnerabilities"]
    )
    counts = {row["severity"]: row["count"] for row in distribution}
    assert counts["Critical"] == 1
    assert counts["High"] == 2
    assert counts["Medium"] == 1
    assert counts["Low"] == 0
    assert counts["Negligible"] == 0
    assert counts["Unknown"] == 0


def test_compute_top_cves_counts_and_repos(tmp_path):
    _, records = load_rich(tmp_path)

    rows = compute_top_cves(records)

    assert rows == [
        {"id": "CVE-1", "severity": "Critical", "count": 2, "repos_affected": 1},
        {"id": "CVE-2", "severity": "High", "count": 1, "repos_affected": 1},
        {"id": "CVE-3", "severity": "Medium", "count": 1, "repos_affected": 1},
    ]


def test_compute_top_packages_counts_and_worst_severity(tmp_path):
    _, records = load_rich(tmp_path)

    rows = compute_top_packages(records)

    assert rows == [
        {
            "package": "openssl",
            "count": 2,
            "repos_affected": 1,
            "worst_severity": "Critical",
        },
        {
            "package": "lodash",
            "count": 1,
            "repos_affected": 1,
            "worst_severity": "High",
        },
        {
            "package": "requests",
            "count": 1,
            "repos_affected": 1,
            "worst_severity": "Medium",
        },
    ]


def test_compute_top_rules_counts_and_repos(tmp_path):
    _, records = load_rich(tmp_path)

    rows = compute_top_rules(records)

    assert rows == [
        {"rule_id": "py/sqli", "count": 2, "repos_affected": 1},
        {"rule_id": "js/xss", "count": 1, "repos_affected": 1},
    ]


def test_top_limit_is_applied(tmp_path):
    _, records = load_rich(tmp_path)

    assert len(compute_top_cves(records, limit=1)) == 1
    assert compute_top_cves(records, limit=1)[0]["id"] == "CVE-1"
    assert len(compute_top_packages(records, limit=2)) == 2
    assert len(compute_top_rules(records, limit=1)) == 1


def test_top_ties_are_deterministic(tmp_path):
    _, records = load_rich(tmp_path)

    first = compute_top_packages(records)
    second = compute_top_packages(records)

    assert first == second
    # Desempate alfabético: lodash antes que requests.
    assert [row["package"] for row in first] == ["openssl", "lodash", "requests"]


# ---------------------------------------------------------------------------
# Distribución y concentración
# ---------------------------------------------------------------------------


def test_compute_repository_distribution_sums_to_detail_rows(tmp_path):
    report, records = load_rich(tmp_path)

    rows = compute_repository_distribution(report)

    assert [row["repo"] for row in rows] == ["alpha", "beta", "gamma"]
    assert sum(row["vulnerabilities"] for row in rows) == len(
        records["vulnerabilities"]
    )
    assert rows[0] == {
        "repo": "alpha",
        "vulnerabilities": 3,
        "findings": 2,
        "components": 10,
        "status": "analyzed",
    }
    assert rows[2]["vulnerabilities"] == 0
    assert rows[2]["findings"] == 0


def test_compute_concentration_single_repo(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "solo",
                        "status": "analyzed",
                        "vulnerabilities": {
                            "status": "scanned",
                            "total": 2,
                            "by_severity": {
                                "Critical": 0,
                                "High": 2,
                                "Medium": 0,
                                "Low": 0,
                                "Negligible": 0,
                                "Unknown": 0,
                            },
                            "vulnerabilities": [
                                {
                                    "id": "CVE-A",
                                    "severity": "High",
                                    "package": "p",
                                    "type": "npm",
                                    "fixed_version": "1",
                                },
                                {
                                    "id": "CVE-A",
                                    "severity": "High",
                                    "package": "p",
                                    "type": "npm",
                                    "fixed_version": None,
                                },
                            ],
                        },
                    }
                ]
            },
        )
    )
    records = to_records(report)

    concentration = compute_concentration(records)

    assert concentration["repositories_with_vulns"] == 1
    assert concentration["top_n_share"] == 1.0
    assert concentration["top_10pct_share"] == 1.0
    assert concentration["hhi"] == 1.0


def test_compute_concentration_without_vulnerabilities(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {"name": "a", "status": "analyzed"},
                    {"name": "b", "status": "analyzed"},
                ]
            },
        )
    )
    records = to_records(report)

    concentration = compute_concentration(records)

    assert concentration["repositories_with_vulns"] == 0
    assert concentration["top_n_share"] == 0.0
    assert concentration["top_10pct_share"] == 0.0
    assert concentration["hhi"] == 0.0


def test_compute_concentration_multiple_repos_hhi_below_one(tmp_path):
    _, records = load_rich(tmp_path)

    concentration = compute_concentration(records)

    assert concentration["repositories_with_vulns"] == 2
    assert concentration["top_n_share"] == 1.0
    assert concentration["top_10pct_share"] == 0.75
    assert concentration["hhi"] == 0.625


# ---------------------------------------------------------------------------
# Relaciones
# ---------------------------------------------------------------------------


def test_compute_relations_fixed_version_share(tmp_path):
    report, records = load_rich(tmp_path)

    relations = compute_relations(report, records)

    # 3 de 4 vulnerabilidades tienen versión corregida.
    assert relations["fixed_version_available_share"] == 0.75


def test_compute_relations_pearson_zero_variance_is_none(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "a",
                        "sbom": {"status": "generated", "components": 0},
                        "vulnerabilities": {"status": "scanned", "total": 0},
                    },
                    {
                        "name": "b",
                        "sbom": {"status": "generated", "components": 0},
                        "vulnerabilities": {"status": "scanned", "total": 0},
                    },
                ]
            },
        )
    )
    records = to_records(report)

    relations = compute_relations(report, records)

    assert relations["components_vs_vulnerabilities"]["pearson"] is None
    assert relations["components_vs_vulnerabilities"]["n"] == 2


def test_compute_relations_pearson_single_repo_is_none(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "a",
                        "sbom": {"status": "generated", "components": 3},
                        "vulnerabilities": {"status": "scanned", "total": 1},
                    }
                ]
            },
        )
    )
    records = to_records(report)

    relations = compute_relations(report, records)

    assert relations["components_vs_vulnerabilities"]["pearson"] is None
    assert relations["components_vs_vulnerabilities"]["n"] == 1


def test_compute_relations_pearson_calculable(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "a",
                        "sbom": {"status": "generated", "components": 1},
                        "vulnerabilities": {"status": "scanned", "total": 2},
                    },
                    {
                        "name": "b",
                        "sbom": {"status": "generated", "components": 2},
                        "vulnerabilities": {"status": "scanned", "total": 4},
                    },
                    {
                        "name": "c",
                        "sbom": {"status": "generated", "components": 3},
                        "vulnerabilities": {"status": "scanned", "total": 6},
                    },
                ]
            },
        )
    )
    records = to_records(report)

    relations = compute_relations(report, records)

    assert relations["components_vs_vulnerabilities"]["pearson"] == 1.0
    assert relations["components_vs_vulnerabilities"]["n"] == 3


def test_compute_relations_language_and_type_breakdown(tmp_path):
    report, records = load_rich(tmp_path)

    relations = compute_relations(report, records)

    # Cada lenguaje del repositorio atribuye cada hallazgo una vez.
    by_lang = {(row["language"], row["rule_id"]): row["count"] for row in relations["findings_by_language"]}
    assert by_lang[("python", "py/sqli")] == 2
    assert by_lang[("python", "js/xss")] == 1
    assert by_lang[("javascript", "js/xss")] == 1

    by_type = {(row["type"], row["severity"]): row["count"] for row in relations["severity_by_package_type"]}
    assert by_type[("deb", "Critical")] == 1
    assert by_type[("deb", "High")] == 1
    assert by_type[("npm", "High")] == 1
    assert by_type[("python", "Medium")] == 1


# ---------------------------------------------------------------------------
# Cobertura
# ---------------------------------------------------------------------------


def test_compute_coverage_ratio_and_statuses(tmp_path):
    report, _ = load_rich(tmp_path)

    coverage = compute_coverage(report)

    assert coverage["repositories_total"] == 3
    assert coverage["by_repo_status"] == {"analyzed": 2, "unsupported": 1}
    assert coverage["by_vuln_status"] == {"failed": 1, "scanned": 2}
    assert coverage["by_sbom_status"] == {"failed": 1, "generated": 2}
    assert coverage["unsupported"] == 1
    assert coverage["vuln_failed"] == 1
    assert coverage["sbom_failed"] == 1
    assert coverage["coverage_ratio"] == 0.6667
    assert len(coverage["warnings"]) == 3


def test_compute_coverage_no_repositories_is_zero(tmp_path):
    report = load_report(write_json(tmp_path, {"repositories": []}))

    coverage = compute_coverage(report)

    assert coverage["repositories_total"] == 0
    assert coverage["coverage_ratio"] == 0.0
    assert coverage["unsupported"] == 0


def test_compute_coverage_counts_sbom_only_repo(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "a",
                        "status": "cloned",
                        "sbom": {"status": "generated", "components": 1},
                    }
                ]
            },
        )
    )

    coverage = compute_coverage(report)

    assert coverage["coverage_ratio"] == 1.0


# ---------------------------------------------------------------------------
# Datasets
# ---------------------------------------------------------------------------


def test_compute_datasets_exposes_expected_keys(tmp_path):
    report, records = load_rich(tmp_path)

    datasets = compute_datasets(report, records)

    assert set(datasets) == {
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
    }
    assert len(datasets["severity_distribution"]) == len(SEVERITIES)


# ---------------------------------------------------------------------------
# Observaciones
# ---------------------------------------------------------------------------


def test_build_observations_with_data_emits_dimensions(tmp_path):
    report, records = load_rich(tmp_path)
    coverage = compute_coverage(report)
    datasets = compute_datasets(report, records)

    observations = build_observations(report, coverage, datasets)

    metrics_used = {obs["metric"] for obs in observations}
    assert "coverage.coverage_ratio" in metrics_used
    assert "datasets.severity_distribution" in metrics_used
    assert "datasets.repository_distribution" in metrics_used
    assert "datasets.concentration" in metrics_used
    assert "datasets.top_packages" in metrics_used
    assert "datasets.top_cves" in metrics_used
    assert "datasets.top_rules" in metrics_used
    assert "relations.fixed_version_available_share" in metrics_used
    assert "relations.findings_by_language" in metrics_used


def test_build_observations_each_has_five_keys_and_unique_id(tmp_path):
    report, records = load_rich(tmp_path)
    coverage = compute_coverage(report)
    datasets = compute_datasets(report, records)

    observations = build_observations(report, coverage, datasets)

    assert observations
    ids = [obs["id"] for obs in observations]
    assert len(ids) == len(set(ids))
    for obs in observations:
        assert set(obs) == {"id", "title", "statement", "metric", "evidence"}
        assert obs["title"]
        assert obs["statement"]
        assert obs["metric"]
        assert isinstance(obs["evidence"], dict)


def test_build_observations_without_findings_omits_rule_observation(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "a",
                        "status": "analyzed",
                        "vulnerabilities": {
                            "status": "scanned",
                            "total": 1,
                            "by_severity": {
                                "Critical": 0,
                                "High": 1,
                                "Medium": 0,
                                "Low": 0,
                                "Negligible": 0,
                                "Unknown": 0,
                            },
                            "vulnerabilities": [
                                {
                                    "id": "CVE-1",
                                    "severity": "High",
                                    "package": "p",
                                    "type": "npm",
                                    "fixed_version": "1",
                                }
                            ],
                        },
                    }
                ]
            },
        )
    )
    records = to_records(report)
    coverage = compute_coverage(report)
    datasets = compute_datasets(report, records)

    observations = build_observations(report, coverage, datasets)

    metrics_used = {obs["metric"] for obs in observations}
    assert "datasets.top_rules" not in metrics_used
    assert "relations.findings_by_language" not in metrics_used
    # La dimensión de severidad sí está presente.
    assert "datasets.severity_distribution" in metrics_used


def test_build_observations_empty_report_only_coverage(tmp_path):
    report = load_report(
        write_json(tmp_path, {"repositories": [{"name": "a", "status": "analyzed"}]})
    )
    records = to_records(report)
    coverage = compute_coverage(report)
    datasets = compute_datasets(report, records)

    observations = build_observations(report, coverage, datasets)

    assert [obs["metric"] for obs in observations] == ["coverage.coverage_ratio"]


# ---------------------------------------------------------------------------
# Limitaciones
# ---------------------------------------------------------------------------


def test_build_limitations_reports_missing_sections(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {"name": "a", "status": "analyzed"},
                    {"name": "b", "status": "analyzed"},
                ]
            },
        )
    )
    coverage = compute_coverage(report)

    limitations = build_limitations(report, coverage)

    joined = "\n".join(limitations)
    assert "no incluye hallazgos de CodeQL" in joined
    assert "no incluye vulnerabilidades de Grype" in joined
    assert "no incluye un SBOM" in joined
    # Muestra pequeña (< 30 repositorios).
    assert "muestra es pequeña" in joined
    # Advertencia metodológica siempre presente.
    assert "no implica causalidad" in joined


def test_build_limitations_reports_failed_states_and_small_sample(tmp_path):
    report, _ = load_rich(tmp_path)
    coverage = compute_coverage(report)

    limitations = build_limitations(report, coverage)

    joined = "\n".join(limitations)
    assert "no soportado(s)" in joined
    assert "fallaron en Grype" in joined
    assert "fallaron al generar el SBOM" in joined
    assert "cobertura de análisis exitoso" in joined
    assert "muestra es pequeña (3 repositorios)" in joined


def test_build_limitations_reports_count_discrepancy(tmp_path):
    data = rich_report_data()
    # El resumen declara más vulnerabilidades que las filas de detalle.
    data["summary"]["vulnerabilities"] = 99
    report = load_report(write_json(tmp_path, data))
    coverage = compute_coverage(report)

    limitations = build_limitations(report, coverage)

    assert any("El resumen declara 99" in item for item in limitations)


def test_build_limitations_includes_loader_warnings(tmp_path):
    report = load_report(write_json(tmp_path, {"repositories": [{}]}))
    coverage = compute_coverage(report)

    limitations = build_limitations(report, coverage)

    assert any("sin 'name'" in item for item in limitations)
