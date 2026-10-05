"""Tests de las métricas y observaciones del Analyzer (``analysis.metrics``).

Solo usan la librería estándar y ``pytest``: no requieren pandas. Se construyen
reportes sintéticos en ``tmp_path`` y se derivan las tablas con ``to_records``.
"""

import json

import pytest

from analysis.loader import SEVERITIES, load_report, to_records
from analysis.metrics import (
    SEVERITY_WEIGHTS,
    build_limitations,
    build_observations,
    compute_concentration,
    compute_coverage,
    compute_datasets,
    compute_relations,
    compute_repository_distribution,
    compute_repository_risk,
    compute_risk_summary,
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
    assert concentration["top_n"] == 1
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
    assert concentration["top_n"] == 0
    assert concentration["top_n_share"] == 0.0
    assert concentration["top_10pct_share"] == 0.0
    assert concentration["hhi"] == 0.0


def test_compute_concentration_multiple_repos_hhi_below_one(tmp_path):
    _, records = load_rich(tmp_path)

    concentration = compute_concentration(records)

    assert concentration["repositories_with_vulns"] == 2
    assert concentration["top_n"] == 2
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


def test_compute_coverage_repo_failed_and_ratios(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "a",
                        "status": "analyzed",
                        "sbom": {"status": "generated", "components": 1},
                        "vulnerabilities": {"status": "scanned", "total": 0},
                    },
                    {
                        "name": "b",
                        "status": "clone_failed",
                        "sbom": {"status": "skipped"},
                        "vulnerabilities": {"status": "skipped"},
                    },
                    {
                        "name": "c",
                        "status": "unsupported",
                        "sbom": {"status": "generated", "components": 1},
                        "vulnerabilities": {"status": "scanned", "total": 0},
                    },
                    {
                        "name": "d",
                        "status": "db_failed",
                        "sbom": {"status": "failed"},
                        "vulnerabilities": {"status": "failed", "total": 0},
                    },
                ]
            },
        )
    )

    coverage = compute_coverage(report)

    assert coverage["repositories_total"] == 4
    assert coverage["repo_failed"] == 2
    assert coverage["unsupported"] == 1
    assert coverage["vuln_failed"] == 1
    assert coverage["sbom_failed"] == 1
    assert coverage["coverage_ratio"] == 0.5
    assert coverage["code_coverage_ratio"] == 0.25
    assert coverage["sbom_coverage_ratio"] == 0.5
    assert coverage["vuln_coverage_ratio"] == 0.5
    for key in (
        "coverage_ratio",
        "code_coverage_ratio",
        "sbom_coverage_ratio",
        "vuln_coverage_ratio",
    ):
        assert 0 <= coverage[key] <= 1
    assert any("fases previas" in warning for warning in coverage["warnings"])


@pytest.mark.parametrize(
    "status",
    ["clone_failed", "db_failed", "analyze_failed", "invalid_name"],
)
def test_compute_coverage_counts_each_failed_status(tmp_path, status):
    report = load_report(
        write_json(tmp_path, {"repositories": [{"name": "a", "status": status}]})
    )

    coverage = compute_coverage(report)

    assert coverage["repo_failed"] == 1


def test_compute_concentration_top_n_is_capped(tmp_path):
    # Con top_n por defecto (3) y 2 repositorios con vulnerabilidades, se acota a 2.
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "a",
                        "vulnerabilities": {
                            "status": "scanned",
                            "total": 1,
                            "by_severity": {"High": 1},
                            "vulnerabilities": [
                                {
                                    "id": "C1",
                                    "severity": "High",
                                    "package": "p",
                                    "type": "npm",
                                }
                            ],
                        },
                    },
                    {
                        "name": "b",
                        "vulnerabilities": {
                            "status": "scanned",
                            "total": 1,
                            "by_severity": {"High": 1},
                            "vulnerabilities": [
                                {
                                    "id": "C2",
                                    "severity": "High",
                                    "package": "p",
                                    "type": "npm",
                                }
                            ],
                        },
                    },
                ]
            },
        )
    )
    records = to_records(report)

    concentration = compute_concentration(records, top_n=10)

    assert concentration["repositories_with_vulns"] == 2
    assert concentration["top_n"] == 2
    assert concentration["top_n_share"] == 1.0


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
        "repository_risk",
        "concentration",
        "risk_summary",
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


# ---------------------------------------------------------------------------
# Observaciones: líder por lenguaje, límites y correcciones exactas
# ---------------------------------------------------------------------------


def finding(rule_id, file, start_line):
    return {
        "rule_id": rule_id,
        "severity": "error",
        "file": file,
        "start_line": start_line,
    }


def test_build_observations_language_leader_by_total(tmp_path):
    # "javascript" ordena antes que "python", pero python acumula más hallazgos:
    # el líder debe elegirse por total, no por el primero alfabéticamente.
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "a",
                        "status": "analyzed",
                        "languages": ["python"],
                        "findings": [
                            finding("py/a", "a.py", 1),
                            finding("py/b", "b.py", 2),
                        ],
                    },
                    {
                        "name": "b",
                        "status": "analyzed",
                        "languages": ["javascript"],
                        "findings": [finding("js/a", "c.js", 3)],
                    },
                ]
            },
        )
    )
    records = to_records(report)
    coverage = compute_coverage(report)
    datasets = compute_datasets(report, records)

    observation = next(
        obs
        for obs in build_observations(report, coverage, datasets)
        if obs["metric"] == "relations.findings_by_language"
    )

    assert datasets["relations"]["findings_by_language"][0]["language"] == "javascript"
    assert observation["evidence"]["leader_language"] == "python"
    assert observation["evidence"]["leader_total"] == 2
    assert observation["evidence"]["language_totals"] == {
        "javascript": 1,
        "python": 2,
    }
    assert "python" in observation["statement"]
    assert "2 hallazgos" in observation["statement"]


def test_build_observations_language_leader_not_alphabetically_first(tmp_path):
    # "python" es el primero alfabéticamente pero "typescript" tiene más hallazgos.
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "a",
                        "status": "analyzed",
                        "languages": ["python"],
                        "findings": [finding("py/a", "a.py", 1)],
                    },
                    {
                        "name": "b",
                        "status": "analyzed",
                        "languages": ["typescript"],
                        "findings": [
                            finding("ts/a", "a.ts", 1),
                            finding("ts/b", "b.ts", 2),
                            finding("ts/c", "c.ts", 3),
                        ],
                    },
                ]
            },
        )
    )
    records = to_records(report)
    coverage = compute_coverage(report)
    datasets = compute_datasets(report, records)

    observation = next(
        obs
        for obs in build_observations(report, coverage, datasets)
        if obs["metric"] == "relations.findings_by_language"
    )

    assert datasets["relations"]["findings_by_language"][0]["language"] == "python"
    assert observation["evidence"]["leader_language"] == "typescript"
    assert observation["evidence"]["leader_total"] == 3


def test_build_observations_fixed_version_exact_count(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "a",
                        "status": "analyzed",
                        "languages": ["python"],
                        "vulnerabilities": {
                            "status": "scanned",
                            "total": 3,
                            "by_severity": {
                                "Critical": 0,
                                "High": 2,
                                "Medium": 1,
                                "Low": 0,
                                "Negligible": 0,
                                "Unknown": 0,
                            },
                            "vulnerabilities": [
                                {
                                    "id": "C1",
                                    "severity": "High",
                                    "package": "p",
                                    "version": "1",
                                    "type": "npm",
                                    "fixed_version": "2",
                                },
                                {
                                    "id": "C2",
                                    "severity": "High",
                                    "package": "p",
                                    "version": "1",
                                    "type": "npm",
                                    "fixed_version": None,
                                },
                                {
                                    "id": "C3",
                                    "severity": "Medium",
                                    "package": "p",
                                    "version": "1",
                                    "type": "npm",
                                    "fixed_version": "3",
                                },
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

    observation = next(
        obs
        for obs in build_observations(report, coverage, datasets)
        if obs["metric"] == "relations.fixed_version_available_share"
    )

    assert observation["evidence"]["with_fixed_version"] == 2
    assert observation["evidence"]["total"] == 3
    assert observation["evidence"]["fixed_version_available_share"] == 0.6667
    assert "(2 de 3)" in observation["statement"]


def test_build_observations_top_limits_and_distinct_totals(tmp_path):
    vulnerabilities = [
        {
            "id": f"CVE-{index}",
            "severity": "High",
            "package": f"pkg-{index}",
            "version": "1",
            "type": "npm",
            "fixed_version": None,
            "namespace": "nvd",
        }
        for index in range(25)
    ]
    findings = [finding(f"r/{index}", f"f{index}.py", index) for index in range(25)]
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "a",
                        "status": "analyzed",
                        "languages": ["python"],
                        "vulnerabilities": {
                            "status": "scanned",
                            "total": 25,
                            "by_severity": {
                                "Critical": 0,
                                "High": 25,
                                "Medium": 0,
                                "Low": 0,
                                "Negligible": 0,
                                "Unknown": 0,
                            },
                            "vulnerabilities": vulnerabilities,
                        },
                        "findings": findings,
                    }
                ]
            },
        )
    )
    records = to_records(report)
    coverage = compute_coverage(report)
    datasets = compute_datasets(report, records)
    observations = {
        obs["metric"]: obs for obs in build_observations(report, coverage, datasets)
    }

    packages = observations["datasets.top_packages"]
    assert packages["evidence"]["packages_distinct"] == 25
    assert len(packages["evidence"]["top_packages"]) == 20
    assert "el top 20 de 25 paquetes distintos" in packages["statement"]

    cves = observations["datasets.top_cves"]
    assert cves["evidence"]["cves_distinct"] == 25
    assert len(cves["evidence"]["top_cves"]) == 20
    assert "el top 20 de 25 identificadores distintos" in cves["statement"]

    rules = observations["datasets.top_rules"]
    assert rules["evidence"]["rules_distinct"] == 25
    assert rules["evidence"]["findings_total"] == 25
    assert len(rules["evidence"]["top_rules"]) == 20
    assert "el top 20 de 25 reglas distintas sobre 25 hallazgos en total" in rules["statement"]


# ---------------------------------------------------------------------------
# Limitaciones: by_severity y concentración degenerada
# ---------------------------------------------------------------------------


def test_build_limitations_by_severity_mismatch(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "summary": {"vulnerabilities": 1},
                "repositories": [
                    {
                        "name": "a",
                        "status": "analyzed",
                        "vulnerabilities": {
                            "status": "scanned",
                            "total": 1,
                            # by_severity declara 5 pero solo hay 1 fila de detalle.
                            "by_severity": {
                                "Critical": 5,
                                "High": 0,
                                "Medium": 0,
                                "Low": 0,
                                "Negligible": 0,
                                "Unknown": 0,
                            },
                            "vulnerabilities": [
                                {
                                    "id": "C1",
                                    "severity": "Critical",
                                    "package": "p",
                                    "type": "npm",
                                    "fixed_version": "1",
                                }
                            ],
                        },
                    }
                ],
            },
        )
    )
    coverage = compute_coverage(report)

    limitations = build_limitations(report, coverage)

    assert any(
        "by_severity' (5) no cuadran con las filas de detalle" in item
        for item in limitations
    )


def test_build_limitations_concentration_small(tmp_path):
    def repo(index):
        return {
            "name": f"r{index}",
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
                        "id": f"C{index}",
                        "severity": "High",
                        "package": "p",
                        "type": "npm",
                        "fixed_version": "1",
                    }
                ],
            },
        }

    report = load_report(
        write_json(tmp_path, {"repositories": [repo(0), repo(1)]}, name="small.json")
    )
    coverage = compute_coverage(report)

    limitations = build_limitations(report, coverage)

    assert any(
        "Solo 2 repositorio(s) tienen vulnerabilidades" in item
        for item in limitations
    )


def test_build_limitations_concentration_not_flagged_for_five(tmp_path):
    def repo(index):
        return {
            "name": f"r{index}",
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
                        "id": f"C{index}",
                        "severity": "High",
                        "package": "p",
                        "type": "npm",
                        "fixed_version": "1",
                    }
                ],
            },
        }

    report = load_report(
        write_json(
            tmp_path,
            {"repositories": [repo(index) for index in range(5)]},
            name="five.json",
        )
    )
    coverage = compute_coverage(report)

    limitations = build_limitations(report, coverage)

    assert not any("tienen vulnerabilidades" in item for item in limitations)


# ---------------------------------------------------------------------------
# Riesgo por repositorio y resumen global (contrato 1.1)
# ---------------------------------------------------------------------------


def synthetic_repo(
    name,
    severities=(),
    components=0,
    languages=(),
    fixed_versions=None,
    findings=0,
):
    """Repositorio sintético con las severidades, lenguajes y hallazgos dados.

    ``fixed_versions`` permite marcar qué vulnerabilidades tienen corrección
    publicada; si se omite, ninguna la tiene.
    """
    if fixed_versions is None:
        fixed_versions = [None] * len(severities)
    vulnerabilities = [
        {
            "id": f"CVE-{name}-{index}",
            "severity": severity,
            "package": f"pkg-{index}",
            "version": "1.0",
            "type": "npm",
            "fixed_version": fixed_versions[index],
        }
        for index, severity in enumerate(severities)
    ]
    return {
        "name": name,
        "status": "analyzed",
        "languages": list(languages),
        "sbom": {"status": "generated", "components": components},
        "vulnerabilities": {
            "status": "scanned",
            "total": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        },
        "findings": [
            finding(f"rule-{index}", f"file{index}.py", index)
            for index in range(findings)
        ],
    }


def test_compute_repository_risk_score_mixed_severities(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    synthetic_repo("alpha", ["Critical", "Medium"], components=10)
                ]
            },
        )
    )

    rows = compute_repository_risk(report)

    assert len(rows) == 1
    row = rows[0]
    # Pesos Critical=10 y Medium=4 -> media 7.0 -> nota 1 + 9*0.7 = 7.3.
    assert row["severity_weighted_average"] == 7.0
    assert row["severity_median"] == 7.0
    assert row["score"] == 7.3
    assert row["worst_severity"] == "Critical"
    assert row["critical"] == 1
    assert row["high"] == 0
    assert row["vulnerabilities"] == 2
    assert SEVERITY_WEIGHTS["Critical"] == 10.0
    assert SEVERITY_WEIGHTS["Medium"] == 4.0


def test_compute_repository_risk_without_vulnerabilities(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    synthetic_repo("limpio", [], components=5, languages=["python"])
                ]
            },
        )
    )

    row = compute_repository_risk(report)[0]

    assert row["vulnerabilities"] == 0
    assert row["score"] == 1.0
    assert row["severity_weighted_average"] == 0.0
    assert row["severity_median"] == 0.0
    assert row["worst_severity"] == "Unknown"
    assert row["critical"] == 0
    assert row["high"] == 0
    assert row["fixed_version_share"] is None
    assert row["vulns_per_component"] == 0.0


def test_compute_repository_risk_ranking_is_deterministic(tmp_path):
    repositories = [
        synthetic_repo("delta", ["Critical"]),
        synthetic_repo("bravo", ["Critical", "Medium"]),
        synthetic_repo("alpha", ["Critical", "Medium"]),
        synthetic_repo("charlie", ["Medium"]),
    ]
    report = load_report(write_json(tmp_path, {"repositories": repositories}))

    first = compute_repository_risk(report)
    second = compute_repository_risk(report)

    assert first == second
    # Orden por nota desc; el empate alpha/bravo se resuelve por nombre asc.
    assert [row["repo"] for row in first] == ["delta", "alpha", "bravo", "charlie"]
    assert [row["score"] for row in first] == [10.0, 7.3, 7.3, 4.6]


def test_compute_repository_risk_tiebreak_by_weighted_average(tmp_path):
    # Misma nota 7.3, distinta media ponderada: 7.0 frente a 6.95.
    mayor = synthetic_repo("mayor", ["Critical", "Medium"])
    menor = synthetic_repo(
        "menor",
        ["Critical"] * 10 + ["High"] * 5 + ["Medium"] + ["Unknown"] * 4,
    )
    report = load_report(write_json(tmp_path, {"repositories": [menor, mayor]}))

    rows = compute_repository_risk(report)

    assert rows[0]["repo"] == "mayor"
    assert rows[1]["repo"] == "menor"
    assert rows[0]["score"] == rows[1]["score"] == 7.3
    assert rows[0]["severity_weighted_average"] == 7.0
    assert rows[1]["severity_weighted_average"] == 6.95


def test_compute_repository_risk_density_none_and_value(tmp_path):
    repositories = [
        synthetic_repo("sin_sbom", ["Critical"], components=0),
        synthetic_repo("con_sbom", ["High", "High", "High"], components=6, findings=1),
    ]
    report = load_report(write_json(tmp_path, {"repositories": repositories}))

    rows = {row["repo"]: row for row in compute_repository_risk(report)}

    # Sin componentes de SBOM la densidad no es calculable.
    assert rows["sin_sbom"]["vulns_per_component"] is None
    assert rows["sin_sbom"]["findings_per_component"] is None
    assert rows["con_sbom"]["vulns_per_component"] == 0.5
    assert rows["con_sbom"]["findings_per_component"] == 0.1667


def test_compute_risk_summary_aggregates(tmp_path):
    repositories = [
        synthetic_repo("alpha", ["Critical", "Medium"], components=10),
        synthetic_repo("beta", ["Critical", "High"], components=5),
        synthetic_repo("delta", ["High"], components=5),
        synthetic_repo("gamma", [], components=0),
    ]
    report = load_report(write_json(tmp_path, {"repositories": repositories}))
    repository_risk = compute_repository_risk(report)

    summary = compute_risk_summary(report, repository_risk)

    # Pesos globales 10,4,10,7,7 -> media 7.6 -> nota 1 + 9*0.76 = 7.84 -> 7.8.
    assert summary["score"] == 7.8
    assert summary["severity_weighted_average"] == 7.6
    assert summary["severity_median"] == 7.0
    assert summary["total_vulnerabilities"] == 5
    assert summary["repositories_scored"] == 3
    assert summary["repositories_with_critical"] == 2
    assert summary["repositories_with_high_or_critical"] == 3
    # Notas: alpha 7.3, beta 8.6, delta 7.3 -> media 7.7333 -> 7.7.
    assert summary["mean_repository_score"] == 7.7
    assert summary["max_repository_score"] == 8.6
    assert summary["critical_hotspots"] == ["alpha", "beta"]
    assert summary["worst_severity"] == "Critical"


def test_compute_risk_summary_without_vulnerabilities(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {"repositories": [synthetic_repo("solo", [], components=3)]},
        )
    )
    repository_risk = compute_repository_risk(report)

    summary = compute_risk_summary(report, repository_risk)

    assert summary["score"] == 1.0
    assert summary["severity_weighted_average"] == 0.0
    assert summary["severity_median"] == 0.0
    assert summary["total_vulnerabilities"] == 0
    assert summary["repositories_scored"] == 0
    assert summary["repositories_with_critical"] == 0
    assert summary["repositories_with_high_or_critical"] == 0
    assert summary["mean_repository_score"] == 0.0
    assert summary["max_repository_score"] == 0.0
    assert summary["critical_hotspots"] == []
    assert summary["worst_severity"] == "Unknown"


def test_compute_relations_severity_by_language_duplicates_and_order(tmp_path):
    repositories = [
        synthetic_repo(
            "a", ["Critical", "Medium"], languages=["python", "javascript"]
        ),
        synthetic_repo("b", ["High"], languages=["python"]),
    ]
    report = load_report(write_json(tmp_path, {"repositories": repositories}))
    records = to_records(report)

    relations = compute_relations(report, records)

    # Orden: lenguaje asc y, dentro de cada lenguaje, severidad canónica
    # (Critical primero).
    assert relations["severity_by_language"] == [
        {"language": "javascript", "severity": "Critical", "count": 1},
        {"language": "javascript", "severity": "Medium", "count": 1},
        {"language": "python", "severity": "Critical", "count": 1},
        {"language": "python", "severity": "High", "count": 1},
        {"language": "python", "severity": "Medium", "count": 1},
    ]
    # La vulnerabilidad de "a" se atribuye a sus dos lenguajes: los conteos no
    # suman el total global (3 vulnerabilidades -> 5 atribuciones).
    assert sum(row["count"] for row in relations["severity_by_language"]) == 5


def test_compute_datasets_includes_repository_risk_and_risk_summary(tmp_path):
    report, records = load_rich(tmp_path)

    datasets = compute_datasets(report, records)

    assert isinstance(datasets["repository_risk"], list)
    assert [row["repo"] for row in datasets["repository_risk"]] == [
        "alpha",
        "beta",
        "gamma",
    ]
    assert datasets["risk_summary"]["total_vulnerabilities"] == 4
    assert datasets["risk_summary"]["critical_hotspots"] == ["alpha"]


def test_build_observations_emits_new_risk_dimensions(tmp_path):
    report, records = load_rich(tmp_path)
    coverage = compute_coverage(report)
    datasets = compute_datasets(report, records)

    observations = build_observations(report, coverage, datasets)
    metrics_used = {obs["metric"] for obs in observations}

    assert "datasets.risk_summary" in metrics_used
    assert "datasets.repository_risk" in metrics_used
    assert "datasets.repository_risk.vulns_per_component" in metrics_used
    assert "datasets.risk_summary.critical_hotspots" in metrics_used
    assert "relations.severity_by_language" in metrics_used

    # La observación de hotspots cita el repositorio con severidad Critical.
    hotspots = next(
        obs
        for obs in observations
        if obs["metric"] == "datasets.risk_summary.critical_hotspots"
    )
    assert hotspots["evidence"]["critical_hotspots"] == ["alpha"]
    assert "alpha" in hotspots["statement"]


def test_build_observations_omits_new_risk_dimensions_without_data(tmp_path):
    report = load_report(
        write_json(
            tmp_path,
            {
                "repositories": [
                    {
                        "name": "vacio",
                        "status": "analyzed",
                        "sbom": {"status": "no_components", "components": 0},
                        "vulnerabilities": {
                            "status": "no_vulnerabilities",
                            "total": 0,
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

    assert metrics_used == {"coverage.coverage_ratio"}
    assert "datasets.risk_summary" not in metrics_used
    assert "datasets.repository_risk" not in metrics_used
    assert "datasets.repository_risk.vulns_per_component" not in metrics_used
    assert "datasets.risk_summary.critical_hotspots" not in metrics_used
    assert "relations.severity_by_language" not in metrics_used
