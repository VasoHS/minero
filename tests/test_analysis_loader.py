"""Tests del cargador tolerante del Analyzer (``analysis.loader``).

Solo usan la librería estándar y ``pytest``: no requieren pandas ni matplotlib.
Construyen reportes sintéticos en ``tmp_path`` (JSON), sin red.
"""

import json

import pytest

from analysis.loader import (
    SEVERITIES,
    RepoData,
    detect_source_kind,
    load_report,
    normalize_severity,
    to_records,
)


def write_json(tmp_path, data, name="report.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# detect_source_kind
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data,expected",
    [
        (
            {"repositories": [{"vulnerabilities": {"status": "scanned"}}]},
            "vuln",
        ),
        (
            {"repositories": [{"sbom": {"status": "generated"}}]},
            "sbom",
        ),
        (
            {
                "repositories": [
                    {
                        "sbom": {"status": "generated"},
                        "vulnerabilities": {"status": "scanned"},
                    }
                ]
            },
            "scan",
        ),
        ({"repositories": [{"name": "x"}]}, "unknown"),
        ({"repositories": []}, "unknown"),
        ({}, "unknown"),
    ],
)
def test_detect_source_kind_variants(data, expected):
    assert detect_source_kind(data) == expected


def test_detect_source_kind_skipped_is_unknown():
    data = {
        "repositories": [
            {
                "sbom": {"status": "skipped"},
                "vulnerabilities": {"status": "skipped"},
            }
        ]
    }
    assert detect_source_kind(data) == "unknown"


def test_detect_source_kind_scan_requires_two_repositories():
    data = {
        "repositories": [
            {"sbom": {"status": "generated"}},
            {"vulnerabilities": {"status": "scanned"}},
        ]
    }
    assert detect_source_kind(data) == "scan"


# ---------------------------------------------------------------------------
# load_report
# ---------------------------------------------------------------------------


def test_load_report_minimal_defaults(tmp_path):
    path = write_json(tmp_path, {})

    report = load_report(path)

    assert report.organization == "desconocida"
    assert report.source_path == str(path)
    assert report.source_kind == "unknown"
    assert report.summary == {}
    assert report.repositories == []
    assert report.warnings == []


def test_load_report_partial_repo_fills_defaults(tmp_path):
    path = write_json(tmp_path, {"repositories": [{"name": "solo"}]})

    report = load_report(path)

    assert len(report.repositories) == 1
    repo = report.repositories[0]
    assert isinstance(repo, RepoData)
    assert repo.name == "solo"
    assert repo.full_name is None
    assert repo.url == ""
    assert repo.commit is None
    assert repo.status == "pending"
    assert repo.languages == []
    assert repo.sbom_status == "skipped"
    assert repo.sbom_components == 0
    assert repo.vuln_status == "skipped"
    assert repo.vuln_total == 0
    assert repo.by_severity == {severity: 0 for severity in SEVERITIES}
    assert repo.findings == []
    assert repo.vulnerabilities == []
    assert report.warnings == []


def test_load_report_repo_without_name_warns_and_indexes(tmp_path):
    path = write_json(tmp_path, {"repositories": [{}, {"name": "ok"}]})

    report = load_report(path)

    assert [repo.name for repo in report.repositories] == ["repo-0", "ok"]
    assert len(report.warnings) == 1
    assert "name" in report.warnings[0]
    assert "repo-0" in report.warnings[0]


def test_load_report_missing_file_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_report(tmp_path / "does-not-exist.json")


def test_load_report_invalid_json_raises_value_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("esto no es JSON {", encoding="utf-8")

    with pytest.raises(ValueError):
        load_report(path)


@pytest.mark.parametrize("payload", ["[1, 2, 3]", '"cadena"', "42", "null"])
def test_load_report_non_object_root_raises_value_error(tmp_path, payload):
    path = tmp_path / "root.json"
    path.write_text(payload, encoding="utf-8")

    with pytest.raises(ValueError):
        load_report(path)


def test_load_report_keeps_summary_and_repository_order(tmp_path):
    path = write_json(
        tmp_path,
        {
            "organization": "acme",
            "summary": {"repositories": 2},
            "repositories": [{"name": "zeta"}, {"name": "alpha"}],
        },
    )

    report = load_report(path)

    assert report.organization == "acme"
    assert report.summary == {"repositories": 2}
    assert [repo.name for repo in report.repositories] == ["zeta", "alpha"]


# ---------------------------------------------------------------------------
# normalize_severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Critical", "Critical"),
        ("critical", "Critical"),
        ("  HIGH  ", "High"),
        ("Medium", "Medium"),
        ("low", "Low"),
        ("Negligible", "Negligible"),
        ("unknown", "Unknown"),
        ("UNKNOWN", "Unknown"),
        ("weird", "Unknown"),
        ("", "Unknown"),
        ("   ", "Unknown"),
        (None, "Unknown"),
        (5, "Unknown"),
        (["High"], "Unknown"),
    ],
)
def test_normalize_severity_variants(value, expected):
    assert normalize_severity(value) == expected


# ---------------------------------------------------------------------------
# to_records
# ---------------------------------------------------------------------------


def records_report_data():
    return {
        "organization": "acme",
        "repositories": [
            {
                "name": "alpha",
                "full_name": "acme/alpha",
                "url": "https://github.com/acme/alpha.git",
                "commit": "a" * 40,
                "status": "analyzed",
                "languages": ["python", 123],
                "sbom": {"status": "generated", "components": 7},
                "vulnerabilities": {
                    "status": "scanned",
                    "total": 3,
                    "by_severity": {
                        "Critical": 2,
                        "High": 1,
                        "Medium": 0,
                        "Low": 0,
                        "Negligible": 0,
                        "Unknown": 0,
                    },
                    "vulnerabilities": [
                        {
                            "id": "CVE-1",
                            "severity": "critical",
                            "package": "openssl",
                            "version": "1.1.1",
                            "type": "deb",
                            "fixed_version": "1.1.1k",
                            "namespace": "debian:11",
                        },
                        {
                            "id": "CVE-2",
                            "severity": "High",
                            "package": "lodash",
                            # Tipos no-cadena deben quedar en None.
                            "version": 42,
                            "type": None,
                            "fixed_version": None,
                            "namespace": None,
                        },
                    ],
                },
                "findings": [
                    {
                        "rule_id": "py/sql-injection",
                        "severity": "error",
                        "file": "app/db.py",
                        "start_line": 42,
                    },
                    {
                        # start_line no entero -> None; campos ausentes -> defaults.
                    },
                ],
            },
            {
                "name": "beta",
                "status": "cloned",
                "sbom": {"status": "skipped"},
                "vulnerabilities": {"status": "skipped", "total": 0},
            },
        ],
    }


def test_to_records_shapes_and_counts(tmp_path):
    report = load_report(write_json(tmp_path, records_report_data()))

    records = to_records(report)

    assert set(records) == {
        "repositories",
        "findings",
        "vulnerabilities",
        "severity_distribution",
    }
    assert len(records["repositories"]) == 2
    assert len(records["findings"]) == 2
    assert len(records["vulnerabilities"]) == 2

    alpha = records["repositories"][0]
    assert alpha == {
        "repo": "alpha",
        "full_name": "acme/alpha",
        "url": "https://github.com/acme/alpha.git",
        "commit": "a" * 40,
        "status": "analyzed",
        "languages": ["python"],
        "sbom_status": "generated",
        "sbom_components": 7,
        "vuln_status": "scanned",
        "vuln_total": 3,
        "findings_total": 2,
    }
    beta = records["repositories"][1]
    assert beta["repo"] == "beta"
    assert beta["findings_total"] == 0
    assert beta["sbom_status"] == "skipped"
    assert beta["vuln_status"] == "skipped"


def test_to_records_findings_normalization(tmp_path):
    report = load_report(write_json(tmp_path, records_report_data()))

    findings = to_records(report)["findings"]

    assert findings[0] == {
        "repo": "alpha",
        "rule_id": "py/sql-injection",
        "severity": "error",
        "file": "app/db.py",
        "start_line": 42,
    }
    # Un hallazgo sin datos usa defaults y start_line None.
    assert findings[1] == {
        "repo": "alpha",
        "rule_id": "unknown",
        "severity": "unknown",
        "file": "",
        "start_line": None,
    }


def test_to_records_vulnerabilities_normalization(tmp_path):
    report = load_report(write_json(tmp_path, records_report_data()))

    vulns = to_records(report)["vulnerabilities"]

    assert vulns[0] == {
        "repo": "alpha",
        "id": "CVE-1",
        "severity": "Critical",
        "package": "openssl",
        "version": "1.1.1",
        "type": "deb",
        "fixed_version": "1.1.1k",
        "namespace": "debian:11",
    }
    # Tipos no-cadena se normalizan a None y la severidad desconocida a Unknown.
    assert vulns[1] == {
        "repo": "alpha",
        "id": "CVE-2",
        "severity": "High",
        "package": "lodash",
        "version": None,
        "type": None,
        "fixed_version": None,
        "namespace": None,
    }


def test_to_records_severity_distribution_only_nonzero(tmp_path):
    report = load_report(write_json(tmp_path, records_report_data()))

    rows = to_records(report)["severity_distribution"]

    # Solo se emiten filas con conteo > 0, en orden canónico por repo.
    assert rows == [
        {"repo": "alpha", "severity": "Critical", "count": 2},
        {"repo": "alpha", "severity": "High", "count": 1},
    ]


def test_to_records_empty_report(tmp_path):
    report = load_report(write_json(tmp_path, {}))

    records = to_records(report)

    assert records == {
        "repositories": [],
        "findings": [],
        "vulnerabilities": [],
        "severity_distribution": [],
    }
