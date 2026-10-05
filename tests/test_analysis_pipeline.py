"""Tests del pipeline del Analyzer (``analysis.pipeline.run_analysis``).

Solo usan la librería estándar y ``pytest``: no requieren pandas ni Jupyter.
Construyen reportes sintéticos en ``tmp_path`` y verifican el contrato de salida.
"""

import json

from analysis.contract import validate_document
from analysis.pipeline import run_analysis

FIXED_TS = "2026-01-01T00:00:00+00:00"


def write_json(tmp_path, data, name="report.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def sample_report_data():
    return {
        "organization": "acme",
        "summary": {"repositories": 2, "vulnerabilities": 1, "findings": 1},
        "repositories": [
            {
                "name": "alpha",
                "full_name": "acme/alpha",
                "url": "https://github.com/acme/alpha.git",
                "commit": "a" * 40,
                "status": "analyzed",
                "languages": ["python"],
                "sbom": {"status": "generated", "components": 4},
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
                            "package": "requests",
                            "version": "1.0",
                            "type": "python",
                            "fixed_version": "1.1",
                            "namespace": "nvd",
                        }
                    ],
                },
                "findings": [
                    {
                        "rule_id": "py/sqli",
                        "severity": "error",
                        "file": "a.py",
                        "start_line": 1,
                    }
                ],
            },
            {
                "name": "beta",
                "status": "analyzed",
                "languages": ["javascript"],
                "sbom": {"status": "generated", "components": 2},
                "vulnerabilities": {
                    "status": "no_vulnerabilities",
                    "total": 0,
                    "by_severity": {},
                },
                "findings": [],
            },
        ],
    }


def empty_report_data():
    return {
        "organization": "acme",
        "summary": {},
        "repositories": [{"name": "alpha", "status": "unsupported"}],
    }


def test_run_analysis_returns_valid_document(tmp_path):
    path = write_json(tmp_path, sample_report_data())

    document = run_analysis(path, generated_at=FIXED_TS)

    assert validate_document(document) == []
    assert document["schema_version"] == "1.1"
    assert document["meta"]["organization"] == "acme"
    assert document["meta"]["source_kind"] == "scan"
    assert document["meta"]["repositories"] == 2
    assert document["meta"]["generated_at"] == FIXED_TS


def test_run_analysis_writes_output_file(tmp_path):
    path = write_json(tmp_path, sample_report_data())
    output = tmp_path / "outputs" / "analyzer_output.json"

    document = run_analysis(path, output_path=output, generated_at=FIXED_TS)

    assert output.exists()
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written == document
    assert validate_document(written) == []


def test_run_analysis_without_output_writes_nothing(tmp_path):
    path = write_json(tmp_path, sample_report_data())
    output = tmp_path / "should-not-exist.json"

    run_analysis(path, generated_at=FIXED_TS)

    assert not output.exists()


def test_run_analysis_respects_generated_at(tmp_path):
    path = write_json(tmp_path, sample_report_data())

    document = run_analysis(path, generated_at=FIXED_TS)

    assert document["meta"]["generated_at"] == FIXED_TS


def test_run_analysis_is_deterministic(tmp_path):
    path = write_json(tmp_path, sample_report_data())

    first = run_analysis(path, generated_at=FIXED_TS)
    second = run_analysis(path, generated_at=FIXED_TS)

    assert first == second


def test_run_analysis_determinism_ignores_only_source_and_timestamp(tmp_path):
    path = write_json(tmp_path, sample_report_data())

    first = run_analysis(path, generated_at=FIXED_TS)
    second = run_analysis(path, generated_at=FIXED_TS)

    # Excluyendo meta.source y meta.generated_at, el contenido es idéntico.
    for doc in (first, second):
        doc["meta"].pop("source")
        doc["meta"].pop("generated_at")
    assert first == second


def test_run_analysis_without_vulnerabilities_or_findings(tmp_path):
    path = write_json(tmp_path, empty_report_data())

    document = run_analysis(path, generated_at=FIXED_TS)

    assert validate_document(document) == []
    assert document["meta"]["source_kind"] == "unknown"
    assert document["datasets"]["findings"] == []
    assert document["datasets"]["vulnerabilities"] == []
    assert document["datasets"]["top_rules"] == []
    assert document["datasets"]["top_cves"] == []
    # La cobertura sí se emite aunque no haya vulnerabilidades.
    assert document["coverage"]["repositories_total"] == 1


def test_run_analysis_missing_input_raises(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        run_analysis(tmp_path / "missing.json", generated_at=FIXED_TS)


# ---------------------------------------------------------------------------
# Varios reportes fusionados
# ---------------------------------------------------------------------------


def sbom_only_data():
    return {
        "organization": "acme",
        "summary": {"repositories": 1, "components": 5, "sboms_generated": 1},
        "repositories": [
            {
                "name": "alpha",
                "status": "cloned",
                "languages": ["python"],
                "sbom": {"status": "generated", "components": 5},
                "vulnerabilities": {"status": "skipped"},
            }
        ],
    }


def vuln_only_data():
    return {
        "organization": "acme",
        "summary": {"repositories": 1, "vulnerabilities": 1},
        "repositories": [
            {
                "name": "alpha",
                "status": "scanned",
                "languages": ["javascript"],
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
                            "package": "requests",
                            "version": "1.0",
                            "type": "python",
                            "fixed_version": "1.1",
                            "namespace": "nvd",
                        }
                    ],
                },
                "findings": [
                    {
                        "rule_id": "js/xss",
                        "severity": "error",
                        "file": "a.js",
                        "start_line": 1,
                    }
                ],
            }
        ],
    }


def test_run_analysis_accepts_list_of_reports(tmp_path):
    sbom = write_json(tmp_path, sbom_only_data(), name="results-sbom.json")
    vuln = write_json(tmp_path, vuln_only_data(), name="results-vuln.json")

    document = run_analysis([sbom, vuln], generated_at=FIXED_TS)

    assert validate_document(document) == []
    assert document["meta"]["source_kind"] == "merged"
    assert document["meta"]["source"] == "results-sbom.json + results-vuln.json"
    assert document["meta"]["repositories"] == 1
    # Los componentes del SBOM y las vulnerabilidades se suman en el resumen.
    assert document["summary"]["components"] == 5
    assert document["summary"]["vulnerabilities"] == 1
    assert document["summary"]["sboms_generated"] == 1
    assert document["summary"]["vulns_scanned"] == 1
    repo = document["datasets"]["repositories"][0]
    assert repo["languages"] == ["python", "javascript"]
    assert repo["sbom_status"] == "generated"
    assert repo["vuln_status"] == "scanned"


def test_run_analysis_merged_list_is_deterministic(tmp_path):
    sbom = write_json(tmp_path, sbom_only_data(), name="results-sbom.json")
    vuln = write_json(tmp_path, vuln_only_data(), name="results-vuln.json")

    first = run_analysis([sbom, vuln], generated_at=FIXED_TS)
    second = run_analysis([sbom, vuln], generated_at=FIXED_TS)

    assert first == second


def test_run_analysis_empty_list_raises_value_error(tmp_path):
    import pytest

    with pytest.raises(ValueError):
        run_analysis([], generated_at=FIXED_TS)
