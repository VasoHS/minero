"""Tests del contrato de salida del Analyzer (``analysis.contract``).

Solo usan la librería estándar y ``pytest``. El ejemplo canónico
``analysis/contracts/example_analyzer_output.json`` se usa como documento válido
de referencia.
"""

import copy
import json
from pathlib import Path

import pytest

from analysis import contract, metrics
from analysis.contract import (
    DATASET_KEYS,
    SCHEMA_VERSION,
    build_document,
    validate_document,
    write_document,
)
from analysis.loader import load_report, to_records

EXAMPLE_PATH = (
    Path(__file__).resolve().parents[1]
    / "analysis"
    / "contracts"
    / "example_analyzer_output.json"
)


def load_example():
    return json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))


def write_json(tmp_path, data, name="report.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def valid_report_data():
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


def build_parts(tmp_path):
    report = load_report(write_json(tmp_path, valid_report_data()))
    records = to_records(report)
    datasets = metrics.compute_datasets(report, records)
    coverage = metrics.compute_coverage(report)
    observations = metrics.build_observations(report, coverage, datasets)
    limitations = metrics.build_limitations(report, coverage)
    return report, datasets, coverage, observations, limitations


# ---------------------------------------------------------------------------
# build_document
# ---------------------------------------------------------------------------


def test_build_document_meta_and_schema(tmp_path):
    report, datasets, coverage, observations, limitations = build_parts(tmp_path)
    generated_at = "2026-01-01T00:00:00+00:00"

    document = build_document(
        report,
        datasets,
        coverage,
        observations,
        limitations,
        generated_at=generated_at,
    )

    assert document["schema_version"] == SCHEMA_VERSION == "1.1"
    meta = document["meta"]
    assert meta["organization"] == "acme"
    assert meta["source"] == report.source_path
    assert meta["source_kind"] == "scan"
    assert meta["generated_at"] == generated_at
    assert meta["repositories"] == 2
    assert meta["warnings"] == []
    assert document["summary"] == report.summary
    assert document["datasets"] is datasets
    assert document["coverage"] is coverage
    assert document["observations"] is observations
    assert document["limitations"] is limitations


def test_build_document_generated_at_defaults_to_now(tmp_path):
    report, datasets, coverage, observations, limitations = build_parts(tmp_path)

    document = build_document(
        report, datasets, coverage, observations, limitations
    )

    assert isinstance(document["meta"]["generated_at"], str)
    assert document["meta"]["generated_at"]


def test_build_document_output_is_valid(tmp_path):
    report, datasets, coverage, observations, limitations = build_parts(tmp_path)

    document = build_document(
        report,
        datasets,
        coverage,
        observations,
        limitations,
        generated_at="2026-01-01T00:00:00+00:00",
    )

    assert validate_document(document) == []


# ---------------------------------------------------------------------------
# validate_document
# ---------------------------------------------------------------------------


def test_validate_document_accepts_example():
    assert validate_document(load_example()) == []


def test_validate_document_constants():
    assert SCHEMA_VERSION == "1.1"
    assert DATASET_KEYS == (
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
    )


def test_validate_document_rejects_non_dict():
    assert validate_document([]) == ["El documento debe ser un objeto JSON (dict)."]


def test_validate_document_missing_top_level_and_dataset_keys():
    document = load_example()
    del document["limitations"]
    del document["datasets"]["top_cves"]

    errors = validate_document(document)

    assert any("limitations" in error for error in errors)
    assert any("datasets.top_cves" in error for error in errors)


def test_validate_document_bad_schema_version():
    document = load_example()
    document["schema_version"] = "9.9"

    errors = validate_document(document)

    assert any("schema_version" in error for error in errors)


def test_validate_document_non_canonical_severity():
    document = load_example()
    document["datasets"]["vulnerabilities"][0]["severity"] = "Weird"

    errors = validate_document(document)

    assert any("no pertenece" in error and "severity" in error for error in errors)


def test_validate_document_duplicate_observation_id():
    document = load_example()
    duplicate = copy.deepcopy(document["observations"][0])
    document["observations"].append(duplicate)

    errors = validate_document(document)

    assert any("duplicado" in error for error in errors)


def test_validate_document_repositories_mismatch():
    document = load_example()
    document["meta"]["repositories"] = 5

    errors = validate_document(document)

    assert any(
        "no coincide" in error and "datasets['repositories']" in error
        for error in errors
    )


def test_validate_document_rejects_bad_dataset_types():
    document = load_example()
    document["datasets"]["repositories"] = {}

    errors = validate_document(document)

    assert any(
        "datasets.repositories debe ser una lista" in error for error in errors
    )


def test_validate_document_accepts_build_from_pipeline(tmp_path):
    from analysis.pipeline import run_analysis

    document = run_analysis(
        write_json(tmp_path, valid_report_data()),
        generated_at="2026-01-01T00:00:00+00:00",
    )

    assert validate_document(document) == []


# ---------------------------------------------------------------------------
# write_document
# ---------------------------------------------------------------------------


def test_write_document_writes_utf8_and_creates_parent(tmp_path):
    document = load_example()
    document["meta"]["organization"] = "organización"
    target = tmp_path / "nested" / "out.json"

    write_document(document, target)

    assert target.exists()
    text = target.read_text(encoding="utf-8")
    assert "organización" in text
    assert json.loads(text) == document


def test_write_document_invalid_raises_and_does_not_write(tmp_path):
    document = load_example()
    del document["coverage"]
    target = tmp_path / "nested" / "out.json"

    with pytest.raises(ValueError) as excinfo:
        write_document(document, target)

    assert "coverage" in str(excinfo.value)
    assert not target.exists()
    assert not target.parent.exists()


def test_write_document_roundtrip_preserves_rows(tmp_path):
    document = load_example()
    target = tmp_path / "out.json"

    write_document(document, target)

    reloaded = json.loads(target.read_text(encoding="utf-8"))
    assert reloaded["datasets"]["repositories"] == document["datasets"]["repositories"]
    assert reloaded["observations"] == document["observations"]


def test_analysis_modules_do_not_import_analyzer_extras():
    # La lógica de `analysis/` debe ser stdlib pura: no importar pandas,
    # matplotlib, nbformat ni nbclient (el extra [analyzer] es opcional).
    import re

    analysis_dir = Path(__file__).resolve().parents[1] / "analysis"
    forbidden = ("pandas", "matplotlib", "nbformat", "nbclient")
    pattern = re.compile(
        r"^\s*(?:import|from)\s+(" + "|".join(forbidden) + r")\b", re.MULTILINE
    )

    for module in ("loader.py", "metrics.py", "contract.py", "pipeline.py"):
        source = (analysis_dir / module).read_text(encoding="utf-8")
        assert not pattern.search(source), f"{module} importa un extra del Analyzer"

    assert contract.SCHEMA_VERSION == "1.1"
