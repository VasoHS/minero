import json
import pytest
from pathlib import Path
from miner.sarif_parser import parse_sarif

def test_parse_sarif_non_existent(tmp_path):
    fake_path = tmp_path / "non_existent.sarif"
    findings = parse_sarif(fake_path)
    assert findings == []

def test_parse_sarif_valid(tmp_path):
    sarif_data = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "error",
                        "message": {"text": "Potential SQL injection"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/db.py"},
                                    "region": {"startLine": 42}
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }
    
    sarif_file = tmp_path / "test.sarif"
    with open(sarif_file, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f)
        
    findings = parse_sarif(sarif_file)
    assert len(findings) == 1
    assert findings[0].rule_id == "py/sql-injection"
    assert findings[0].severity == "error"
    assert findings[0].message == "Potential SQL injection"
    assert findings[0].file == "app/db.py"
    assert findings[0].start_line == 42


def _write(tmp_path, content):
    sarif_file = tmp_path / "test.sarif"
    if isinstance(content, str):
        sarif_file.write_text(content, encoding="utf-8")
    else:
        sarif_file.write_text(json.dumps(content), encoding="utf-8")
    return sarif_file


def test_parse_sarif_invalid_json_returns_empty(tmp_path):
    assert parse_sarif(_write(tmp_path, "{no es json")) == []


def test_parse_sarif_non_object_returns_empty(tmp_path):
    assert parse_sarif(_write(tmp_path, [1, 2, 3])) == []


@pytest.mark.parametrize("data", [{}, {"runs": None}, {"runs": "x"}, {"runs": []}])
def test_parse_sarif_missing_runs_returns_empty(tmp_path, data):
    assert parse_sarif(_write(tmp_path, data)) == []


def test_parse_sarif_results_not_list_returns_empty(tmp_path):
    assert parse_sarif(_write(tmp_path, {"runs": [{"results": None}]})) == []


def test_parse_sarif_skips_malformed_results(tmp_path):
    data = {
        "runs": [
            {"results": ["no soy dict", {"message": "no soy dict"}]},
            "no soy dict",
        ]
    }
    findings = parse_sarif(_write(tmp_path, data))
    # Los dos resultados no-dict se omiten; el resultado dict sin datos es válido.
    assert len(findings) == 1
    assert findings[0].rule_id == "unknown"
    assert findings[0].severity == "warning"
    assert findings[0].message == ""
    assert findings[0].file == "unknown"
    assert findings[0].start_line is None


def test_parse_sarif_ignores_non_integer_start_line(tmp_path):
    data = {
        "runs": [{"results": [{
            "ruleId": "py/test",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"startLine": True},
                }
            }],
        }]}]
    }
    findings = parse_sarif(_write(tmp_path, data))
    assert findings[0].start_line is None
    assert findings[0].file == "a.py"


def test_parse_sarif_aggregates_multiple_runs(tmp_path):
    data = {
        "runs": [
            {"results": [{"ruleId": "r1", "message": {"text": "uno"}}]},
            {"results": [{"ruleId": "r2", "message": {"text": "dos"}}]},
        ]
    }
    findings = parse_sarif(_write(tmp_path, data))
    assert [f.rule_id for f in findings] == ["r1", "r2"]
