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
