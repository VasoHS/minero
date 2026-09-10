import pytest
from miner.models import Finding, RepositoryResult, Summary, OrganizationReport

def test_summary_defaults():
    summary = Summary()
    assert summary.repositories == 0
    assert summary.analyzed == 0
    assert summary.failed == 0
    assert summary.unsupported == 0
    assert summary.findings == 0

def test_organization_report_serialization():
    finding = Finding(
        rule_id="py/test-rule",
        severity="warning",
        message="Test warning",
        file="src/main.py",
        start_line=10
    )
    repo_result = RepositoryResult(
        name="test-repo",
        url="https://github.com/org/test-repo",
        status="analyzed",
        languages=["python"],
        findings=[finding]
    )
    summary = Summary(repositories=1, analyzed=1, findings=1)
    report = OrganizationReport(
        organization="test-org",
        summary=summary,
        repositories=[repo_result]
    )
    
    json_data = report.model_dump_json()
    assert "test-org" in json_data
    assert "test-repo" in json_data
    assert "py/test-rule" in json_data
