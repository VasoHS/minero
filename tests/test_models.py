import json

from miner.models import (
    Finding,
    OrganizationReport,
    RepositoryResult,
    SbomResult,
    Summary,
    Vulnerability,
    VulnResult,
)


def test_summary_defaults():
    summary = Summary()
    assert summary.repositories == 0
    assert summary.analyzed == 0
    assert summary.failed == 0
    assert summary.unsupported == 0
    assert summary.findings == 0
    assert summary.sboms_generated == 0
    assert summary.sboms_failed == 0
    assert summary.components == 0
    assert summary.vulns_scanned == 0
    assert summary.vulns_failed == 0
    assert summary.vulnerabilities == 0
    assert summary.vulns_critical == 0
    assert summary.vulns_high == 0
    assert summary.vulns_medium == 0
    assert summary.vulns_low == 0


def test_vuln_result_defaults():
    result = VulnResult()
    assert result.status == "skipped"
    assert result.total == 0
    assert result.by_severity == {}
    assert result.vulnerabilities == []
    assert result.grype_version is None
    assert result.generated_at is None
    assert result.file is None


def test_sbom_result_defaults():
    sbom = SbomResult()
    assert sbom.status == "skipped"
    assert sbom.components == 0
    assert sbom.syft_version is None
    assert sbom.generated_at is None
    assert sbom.file is None


def test_repository_result_defaults():
    repo = RepositoryResult(
        name="test-repo",
        url="https://github.com/org/test-repo",
        status="cloned",
    )
    assert repo.full_name is None
    assert repo.commit is None
    assert isinstance(repo.sbom, SbomResult)
    assert repo.sbom.status == "skipped"
    assert isinstance(repo.vulnerabilities, VulnResult)
    assert repo.vulnerabilities.status == "skipped"
    assert repo.languages == []
    assert repo.findings == []


def test_repository_result_serializes_vulnerabilities():
    vulnerability = Vulnerability(
        id="CVE-2021-1234",
        severity="High",
        package="lodash",
        version="4.17.20",
        type="npm",
        fixed_version="4.17.21",
        namespace="nvd:cpe",
    )
    vuln_result = VulnResult(
        status="scanned",
        total=1,
        by_severity={
            "Critical": 0, "High": 1, "Medium": 0,
            "Low": 0, "Negligible": 0, "Unknown": 0,
        },
        vulnerabilities=[vulnerability],
        grype_version="0.87.0",
        generated_at="2026-01-01T00:00:00+00:00",
        file="vulns/test-repo.grype.json",
    )
    repo = RepositoryResult(
        name="test-repo",
        url="https://github.com/org/test-repo",
        status="analyzed",
        vulnerabilities=vuln_result,
    )

    data = json.loads(repo.model_dump_json())
    assert data["vulnerabilities"]["status"] == "scanned"
    assert data["vulnerabilities"]["total"] == 1
    assert data["vulnerabilities"]["grype_version"] == "0.87.0"
    assert data["vulnerabilities"]["file"] == "vulns/test-repo.grype.json"
    assert data["vulnerabilities"]["vulnerabilities"] == [{
        "id": "CVE-2021-1234",
        "severity": "High",
        "package": "lodash",
        "version": "4.17.20",
        "type": "npm",
        "fixed_version": "4.17.21",
        "namespace": "nvd:cpe",
    }]


def test_repository_result_serializes_new_fields():
    sbom = SbomResult(
        status="generated",
        components=5,
        syft_version="1.2.3",
        generated_at="2026-01-01T00:00:00+00:00",
        file="sboms/test-repo.cdx.json",
    )
    repo = RepositoryResult(
        name="test-repo",
        full_name="org/test-repo",
        commit="abc123",
        url="https://github.com/org/test-repo",
        status="analyzed",
        sbom=sbom,
    )

    data = json.loads(repo.model_dump_json())
    assert data["full_name"] == "org/test-repo"
    assert data["commit"] == "abc123"
    assert data["sbom"] == {
        "status": "generated",
        "components": 5,
        "syft_version": "1.2.3",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "file": "sboms/test-repo.cdx.json",
    }


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


def test_organization_report_preserves_repository_order():
    repos = [
        RepositoryResult(name=name, url=f"https://github.com/org/{name}",
                         status="cloned")
        for name in ("repo-a", "repo-b", "repo-c")
    ]
    report = OrganizationReport(
        organization="test-org",
        summary=Summary(repositories=3),
        repositories=repos,
    )

    data = json.loads(report.model_dump_json())
    assert [r["name"] for r in data["repositories"]] == [
        "repo-a",
        "repo-b",
        "repo-c",
    ]
