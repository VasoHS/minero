import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from miner.cli import app, _cleanup, _inside, _is_safe_repo_name
from miner.models import Finding, SbomResult, Vulnerability, VulnResult
from miner.progress import VulnProgress

runner = CliRunner()


def make_repo(name, language="python", clone_url=None):
    return {
        "name": name,
        "clone_url": clone_url or f"https://github.com/test-org/{name}.git",
        "language": language,
    }


def make_sbom(status="generated", components=2, syft_version="9.9.9", file=None):
    return SbomResult(
        status=status,
        components=components,
        syft_version=syft_version,
        generated_at="2026-01-01T00:00:00+00:00",
        file=file,
    )


def make_vuln(status="scanned", total=2, by_severity=None, grype_version="0.87.0",
              file=None, vulnerabilities=None):
    return VulnResult(
        status=status,
        total=total,
        by_severity=by_severity or {
            "Critical": 0, "High": 1, "Medium": 1,
            "Low": 0, "Negligible": 0, "Unknown": 0,
        },
        vulnerabilities=vulnerabilities or [],
        grype_version=grype_version,
        generated_at="2026-01-01T00:00:00+00:00",
        file=file,
    )


def run_scan(
    tmp_path,
    repos,
    monkeypatch,
    *,
    clone=True,
    create=True,
    analyze=True,
    findings=None,
    output=None,
    clone_side_effect=None,
    sbom=True,
    sbom_result=None,
    sbom_side_effect=None,
    syft_version="9.9.9",
    vuln=True,
    vuln_result=None,
    vuln_side_effect=None,
    grype_version="0.87.0",
    extra_args=None,
):
    """Ejecuta `scan` con todas las dependencias externas monkeypatcheadas."""
    monkeypatch.chdir(tmp_path)
    org_repos_mock = Mock(return_value=list(repos))
    monkeypatch.setattr("miner.cli.get_organization_repos", org_repos_mock)

    if clone_side_effect is not None:
        clone_mock = Mock(side_effect=clone_side_effect)
    else:
        clone_mock = Mock(return_value=clone)

    create_mock = Mock(return_value=create)
    analyze_mock = Mock(return_value=analyze)
    parse_mock = Mock(return_value=list(findings) if findings else [])

    syft_mock = Mock(return_value=syft_version)
    if sbom_side_effect is not None:
        generate_mock = Mock(side_effect=sbom_side_effect)
    else:
        default_sbom = (
            sbom_result if sbom_result is not None
            else make_sbom(syft_version=syft_version)
        )
        generate_mock = Mock(return_value=default_sbom)

    grype_mock = Mock(return_value=grype_version)
    if vuln_side_effect is not None:
        vuln_mock = Mock(side_effect=vuln_side_effect)
    else:
        default_vuln = (
            vuln_result if vuln_result is not None
            else make_vuln(grype_version=grype_version)
        )
        vuln_mock = Mock(return_value=default_vuln)

    monkeypatch.setattr("miner.cli.clone_repository", clone_mock)
    monkeypatch.setattr("miner.cli.create_database", create_mock)
    monkeypatch.setattr("miner.cli.analyze_database", analyze_mock)
    monkeypatch.setattr("miner.cli.parse_sarif", parse_mock)
    monkeypatch.setattr("miner.cli.get_syft_version", syft_mock)
    monkeypatch.setattr("miner.cli.generate_sbom", generate_mock)
    monkeypatch.setattr("miner.cli.get_grype_version", grype_mock)
    monkeypatch.setattr("miner.cli.scan_vulnerabilities", vuln_mock)

    out_path = Path(output) if output is not None else tmp_path / "out.json"
    args = ["scan", "--organization", "test-org", "--output", str(out_path)]
    if not sbom:
        args.append("--no-sbom")
    if not vuln:
        args.append("--no-vuln")
    if extra_args:
        args.extend(extra_args)

    result = runner.invoke(app, args)

    return SimpleNamespace(
        result=result,
        out=out_path,
        clone=clone_mock,
        create=create_mock,
        analyze=analyze_mock,
        parse=parse_mock,
        get_syft_version=syft_mock,
        generate_sbom=generate_mock,
        get_grype_version=grype_mock,
        scan_vulnerabilities=vuln_mock,
        get_organization_repos=org_repos_mock,
    )


@pytest.mark.parametrize("language", [None, "cobol"])
def test_scan_unsupported_language(tmp_path, monkeypatch, language):
    run = run_scan(
        tmp_path, [make_repo("repo-a", language=language)], monkeypatch
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    repo = data["repositories"][0]
    assert repo["status"] == "unsupported"
    # El SBOM se genera antes de validar el lenguaje.
    assert repo["sbom"]["status"] == "generated"
    assert data["summary"]["unsupported"] == 1
    assert data["summary"]["failed"] == 0
    assert data["summary"]["analyzed"] == 0
    assert data["summary"]["sboms_generated"] == 1
    run.clone.assert_called_once()
    run.generate_sbom.assert_called_once()
    run.create.assert_not_called()
    run.analyze.assert_not_called()
    run.parse.assert_not_called()


def test_scan_clone_failed(tmp_path, monkeypatch):
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, clone=False
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    assert data["repositories"][0]["status"] == "clone_failed"
    assert data["summary"]["failed"] == 1
    run.clone.assert_called_once()
    # Un clon fallido no genera SBOM.
    run.generate_sbom.assert_not_called()
    run.create.assert_not_called()
    run.analyze.assert_not_called()


def test_scan_db_failed(tmp_path, monkeypatch):
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, create=False
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    assert data["repositories"][0]["status"] == "db_failed"
    assert data["summary"]["failed"] == 1
    run.clone.assert_called_once()
    run.create.assert_called_once()
    run.analyze.assert_not_called()


def test_scan_analyze_failed(tmp_path, monkeypatch):
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, analyze=False
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    assert data["repositories"][0]["status"] == "analyze_failed"
    assert data["summary"]["failed"] == 1
    run.clone.assert_called_once()
    run.create.assert_called_once()
    run.analyze.assert_called_once()


def test_scan_analyzed_success(tmp_path, monkeypatch):
    finding = Finding(
        rule_id="py/sql-injection",
        severity="error",
        message="Potential SQL injection",
        file="app/db.py",
        start_line=42,
    )
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, findings=[finding]
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    repo_result = data["repositories"][0]
    assert repo_result["status"] == "analyzed"
    assert data["summary"]["analyzed"] == 1
    assert data["summary"]["findings"] == 1
    assert data["summary"]["failed"] == 0
    assert repo_result["languages"] == ["python"]
    assert repo_result["findings"][0]["rule_id"] == "py/sql-injection"
    assert repo_result["findings"][0]["start_line"] == 42
    run.parse.assert_called_once()
    assert (
        Path(run.parse.call_args.args[0]).resolve()
        == (tmp_path / "workdir" / "repo-a.sarif").resolve()
    )


def test_scan_sbom_failed_still_analyzed(tmp_path, monkeypatch):
    failed_sbom = make_sbom(status="failed", components=0)
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, sbom_result=failed_sbom
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    repo = data["repositories"][0]
    assert repo["status"] == "analyzed"
    assert repo["sbom"]["status"] == "failed"
    assert data["summary"]["analyzed"] == 1
    assert data["summary"]["sboms_failed"] == 1
    assert data["summary"]["sboms_generated"] == 0
    assert data["summary"]["components"] == 0
    run.generate_sbom.assert_called_once()
    run.create.assert_called_once()
    run.analyze.assert_called_once()


def test_scan_no_sbom_skips_generation(tmp_path, monkeypatch):
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, sbom=False
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    repo = data["repositories"][0]
    assert repo["status"] == "analyzed"
    assert repo["sbom"]["status"] == "skipped"
    assert data["summary"]["sboms_generated"] == 0
    assert data["summary"]["sboms_failed"] == 0
    run.generate_sbom.assert_not_called()
    run.get_syft_version.assert_not_called()


def test_scan_sbom_records_components(tmp_path, monkeypatch):
    sbom_result = make_sbom(status="generated", components=7)
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, sbom_result=sbom_result
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    assert data["summary"]["sboms_generated"] == 1
    assert data["summary"]["components"] == 7
    assert data["repositories"][0]["sbom"]["components"] == 7
    # La ruta de salida del SBOM sigue el patrón sbom_dir/<repo>.cdx.json.
    dest = Path(run.generate_sbom.call_args.args[1])
    assert dest.name == "repo-a.cdx.json"


def test_scan_grype_uses_sbom_when_available(tmp_path, monkeypatch):
    sbom_result = make_sbom(
        status="generated", components=7, file="sboms/repo-a.cdx.json"
    )
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, sbom_result=sbom_result
    )

    assert run.result.exit_code == 0
    run.get_grype_version.assert_called_once()
    run.scan_vulnerabilities.assert_called_once()
    source = run.scan_vulnerabilities.call_args.args[0]
    assert source == "sbom:sboms/repo-a.cdx.json"
    # La ruta de salida sigue el patrón vuln_dir/<repo>.grype.json.
    dest = Path(run.scan_vulnerabilities.call_args.args[1])
    assert dest.name == "repo-a.grype.json"


def test_scan_grype_falls_back_to_dir_without_sbom(tmp_path, monkeypatch):
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, sbom=False, vuln=True
    )

    assert run.result.exit_code == 0
    run.scan_vulnerabilities.assert_called_once()
    source = run.scan_vulnerabilities.call_args.args[0]
    assert source == "dir:workdir/repo-a"


def test_scan_grype_falls_back_to_dir_when_sbom_failed(tmp_path, monkeypatch):
    failed_sbom = make_sbom(status="failed", components=0, file=None)
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, sbom_result=failed_sbom
    )

    assert run.result.exit_code == 0
    run.scan_vulnerabilities.assert_called_once()
    source = run.scan_vulnerabilities.call_args.args[0]
    assert source == "dir:workdir/repo-a"


def test_scan_records_vulnerability_summary(tmp_path, monkeypatch):
    vuln_result = make_vuln(
        status="scanned",
        total=4,
        by_severity={
            "Critical": 1, "High": 2, "Medium": 1,
            "Low": 0, "Negligible": 0, "Unknown": 0,
        },
    )
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, vuln_result=vuln_result
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    summary = data["summary"]
    assert summary["vulns_scanned"] == 1
    assert summary["vulns_failed"] == 0
    assert summary["vulnerabilities"] == 4
    assert summary["vulns_critical"] == 1
    assert summary["vulns_high"] == 2
    assert summary["vulns_medium"] == 1
    assert summary["vulns_low"] == 0
    repo = data["repositories"][0]
    assert repo["vulnerabilities"]["status"] == "scanned"
    assert repo["vulnerabilities"]["total"] == 4


def test_scan_records_no_vulnerabilities_summary(tmp_path, monkeypatch):
    vuln_result = make_vuln(
        status="no_vulnerabilities",
        total=0,
        by_severity={
            "Critical": 0, "High": 0, "Medium": 0,
            "Low": 0, "Negligible": 0, "Unknown": 0,
        },
    )
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, vuln_result=vuln_result
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    summary = data["summary"]
    # Un escaneo correcto sin hallazgos cuenta como escaneado, no como fallo.
    assert summary["vulns_scanned"] == 1
    assert summary["vulns_failed"] == 0
    assert summary["vulnerabilities"] == 0
    assert summary["vulns_critical"] == 0
    assert summary["vulns_high"] == 0
    assert summary["vulns_medium"] == 0
    assert summary["vulns_low"] == 0
    repo = data["repositories"][0]
    assert repo["vulnerabilities"]["status"] == "no_vulnerabilities"
    assert repo["vulnerabilities"]["total"] == 0


def test_scan_ignores_unknown_and_negligible_in_severity_breakdown(tmp_path, monkeypatch):
    vuln_result = make_vuln(
        status="scanned",
        total=5,
        by_severity={
            "Critical": 0, "High": 0, "Medium": 0,
            "Low": 0, "Negligible": 2, "Unknown": 3,
        },
    )
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, vuln_result=vuln_result
    )

    assert run.result.exit_code == 0
    summary = json.loads(run.out.read_text())["summary"]
    assert summary["vulns_scanned"] == 1
    # Unknown y Negligible suman al total pero no al desglose por gravedad.
    assert summary["vulnerabilities"] == 5
    assert summary["vulns_critical"] == 0
    assert summary["vulns_high"] == 0
    assert summary["vulns_medium"] == 0
    assert summary["vulns_low"] == 0


def test_scan_missing_grype_version_still_processes_repo(tmp_path, monkeypatch):
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, grype_version=None
    )

    assert run.result.exit_code == 0
    run.get_grype_version.assert_called_once()
    run.scan_vulnerabilities.assert_called_once()
    # Se avisa de la ausencia de Grype pero el repositorio sigue procesándose.
    assert "Grype" in run.result.output
    data = json.loads(run.out.read_text())
    repo = data["repositories"][0]
    assert repo["status"] == "analyzed"
    assert repo["vulnerabilities"]["status"] == "scanned"
    assert repo["vulnerabilities"]["grype_version"] is None


def test_scan_serializes_vulnerability_findings(tmp_path, monkeypatch):
    finding = Vulnerability(
        id="CVE-2021-1234",
        severity="Critical",
        package="openssl",
        version="1.1.1",
        type="deb",
        fixed_version="1.1.1k",
        namespace="debian:11",
    )
    vuln_result = make_vuln(
        status="scanned",
        total=1,
        by_severity={
            "Critical": 1, "High": 0, "Medium": 0,
            "Low": 0, "Negligible": 0, "Unknown": 0,
        },
        vulnerabilities=[finding],
    )
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, vuln_result=vuln_result
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    vulns = data["repositories"][0]["vulnerabilities"]["vulnerabilities"]
    assert vulns == [{
        "id": "CVE-2021-1234",
        "severity": "Critical",
        "package": "openssl",
        "version": "1.1.1",
        "type": "deb",
        "fixed_version": "1.1.1k",
        "namespace": "debian:11",
    }]


def test_scan_no_vuln_skips_grype(tmp_path, monkeypatch):
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, vuln=False
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    repo = data["repositories"][0]
    assert repo["status"] == "analyzed"
    assert repo["vulnerabilities"]["status"] == "skipped"
    assert data["summary"]["vulns_scanned"] == 0
    assert data["summary"]["vulns_failed"] == 0
    run.scan_vulnerabilities.assert_not_called()
    run.get_grype_version.assert_not_called()


def test_scan_vuln_failed_still_analyzed(tmp_path, monkeypatch):
    failed_vuln = make_vuln(status="failed", total=0)
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, vuln_result=failed_vuln
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    repo = data["repositories"][0]
    assert repo["status"] == "analyzed"
    assert repo["vulnerabilities"]["status"] == "failed"
    assert data["summary"]["analyzed"] == 1
    assert data["summary"]["vulns_failed"] == 1
    assert data["summary"]["vulns_scanned"] == 0
    assert data["summary"]["vulnerabilities"] == 0


def test_scan_vuln_runs_for_unsupported_language(tmp_path, monkeypatch):
    run = run_scan(
        tmp_path, [make_repo("repo-a", language=None)], monkeypatch
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    repo = data["repositories"][0]
    assert repo["status"] == "unsupported"
    # El escaneo de vulnerabilidades ocurre antes de validar el lenguaje.
    assert repo["vulnerabilities"]["status"] == "scanned"
    run.scan_vulnerabilities.assert_called_once()


def test_scan_invalid_name_rejected(tmp_path, monkeypatch):
    deleted_paths = []
    real_rmtree = shutil.rmtree

    def spy_rmtree(path, *args, **kwargs):
        deleted_paths.append(Path(path).resolve())
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr("miner.cli.shutil.rmtree", spy_rmtree)

    run = run_scan(
        tmp_path, [make_repo("../evil")], monkeypatch
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    assert data["repositories"][0]["status"] == "invalid_name"
    assert data["summary"]["failed"] == 1
    assert data["summary"]["analyzed"] == 0
    run.clone.assert_not_called()
    run.create.assert_not_called()
    run.generate_sbom.assert_not_called()
    # No se crea nada con la ruta de escape.
    assert not (tmp_path / "evil").exists()
    # Ninguna limpieza toca rutas fuera de tmp_path.
    for path in deleted_paths:
        assert path == tmp_path or tmp_path in path.parents


def test_scan_invalid_name_does_not_delete_outside_workdir(tmp_path, monkeypatch):
    """Regresión: un nombre con traversal profundo no debe borrar fuera del workdir."""
    victim = tmp_path.parent / "victim_escape_regression"
    victim.mkdir(exist_ok=True)
    marker = victim / "important.txt"
    marker.write_text("no borrar")

    deleted_paths = []
    real_rmtree = shutil.rmtree

    def spy_rmtree(path, *args, **kwargs):
        deleted_paths.append(Path(path).resolve())
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr("miner.cli.shutil.rmtree", spy_rmtree)

    try:
        run = run_scan(
            tmp_path, [make_repo(f"../../{victim.name}")], monkeypatch
        )

        assert run.result.exit_code == 0
        data = json.loads(run.out.read_text())
        assert data["repositories"][0]["status"] == "invalid_name"
        assert data["summary"]["failed"] == 1
        run.clone.assert_not_called()
        # El directorio fuera del workdir sigue intacto.
        assert marker.exists()
        assert marker.read_text() == "no borrar"
        for path in deleted_paths:
            assert path == tmp_path or tmp_path in path.parents
    finally:
        real_rmtree(victim, ignore_errors=True)


def test_scan_cleans_previous_artifacts(tmp_path, monkeypatch):
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    repo_dir = workdir / "repo-a"
    db_dir = workdir / "repo-a_db"
    sarif_file = workdir / "repo-a.sarif"

    repo_dir.mkdir()
    (repo_dir / "stale.txt").write_text("stale")
    db_dir.mkdir()
    sarif_file.write_text("{}")

    observed = {}

    def fake_clone(url, dest):
        observed["dest_existed_at_clone"] = Path(dest).exists()
        Path(dest).mkdir(parents=True, exist_ok=True)
        return True

    run = run_scan(
        tmp_path,
        [make_repo("repo-a")],
        monkeypatch,
        clone_side_effect=fake_clone,
    )

    assert run.result.exit_code == 0
    # El clonado recibe un destino limpio (los restos se borraron antes).
    assert observed["dest_existed_at_clone"] is False
    data = json.loads(run.out.read_text())
    assert data["repositories"][0]["status"] == "analyzed"
    # Con --keep-repos (por defecto) el repo se conserva; los temporales se eliminan.
    assert repo_dir.exists()
    assert not (repo_dir / "stale.txt").exists()
    assert not db_dir.exists()
    assert not sarif_file.exists()


def test_scan_cleanup_repos_removes_repo(tmp_path, monkeypatch):
    run = run_scan(
        tmp_path,
        [make_repo("repo-a")],
        monkeypatch,
        extra_args=["--cleanup-repos"],
    )

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    assert data["repositories"][0]["status"] == "analyzed"
    assert not (tmp_path / "workdir" / "repo-a").exists()


def test_scan_summary_counts_all_repositories(tmp_path, monkeypatch):
    repos = [
        make_repo("repo-a"),
        make_repo("repo-b", language=None),
        make_repo("repo-c", language="cobol"),
    ]
    run = run_scan(tmp_path, repos, monkeypatch)

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    assert data["summary"]["repositories"] == 3
    assert len(data["repositories"]) == 3
    assert data["summary"]["analyzed"] == 1
    assert data["summary"]["unsupported"] == 2
    assert data["summary"]["sboms_generated"] == 3
    assert [r["name"] for r in data["repositories"]] == [
        "repo-a",
        "repo-b",
        "repo-c",
    ]


def test_scan_limit_processes_first_n_in_github_order(tmp_path, monkeypatch):
    repos = [
        make_repo("zeta"),
        make_repo("alpha"),
        make_repo("beta"),
    ]
    run = run_scan(tmp_path, repos, monkeypatch, extra_args=["--limit", "2"])

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    # Se conserva el orden de GitHub (aquí simulado por el orden de entrada) y
    # se toman los dos primeros, sin reordenar alfabéticamente.
    assert [r["name"] for r in data["repositories"]] == ["zeta", "alpha"]
    assert data["summary"]["repositories"] == 2
    assert len(data["repositories"]) == 2
    assert (
        "Límite aplicado: se procesarán 2 de 3 repositorios."
        in run.result.output
    )
    # Solo se clonan los repos seleccionados.
    cloned = [call.args[1].name for call in run.clone.call_args_list]
    assert cloned == ["zeta", "alpha"]


def test_scan_limit_keeps_github_order_not_alphabetical(tmp_path, monkeypatch):
    repos = [
        make_repo("Beta"),
        make_repo("alpha"),
        make_repo("gamma"),
    ]
    run = run_scan(tmp_path, repos, monkeypatch, extra_args=["--limit", "2"])

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    # El orden de GitHub manda: no se reordena por nombre (que daría
    # "alpha", "Beta"), se toman los dos primeros de la lista devuelta.
    assert [r["name"] for r in data["repositories"]] == ["Beta", "alpha"]
    assert data["summary"]["repositories"] == 2


def test_scan_limit_equal_to_total_processes_all(tmp_path, monkeypatch):
    repos = [make_repo("repo-a"), make_repo("repo-b"), make_repo("repo-c")]
    run = run_scan(tmp_path, repos, monkeypatch, extra_args=["--limit", "3"])

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    assert [r["name"] for r in data["repositories"]] == [
        "repo-a",
        "repo-b",
        "repo-c",
    ]
    assert data["summary"]["repositories"] == 3
    # Al no recortar nada, no se anuncia el límite.
    assert "Límite aplicado" not in run.result.output


def test_scan_limit_greater_than_total_processes_all(tmp_path, monkeypatch):
    repos = [make_repo("repo-a"), make_repo("repo-b")]
    run = run_scan(tmp_path, repos, monkeypatch, extra_args=["--limit", "10"])

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    assert [r["name"] for r in data["repositories"]] == ["repo-a", "repo-b"]
    assert data["summary"]["repositories"] == 2
    assert "Límite aplicado" not in run.result.output


def test_scan_limit_zero_processes_no_repositories(tmp_path, monkeypatch):
    repos = [make_repo("repo-a"), make_repo("repo-b"), make_repo("repo-c")]
    run = run_scan(tmp_path, repos, monkeypatch, extra_args=["--limit", "0"])

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    assert data["repositories"] == []
    assert data["summary"]["repositories"] == 0
    assert data["summary"]["analyzed"] == 0
    assert (
        "Límite aplicado: se procesarán 0 de 3 repositorios."
        in run.result.output
    )
    run.clone.assert_not_called()
    run.create.assert_not_called()
    # Sin repositorios no se genera SBOM ni se escanean vulnerabilidades.
    run.generate_sbom.assert_not_called()
    run.scan_vulnerabilities.assert_not_called()


def test_scan_negative_limit_rejected_before_fetching_repos(tmp_path, monkeypatch):
    repos = [make_repo("repo-a"), make_repo("repo-b")]
    run = run_scan(tmp_path, repos, monkeypatch, extra_args=["--limit", "-1"])

    assert run.result.exit_code == 1
    assert (
        "El límite de repositorios (--limit) no puede ser negativo."
        in run.result.output
    )
    # La validación ocurre antes de consultar la organización.
    run.get_organization_repos.assert_not_called()
    run.clone.assert_not_called()
    assert not run.out.exists()


def test_scan_without_limit_processes_all_repositories(tmp_path, monkeypatch):
    repos = [make_repo("zeta"), make_repo("alpha"), make_repo("beta")]
    run = run_scan(tmp_path, repos, monkeypatch)

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    # Sin --limit se procesan todos, conservando el orden de GitHub.
    assert [r["name"] for r in data["repositories"]] == [
        "zeta",
        "alpha",
        "beta",
    ]
    assert data["summary"]["repositories"] == 3
    assert "Límite aplicado" not in run.result.output


def test_scan_limit_with_empty_organization(tmp_path, monkeypatch):
    run = run_scan(tmp_path, [], monkeypatch, extra_args=["--limit", "5"])

    assert run.result.exit_code == 0
    data = json.loads(run.out.read_text())
    assert data["repositories"] == []
    assert data["summary"]["repositories"] == 0
    # No hay nada que recortar, así que no se anuncia el límite.
    assert "Límite aplicado" not in run.result.output
    run.clone.assert_not_called()


@pytest.mark.parametrize(
    "name,expected",
    [
        ("repo-a", True),
        ("a.b_c-d", True),
        ("repo123", True),
        ("", False),
        (".", False),
        ("..", False),
        ("...", False),
        ("../evil", False),
        ("a/b", False),
        ("a\\b", False),
        ("a b", False),
    ],
)
def test_is_safe_repo_name(name, expected):
    assert _is_safe_repo_name(name) is expected


def test_inside_is_strict_and_safe(tmp_path):
    base = tmp_path / "workdir"
    base.mkdir()

    assert _inside(base, base / "repo-a") is True
    # El propio workdir no se considera "dentro".
    assert _inside(base, base) is False
    # Rutas fuera del workdir.
    assert _inside(base, tmp_path / "victim") is False
    assert _inside(base, base / ".." / "victim") is False


def test_cleanup_removes_only_inside_base(tmp_path):
    base = tmp_path / "workdir"
    base.mkdir()

    repo_dir = base / "repo-a"
    db_dir = base / "repo-a_db"
    sarif_file = base / "repo-a.sarif"
    repo_dir.mkdir()
    (repo_dir / "f.txt").write_text("x")
    db_dir.mkdir()
    sarif_file.write_text("{}")

    victim = tmp_path / "victim"
    victim.mkdir()
    marker = victim / "important.txt"
    marker.write_text("no borrar")

    _cleanup(base, repo_dir, db_dir, sarif_file)
    assert not repo_dir.exists()
    assert not db_dir.exists()
    assert not sarif_file.exists()

    # Rutas fuera del workdir nunca se tocan.
    _cleanup(base, victim, victim / "db", victim / "x.sarif")
    assert marker.exists()


def test_scan_creates_output_parent_directory(tmp_path, monkeypatch):
    out = tmp_path / "sub" / "dir" / "out.json"
    run = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, output=out
    )

    assert run.result.exit_code == 0
    assert run.out.exists()
    data = json.loads(run.out.read_text())
    assert data["organization"] == "test-org"
    assert data["summary"]["analyzed"] == 1


# ---------------------------------------------------------------------------
# Comando `sbom`
# ---------------------------------------------------------------------------

def make_git_repo(workdir, name):
    repo_dir = workdir / name
    (repo_dir / ".git").mkdir(parents=True)
    return repo_dir


def test_sbom_command_generates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    workdir = tmp_path / "workdir"
    make_git_repo(workdir, "repo-a")
    make_git_repo(workdir, "repo-b")
    sbom_dir = tmp_path / "sboms"
    out = tmp_path / "sbom-report.json"

    monkeypatch.setattr("miner.cli.get_syft_version", Mock(return_value="9.9.9"))
    generate_mock = Mock(
        return_value=make_sbom(status="generated", components=3)
    )
    monkeypatch.setattr("miner.cli.generate_sbom", generate_mock)
    monkeypatch.setattr(
        "miner.cli.get_remote_url",
        Mock(side_effect=lambda d: f"https://github.com/org/{d.name}.git"),
    )
    monkeypatch.setattr(
        "miner.cli.get_head_commit",
        Mock(side_effect=lambda d: f"sha-{d.name}"),
    )

    result = runner.invoke(
        app,
        [
            "sbom",
            "--repos-dir", str(workdir),
            "--sbom-dir", str(sbom_dir),
            "--output", str(out),
        ],
    )

    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["summary"]["repositories"] == 2
    assert data["summary"]["sboms_generated"] == 2
    assert data["summary"]["components"] == 6

    repos = {r["name"]: r for r in data["repositories"]}
    assert set(repos) == {"repo-a", "repo-b"}
    assert repos["repo-a"]["full_name"] == "org/repo-a"
    assert repos["repo-a"]["commit"] == "sha-repo-a"
    assert repos["repo-a"]["url"] == "https://github.com/org/repo-a.git"
    assert repos["repo-a"]["status"] == "cloned"

    called = {
        call.args[0].name: call.args[1] for call in generate_mock.call_args_list
    }
    assert set(called) == {"repo-a", "repo-b"}
    assert called["repo-a"] == sbom_dir / "repo-a.cdx.json"
    assert called["repo-b"] == sbom_dir / "repo-b.cdx.json"


def test_sbom_command_without_output_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    workdir = tmp_path / "workdir"
    make_git_repo(workdir, "repo-a")

    monkeypatch.setattr("miner.cli.get_syft_version", Mock(return_value="9.9.9"))
    monkeypatch.setattr(
        "miner.cli.generate_sbom",
        Mock(return_value=make_sbom(status="generated", components=1)),
    )
    monkeypatch.setattr("miner.cli.get_remote_url", Mock(return_value=None))
    monkeypatch.setattr("miner.cli.get_head_commit", Mock(return_value=None))

    result = runner.invoke(
        app, ["sbom", "--repos-dir", str(workdir), "--sbom-dir", str(tmp_path / "sboms")]
    )

    assert result.exit_code == 0
    assert not (tmp_path / "sbom-report.json").exists()


def test_sbom_command_missing_repos_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app, ["sbom", "--repos-dir", str(tmp_path / "does-not-exist")]
    )

    assert result.exit_code != 0


def test_sbom_command_no_git_repos(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "not-a-repo").mkdir()

    result = runner.invoke(app, ["sbom", "--repos-dir", str(workdir)])

    assert result.exit_code != 0


def test_sbom_command_iterdir_oserror(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    workdir = tmp_path / "workdir"
    workdir.mkdir()

    # is_dir() debe seguir funcionando; solo falla el listado del directorio.
    monkeypatch.setattr(
        "miner.cli.Path.iterdir", Mock(side_effect=OSError("boom"))
    )

    result = runner.invoke(app, ["sbom", "--repos-dir", str(workdir)])

    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Comando `vuln`
# ---------------------------------------------------------------------------

def make_sbom_file(sbom_dir, name):
    sbom_dir.mkdir(parents=True, exist_ok=True)
    sbom_file = sbom_dir / f"{name}.cdx.json"
    sbom_file.write_text('{"components": []}', encoding="utf-8")
    return sbom_file


def test_vuln_command_generates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sbom_dir = tmp_path / "sboms"
    make_sbom_file(sbom_dir, "repo-a")
    make_sbom_file(sbom_dir, "repo-b")
    vuln_dir = tmp_path / "vulns"
    out = tmp_path / "vuln-report.json"

    monkeypatch.setattr("miner.cli.get_grype_version", Mock(return_value="0.87.0"))
    scan_mock = Mock(
        return_value=make_vuln(status="scanned", total=3)
    )
    monkeypatch.setattr("miner.cli.scan_vulnerabilities", scan_mock)

    result = runner.invoke(
        app,
        [
            "vuln",
            "--sbom-dir", str(sbom_dir),
            "--vuln-dir", str(vuln_dir),
            "--output", str(out),
        ],
    )

    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["summary"]["repositories"] == 2
    assert data["summary"]["vulns_scanned"] == 2
    assert data["summary"]["vulnerabilities"] == 6

    repos = {r["name"]: r for r in data["repositories"]}
    assert set(repos) == {"repo-a", "repo-b"}
    assert repos["repo-a"]["status"] == "scanned"
    assert repos["repo-a"]["vulnerabilities"]["total"] == 3

    called = {
        call.args[0].split(":", 1)[1].rsplit("/", 1)[-1]: call.args[1]
        for call in scan_mock.call_args_list
    }
    assert called["repo-a.cdx.json"] == vuln_dir / "repo-a.grype.json"
    assert called["repo-b.cdx.json"] == vuln_dir / "repo-b.grype.json"
    for call in scan_mock.call_args_list:
        assert call.args[0].startswith("sbom:")


def test_vuln_command_uses_exact_sbom_target_and_output(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sbom_dir = tmp_path / "sboms"
    make_sbom_file(sbom_dir, "repo-a")
    vuln_dir = tmp_path / "vulns"

    monkeypatch.setattr("miner.cli.get_grype_version", Mock(return_value="0.87.0"))
    scan_mock = Mock(return_value=make_vuln(status="scanned", total=1))
    monkeypatch.setattr("miner.cli.scan_vulnerabilities", scan_mock)

    result = runner.invoke(
        app,
        ["vuln", "--sbom-dir", str(sbom_dir), "--vuln-dir", str(vuln_dir)],
    )

    assert result.exit_code == 0
    assert scan_mock.call_count == 1
    assert scan_mock.call_args.args[0] == f"sbom:{sbom_dir / 'repo-a.cdx.json'}"
    assert scan_mock.call_args.args[1] == vuln_dir / "repo-a.grype.json"


def test_vuln_command_sorts_sboms_alphabetically(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sbom_dir = tmp_path / "sboms"
    for name in ("repo-c", "repo-a", "repo-b"):
        make_sbom_file(sbom_dir, name)

    monkeypatch.setattr("miner.cli.get_grype_version", Mock(return_value="0.87.0"))
    scan_mock = Mock(return_value=make_vuln(status="scanned", total=1))
    monkeypatch.setattr("miner.cli.scan_vulnerabilities", scan_mock)

    out = tmp_path / "vuln-report.json"
    result = runner.invoke(
        app,
        [
            "vuln",
            "--sbom-dir", str(sbom_dir),
            "--vuln-dir", str(tmp_path / "vulns"),
            "--output", str(out),
        ],
    )

    assert result.exit_code == 0
    called = [
        Path(call.args[0].split(":", 1)[1]).name
        for call in scan_mock.call_args_list
    ]
    assert called == ["repo-a.cdx.json", "repo-b.cdx.json", "repo-c.cdx.json"]
    data = json.loads(out.read_text())
    assert [r["name"] for r in data["repositories"]] == [
        "repo-a", "repo-b", "repo-c"
    ]


def test_vuln_command_records_failed_scan(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sbom_dir = tmp_path / "sboms"
    make_sbom_file(sbom_dir, "repo-a")
    make_sbom_file(sbom_dir, "repo-b")

    monkeypatch.setattr("miner.cli.get_grype_version", Mock(return_value="0.87.0"))
    scan_mock = Mock(side_effect=[
        make_vuln(status="failed", total=0),
        make_vuln(status="scanned", total=2),
    ])
    monkeypatch.setattr("miner.cli.scan_vulnerabilities", scan_mock)

    out = tmp_path / "vuln-report.json"
    result = runner.invoke(
        app,
        [
            "vuln",
            "--sbom-dir", str(sbom_dir),
            "--vuln-dir", str(tmp_path / "vulns"),
            "--output", str(out),
        ],
    )

    assert result.exit_code == 0
    data = json.loads(out.read_text())
    summary = data["summary"]
    assert summary["vulns_failed"] == 1
    assert summary["vulns_scanned"] == 1
    assert summary["vulnerabilities"] == 2
    repos = {r["name"]: r for r in data["repositories"]}
    assert repos["repo-a"]["vulnerabilities"]["status"] == "failed"
    assert repos["repo-b"]["vulnerabilities"]["status"] == "scanned"


def test_vuln_command_missing_grype_version_still_scans(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sbom_dir = tmp_path / "sboms"
    make_sbom_file(sbom_dir, "repo-a")

    monkeypatch.setattr("miner.cli.get_grype_version", Mock(return_value=None))
    scan_mock = Mock(return_value=make_vuln(status="scanned", total=1))
    monkeypatch.setattr("miner.cli.scan_vulnerabilities", scan_mock)

    result = runner.invoke(
        app,
        ["vuln", "--sbom-dir", str(sbom_dir), "--vuln-dir", str(tmp_path / "vulns")],
    )

    assert result.exit_code == 0
    assert "Grype" in result.output
    # La versión ausente se propaga como None sin impedir el escaneo.
    assert scan_mock.call_args.args[2] is None


def test_vuln_command_without_output_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sbom_dir = tmp_path / "sboms"
    make_sbom_file(sbom_dir, "repo-a")

    monkeypatch.setattr("miner.cli.get_grype_version", Mock(return_value="0.87.0"))
    monkeypatch.setattr(
        "miner.cli.scan_vulnerabilities",
        Mock(return_value=make_vuln(status="no_vulnerabilities", total=0)),
    )

    result = runner.invoke(
        app, ["vuln", "--sbom-dir", str(sbom_dir), "--vuln-dir", str(tmp_path / "vulns")]
    )

    assert result.exit_code == 0
    assert not (tmp_path / "vuln-report.json").exists()


def test_vuln_command_missing_sbom_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app, ["vuln", "--sbom-dir", str(tmp_path / "does-not-exist")]
    )

    assert result.exit_code != 0


def test_vuln_command_no_sboms(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sbom_dir = tmp_path / "sboms"
    sbom_dir.mkdir()
    (sbom_dir / "no-es-sbom.txt").write_text("x", encoding="utf-8")

    result = runner.invoke(app, ["vuln", "--sbom-dir", str(sbom_dir)])

    assert result.exit_code != 0


def test_vuln_command_iterdir_oserror(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sbom_dir = tmp_path / "sboms"
    sbom_dir.mkdir()

    monkeypatch.setattr(
        "miner.cli.Path.iterdir", Mock(side_effect=OSError("boom"))
    )

    result = runner.invoke(app, ["vuln", "--sbom-dir", str(sbom_dir)])

    assert result.exit_code != 0


def test_scan_repos_dir_is_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    blocker = tmp_path / "workdir-file"
    blocker.write_text("no soy un directorio", encoding="utf-8")
    monkeypatch.setattr("miner.cli.get_organization_repos", Mock(return_value=[]))

    result = runner.invoke(
        app,
        [
            "scan",
            "--organization", "test-org",
            "--output", str(tmp_path / "out.json"),
            "--repos-dir", str(blocker),
        ],
    )

    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Progreso de Grype (--progress / --no-progress / --error-log)
# ---------------------------------------------------------------------------

def test_scan_progress_forces_live_output(tmp_path, monkeypatch):
    def noisy_scan(source, output, grype_version, progress=None):
        progress.info("linea de avance")
        return make_vuln(status="scanned", total=1)

    run = run_scan(
        tmp_path,
        [make_repo("repo-a")],
        monkeypatch,
        vuln_side_effect=noisy_scan,
        extra_args=["--progress"],
    )

    assert run.result.exit_code == 0
    progress = run.scan_vulnerabilities.call_args.kwargs["progress"]
    assert isinstance(progress, VulnProgress)
    assert progress.enabled is True
    assert "linea de avance" in run.result.output


def test_scan_no_progress_hides_live_output_but_writes_log(tmp_path, monkeypatch):
    def noisy_scan(source, output, grype_version, progress=None):
        progress.info("linea de avance")
        progress.error("fallo simulado")
        return make_vuln(status="failed", total=0)

    run = run_scan(
        tmp_path,
        [make_repo("repo-a")],
        monkeypatch,
        vuln_side_effect=noisy_scan,
        extra_args=["--no-progress"],
    )

    assert run.result.exit_code == 0
    progress = run.scan_vulnerabilities.call_args.kwargs["progress"]
    assert isinstance(progress, VulnProgress)
    assert progress.enabled is False
    # El avance no se imprime, pero el log de errores sí se escribe.
    assert "linea de avance" not in run.result.output
    log = tmp_path / "vulns" / "errores.log"
    assert log.exists()
    content = log.read_text(encoding="utf-8")
    assert "fallo simulado" in content
    assert "linea de avance" not in content


def test_scan_default_error_log_is_under_vuln_dir(tmp_path, monkeypatch):
    def failing_scan(source, output, grype_version, progress=None):
        progress.error("fallo simulado")
        return make_vuln(status="failed", total=0)

    run = run_scan(
        tmp_path,
        [make_repo("repo-a")],
        monkeypatch,
        vuln_side_effect=failing_scan,
        extra_args=["--progress"],
    )

    assert run.result.exit_code == 0
    progress = run.scan_vulnerabilities.call_args.kwargs["progress"]
    assert progress.log_file.resolve() == (tmp_path / "vulns" / "errores.log").resolve()
    log = tmp_path / "vulns" / "errores.log"
    assert log.exists()
    assert "fallo simulado" in log.read_text(encoding="utf-8")


def test_scan_custom_error_log_path(tmp_path, monkeypatch):
    custom_log = tmp_path / "custom" / "grype-errores.log"

    def failing_scan(source, output, grype_version, progress=None):
        progress.error("fallo personalizado")
        return make_vuln(status="failed", total=0)

    run = run_scan(
        tmp_path,
        [make_repo("repo-a")],
        monkeypatch,
        vuln_side_effect=failing_scan,
        extra_args=["--error-log", str(custom_log)],
    )

    assert run.result.exit_code == 0
    progress = run.scan_vulnerabilities.call_args.kwargs["progress"]
    assert progress.log_file == custom_log
    assert custom_log.exists()
    assert "fallo personalizado" in custom_log.read_text(encoding="utf-8")
    # No se crea el log por defecto si se indicó uno explícito.
    assert not (tmp_path / "vulns" / "errores.log").exists()


def test_scan_without_vuln_creates_no_progress_log(tmp_path, monkeypatch):
    run = run_scan(
        tmp_path,
        [make_repo("repo-a")],
        monkeypatch,
        vuln=False,
        extra_args=["--progress"],
    )

    assert run.result.exit_code == 0
    run.scan_vulnerabilities.assert_not_called()
    assert not (tmp_path / "vulns" / "errores.log").exists()


def test_vuln_command_passes_progress(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sbom_dir = tmp_path / "sboms"
    make_sbom_file(sbom_dir, "repo-a")
    vuln_dir = tmp_path / "vulns"

    monkeypatch.setattr("miner.cli.get_grype_version", Mock(return_value="0.87.0"))
    scan_mock = Mock(return_value=make_vuln(status="scanned", total=1))
    monkeypatch.setattr("miner.cli.scan_vulnerabilities", scan_mock)

    result = runner.invoke(
        app,
        [
            "vuln",
            "--sbom-dir", str(sbom_dir),
            "--vuln-dir", str(vuln_dir),
            "--progress",
        ],
    )

    assert result.exit_code == 0
    progress = scan_mock.call_args.kwargs["progress"]
    assert isinstance(progress, VulnProgress)
    assert progress.enabled is True
    assert progress.log_file == vuln_dir / "errores.log"


def test_vuln_command_no_progress_writes_error_log(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sbom_dir = tmp_path / "sboms"
    make_sbom_file(sbom_dir, "repo-a")
    vuln_dir = tmp_path / "vulns"

    def failing_scan(source, output, grype_version, progress=None):
        progress.info("linea de avance")
        progress.error("fallo en vuln")
        return make_vuln(status="failed", total=0)

    monkeypatch.setattr("miner.cli.get_grype_version", Mock(return_value="0.87.0"))
    scan_mock = Mock(side_effect=failing_scan)
    monkeypatch.setattr("miner.cli.scan_vulnerabilities", scan_mock)

    result = runner.invoke(
        app,
        [
            "vuln",
            "--sbom-dir", str(sbom_dir),
            "--vuln-dir", str(vuln_dir),
            "--no-progress",
        ],
    )

    assert result.exit_code == 0
    progress = scan_mock.call_args.kwargs["progress"]
    assert progress.enabled is False
    assert "linea de avance" not in result.output
    log = vuln_dir / "errores.log"
    assert log.exists()
    assert "fallo en vuln" in log.read_text(encoding="utf-8")
