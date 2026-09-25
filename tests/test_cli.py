import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from miner.cli import app, _cleanup, _inside, _is_safe_repo_name
from miner.models import Finding, SbomResult

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
    extra_args=None,
):
    """Ejecuta `scan` con todas las dependencias externas monkeypatcheadas."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "miner.cli.get_organization_repos", Mock(return_value=list(repos))
    )

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

    monkeypatch.setattr("miner.cli.clone_repository", clone_mock)
    monkeypatch.setattr("miner.cli.create_database", create_mock)
    monkeypatch.setattr("miner.cli.analyze_database", analyze_mock)
    monkeypatch.setattr("miner.cli.parse_sarif", parse_mock)
    monkeypatch.setattr("miner.cli.get_syft_version", syft_mock)
    monkeypatch.setattr("miner.cli.generate_sbom", generate_mock)

    out_path = Path(output) if output is not None else tmp_path / "out.json"
    args = ["scan", "--organization", "test-org", "--output", str(out_path)]
    if not sbom:
        args.append("--no-sbom")
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
