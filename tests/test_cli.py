import json
import shutil
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from miner.cli import app, _cleanup, _inside, _is_safe_repo_name
from miner.models import Finding

runner = CliRunner()


def make_repo(name, language="python", clone_url=None):
    return {
        "name": name,
        "clone_url": clone_url or f"https://github.com/test-org/{name}.git",
        "language": language,
    }


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

    monkeypatch.setattr("miner.cli.clone_repository", clone_mock)
    monkeypatch.setattr("miner.cli.create_database", create_mock)
    monkeypatch.setattr("miner.cli.analyze_database", analyze_mock)
    monkeypatch.setattr("miner.cli.parse_sarif", parse_mock)

    out_path = Path(output) if output is not None else tmp_path / "out.json"
    result = runner.invoke(
        app, ["scan", "--organization", "test-org", "--output", str(out_path)]
    )

    return result, out_path, clone_mock, create_mock, analyze_mock, parse_mock


@pytest.mark.parametrize("language", [None, "cobol"])
def test_scan_unsupported_language(tmp_path, monkeypatch, language):
    result, out, clone_mock, create_mock, analyze_mock, parse_mock = run_scan(
        tmp_path, [make_repo("repo-a", language=language)], monkeypatch
    )

    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["repositories"][0]["status"] == "unsupported"
    assert data["summary"]["unsupported"] == 1
    assert data["summary"]["failed"] == 0
    assert data["summary"]["analyzed"] == 0
    # El lenguaje se valida antes de clonar.
    clone_mock.assert_not_called()
    create_mock.assert_not_called()
    analyze_mock.assert_not_called()
    parse_mock.assert_not_called()


def test_scan_clone_failed(tmp_path, monkeypatch):
    result, out, clone_mock, create_mock, analyze_mock, _ = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, clone=False
    )

    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["repositories"][0]["status"] == "clone_failed"
    assert data["summary"]["failed"] == 1
    clone_mock.assert_called_once()
    create_mock.assert_not_called()
    analyze_mock.assert_not_called()


def test_scan_db_failed(tmp_path, monkeypatch):
    result, out, clone_mock, create_mock, analyze_mock, _ = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, create=False
    )

    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["repositories"][0]["status"] == "db_failed"
    assert data["summary"]["failed"] == 1
    clone_mock.assert_called_once()
    create_mock.assert_called_once()
    analyze_mock.assert_not_called()


def test_scan_analyze_failed(tmp_path, monkeypatch):
    result, out, clone_mock, create_mock, analyze_mock, _ = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, analyze=False
    )

    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["repositories"][0]["status"] == "analyze_failed"
    assert data["summary"]["failed"] == 1
    clone_mock.assert_called_once()
    create_mock.assert_called_once()
    analyze_mock.assert_called_once()


def test_scan_analyzed_success(tmp_path, monkeypatch):
    finding = Finding(
        rule_id="py/sql-injection",
        severity="error",
        message="Potential SQL injection",
        file="app/db.py",
        start_line=42,
    )
    result, out, clone_mock, create_mock, analyze_mock, parse_mock = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, findings=[finding]
    )

    assert result.exit_code == 0
    data = json.loads(out.read_text())
    repo_result = data["repositories"][0]
    assert repo_result["status"] == "analyzed"
    assert data["summary"]["analyzed"] == 1
    assert data["summary"]["findings"] == 1
    assert data["summary"]["failed"] == 0
    assert repo_result["languages"] == ["python"]
    assert repo_result["findings"][0]["rule_id"] == "py/sql-injection"
    assert repo_result["findings"][0]["start_line"] == 42
    parse_mock.assert_called_once()
    assert (
        Path(parse_mock.call_args.args[0]).resolve()
        == (tmp_path / "workdir" / "repo-a.sarif").resolve()
    )


def test_scan_invalid_name_rejected(tmp_path, monkeypatch):
    deleted_paths = []
    real_rmtree = shutil.rmtree

    def spy_rmtree(path, *args, **kwargs):
        deleted_paths.append(Path(path).resolve())
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr("miner.cli.shutil.rmtree", spy_rmtree)

    result, out, clone_mock, create_mock, _, _ = run_scan(
        tmp_path, [make_repo("../evil")], monkeypatch
    )

    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["repositories"][0]["status"] == "invalid_name"
    assert data["summary"]["failed"] == 1
    assert data["summary"]["analyzed"] == 0
    clone_mock.assert_not_called()
    create_mock.assert_not_called()
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
        result, out, clone_mock, _, _, _ = run_scan(
            tmp_path, [make_repo(f"../../{victim.name}")], monkeypatch
        )

        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["repositories"][0]["status"] == "invalid_name"
        assert data["summary"]["failed"] == 1
        clone_mock.assert_not_called()
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

    result, out, clone_mock, _, _, _ = run_scan(
        tmp_path,
        [make_repo("repo-a")],
        monkeypatch,
        clone_side_effect=fake_clone,
    )

    assert result.exit_code == 0
    # El clonado recibe un destino limpio (los restos se borraron antes).
    assert observed["dest_existed_at_clone"] is False
    data = json.loads(out.read_text())
    assert data["repositories"][0]["status"] == "analyzed"
    # Los temporales se eliminan al terminar.
    assert not repo_dir.exists()
    assert not db_dir.exists()
    assert not sarif_file.exists()


def test_scan_summary_counts_all_repositories(tmp_path, monkeypatch):
    repos = [
        make_repo("repo-a"),
        make_repo("repo-b", language=None),
        make_repo("repo-c", language="cobol"),
    ]
    result, out, _, _, _, _ = run_scan(tmp_path, repos, monkeypatch)

    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["summary"]["repositories"] == 3
    assert len(data["repositories"]) == 3
    assert data["summary"]["analyzed"] == 1
    assert data["summary"]["unsupported"] == 2
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
    result, out_path, _, _, _, _ = run_scan(
        tmp_path, [make_repo("repo-a")], monkeypatch, output=out
    )

    assert result.exit_code == 0
    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert data["organization"] == "test-org"
    assert data["summary"]["analyzed"] == 1
