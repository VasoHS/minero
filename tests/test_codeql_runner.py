import subprocess
from unittest.mock import patch

from miner.codeql_runner import create_database, analyze_database


def test_create_database_success(tmp_path):
    source_dir = tmp_path / "src"
    db_dir = tmp_path / "db"
    with patch("miner.codeql_runner.subprocess.run") as mock_run:
        result = create_database(source_dir, db_dir, "python")

    assert result is True
    mock_run.assert_called_once()

    cmd = mock_run.call_args.args[0]
    assert cmd[0:3] == ["codeql", "database", "create"]
    assert cmd[3] == str(db_dir)
    assert cmd[cmd.index("--language") + 1] == "python"
    assert cmd[cmd.index("--source-root") + 1] == str(source_dir)
    assert mock_run.call_args.kwargs["check"] is True


def test_create_database_called_process_error(tmp_path):
    error = subprocess.CalledProcessError(returncode=1, cmd="codeql database create")
    with patch("miner.codeql_runner.subprocess.run", side_effect=error):
        result = create_database(tmp_path / "src", tmp_path / "db", "python")

    assert result is False


def test_create_database_file_not_found(tmp_path):
    with patch("miner.codeql_runner.subprocess.run", side_effect=FileNotFoundError):
        result = create_database(tmp_path / "src", tmp_path / "db", "python")

    assert result is False


def test_analyze_database_success(tmp_path):
    db_dir = tmp_path / "db"
    sarif_file = tmp_path / "out.sarif"
    with patch("miner.codeql_runner.subprocess.run") as mock_run:
        result = analyze_database(db_dir, sarif_file)

    assert result is True
    mock_run.assert_called_once()

    cmd = mock_run.call_args.args[0]
    assert cmd[0:3] == ["codeql", "database", "analyze"]
    assert cmd[3] == str(db_dir)
    assert "--format=sarif-latest" in cmd
    assert f"--output={sarif_file}" in cmd
    assert mock_run.call_args.kwargs["check"] is True


def test_analyze_database_called_process_error(tmp_path):
    error = subprocess.CalledProcessError(returncode=1, cmd="codeql database analyze")
    with patch("miner.codeql_runner.subprocess.run", side_effect=error):
        result = analyze_database(tmp_path / "db", tmp_path / "out.sarif")

    assert result is False


def test_analyze_database_file_not_found(tmp_path):
    with patch("miner.codeql_runner.subprocess.run", side_effect=FileNotFoundError):
        result = analyze_database(tmp_path / "db", tmp_path / "out.sarif")

    assert result is False
