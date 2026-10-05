import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from miner.codeql_runner import (
    DEFAULT_QUERY_SUITE,
    MAX_THREADS,
    _MAX_ERROR_CHARS,
    _describe_error,
    analyze_database,
    create_database,
    get_codeql_version,
)


# ---------------------------------------------------------------------------
# get_codeql_version
# ---------------------------------------------------------------------------

def test_get_codeql_version_json():
    completed = SimpleNamespace(stdout=json.dumps({"version": "2.20.0"}))
    with patch("miner.codeql_runner.subprocess.run", return_value=completed):
        assert get_codeql_version() == "2.20.0"


def test_get_codeql_version_text_fallback():
    completed = [
        SimpleNamespace(stdout="no es json"),
        SimpleNamespace(
            stdout="CodeQL command-line toolchain release 2.18.4.\nCopyright ..."
        ),
    ]
    with patch("miner.codeql_runner.subprocess.run", side_effect=completed):
        assert get_codeql_version() == "2.18.4"


def test_get_codeql_version_missing_binary():
    with patch("miner.codeql_runner.subprocess.run", side_effect=FileNotFoundError):
        assert get_codeql_version() is None


def test_get_codeql_version_json_without_version_falls_back_to_text():
    # JSON válido pero sin la clave "version": se usa el respaldo de texto.
    completed = [
        SimpleNamespace(stdout=json.dumps({"foo": "bar"})),
        SimpleNamespace(stdout="CodeQL command-line toolchain release 2.19.1."),
    ]
    with patch("miner.codeql_runner.subprocess.run", side_effect=completed):
        assert get_codeql_version() == "2.19.1"


def test_get_codeql_version_json_not_object_falls_back_to_text():
    # La salida JSON no es un objeto: se ignora y se prueba el respaldo.
    completed = [
        SimpleNamespace(stdout=json.dumps(["2.20.0"])),
        SimpleNamespace(stdout="release 2.20.0"),
    ]
    with patch("miner.codeql_runner.subprocess.run", side_effect=completed):
        assert get_codeql_version() == "2.20.0"


def test_get_codeql_version_json_command_fails_uses_text_fallback():
    error = subprocess.CalledProcessError(returncode=1, cmd="codeql version")
    completed = [error, SimpleNamespace(stdout="release 2.17.6")]
    with patch("miner.codeql_runner.subprocess.run", side_effect=completed):
        assert get_codeql_version() == "2.17.6"


def test_get_codeql_version_text_without_release_returns_none():
    completed = [
        SimpleNamespace(stdout="no es json"),
        SimpleNamespace(stdout="salida sin version reconocible"),
    ]
    with patch("miner.codeql_runner.subprocess.run", side_effect=completed):
        assert get_codeql_version() is None


# ---------------------------------------------------------------------------
# _describe_error
# ---------------------------------------------------------------------------

def test_describe_error_file_not_found():
    assert _describe_error(FileNotFoundError()) == (
        "no se encontró el ejecutable 'codeql' en el PATH"
    )


def test_describe_error_called_process_without_detail():
    error = subprocess.CalledProcessError(returncode=3, cmd="codeql")
    assert _describe_error(error) == "código de salida 3"


def test_describe_error_normalizes_stderr():
    error = subprocess.CalledProcessError(
        returncode=2, cmd="codeql", stderr="  boom\nsegunda   linea  "
    )
    assert _describe_error(error) == "código de salida 2: boom segunda linea"


def test_describe_error_truncates_long_detail():
    error = subprocess.CalledProcessError(
        returncode=1, cmd="codeql", stderr="x" * (_MAX_ERROR_CHARS + 100)
    )
    prefix = "código de salida 1: "
    message = _describe_error(error)
    assert message.startswith(prefix)
    detail = message[len(prefix):]
    assert detail.endswith("...")
    assert len(detail) == _MAX_ERROR_CHARS + 3


# ---------------------------------------------------------------------------
# create_database
# ---------------------------------------------------------------------------

def test_create_database_success_uses_build_mode_none(tmp_path):
    source_dir = tmp_path / "src"
    db_dir = tmp_path / "db"
    with patch("miner.codeql_runner.subprocess.run") as mock_run:
        result = create_database(source_dir, db_dir, "python")

    assert result is True
    mock_run.assert_called_once()

    cmd = mock_run.call_args.args[0]
    assert cmd[0:3] == ["codeql", "database", "create"]
    assert cmd[3] == str(db_dir)
    assert cmd[cmd.index("--language=python")] == "--language=python"
    assert f"--source-root={source_dir}" in cmd
    assert f"--threads={MAX_THREADS}" in cmd
    assert "--build-mode=none" in cmd
    assert "--overwrite" in cmd
    assert mock_run.call_args.kwargs["check"] is True


def test_create_database_compiled_language_uses_build_mode_none(tmp_path):
    with patch("miner.codeql_runner.subprocess.run") as mock_run:
        result = create_database(tmp_path / "src", tmp_path / "db", "cpp")

    assert result is True
    cmd = mock_run.call_args.args[0]
    assert "--language=cpp" in cmd
    assert "--build-mode=none" in cmd


def test_create_database_go_uses_default_build_mode(tmp_path):
    with patch("miner.codeql_runner.subprocess.run") as mock_run:
        result = create_database(tmp_path / "src", tmp_path / "db", "go")

    assert result is True
    cmd = mock_run.call_args.args[0]
    assert "--language=go" in cmd
    # Go no admite build-mode none: se usa el modo por defecto (autobuild).
    assert not any(arg.startswith("--build-mode") for arg in cmd)


def test_create_database_retries_without_build_mode(tmp_path):
    error = subprocess.CalledProcessError(returncode=1, cmd="codeql database create")
    with patch("miner.codeql_runner.subprocess.run",
               side_effect=[error, None]) as mock_run:
        result = create_database(tmp_path / "src", tmp_path / "db", "python")

    assert result is True
    assert mock_run.call_count == 2
    first_cmd = mock_run.call_args_list[0].args[0]
    second_cmd = mock_run.call_args_list[1].args[0]
    assert "--build-mode=none" in first_cmd
    assert not any(arg.startswith("--build-mode") for arg in second_cmd)
    # El tope de hilos se mantiene en ambos intentos.
    assert f"--threads={MAX_THREADS}" in first_cmd
    assert f"--threads={MAX_THREADS}" in second_cmd


def test_create_database_all_attempts_fail_records_errors(tmp_path):
    error = subprocess.CalledProcessError(
        returncode=2, cmd="codeql database create", stderr="extractor no disponible"
    )
    errors = []
    with patch("miner.codeql_runner.subprocess.run", side_effect=error):
        result = create_database(tmp_path / "src", tmp_path / "db", "python",
                                 errors=errors)

    assert result is False
    assert errors
    assert "extractor no disponible" in errors[0]


def test_create_database_unsupported_language(tmp_path):
    errors = []
    with patch("miner.codeql_runner.subprocess.run") as mock_run:
        result = create_database(tmp_path / "src", tmp_path / "db", "cobol",
                                 errors=errors)

    assert result is False
    mock_run.assert_not_called()
    assert "cobol" in errors[0]


def test_create_database_file_not_found(tmp_path):
    errors = []
    with patch("miner.codeql_runner.subprocess.run", side_effect=FileNotFoundError):
        result = create_database(tmp_path / "src", tmp_path / "db", "python",
                                 errors=errors)

    assert result is False
    assert "PATH" in errors[0]


def test_create_database_failure_without_errors_list(tmp_path):
    # Sin lista de errores no debe lanzar: solo devuelve False.
    with patch("miner.codeql_runner.subprocess.run", side_effect=FileNotFoundError):
        assert create_database(tmp_path / "src", tmp_path / "db", "python") is False


def test_create_database_resets_db_dir_between_attempts(tmp_path):
    error = subprocess.CalledProcessError(returncode=1, cmd="codeql")
    db_dir = tmp_path / "db"
    with patch("miner.codeql_runner.subprocess.run", side_effect=[error, None]), \
            patch("miner.codeql_runner.shutil.rmtree") as mock_rmtree:
        result = create_database(tmp_path / "src", db_dir, "python")

    assert result is True
    # Se limpia antes de cada intento (2), para evitar bases parciales.
    assert mock_rmtree.call_count == 2
    for call in mock_rmtree.call_args_list:
        assert call.args[0] == db_dir


def test_create_database_all_attempts_fail_cleans_partial_db(tmp_path):
    error = subprocess.CalledProcessError(returncode=1, cmd="codeql")
    db_dir = tmp_path / "db"
    with patch("miner.codeql_runner.subprocess.run", side_effect=error), \
            patch("miner.codeql_runner.shutil.rmtree") as mock_rmtree:
        result = create_database(tmp_path / "src", db_dir, "python")

    assert result is False
    # Un reset por intento (2) más la limpieza final.
    assert mock_rmtree.call_count == 3


def test_create_database_go_failure_uses_single_attempt(tmp_path):
    # Go no admite --build-mode=none: solo hay un intento (autobuild).
    error = subprocess.CalledProcessError(returncode=1, cmd="codeql")
    errors = []
    with patch("miner.codeql_runner.subprocess.run", side_effect=error) as mock_run:
        result = create_database(tmp_path / "src", tmp_path / "db", "go",
                                 errors=errors)

    assert result is False
    assert mock_run.call_count == 1
    assert len(errors) == 1
    assert "intento 1" in errors[0]


# ---------------------------------------------------------------------------
# analyze_database
# ---------------------------------------------------------------------------

def test_analyze_database_success(tmp_path):
    db_dir = tmp_path / "db"
    sarif_file = tmp_path / "out.sarif"
    with patch("miner.codeql_runner.subprocess.run") as mock_run:
        result = analyze_database(db_dir, sarif_file, "python")

    assert result is True
    mock_run.assert_called_once()

    cmd = mock_run.call_args.args[0]
    assert cmd[0:3] == ["codeql", "database", "analyze"]
    assert cmd[3] == str(db_dir)
    assert "codeql/python-queries:codeql-suites/python-security-extended.qls" in cmd
    assert "--download" in cmd
    assert "--format=sarif-latest" in cmd
    assert f"--output={sarif_file}" in cmd
    assert f"--threads={MAX_THREADS}" in cmd
    assert mock_run.call_args.kwargs["check"] is True


def test_analyze_database_custom_suite(tmp_path):
    with patch("miner.codeql_runner.subprocess.run") as mock_run:
        result = analyze_database(tmp_path / "db", tmp_path / "out.sarif",
                                  "javascript",
                                  query_suite="security-and-quality")

    assert result is True
    cmd = mock_run.call_args.args[0]
    assert ("codeql/javascript-queries:codeql-suites/"
            "javascript-security-and-quality.qls") in cmd


def test_analyze_database_falls_back_to_pack_default(tmp_path):
    error = subprocess.CalledProcessError(returncode=1, cmd="codeql database analyze")
    with patch("miner.codeql_runner.subprocess.run",
               side_effect=[error, None]) as mock_run:
        result = analyze_database(tmp_path / "db", tmp_path / "out.sarif", "python")

    assert result is True
    assert mock_run.call_count == 2
    first_spec = mock_run.call_args_list[0].args[0][4]
    second_spec = mock_run.call_args_list[1].args[0][4]
    assert first_spec.endswith("python-security-extended.qls")
    assert second_spec == "codeql/python-queries"
    # El tope de hilos se mantiene en ambos intentos.
    assert all(
        f"--threads={MAX_THREADS}" in call.args[0]
        for call in mock_run.call_args_list
    )


def test_analyze_database_unknown_language(tmp_path):
    errors = []
    with patch("miner.codeql_runner.subprocess.run") as mock_run:
        result = analyze_database(tmp_path / "db", tmp_path / "out.sarif",
                                  "cobol", errors=errors)

    assert result is False
    mock_run.assert_not_called()
    assert "cobol" in errors[0]


def test_analyze_database_unknown_suite(tmp_path):
    errors = []
    with patch("miner.codeql_runner.subprocess.run") as mock_run:
        result = analyze_database(tmp_path / "db", tmp_path / "out.sarif",
                                  "python", query_suite="no-existe", errors=errors)

    assert result is False
    mock_run.assert_not_called()
    assert "no-existe" in errors[0]


def test_analyze_database_called_process_error(tmp_path):
    errors = []
    error = subprocess.CalledProcessError(returncode=1, cmd="codeql database analyze")
    with patch("miner.codeql_runner.subprocess.run", side_effect=error):
        result = analyze_database(tmp_path / "db", tmp_path / "out.sarif",
                                  "python", errors=errors)

    assert result is False
    assert errors


def test_analyze_database_file_not_found(tmp_path):
    with patch("miner.codeql_runner.subprocess.run", side_effect=FileNotFoundError):
        result = analyze_database(tmp_path / "db", tmp_path / "out.sarif", "python")

    assert result is False


def test_analyze_database_failure_without_errors_list(tmp_path):
    # Sin lista de errores no debe lanzar: solo devuelve False.
    with patch("miner.codeql_runner.subprocess.run", side_effect=FileNotFoundError):
        assert analyze_database(tmp_path / "db", tmp_path / "out.sarif",
                                "python") is False


def test_analyze_database_oserror(tmp_path):
    errors = []
    with patch("miner.codeql_runner.subprocess.run", side_effect=OSError("boom")):
        result = analyze_database(tmp_path / "db", tmp_path / "out.sarif",
                                  "python", errors=errors)

    assert result is False
    assert errors


def test_analyze_database_all_attempts_fail_records_two_errors(tmp_path):
    error = subprocess.CalledProcessError(returncode=1, cmd="codeql database analyze")
    errors = []
    with patch("miner.codeql_runner.subprocess.run", side_effect=error):
        result = analyze_database(tmp_path / "db", tmp_path / "out.sarif",
                                  "python", errors=errors)

    assert result is False
    # Un error por la suite pedida y otro por el pack por defecto.
    assert len(errors) == 2


def test_analyze_database_custom_suite_falls_back_to_pack_default(tmp_path):
    error = subprocess.CalledProcessError(returncode=1, cmd="codeql database analyze")
    with patch("miner.codeql_runner.subprocess.run",
               side_effect=[error, None]) as mock_run:
        result = analyze_database(tmp_path / "db", tmp_path / "out.sarif",
                                  "javascript", query_suite="code-scanning")

    assert result is True
    assert mock_run.call_count == 2
    first_spec = mock_run.call_args_list[0].args[0][4]
    second_spec = mock_run.call_args_list[1].args[0][4]
    assert first_spec.endswith("javascript-code-scanning.qls")
    assert second_spec == "codeql/javascript-queries"


def test_create_database_rejects_db_dir_equal_to_source(tmp_path):
    errors = []
    with patch("miner.codeql_runner.subprocess.run") as mock_run:
        result = create_database(tmp_path, tmp_path, "python", errors=errors)

    assert result is False
    mock_run.assert_not_called()
    assert errors


def test_default_query_suite_is_security_extended():
    assert DEFAULT_QUERY_SUITE == "security-extended"


def test_max_threads_cap_is_eight():
    # El Miner limita las operaciones de CodeQL a 8 hilos.
    assert MAX_THREADS == 8
