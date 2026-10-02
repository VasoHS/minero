import typer
from unittest.mock import patch

import pytest

from miner.progress import VulnProgress


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

def test_info_enabled_prints_without_label():
    progress = VulnProgress(enabled=True)
    with patch("miner.progress.typer.echo") as mock_echo:
        progress.info("avanzando")

    mock_echo.assert_called_once_with("  avanzando")


def test_info_with_label_prefixes_message():
    progress = VulnProgress(enabled=True)
    progress.set_label("repo-a")
    with patch("miner.progress.typer.echo") as mock_echo:
        progress.info("avanzando")

    mock_echo.assert_called_once_with("  [repo-a] avanzando")


def test_info_disabled_does_not_print():
    progress = VulnProgress(enabled=False)
    progress.set_label("repo-a")
    with patch("miner.progress.typer.echo") as mock_echo:
        progress.info("no se debe ver")

    mock_echo.assert_not_called()


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

def test_error_enabled_registers_and_prints_red_prefix(tmp_path):
    progress = VulnProgress(log_file=tmp_path / "errores.log", enabled=True)
    with patch("miner.progress.typer.secho") as mock_secho:
        progress.error("boom")

    assert progress.errors == ["boom"]
    mock_secho.assert_called_once()
    args, kwargs = mock_secho.call_args
    assert args[0] == "  ERROR: boom"
    assert kwargs["fg"] == typer.colors.RED


def test_error_with_label_and_prefix_false_keeps_message_clean(tmp_path):
    progress = VulnProgress(log_file=tmp_path / "errores.log", enabled=True)
    progress.set_label("repo-b")
    with patch("miner.progress.typer.secho") as mock_secho:
        progress.error("warning de grype", prefix=False)

    args, _ = mock_secho.call_args
    assert args[0] == "  [repo-b] warning de grype"


def test_error_disabled_still_registers_and_writes_log(tmp_path):
    log = tmp_path / "errores.log"
    progress = VulnProgress(log_file=log, enabled=False)
    with patch("miner.progress.typer.secho") as mock_secho:
        progress.error("fallo silencioso")

    mock_secho.assert_not_called()
    assert progress.errors == ["fallo silencioso"]
    assert "fallo silencioso" in log.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# line / clasificación
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "line",
    [
        "error: no se pudo conectar",
        "FATAL something broke",
        "panic: runtime error",
        "WARNING: base de datos desactualizada",
        "operation failed",
    ],
)
def test_line_error_like_is_registered(tmp_path, line):
    progress = VulnProgress(log_file=tmp_path / "errores.log", enabled=False)
    with patch("miner.progress.typer.secho") as mock_secho:
        progress.line(line)

    assert progress.errors == [line]
    mock_secho.assert_not_called()


@pytest.mark.parametrize(
    "line",
    [
        "scanning image",
        "found 3 vulnerabilities",
        "complete",
    ],
)
def test_line_normal_is_shown_as_info(tmp_path, line):
    progress = VulnProgress(log_file=tmp_path / "errores.log", enabled=True)
    with patch("miner.progress.typer.echo") as mock_echo:
        progress.line(line)

    assert progress.errors == []
    mock_echo.assert_called_once_with(f"  {line}")


@pytest.mark.parametrize(
    "line,expected",
    [
        ("error", True),
        ("ERROR", True),
        ("errors", True),
        ("fatal", True),
        ("panic", True),
        ("warning", True),
        ("warnings", True),
        ("warn", True),
        ("failed", True),
        ("failure", True),
        ("failures", True),
        ("Failed to do X", True),
        ("scanning...", False),
        ("found 3 vulnerabilities", False),
        ("complete", False),
        ("", False),
    ],
)
def test_looks_like_error(line, expected):
    assert VulnProgress._looks_like_error(line) is expected


# ---------------------------------------------------------------------------
# archivo de log
# ---------------------------------------------------------------------------

def test_log_file_is_created_and_truncated_on_init(tmp_path):
    log = tmp_path / "nested" / "errores.log"
    log.parent.mkdir(parents=True)
    log.write_text("contenido previo\n", encoding="utf-8")

    progress = VulnProgress(log_file=log)

    assert progress.log_file == log
    assert log.exists()
    assert log.read_text(encoding="utf-8") == ""


def test_log_file_creates_missing_parent_directories(tmp_path):
    log = tmp_path / "a" / "b" / "errores.log"

    progress = VulnProgress(log_file=log)

    assert progress.log_file == log
    assert log.parent.is_dir()
    assert log.read_text(encoding="utf-8") == ""


def test_error_appends_timestamped_lines(tmp_path):
    log = tmp_path / "errores.log"
    progress = VulnProgress(log_file=log, enabled=False)

    progress.error("primer fallo")
    progress.error("segundo fallo")

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert lines[0].endswith(" primer fallo")
    assert lines[1].endswith(" segundo fallo")
    # Cada línea empieza por un timestamp UTC en formato ISO.
    assert "T" in lines[0].split(" ", 1)[0]
    assert progress.errors == ["primer fallo", "segundo fallo"]


def test_log_file_none_does_not_write(tmp_path):
    progress = VulnProgress(log_file=None)

    progress.error("sin archivo de log")

    assert progress.log_file is None
    assert progress.errors == ["sin archivo de log"]


def test_log_file_oserror_leaves_log_file_none(tmp_path):
    blocker = tmp_path / "bloqueado"
    blocker.write_text("no soy un directorio", encoding="utf-8")

    progress = VulnProgress(log_file=blocker / "sub" / "errores.log")

    assert progress.log_file is None
    # Aun sin log, el error debe registrarse sin propagar la excepción.
    progress.error("aun asi se registra")
    assert progress.errors == ["aun asi se registra"]


def test_write_log_oserror_is_ignored(tmp_path):
    log = tmp_path / "errores.log"
    progress = VulnProgress(log_file=log, enabled=False)

    blocker = tmp_path / "bloqueado"
    blocker.write_text("no soy un directorio", encoding="utf-8")
    # Se fuerza una ruta no escribible después de una inicialización correcta.
    progress.log_file = blocker / "sub" / "errores.log"

    progress.error("no se puede escribir")

    assert progress.errors == ["no se puede escribir"]
