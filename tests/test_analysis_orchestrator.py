"""Tests de la orquestación end-to-end (``analysis.orchestrator``).

Solo usan la librería estándar y ``pytest``. No ejecutan el Miner real ni
acceden a la red: ``run_command`` se prueba con comandos triviales de
``sys.executable`` y el resto son funciones puras sobre ``tmp_path``.
"""

import os
import sys

import pytest

from analysis.orchestrator import (
    SCAN_REPORT,
    SBOM_REPORT,
    VULN_REPORT,
    build_miner_command,
    existing_reports,
    github_token_present,
    run_command,
    should_run_miner,
)


def touch(root, name):
    """Crea un archivo vacío ``name`` dentro de ``root`` y lo devuelve."""
    path = root / name
    path.write_text("{}", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# existing_reports
# ---------------------------------------------------------------------------


def test_existing_reports_scan_gana_a_los_demas(tmp_path):
    scan = touch(tmp_path, SCAN_REPORT)
    touch(tmp_path, SBOM_REPORT)
    touch(tmp_path, VULN_REPORT)

    assert existing_reports(tmp_path) == [scan]


def test_existing_reports_devuelve_sbom_y_vuln_en_orden(tmp_path):
    sbom = touch(tmp_path, SBOM_REPORT)
    vuln = touch(tmp_path, VULN_REPORT)

    assert existing_reports(tmp_path) == [sbom, vuln]


def test_existing_reports_sin_reportes_es_vacio(tmp_path):
    assert existing_reports(tmp_path) == []


# ---------------------------------------------------------------------------
# should_run_miner
# ---------------------------------------------------------------------------


def test_should_run_miner_auto_sin_reportes(tmp_path):
    assert should_run_miner(tmp_path, "auto") is True


def test_should_run_miner_auto_con_reportes(tmp_path):
    touch(tmp_path, SCAN_REPORT)

    assert should_run_miner(tmp_path, "auto") is False


def test_should_run_miner_force_siempre(tmp_path):
    touch(tmp_path, SCAN_REPORT)

    assert should_run_miner(tmp_path, "force") is True


def test_should_run_miner_off_nunca(tmp_path):
    assert should_run_miner(tmp_path, "off") is False


def test_should_run_miner_modo_invalido(tmp_path):
    with pytest.raises(ValueError):
        should_run_miner(tmp_path, "desconocido")


# ---------------------------------------------------------------------------
# github_token_present
# ---------------------------------------------------------------------------


def test_github_token_present_con_token_inyectado():
    assert github_token_present({"GITHUB_TOKEN": "secreto"}) is True


def test_github_token_present_sin_token_inyectado():
    assert github_token_present({}) is False


def test_github_token_present_no_muta_el_entorno(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    assert github_token_present({"GITHUB_TOKEN": "secreto"}) is True
    # El diccionario inyectado no debe filtrarse a ``os.environ``.
    assert "GITHUB_TOKEN" not in os.environ


def test_github_token_present_lee_el_entorno_real(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "secreto")

    assert github_token_present() is True


# ---------------------------------------------------------------------------
# build_miner_command
# ---------------------------------------------------------------------------


def test_build_miner_command_caso_base(tmp_path):
    output = tmp_path / "results.json"

    command = build_miner_command(organization="acme", output=output)

    assert command == [
        sys.executable,
        "-m",
        "miner.cli",
        "scan",
        "--organization",
        "acme",
        "--output",
        str(output),
    ]


def test_build_miner_command_con_todas_las_opciones():
    command = build_miner_command(
        organization="acme",
        output="results.json",
        limit=5,
        sbom=False,
        vuln=False,
        repos_dir="repos",
        sbom_dir="sboms",
        vuln_dir="vulns",
        keep_repos=False,
    )

    assert command == [
        sys.executable,
        "-m",
        "miner.cli",
        "scan",
        "--organization",
        "acme",
        "--output",
        "results.json",
        "--limit",
        "5",
        "--no-sbom",
        "--no-vuln",
        "--repos-dir",
        "repos",
        "--sbom-dir",
        "sboms",
        "--vuln-dir",
        "vulns",
        "--cleanup-repos",
    ]


def test_build_miner_command_permite_python_override():
    command = build_miner_command(
        organization="acme", output="results.json", python="/opt/python"
    )

    assert command[0] == "/opt/python"


def test_build_miner_command_limit_cero_es_valido():
    command = build_miner_command(organization="acme", output="out.json", limit=0)

    assert "--limit" in command
    assert command[command.index("--limit") + 1] == "0"


def test_build_miner_command_organizacion_vacia():
    with pytest.raises(ValueError):
        build_miner_command(organization="", output="out.json")


def test_build_miner_command_organizacion_en_blanco():
    with pytest.raises(ValueError):
        build_miner_command(organization="   ", output="out.json")


def test_build_miner_command_limit_negativo():
    with pytest.raises(ValueError):
        build_miner_command(organization="acme", output="out.json", limit=-1)


# ---------------------------------------------------------------------------
# run_command
# ---------------------------------------------------------------------------


def test_run_command_devuelve_cero_y_reenvia_salida():
    lineas = []

    code = run_command(
        [sys.executable, "-c", "print('hola')"], echo=lineas.append
    )

    assert code == 0
    assert lineas == ["hola"]


def test_run_command_devuelve_codigo_de_error():
    code = run_command([sys.executable, "-c", "raise SystemExit(1)"])

    assert code == 1


def test_run_command_combina_stderr_en_la_salida():
    lineas = []
    script = "import sys; print('out'); print('err', file=sys.stderr)"

    code = run_command([sys.executable, "-c", script], echo=lineas.append)

    assert code == 0
    assert "out" in lineas
    assert "err" in lineas


def test_run_command_echo_none_no_imprime(capsys):
    code = run_command([sys.executable, "-c", "print('hola')"], echo=None)

    assert code == 0
    captured = capsys.readouterr()
    assert "hola" not in captured.out


def test_run_command_respeta_cwd(tmp_path):
    lineas = []

    code = run_command(
        [sys.executable, "-c", "import os; print(os.getcwd())"],
        cwd=tmp_path,
        echo=lineas.append,
    )

    assert code == 0
    assert lineas == [os.path.realpath(str(tmp_path))]
