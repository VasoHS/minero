import subprocess
import pytest
from typer.testing import CliRunner

from miner.cli import app
from miner.reporter import collector, report as report_mod

runner = CliRunner()


@pytest.fixture(autouse=True)
def sin_herramientas(monkeypatch):
    """Evita depender de Syft/Grype en las pruebas."""
    monkeypatch.setattr(collector, "scan_dependencies",
                        lambda root: ([], "omitido: prueba"))


def test_detecta_secreto_sin_guardar_el_valor(tmp_path):
    (tmp_path / "app.py").write_text("k = 'AKIAABCDEFGHIJKLMNOP'\n")
    f = collector.scan_secrets(tmp_path)
    assert len(f) == 1
    assert f[0].file == "app.py" and f[0].line == 1
    assert "AKIA" not in f[0].evidence


def test_workflow_sin_permissions_y_accion_sin_sha(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n")
    found = collector.scan_workflows(tmp_path)
    text = " ".join(f"{f.rule} {f.evidence}" for f in found)
    assert "permissions" in text
    assert "SHA" in text
    assert len(found) == 2

def test_dockerfile_sin_user_y_curl_sh(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:latest\nRUN curl -sSf https://x.sh | sh\n")
    rules = " ".join(f.rule for f in collector.scan_docker(tmp_path))
    assert "root" in rules and "latest" in rules and "remoto" in rules


def test_gitignore_sin_env(tmp_path):
    (tmp_path / ".gitignore").write_text("*.pyc\n")
    assert collector.scan_hygiene(tmp_path)[0].id == "HY-001"


def test_reporte_sin_llm(tmp_path):
    (tmp_path / "app.py").write_text("k = 'AKIAABCDEFGHIJKLMNOP'\n")
    out = report_mod.build_report(tmp_path, tmp_path / "r.md", use_llm=False)
    text = out.read_text(encoding="utf-8")
    assert "Cobertura del análisis" in text and "SEC-001" in text
    assert "AKIAABCDEFGHIJKLMNOP" not in text


def test_reporte_advierte_ids_inventados(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("k = 'AKIAABCDEFGHIJKLMNOP'\n")
    monkeypatch.setattr(report_mod, "ask", lambda s, u: "Problema grave [SEC-001] y [XXX-999].")
    text = report_mod.build_report(tmp_path, tmp_path / "r.md").read_text(encoding="utf-8")
    assert "XXX-999" in text and "Advertencia" in text


def test_cli_falla_sin_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    (tmp_path / "app.py").write_text("k = 'AKIAABCDEFGHIJKLMNOP'\n")
    res = runner.invoke(app, ["report", "--root", str(tmp_path),
                              "--output", str(tmp_path / "r.md")])
    assert res.exit_code == 1
    assert "OPENROUTER_API_KEY" in res.output


def test_cli_no_llm_funciona(tmp_path):
    res = runner.invoke(app, ["report", "--no-llm", "--root", str(tmp_path),
                              "--output", str(tmp_path / "r.md")])
    assert res.exit_code == 0
    assert (tmp_path / "r.md").exists()

def test_env_ignorado_por_git_no_se_escanea(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env").write_text("K=AKIAABCDEFGHIJKLMNOP\n")
    assert collector.scan_secrets(tmp_path) == []


def test_curl_sh_en_workflow(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "permissions:\n  contents: read\njobs:\n  a:\n    steps:\n"
        "      - run: curl -sSf https://x.sh | sh\n")
    rules = " ".join(f.rule for f in collector.scan_workflows(tmp_path))
    assert "remoto" in rules