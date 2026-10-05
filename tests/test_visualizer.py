"""Tests del Visualizer: render, carga, build y CLI ``miner visualize``.

Solo usan stdlib + pytest: no hay red ni CodeQL real. El HTML se genera a partir
de documentos de ejemplo y, cuando aplica, se parsea el JSON embebido para
comprobar que el dato es recuperable.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from miner.cli import app
from miner.visualizer import (
    build_visualizer,
    load_document,
    main,
    render_html,
)
from miner.visualizer.render import ASSETS_DIR

runner = CliRunner()

#: Captura el contenido del bloque ``<script id="analyzer-data">``.
_EMBED_RE = re.compile(
    r'<script id="analyzer-data" type="application/json">(.*?)</script>',
    re.DOTALL,
)


def make_document():
    """Documento mínimo con la forma del Analyzer (schema_version 1.1)."""
    return {
        "schema_version": "1.1",
        "meta": {
            "organization": "acme",
            "generated_at": "2026-10-05T12:00:00+00:00",
        },
        "summary": {"repositories": 1, "vulnerabilities": 1},
        "datasets": {
            "repositories": [
                {
                    "repo": "alpha",
                    "url": "https://github.com/acme/alpha.git",
                    "status": "scanned",
                }
            ]
        },
    }


def leer_asset(nombre):
    return (ASSETS_DIR / nombre).read_text(encoding="utf-8")


def extraer_bloque_embebido(html):
    """Devuelve el contenido crudo del bloque ``analyzer-data``."""
    match = _EMBED_RE.search(html)
    assert match is not None, "no se encontró el bloque analyzer-data"
    return match.group(1)


def extraer_json_embebido(html):
    """Parsea el JSON del bloque ``analyzer-data`` embebido en el HTML."""
    return json.loads(extraer_bloque_embebido(html))


def sin_bloque_de_datos(html):
    """HTML sin el bloque ``analyzer-data`` (para comprobaciones de assets)."""
    match = _EMBED_RE.search(html)
    assert match is not None, "no se encontró el bloque analyzer-data"
    return html[: match.start()] + html[match.end():]


# ---------------------------------------------------------------------------
# render_html
# ---------------------------------------------------------------------------

def test_render_embebe_datos_css_y_js():
    documento = make_document()
    html = render_html(documento)

    assert 'id="analyzer-data"' in html
    assert 'type="application/json"' in html
    # El CSS y el JS del tablero viajan dentro del propio HTML.
    assert leer_asset("dashboard.css") in html
    assert leer_asset("dashboard.js") in html
    # El documento es recuperable desde el HTML generado.
    assert extraer_json_embebido(html) == documento


def test_titulo_por_defecto_usa_organizacion():
    html = render_html({"meta": {"organization": "acme"}})

    assert "<title>Visualizer · acme</title>" in html


def test_titulo_personalizado():
    html = render_html({"meta": {"organization": "acme"}}, title="Mi tablero")

    assert "<title>Mi tablero</title>" in html


def test_titulo_escapa_html():
    html = render_html({}, title='<b>"x" & y</b>')

    assert "&lt;b&gt;&quot;x&quot; &amp; y&lt;/b&gt;" in html
    # El título crudo no debe aparecer sin escapar.
    assert '<b>"x" & y</b>' not in html


def test_cadena_maliciosa_no_rompe_el_script():
    payload = "</script><script>alert(1)</script>"
    documento = {"meta": {"organization": "acme"}, "nota": payload}

    html = render_html(documento)

    # El cierre de <script> malicioso queda escapado (p. ej. \u003c) y no parte
    # el bloque.
    assert "</script><script>alert(1)" not in html
    recuperado = extraer_json_embebido(html)
    assert recuperado == documento
    assert recuperado["nota"] == payload


def test_payload_script_comment_no_inyecta_etiquetas():
    payload = "<!--<script>"
    documento = {"meta": {"organization": "acme"}, "nota": payload}

    html = render_html(documento)
    bloque = extraer_bloque_embebido(html)

    # El bloque de datos no contiene ninguna etiqueta <script literal: el payload
    # se neutraliza como \u003cscript\u003e.
    assert "<script" not in bloque
    assert "</script" not in bloque
    recuperado = extraer_json_embebido(html)
    assert recuperado == documento
    assert recuperado["nota"] == payload


def test_render_desde_ruta_equivale_a_dict(tmp_path):
    documento = make_document()
    ruta = tmp_path / "analyzer_output.json"
    ruta.write_text(json.dumps(documento), encoding="utf-8")

    esperado = render_html(documento)
    assert render_html(ruta) == esperado
    assert render_html(str(ruta)) == esperado


def test_render_typeerror_con_lista():
    with pytest.raises(TypeError):
        render_html([1, 2, 3])


@pytest.mark.parametrize(
    "documento",
    [{}, {"schema_version": "1.1"}],
)
def test_render_documentos_minimos_no_fallan(documento):
    html = render_html(documento)

    assert 'id="analyzer-data"' in html
    assert extraer_json_embebido(html) == documento


# ---------------------------------------------------------------------------
# load_document
# ---------------------------------------------------------------------------

def test_load_document_inexistente(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_document(tmp_path / "no-existe.json")


def test_load_document_json_invalido(tmp_path):
    ruta = tmp_path / "mal.json"
    ruta.write_text("{esto no es json", encoding="utf-8")

    with pytest.raises(ValueError):
        load_document(ruta)


def test_load_document_no_objeto(tmp_path):
    ruta = tmp_path / "lista.json"
    ruta.write_text("[1, 2, 3]", encoding="utf-8")

    with pytest.raises(ValueError):
        load_document(ruta)


def test_load_document_tolera_bom_utf8(tmp_path):
    documento = make_document()
    ruta = tmp_path / "con-bom.json"
    # ``utf-8-sig`` antepone el BOM al archivo.
    ruta.write_text(json.dumps(documento), encoding="utf-8-sig")

    assert load_document(ruta) == documento


# ---------------------------------------------------------------------------
# build_visualizer
# ---------------------------------------------------------------------------

def test_build_visualizer_crea_directorios_y_utf8(tmp_path):
    documento = make_document()
    documento["meta"]["organization"] = "café"
    entrada = tmp_path / "entrada" / "analyzer_output.json"
    entrada.parent.mkdir(parents=True)
    entrada.write_text(json.dumps(documento, ensure_ascii=False), encoding="utf-8")
    salida = tmp_path / "sub" / "dir" / "tablero.html"

    resultado = build_visualizer(entrada, salida)

    assert isinstance(resultado, Path)
    assert resultado == salida
    assert salida.exists()
    # El directorio padre se crea de forma recursiva.
    assert salida.parent.is_dir()
    contenido = salida.read_text(encoding="utf-8")
    assert "Visualizer · café" in contenido
    assert extraer_json_embebido(contenido)["meta"]["organization"] == "café"


def test_build_visualizer_es_determinista(tmp_path):
    documento = make_document()
    entrada = tmp_path / "doc.json"
    entrada.write_text(json.dumps(documento), encoding="utf-8")
    primera = tmp_path / "a.html"
    segunda = tmp_path / "b.html"

    build_visualizer(entrada, primera)
    build_visualizer(entrada, segunda)

    assert primera.read_text(encoding="utf-8") == segunda.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# main (CLI sin Typer)
# ---------------------------------------------------------------------------

def test_main_exito(tmp_path):
    entrada = tmp_path / "doc.json"
    entrada.write_text(json.dumps(make_document()), encoding="utf-8")
    salida = tmp_path / "out.html"

    codigo = main(["--input", str(entrada), "--output", str(salida)])

    assert codigo == 0
    assert salida.exists()


def test_main_entrada_inexistente(tmp_path):
    salida = tmp_path / "out.html"

    codigo = main(["--input", str(tmp_path / "no-existe.json"), "--output", str(salida)])

    assert codigo == 1
    assert not salida.exists()


def test_main_acepta_flags_cortas(tmp_path):
    entrada = tmp_path / "doc.json"
    entrada.write_text(json.dumps(make_document()), encoding="utf-8")
    salida = tmp_path / "out.html"

    assert main(["-i", str(entrada), "-o", str(salida)]) == 0
    assert salida.exists()

    faltante = tmp_path / "falta.html"
    assert main(["-i", str(tmp_path / "no-existe.json"), "-o", str(faltante)]) == 1
    assert not faltante.exists()


# ---------------------------------------------------------------------------
# CLI Typer: miner visualize
# ---------------------------------------------------------------------------

def test_cli_visualize_exito(tmp_path):
    entrada = tmp_path / "doc.json"
    entrada.write_text(json.dumps(make_document()), encoding="utf-8")
    salida = tmp_path / "out.html"

    resultado = runner.invoke(
        app,
        ["visualize", "--input", str(entrada), "--output", str(salida)],
    )

    assert resultado.exit_code == 0
    assert salida.exists()


def test_cli_visualize_fallo_entrada_inexistente(tmp_path):
    salida = tmp_path / "out.html"
    inexistente = tmp_path / "no-existe.json"

    resultado = runner.invoke(
        app,
        ["visualize", "--input", str(inexistente), "--output", str(salida)],
    )

    assert resultado.exit_code == 1
    assert not salida.exists()
    assert "No existe el documento de entrada" in resultado.output
    assert str(inexistente) in resultado.output


def test_cli_visualize_fallo_json_invalido(tmp_path):
    entrada = tmp_path / "mal.json"
    entrada.write_text("{esto no es json", encoding="utf-8")
    salida = tmp_path / "out.html"

    resultado = runner.invoke(
        app,
        ["visualize", "--input", str(entrada), "--output", str(salida)],
    )

    assert resultado.exit_code == 1
    assert not salida.exists()


def test_cli_visualize_fallo_no_objeto(tmp_path):
    entrada = tmp_path / "lista.json"
    entrada.write_text("[1, 2, 3]", encoding="utf-8")
    salida = tmp_path / "out.html"

    resultado = runner.invoke(
        app,
        ["visualize", "--input", str(entrada), "--output", str(salida)],
    )

    assert resultado.exit_code == 1
    assert not salida.exists()


def test_modulo_ejecutable_python_m(tmp_path):
    entrada = tmp_path / "doc.json"
    entrada.write_text(json.dumps(make_document()), encoding="utf-8")
    salida = tmp_path / "out.html"

    env = dict(os.environ)
    raiz = Path(__file__).resolve().parents[1]
    env["PYTHONPATH"] = os.pathsep.join(
        [str(raiz / "src"), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)

    proceso = subprocess.run(
        [
            sys.executable, "-m", "miner.visualizer",
            "--input", str(entrada),
            "--output", str(salida),
        ],
        capture_output=True,
        text=True,
        env=env,
    )

    assert proceso.returncode == 0, proceso.stderr
    assert salida.exists()
    assert extraer_json_embebido(salida.read_text(encoding="utf-8")) == make_document()


# ---------------------------------------------------------------------------
# Autocontenido / offline
# ---------------------------------------------------------------------------

def test_html_es_offline_aunque_el_documento_tenga_urls():
    documento = make_document()
    html = render_html(documento)

    # Se inspecciona el HTML sin el bloque JSON de datos: el documento sí puede
    # contener URLs legítimas sin convertirse en recursos remotos.
    sin_datos = sin_bloque_de_datos(html)
    assert 'src="http' not in sin_datos
    assert 'href="http' not in sin_datos
    assert "@import url(http" not in sin_datos
    assert "fetch(" not in sin_datos
    # El documento de datos conserva su URL.
    assert "https://github.com/acme/alpha.git" in html


def test_offline_no_da_falso_positivo_con_datos_que_parecen_recursos():
    # Subcadenas que, si se inspeccionara el bloque JSON, darían un falso fallo.
    documento = {
        "meta": {"organization": "acme"},
        "nota": 'fetch("http://evil") y @import url(http://evil)',
    }
    html = render_html(documento)

    sin_datos = sin_bloque_de_datos(html)
    assert 'src="http' not in sin_datos
    assert 'href="http' not in sin_datos
    assert "@import url(http" not in sin_datos
    assert "fetch(" not in sin_datos
    # El dato sigue íntegro dentro del bloque embebido.
    assert extraer_json_embebido(html) == documento
