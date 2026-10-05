"""Visualizer: tablero HTML autocontenido que consume el contrato del Analyzer.

El Visualizer no recalcula métricas: lee el documento JSON que produce el
Analyzer (``analysis/outputs/analyzer_output.json``, ``schema_version`` 1.1) y
genera un único archivo HTML con los datos y los assets embebidos, listo para
abrir sin conexión.
"""

from .build import build_visualizer, load_document, main
from .render import render_html

__all__ = ["build_visualizer", "load_document", "main", "render_html"]
