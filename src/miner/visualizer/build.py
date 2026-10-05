"""Generación y punto de entrada del Visualizer.

``build_visualizer`` lee el documento del Analyzer, renderiza el tablero y lo
escribe en disco. ``main`` ofrece una interfaz de línea de comandos equivalente
a ``miner visualize`` para usarla sin Typer (p. ej. desde scripts).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .render import render_html

__all__ = ["build_visualizer", "load_document", "main"]

PathLike = Union[str, Path]


def load_document(path: PathLike) -> Dict[str, Any]:
    """Carga y valida mínimamente el documento del Analyzer.

    Lanza ``FileNotFoundError`` si la ruta no existe, ``ValueError`` si no es
    JSON válido o no es un objeto, y ``UnicodeDecodeError`` si no es UTF-8.
    """
    source = Path(path)
    # ``utf-8-sig`` tolera el BOM que añaden algunos editores en Windows.
    text = source.read_text(encoding="utf-8-sig")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"El archivo {source} no es JSON válido: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"El archivo {source} no contiene un objeto JSON.")
    return data


def build_visualizer(
    input_path: PathLike,
    output_path: PathLike,
    *,
    title: Optional[str] = None,
) -> Path:
    """Genera el tablero HTML a partir del documento del Analyzer.

    Devuelve la ruta del HTML escrito. Crea el directorio padre si no existe.
    """
    document = load_document(input_path)
    html = render_html(document, title=title)

    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html, encoding="utf-8")
    return target


def main(argv: Optional[List[str]] = None) -> int:
    """CLI del Visualizer: ``python -m miner.visualizer`` o ``miner visualize``."""
    parser = argparse.ArgumentParser(
        prog="miner-visualize",
        description=(
            "Genera un tablero HTML autocontenido a partir del documento JSON "
            "del Analyzer."
        ),
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Documento JSON del Analyzer (analyzer_output.json).",
    )
    parser.add_argument(
        "-o", "--output", required=True,
        help="Archivo HTML de salida.",
    )
    parser.add_argument(
        "-t", "--title", default=None,
        help="Título del tablero (por defecto: 'Visualizer · <organización>').",
    )
    args = parser.parse_args(argv)

    if not Path(args.input).is_file():
        print(f"Error: no existe el documento de entrada: {args.input}")
        return 1

    try:
        target = build_visualizer(args.input, args.output, title=args.title)
    except (ValueError, OSError) as exc:
        print(f"Error al generar el Visualizer: {exc}")
        return 1

    print(f"Visualizer generado en {target}")
    return 0


if __name__ == "__main__":  # pragma: no cover - entrada manual.
    raise SystemExit(main())
