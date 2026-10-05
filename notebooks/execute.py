#!/usr/bin/env python
"""Ejecuta notebooks con nbclient.

Uso:
    .venv/bin/python notebooks/execute.py            # solo el notebook maestro
    .venv/bin/python notebooks/execute.py --all      # 00-04 en orden
    .venv/bin/python notebooks/execute.py --notebook 02_analisis_vulnerabilidades

- Por defecto ejecuta solo ``00_pipeline_completo.ipynb`` (Miner opcional →
  Analyzer → Visualizer). Si no existe, ejecuta todos los ``*.ipynb``.
- ``--all`` ejecuta todos los notebooks en orden alfabético (00, 01, 02, 03, 04).
- ``--notebook`` ejecuta un único notebook (por nombre o por nombre sin extensión).
- Usa el kernel ``python3`` y fija el directorio de trabajo en la raíz del repo.
- Devuelve un código de salida distinto de 0 si algún notebook falla.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional, Sequence

import nbformat
from nbclient import NotebookClient
from nbclient.exceptions import CellExecutionError

#: Notebook maestro que orquesta todo el flujo.
MASTER_NOTEBOOK = "00_pipeline_completo.ipynb"


def find_repo_root(start: Path) -> Path:
    """Sube desde ``start`` hasta encontrar ``pyproject.toml``."""
    for candidate in (start, *start.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return start


def select_notebooks(
    notebooks_dir: Path,
    *,
    run_all: bool = False,
    only: Optional[str] = None,
) -> List[Path]:
    """Selecciona los notebooks a ejecutar.

    - ``only``: un único notebook, por nombre de archivo o sin extensión.
    - ``run_all``: todos los ``*.ipynb`` en orden alfabético.
    - por defecto: el maestro si existe; si no, todos.
    """
    available = sorted(notebooks_dir.glob("*.ipynb"))

    if only:
        wanted = only if only.endswith(".ipynb") else f"{only}.ipynb"
        matches = [path for path in available if path.name == wanted]
        if not matches:
            raise FileNotFoundError(
                f"No se encontró el notebook {only!r} en {notebooks_dir}"
            )
        return matches

    if run_all:
        return available

    master = notebooks_dir / MASTER_NOTEBOOK
    if master.is_file():
        return [master]
    return available


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--all", action="store_true",
        help="Ejecuta todos los notebooks en orden alfabético.",
    )
    parser.add_argument(
        "--notebook", default=None,
        help="Ejecuta un único notebook (por nombre o nombre sin extensión).",
    )
    args = parser.parse_args(argv)

    notebooks_dir = Path(__file__).resolve().parent
    repo_root = find_repo_root(notebooks_dir)

    try:
        notebooks = select_notebooks(
            notebooks_dir, run_all=args.all, only=args.notebook
        )
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if not notebooks:
        print(f"No se encontraron notebooks en {notebooks_dir}", file=sys.stderr)
        return 1

    # El kernelspec del venv invoca ``python`` sin ruta absoluta: aseguramos que
    # el intérprete del venv sea el primero del PATH para el proceso del kernel.
    venv_bin = str(Path(sys.executable).resolve().parent)
    os.environ["PATH"] = venv_bin + os.pathsep + os.environ.get("PATH", "")

    print(f"Raíz del repo: {repo_root}")
    print(f"Intérprete   : {sys.executable}")

    for notebook_path in notebooks:
        print(f"\n=== Ejecutando {notebook_path.name} ===", flush=True)
        notebook = nbformat.read(notebook_path, as_version=4)
        client = NotebookClient(
            notebook,
            timeout=600,
            kernel_name="python3",
            resources={"metadata": {"path": str(repo_root)}},
            allow_errors=False,
        )
        try:
            client.execute()
        except CellExecutionError as exc:
            print(
                f"\nERROR ejecutando {notebook_path.name}:\n{exc}",
                file=sys.stderr,
            )
            return 1
        print(f"OK: {notebook_path.name}")

    print("\nTodos los notebooks se ejecutaron correctamente.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
