#!/usr/bin/env python
"""Ejecuta los notebooks del Analyzer en orden con nbclient.

Uso:
    .venv/bin/python notebooks/execute.py

- Ejecuta todos los ``notebooks/*.ipynb`` en orden alfabético (01, 02, 03, 04).
- Usa el kernel ``python3`` y fija el directorio de trabajo en la raíz del repo.
- Devuelve un código de salida distinto de 0 si algún notebook falla.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import nbformat
from nbclient import NotebookClient
from nbclient.exceptions import CellExecutionError


def find_repo_root(start: Path) -> Path:
    """Sube desde ``start`` hasta encontrar ``pyproject.toml``."""
    for candidate in (start, *start.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return start


def main() -> int:
    notebooks_dir = Path(__file__).resolve().parent
    repo_root = find_repo_root(notebooks_dir)
    notebooks = sorted(notebooks_dir.glob("*.ipynb"))

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
