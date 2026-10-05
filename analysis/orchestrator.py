"""Orquestación end-to-end: Miner (opcional) → Analyzer → Visualizer.

Este módulo concentra la lógica del **notebook maestro**
(``notebooks/00_pipeline_completo.ipynb``) para que sea testeable y
reproducible, en línea con el resto del Analyzer:

- decide si hay que ejecutar el Miner o si basta con reutilizar reportes;
- construye el comando ``miner scan`` (invocado por ``subprocess``);
- ejecuta el comando mostrando su salida en vivo.

Solo usa la librería estándar. Nunca lee ni imprime el token: solo comprueba su
presencia en el entorno.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Union

__all__ = [
    "MINER_MODES",
    "SCAN_REPORT",
    "SBOM_REPORT",
    "VULN_REPORT",
    "existing_reports",
    "should_run_miner",
    "github_token_present",
    "build_miner_command",
    "run_command",
]

PathLike = Union[str, Path]

#: Modos de ejecución del Miner.
#: - ``auto``: reutiliza reportes si existen; si no, ejecuta el Miner.
#: - ``force``: ejecuta siempre el Miner.
#: - ``off``: nunca ejecuta el Miner (exige reportes existentes).
MINER_MODES = ("auto", "force", "off")

SCAN_REPORT = "results.json"
SBOM_REPORT = "results-sbom.json"
VULN_REPORT = "results-vuln.json"


def existing_reports(repo_root: PathLike) -> List[Path]:
    """Reportes del Miner disponibles en la raíz del repositorio.

    Si existe ``results.json`` (``scan``) se devuelve solo ese; en caso
    contrario, los que existan de ``results-sbom.json`` y ``results-vuln.json``
    (en ese orden), tal como hacen los notebooks del Analyzer.
    """
    root = Path(repo_root)
    scan = root / SCAN_REPORT
    if scan.is_file():
        return [scan]
    candidates = [root / SBOM_REPORT, root / VULN_REPORT]
    return [path for path in candidates if path.is_file()]


def should_run_miner(repo_root: PathLike, mode: str = "auto") -> bool:
    """Decide si hay que ejecutar el Miner según ``mode``.

    Lanza ``ValueError`` si el modo no pertenece a :data:`MINER_MODES`.
    """
    if mode not in MINER_MODES:
        raise ValueError(
            f"Modo del Miner no válido: {mode!r}. Opciones: {', '.join(MINER_MODES)}."
        )
    if mode == "force":
        return True
    if mode == "off":
        return False
    return not existing_reports(repo_root)


def github_token_present(env: Optional[Dict[str, str]] = None) -> bool:
    """``True`` si ``GITHUB_TOKEN`` está definido. Nunca devuelve su valor."""
    source = os.environ if env is None else env
    return bool(source.get("GITHUB_TOKEN"))


def build_miner_command(
    *,
    organization: str,
    output: PathLike,
    limit: Optional[int] = None,
    sbom: bool = True,
    vuln: bool = True,
    repos_dir: Optional[PathLike] = None,
    sbom_dir: Optional[PathLike] = None,
    vuln_dir: Optional[PathLike] = None,
    keep_repos: bool = True,
    python: Optional[PathLike] = None,
) -> List[str]:
    """Construye el comando ``miner scan`` para ejecutarlo por ``subprocess``.

    Se invoca ``python -m miner.cli`` (en vez del script ``miner``) para no
    depender de que el ejecutable esté en el ``PATH``. Lanza ``ValueError`` si
    ``organization`` está vacío o ``limit`` es negativo.
    """
    if not organization or not str(organization).strip():
        raise ValueError("Se requiere una organización para ejecutar el Miner.")
    if limit is not None and limit < 0:
        raise ValueError("El límite de repositorios (--limit) no puede ser negativo.")

    interpreter = str(python) if python is not None else sys.executable
    command = [
        interpreter,
        "-m",
        "miner.cli",
        "scan",
        "--organization",
        str(organization),
        "--output",
        str(output),
    ]
    if limit is not None:
        command += ["--limit", str(limit)]
    if not sbom:
        command += ["--no-sbom"]
    if not vuln:
        command += ["--no-vuln"]
    if repos_dir is not None:
        command += ["--repos-dir", str(repos_dir)]
    if sbom_dir is not None:
        command += ["--sbom-dir", str(sbom_dir)]
    if vuln_dir is not None:
        command += ["--vuln-dir", str(vuln_dir)]
    if not keep_repos:
        command += ["--cleanup-repos"]
    return command


def run_command(
    command: Sequence[PathLike],
    *,
    cwd: Optional[PathLike] = None,
    env: Optional[Dict[str, str]] = None,
    echo: Optional[Callable[[str], None]] = print,
) -> int:
    """Ejecuta ``command`` mostrando su salida en vivo y devuelve el código.

    ``echo`` recibe cada línea de salida (stdout y stderr combinados); usa
    ``None`` para silenciarla. El entorno se hereda si ``env`` es ``None``, de
    modo que ``GITHUB_TOKEN`` sigue disponible sin exponerlo.
    """
    process = subprocess.Popen(
        [str(part) for part in command],
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    if process.stdout is not None:
        for line in process.stdout:
            if echo is not None:
                echo(line.rstrip("\n"))
    return process.wait()
