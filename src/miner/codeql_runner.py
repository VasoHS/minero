"""Ejecución de CodeQL: creación de bases de datos y análisis con query packs.

El análisis de CodeQL requiere indicar explícitamente qué consultas ejecutar.
Se usan los paquetes estándar de GitHub ``codeql/<lenguaje>-queries`` y la
suite de seguridad extendida, con ``--download`` para obtener los packs desde
el registro si no están en la caché local.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

# Paquete estándar de consultas de GitHub por lenguaje de CodeQL.
QUERY_PACKS = {
    "python": "codeql/python-queries",
    "javascript": "codeql/javascript-queries",
    "java": "codeql/java-queries",
    "cpp": "codeql/cpp-queries",
    "csharp": "codeql/csharp-queries",
    "go": "codeql/go-queries",
    "ruby": "codeql/ruby-queries",
    "swift": "codeql/swift-queries",
    "rust": "codeql/rust-queries",
}

# Suites disponibles en cada paquete de consultas estándar.
QUERY_SUITES = ("security-extended", "security-and-quality", "code-scanning")
DEFAULT_QUERY_SUITE = "security-extended"

# Lenguajes para los que CodeQL admite crear la base sin compilar el proyecto.
# En el resto (Go, Swift) se usa el modo por defecto (autobuild).
_BUILD_MODE_NONE = {"python", "javascript", "java", "csharp", "cpp", "ruby", "rust"}

# Longitud máxima del detalle de error que se conserva para el reporte.
_MAX_ERROR_CHARS = 800

# Tope de hilos para las operaciones de CodeQL (la fase más pesada del Miner).
# Se pasa explícitamente con ``--threads`` para no saturar la máquina.
MAX_THREADS = 8


def get_codeql_version() -> Optional[str]:
    """Obtiene la versión de CodeQL instalada, o None si no está disponible."""
    try:
        result = subprocess.run(
            ["codeql", "version", "--format=json"],
            check=True, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
        data = json.loads(result.stdout)
        version = data.get("version") if isinstance(data, dict) else None
        if isinstance(version, str) and version:
            return version
    except (subprocess.CalledProcessError, FileNotFoundError, OSError,
            json.JSONDecodeError, TypeError, ValueError):
        pass

    # Respaldo para versiones antiguas que no admiten --format=json.
    try:
        result = subprocess.run(
            ["codeql", "version"],
            check=True, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None
    match = re.search(r"release\s+([0-9]+(?:\.[0-9]+)+)", result.stdout)
    return match.group(1) if match else None


def _describe_error(exc: BaseException) -> str:
    """Resume un fallo de subprocess incluyendo la salida de error de CodeQL."""
    if isinstance(exc, FileNotFoundError):
        return "no se encontró el ejecutable 'codeql' en el PATH"
    if isinstance(exc, subprocess.CalledProcessError):
        detail = (exc.stderr or exc.stdout or "").strip()
        if detail:
            detail = " ".join(detail.split())
            if len(detail) > _MAX_ERROR_CHARS:
                detail = detail[:_MAX_ERROR_CHARS] + "..."
            return f"código de salida {exc.returncode}: {detail}"
        return f"código de salida {exc.returncode}"
    return str(exc)


def _record(errors: Optional[List[str]], message: str) -> None:
    """Acumula el motivo de un fallo si el llamador pidió capturarlo."""
    if errors is not None:
        errors.append(message)


def _run_codeql(cmd: List[str]) -> None:
    subprocess.run(
        cmd, check=True, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )


def _reset_dir(db_dir: Path) -> None:
    """Elimina una base parcial para que CodeQL pueda recrearla."""
    shutil.rmtree(db_dir, ignore_errors=True)


def create_database(source_dir: Path, db_dir: Path, language: str,
                    errors: Optional[List[str]] = None) -> bool:
    """Crea una base de datos CodeQL para ``language``.

    Intenta primero sin compilar (``--build-mode none``) en los lenguajes que lo
    admiten y, si falla, reintenta con el modo por defecto (autobuild). Devuelve
    True si alguna estrategia tuvo éxito. Los motivos de fallo se acumulan en
    ``errors`` cuando se proporciona.
    """
    if language not in QUERY_PACKS:
        _record(errors, f"lenguaje CodeQL no soportado: {language}")
        return False

    # Evita borrar el código fuente si el llamador confunde las rutas.
    try:
        if db_dir.resolve() == source_dir.resolve():
            _record(errors, "la base de datos no puede crearse sobre el código fuente")
            return False
    except (OSError, RuntimeError):
        pass

    base = [
        "codeql", "database", "create", str(db_dir),
        f"--language={language}",
        f"--source-root={source_dir}",
        f"--threads={MAX_THREADS}",
        "--overwrite",
    ]

    attempts: List[List[str]] = []
    if language in _BUILD_MODE_NONE:
        attempts.append(base + ["--build-mode=none"])
    # Modo por defecto: autobuild (o extracción directa en lenguajes interpretados).
    attempts.append(list(base))

    for attempt, cmd in enumerate(attempts, start=1):
        _reset_dir(db_dir)
        try:
            _run_codeql(cmd)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
            _record(errors,
                    f"creación de base (intento {attempt}): {_describe_error(exc)}")

    _reset_dir(db_dir)
    return False


def analyze_database(db_dir: Path, output_sarif: Path, language: str,
                     query_suite: str = DEFAULT_QUERY_SUITE,
                     errors: Optional[List[str]] = None) -> bool:
    """Ejecuta consultas de seguridad sobre una base CodeQL y genera SARIF.

    Usa el paquete estándar ``codeql/<lenguaje>-queries`` con la suite indicada y
    ``--download`` para descargar los packs si no están en la caché local. Si la
    suite pedida falla, reintenta con la suite por defecto del paquete. Devuelve
    True si alguna estrategia tuvo éxito.
    """
    pack = QUERY_PACKS.get(language)
    if pack is None:
        _record(errors, f"no hay paquete de consultas para el lenguaje: {language}")
        return False
    if query_suite not in QUERY_SUITES:
        _record(errors, f"suite de consultas desconocida: {query_suite}")
        return False

    specs = [f"{pack}:codeql-suites/{language}-{query_suite}.qls", pack]
    for attempt, spec in enumerate(specs, start=1):
        cmd = [
            "codeql", "database", "analyze", str(db_dir), spec,
            "--download",
            "--format=sarif-latest",
            f"--output={output_sarif}",
            f"--threads={MAX_THREADS}",
        ]
        try:
            _run_codeql(cmd)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
            _record(errors,
                    f"análisis (intento {attempt}): {_describe_error(exc)}")
    return False
