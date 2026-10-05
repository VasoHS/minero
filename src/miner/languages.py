"""Detección y normalización de lenguajes soportados por CodeQL.

GitHub reporta nombres de lenguaje que no siempre coinciden con el identificador
que espera CodeQL (por ejemplo ``C++`` frente a ``cpp``). Además, el lenguaje
primario puede faltar o no estar soportado aunque el repositorio contenga código
analizable (casos como plantillas detectadas como ``Smarty``). Este módulo
centraliza el mapeo y ofrece una detección de respaldo basada en extensiones.
"""

import os
from pathlib import Path
from typing import Dict, Optional

# Lenguaje reportado por GitHub -> identificador de CodeQL.
LANGUAGE_MAPPING: Dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",
    "java": "java",
    "kotlin": "java",
    "cpp": "cpp",
    "c++": "cpp",
    "c": "cpp",
    "c#": "csharp",
    "go": "go",
    "ruby": "ruby",
    "swift": "swift",
    "rust": "rust",
}

# Extensión de archivo -> identificador de CodeQL.
EXTENSION_MAPPING: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".java": "java",
    ".kt": "java",
    ".kts": "java",
    ".c": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "cpp",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".swift": "swift",
    ".rs": "rust",
}

# Directorios que no aportan código propio y encarecen el recorrido.
_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "site-packages",
    "dist",
    "build",
    "target",
    ".tox",
    ".mypy_cache",
    "__pycache__",
}

# Cota de archivos inspeccionados para acotar el coste en repositorios grandes.
MAX_FILES_SCANNED = 20000


def map_github_language(gh_lang: Optional[str]) -> Optional[str]:
    """Traduce el lenguaje de GitHub a un identificador de CodeQL, o None."""
    if not isinstance(gh_lang, str):
        return None
    return LANGUAGE_MAPPING.get(gh_lang.strip().lower())


def detect_language(repo_dir: Path, gh_lang: Optional[str] = None) -> Optional[str]:
    """Determina el lenguaje CodeQL de un repositorio clonado.

    Prefiere el lenguaje primario que reporta GitHub. Si no es válido o no está
    soportado, inspecciona los archivos clonados y elige el lenguaje soportado
    con más archivos (desempate alfabético para que sea determinista).
    """
    mapped = map_github_language(gh_lang)
    if mapped is not None:
        return mapped
    return _detect_from_files(repo_dir)


def _detect_from_files(repo_dir: Path) -> Optional[str]:
    """Cuenta archivos por lenguaje soportado y devuelve el más frecuente."""
    try:
        if not repo_dir.is_dir():
            return None
    except OSError:
        return None

    counts: Dict[str, int] = {}
    scanned = 0
    # os.walk con entradas ordenadas => recorrido y resultado deterministas.
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in sorted(files):
            if scanned >= MAX_FILES_SCANNED:
                break
            scanned += 1
            language = EXTENSION_MAPPING.get(Path(name).suffix.lower())
            if language:
                counts[language] = counts.get(language, 0) + 1
        if scanned >= MAX_FILES_SCANNED:
            break

    if not counts:
        return None
    # Mayor número de archivos; empate resuelto alfabéticamente.
    return min(counts, key=lambda lang: (-counts[lang], lang))
