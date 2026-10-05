from pathlib import Path
from unittest.mock import Mock

import pytest

from miner.languages import detect_language, map_github_language


@pytest.mark.parametrize(
    "gh_lang,expected",
    [
        ("Python", "python"),
        ("JavaScript", "javascript"),
        ("TypeScript", "javascript"),
        ("Java", "java"),
        ("Kotlin", "java"),
        ("C++", "cpp"),
        ("cpp", "cpp"),
        ("C", "cpp"),
        ("C#", "csharp"),
        ("Go", "go"),
        ("Ruby", "ruby"),
        ("Swift", "swift"),
        ("Rust", "rust"),
        (None, None),
        ("", None),
        ("COBOL", None),
        ("Smarty", None),
    ],
)
def test_map_github_language(gh_lang, expected):
    assert map_github_language(gh_lang) == expected


@pytest.mark.parametrize("value", [123, 1.5, True, [], {}])
def test_map_github_language_non_string_returns_none(value):
    assert map_github_language(value) is None


def test_map_github_language_strips_and_lowercases():
    assert map_github_language("  Python  ") == "python"
    assert map_github_language("C++") == "cpp"


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("app.tsx", "javascript"),
        ("app.cjs", "javascript"),
        ("Main.kt", "java"),
        ("script.kts", "java"),
        ("lib.hpp", "cpp"),
        ("main.c", "cpp"),
        ("Program.cs", "csharp"),
        ("lib.rs", "rust"),
        ("script.RB", "ruby"),
        ("app.PY", "python"),
    ],
)
def test_detect_language_by_extension(tmp_path, filename, expected):
    (tmp_path / filename).write_text("x")
    assert detect_language(tmp_path, None) == expected


def test_detect_language_prefers_github_language(tmp_path):
    # Aunque haya archivos de otro lenguaje, manda el lenguaje de GitHub.
    (tmp_path / "main.go").write_text("package main")
    assert detect_language(tmp_path, "Python") == "python"


def test_detect_language_falls_back_to_files(tmp_path):
    (tmp_path / "a.py").write_text("print('hola')")
    (tmp_path / "b.py").write_text("print('mundo')")
    assert detect_language(tmp_path, None) == "python"


def test_detect_language_falls_back_when_github_unsupported(tmp_path):
    # GitHub puede reportar un lenguaje no soportado (p. ej. plantillas como
    # "Smarty") aunque el repositorio tenga C++ analizable.
    (tmp_path / "main.cpp").write_text("int main() { return 0; }")
    assert detect_language(tmp_path, "Smarty") == "cpp"


def test_detect_language_picks_most_frequent(tmp_path):
    for name in ("a.cpp", "b.cpp", "c.cpp"):
        (tmp_path / name).write_text("// cpp")
    (tmp_path / "script.py").write_text("print('x')")
    assert detect_language(tmp_path, None) == "cpp"


def test_detect_language_tie_break_is_deterministic(tmp_path):
    (tmp_path / "main.go").write_text("package main")
    (tmp_path / "main.py").write_text("print('x')")
    # Empate a uno: se resuelve alfabéticamente ("go" < "python").
    assert detect_language(tmp_path, None) == "go"


def test_detect_language_skips_vendored_dirs(tmp_path):
    vendor = tmp_path / "node_modules" / "paquete"
    vendor.mkdir(parents=True)
    (vendor / "index.js").write_text("module.exports = {}")
    (tmp_path / "main.cpp").write_text("int main() { return 0; }")
    assert detect_language(tmp_path, None) == "cpp"


def test_detect_language_ignores_unsupported_extensions(tmp_path):
    (tmp_path / "README.md").write_text("# docs")
    (tmp_path / "data.json").write_text("{}")
    assert detect_language(tmp_path, None) is None


def test_detect_language_missing_directory(tmp_path):
    assert detect_language(tmp_path / "no-existe", None) is None


def test_detect_language_empty_directory(tmp_path):
    assert detect_language(tmp_path, None) is None


def test_detect_language_path_is_file(tmp_path):
    archivo = tmp_path / "notas.txt"
    archivo.write_text("no es un directorio")
    assert detect_language(archivo, None) is None


def test_detect_language_scans_subdirectories(tmp_path):
    nested = tmp_path / "src" / "paquete"
    nested.mkdir(parents=True)
    (nested / "main.py").write_text("print('x')")
    assert detect_language(tmp_path, None) == "python"


def test_detect_language_stops_at_max_files_scanned(tmp_path, monkeypatch):
    # Con el tope en 1 solo se inspecciona "a.py"; si no se aplicara el tope,
    # el empate entre python/javascript/cpp se resolvería como "cpp".
    (tmp_path / "a.py").write_text("print('x')")
    (tmp_path / "b.js").write_text("x")
    (tmp_path / "c.cpp").write_text("x")
    monkeypatch.setattr("miner.languages.MAX_FILES_SCANNED", 1)
    assert detect_language(tmp_path, None) == "python"


def test_detect_language_handles_oserror(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "miner.languages.Path.is_dir", Mock(side_effect=OSError("boom"))
    )
    assert detect_language(tmp_path, None) is None
