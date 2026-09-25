import subprocess
from pathlib import Path

def create_database(source_dir: Path, db_dir: Path, language: str) -> bool:
    try:
        subprocess.run(
            ["codeql", "database", "create", str(db_dir), "--language", language, "--source-root", str(source_dir)],
            check=True, capture_output=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False

def analyze_database(db_dir: Path, output_sarif: Path) -> bool:
    try:
        subprocess.run(
            ["codeql", "database", "analyze", str(db_dir),
             "--format=sarif-latest", f"--output={output_sarif}"],
            check=True, capture_output=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False
