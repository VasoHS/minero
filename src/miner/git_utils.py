import subprocess
from pathlib import Path
from typing import Optional

def clone_repository(repo_url: str, dest_dir: Path) -> bool:
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(dest_dir)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False

def get_head_commit(repo_dir: Path) -> Optional[str]:
    """Devuelve el SHA del commit actual (HEAD) de un repositorio clonado."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None
    commit = result.stdout.strip()
    return commit or None

def get_remote_url(repo_dir: Path) -> Optional[str]:
    """Devuelve la URL del remoto 'origin' de un repositorio clonado."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "remote", "get-url", "origin"],
            check=True, capture_output=True, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None
    remote = result.stdout.strip()
    return remote or None

def parse_full_name(remote_url: Optional[str]) -> Optional[str]:
    """Extrae 'propietario/repositorio' de una URL remota de git."""
    if not remote_url:
        return None

    cleaned = remote_url.strip().rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]

    if "@" in cleaned and ":" in cleaned:          # git@github.com:owner/repo
        cleaned = cleaned.split(":", 1)[1]
    elif "://" in cleaned:                          # https://github.com/owner/repo
        cleaned = cleaned.split("://", 1)[1]
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[1]

    parts = [p for p in cleaned.split("/") if p]
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return None
