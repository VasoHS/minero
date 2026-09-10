import subprocess
from pathlib import Path

def clone_repository(repo_url: str, dest_dir: Path) -> bool:
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(dest_dir)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False
