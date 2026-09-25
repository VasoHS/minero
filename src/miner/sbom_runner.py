import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import SbomResult

def get_syft_version() -> Optional[str]:
    """Obtiene la versión de Syft instalada, o None si no está disponible."""
    try:
        result = subprocess.run(
            ["syft", "version", "-o", "json"],
            check=True, capture_output=True, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return None
    version = data.get("version") if isinstance(data, dict) else None
    return version if isinstance(version, str) and version else None

def count_components(sbom_path: Path) -> Optional[int]:
    """Cuenta los componentes de un SBOM CycloneDX JSON.

    Devuelve None si el archivo no se puede leer/parsear o no es un objeto JSON,
    para distinguir un error de un SBOM válido sin componentes (0).
    """
    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None

    if not isinstance(data, dict):
        return None
    components = data.get("components")
    if components is None:
        return 0
    if not isinstance(components, list):
        return None
    return len(components)

def _discard(path: Path) -> None:
    """Elimina un archivo best-effort (evita dejar SBOM previos/parciales)."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass

def generate_sbom(source_dir: Path, output_file: Path,
                  syft_version: Optional[str] = None) -> SbomResult:
    """Genera un SBOM CycloneDX JSON con Syft para un directorio local."""
    generated_at = datetime.now(timezone.utc).isoformat()
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return SbomResult(status="failed", syft_version=syft_version,
                          generated_at=generated_at)

    # Evita que un SBOM de una ejecución previa sobreviva si esta falla.
    _discard(output_file)

    try:
        subprocess.run(
            ["syft", f"dir:{source_dir}", "-o", f"cyclonedx-json={output_file}"],
            check=True, capture_output=True, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        _discard(output_file)
        return SbomResult(status="failed", syft_version=syft_version,
                          generated_at=generated_at)

    components = count_components(output_file)
    if components is None:
        # Syft terminó "bien" pero el SBOM no es legible: se considera fallo.
        _discard(output_file)
        return SbomResult(status="failed", syft_version=syft_version,
                          generated_at=generated_at)

    status = "generated" if components > 0 else "no_components"
    return SbomResult(
        status=status,
        components=components,
        syft_version=syft_version,
        generated_at=generated_at,
        file=str(output_file)
    )
