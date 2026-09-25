import shutil
from pathlib import Path
from typing import Optional

import typer

from .github_api import get_organization_repos
from .git_utils import (
    clone_repository,
    get_head_commit,
    get_remote_url,
    parse_full_name,
)
from .codeql_runner import create_database, analyze_database
from .sarif_parser import parse_sarif
from .sbom_runner import generate_sbom, get_syft_version
from .models import OrganizationReport, RepositoryResult, SbomResult, Summary

app = typer.Typer()

@app.callback()
def main() -> None:
    """Miner automatizado para análisis de vulnerabilidades con CodeQL y SBOM."""

# Mapeo de lenguajes de GitHub a CodeQL
LANGUAGE_MAPPING = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",
    "java": "java",
    "cpp": "cpp",
    "c": "cpp",
    "c#": "csharp",
    "go": "go",
    "ruby": "ruby",
    "swift": "swift"
}

DEFAULT_REPOS_DIR = Path("./workdir")
DEFAULT_SBOM_DIR = Path("./sboms")

def _is_safe_repo_name(name: str) -> bool:
    """Valida el nombre de repositorio para que no escape del workdir (path traversal)."""
    if not name or set(name) <= {"."}:
        return False
    return all(c.isalnum() or c in "._-" for c in name)

def _inside(base_dir: Path, path: Path) -> bool:
    """Indica si 'path' está contenido estrictamente dentro de 'base_dir'."""
    try:
        resolved = path.resolve()
        base_resolved = base_dir.resolve()
    except (OSError, RuntimeError):
        return False
    return resolved != base_resolved and base_resolved in resolved.parents

def _cleanup(base_dir: Path, repo_dir: Path, db_dir: Path, sarif_file: Path,
             remove_repo: bool = True) -> None:
    """Elimina los artefactos temporales, solo si están dentro del workdir base."""
    if remove_repo and _inside(base_dir, repo_dir):
        shutil.rmtree(repo_dir, ignore_errors=True)
    if _inside(base_dir, db_dir):
        shutil.rmtree(db_dir, ignore_errors=True)
    if _inside(base_dir, sarif_file):
        try:
            sarif_file.unlink(missing_ok=True)
        except OSError:
            pass

def _record_sbom(summary: Summary, sbom_result: SbomResult) -> None:
    """Actualiza los contadores del resumen a partir del resultado del SBOM."""
    if sbom_result.status in ("generated", "no_components"):
        summary.sboms_generated += 1
        summary.components += sbom_result.components
    elif sbom_result.status == "failed":
        summary.sboms_failed += 1

def _write_report(report: OrganizationReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))

def _warn_if_syft_missing(syft_version: Optional[str]) -> None:
    if syft_version is None:
        typer.secho(
            "Advertencia: no se pudo determinar la versión de Syft. "
            "Verifique que 'syft' esté instalado y disponible en el PATH.",
            fg=typer.colors.YELLOW
        )

@app.command()
def scan(organization: str = typer.Option(..., help="Nombre de la organización de GitHub"),
         output: Path = typer.Option(..., help="Archivo JSON de salida"),
         repos_dir: Path = typer.Option(DEFAULT_REPOS_DIR,
                                        help="Directorio donde se clonan los repositorios"),
         sbom_dir: Path = typer.Option(DEFAULT_SBOM_DIR,
                                       help="Directorio de salida de los SBOM (CycloneDX JSON)"),
         sbom: bool = typer.Option(True, "--sbom/--no-sbom",
                                   help="Generar un SBOM con Syft por cada repositorio"),
         keep_repos: bool = typer.Option(True, "--keep-repos/--cleanup-repos",
                                         help="Conservar los repositorios clonados al finalizar")):
    """Analiza los repositorios de una organización y genera un SBOM por repositorio."""
    
    typer.echo(f"Iniciando escaneo para la organización: {organization}")
    
    try:
        repos_data = get_organization_repos(organization)
    except Exception as e:
        typer.secho(f"Error al obtener repositorios: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    
    # Ordenar alfabéticamente para resultados reproducibles
    repos_data.sort(key=lambda r: (r.get("name") or "").lower())
    
    report = OrganizationReport(
        organization=organization,
        summary=Summary(repositories=len(repos_data))
    )
    
    base_workdir = repos_dir
    try:
        base_workdir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        typer.secho(f"Error al crear {base_workdir}: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    
    syft_version = get_syft_version() if sbom else None
    if sbom:
        _warn_if_syft_missing(syft_version)
    
    for repo_info in repos_data:
        repo_name = repo_info.get("name") or ""
        repo_url = repo_info.get("clone_url") or ""
        gh_lang = repo_info.get("language")
        full_name = repo_info.get("full_name") or parse_full_name(repo_url)
        
        typer.echo(f"Procesando: {repo_name}...")
        
        repo_dir = base_workdir / repo_name
        db_dir = base_workdir / f"{repo_name}_db"
        sarif_file = base_workdir / f"{repo_name}.sarif"
        
        repo_result = RepositoryResult(
            name=repo_name,
            full_name=full_name,
            url=repo_url,
            status="pending"
        )
        is_safe = _is_safe_repo_name(repo_name)
        cloned = False
        
        try:
            # 1. Validación defensiva del nombre (evita rutas fuera de workdir)
            if not is_safe:
                repo_result.status = "invalid_name"
                report.summary.failed += 1
                continue
            
            # 2. Limpieza de restos de ejecuciones previas (hace el scan idempotente)
            _cleanup(base_workdir, repo_dir, db_dir, sarif_file)
            
            # 3. Clonar
            if not clone_repository(repo_url, repo_dir):
                repo_result.status = "clone_failed"
                report.summary.failed += 1
                continue
            cloned = True
            repo_result.commit = get_head_commit(repo_dir)
            
            # 4. Generar SBOM con Syft (independiente del lenguaje/CodeQL)
            if sbom:
                repo_result.sbom = generate_sbom(
                    repo_dir, sbom_dir / f"{repo_name}.cdx.json", syft_version
                )
                _record_sbom(report.summary, repo_result.sbom)
            
            # 5. Detección y validación de lenguaje
            if not gh_lang or gh_lang.lower() not in LANGUAGE_MAPPING:
                repo_result.status = "unsupported"
                report.summary.unsupported += 1
                continue
            
            detected_language = LANGUAGE_MAPPING[gh_lang.lower()]
            repo_result.languages.append(detected_language)
            
            # 6. Crear Base de Datos CodeQL
            if not create_database(repo_dir, db_dir, detected_language):
                repo_result.status = "db_failed"
                report.summary.failed += 1
                continue
            
            # 7. Analizar Base de Datos
            if not analyze_database(db_dir, sarif_file):
                repo_result.status = "analyze_failed"
                report.summary.failed += 1
                continue
            
            # 8. Parsear Resultados
            findings = parse_sarif(sarif_file)
            
            # Ordenar hallazgos (archivo, linea, regla) para reproducibilidad
            findings.sort(key=lambda f: (f.file, f.start_line or 0, f.rule_id))
            
            repo_result.status = "analyzed"
            repo_result.findings = findings
            report.summary.analyzed += 1
            report.summary.findings += len(findings)
        finally:
            # Registrar el resultado y limpiar los temporales solo si el nombre es seguro.
            # Un clon fallido o parcial siempre se elimina; el resto se conserva si keep_repos.
            report.repositories.append(repo_result)
            if is_safe:
                remove_repo = (not keep_repos) or (not cloned)
                _cleanup(base_workdir, repo_dir, db_dir, sarif_file, remove_repo=remove_repo)
    
    _write_report(report, output)
    
    typer.secho(f"\nEscaneo completado. Resultados guardados en {output}", fg=typer.colors.GREEN)

@app.command()
def sbom(repos_dir: Path = typer.Option(DEFAULT_REPOS_DIR,
                                        help="Directorio con los repositorios ya clonados"),
         sbom_dir: Path = typer.Option(DEFAULT_SBOM_DIR,
                                       help="Directorio de salida de los SBOM (CycloneDX JSON)"),
         output: Optional[Path] = typer.Option(None,
                                               help="Archivo JSON del reporte (opcional)"),
         organization: str = typer.Option("local",
                                          help="Nombre de organización para el reporte")):
    """Genera un SBOM por repositorio reutilizando los repos ya clonados (sin CodeQL)."""
    
    if not repos_dir.is_dir():
        typer.secho(f"El directorio de repositorios no existe: {repos_dir}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    
    try:
        repo_dirs = sorted(
            (d for d in repos_dir.iterdir() if d.is_dir() and (d / ".git").exists()),
            key=lambda p: p.name.lower()
        )
    except OSError as e:
        typer.secho(f"Error al leer {repos_dir}: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    
    if not repo_dirs:
        typer.secho(f"No se encontraron repositorios clonados en {repos_dir}", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)
    
    report = OrganizationReport(
        organization=organization,
        summary=Summary(repositories=len(repo_dirs))
    )
    
    syft_version = get_syft_version()
    _warn_if_syft_missing(syft_version)
    
    for repo_dir in repo_dirs:
        repo_name = repo_dir.name
        remote_url = get_remote_url(repo_dir) or ""
        
        repo_result = RepositoryResult(
            name=repo_name,
            full_name=parse_full_name(remote_url),
            url=remote_url,
            commit=get_head_commit(repo_dir),
            status="cloned"
        )
        repo_result.sbom = generate_sbom(
            repo_dir, sbom_dir / f"{repo_name}.cdx.json", syft_version
        )
        _record_sbom(report.summary, repo_result.sbom)
        report.repositories.append(repo_result)
        
        typer.echo(
            f"{repo_name}: {repo_result.sbom.status} "
            f"({repo_result.sbom.components} componentes)"
        )
    
    if output is not None:
        _write_report(report, output)
    
    typer.secho(
        f"\nSBOM generados: {report.summary.sboms_generated} "
        f"(fallidos: {report.summary.sboms_failed}, "
        f"componentes: {report.summary.components})",
        fg=typer.colors.GREEN
    )

if __name__ == "__main__":
    app()
