import typer
import shutil
from pathlib import Path
from .github_api import get_organization_repos
from .git_utils import clone_repository
from .codeql_runner import create_database, analyze_database
from .sarif_parser import parse_sarif
from .models import OrganizationReport, RepositoryResult, Summary

app = typer.Typer()

@app.callback()
def main() -> None:
    """Miner automatizado para análisis de vulnerabilidades con CodeQL."""

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

def _cleanup(base_dir: Path, repo_dir: Path, db_dir: Path, sarif_file: Path) -> None:
    """Elimina los artefactos temporales, solo si están dentro del workdir base."""
    if _inside(base_dir, repo_dir):
        shutil.rmtree(repo_dir, ignore_errors=True)
    if _inside(base_dir, db_dir):
        shutil.rmtree(db_dir, ignore_errors=True)
    if _inside(base_dir, sarif_file):
        try:
            sarif_file.unlink(missing_ok=True)
        except OSError:
            pass

@app.command()
def scan(organization: str = typer.Option(..., help="Nombre de la organización de GitHub"),
         output: Path = typer.Option(..., help="Archivo JSON de salida")):
    
    typer.echo(f"Iniciando escaneo para la organización: {organization}")
    
    try:
        repos_data = get_organization_repos(organization)
    except Exception as e:
        typer.secho(f"Error al obtener repositorios: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    
    # Ordenar alfabéticamente para resultados reproducibles
    repos_data.sort(key=lambda r: r["name"].lower())
    
    report = OrganizationReport(
        organization=organization,
        summary=Summary(repositories=len(repos_data))
    )
    
    base_workdir = Path("./workdir")
    base_workdir.mkdir(parents=True, exist_ok=True)
    
    for repo_info in repos_data:
        repo_name = repo_info["name"]
        repo_url = repo_info["clone_url"]
        gh_lang = repo_info.get("language")
        
        typer.echo(f"Procesando: {repo_name}...")
        
        repo_dir = base_workdir / repo_name
        db_dir = base_workdir / f"{repo_name}_db"
        sarif_file = base_workdir / f"{repo_name}.sarif"
        
        repo_result = RepositoryResult(name=repo_name, url=repo_url, status="pending")
        is_safe = _is_safe_repo_name(repo_name)
        
        try:
            # 1. Validación defensiva del nombre (evita rutas fuera de workdir)
            if not is_safe:
                repo_result.status = "invalid_name"
                report.summary.failed += 1
                continue
            
            # 2. Detección y validación de lenguaje (antes de clonar)
            if not gh_lang or gh_lang.lower() not in LANGUAGE_MAPPING:
                repo_result.status = "unsupported"
                report.summary.unsupported += 1
                continue
            
            detected_language = LANGUAGE_MAPPING[gh_lang.lower()]
            repo_result.languages.append(detected_language)
            
            # 3. Limpieza de restos de ejecuciones previas (hace el scan idempotente)
            _cleanup(base_workdir, repo_dir, db_dir, sarif_file)
            
            # 4. Clonar
            if not clone_repository(repo_url, repo_dir):
                repo_result.status = "clone_failed"
                report.summary.failed += 1
                continue
            
            # 5. Crear Base de Datos CodeQL
            if not create_database(repo_dir, db_dir, detected_language):
                repo_result.status = "db_failed"
                report.summary.failed += 1
                continue
            
            # 6. Analizar Base de Datos
            if not analyze_database(db_dir, sarif_file):
                repo_result.status = "analyze_failed"
                report.summary.failed += 1
                continue
            
            # 7. Parsear Resultados
            findings = parse_sarif(sarif_file)
            
            # Ordenar hallazgos (archivo, linea, regla) para reproducibilidad
            findings.sort(key=lambda f: (f.file, f.start_line or 0, f.rule_id))
            
            repo_result.status = "analyzed"
            repo_result.findings = findings
            report.summary.analyzed += 1
            report.summary.findings += len(findings)
        finally:
            # Registrar el resultado y limpiar los temporales solo si el nombre es seguro
            report.repositories.append(repo_result)
            if is_safe:
                _cleanup(base_workdir, repo_dir, db_dir, sarif_file)
    
    # Guardar JSON usando Pydantic
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))
    
    typer.secho(f"\nEscaneo completado. Resultados guardados en {output}", fg=typer.colors.GREEN)

if __name__ == "__main__":
    app()
