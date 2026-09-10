import typer
import json
import shutil
from pathlib import Path
from .github_api import get_organization_repos
from .git_utils import clone_repository
from .codeql_runner import create_database, analyze_database
from .sarif_parser import parse_sarif
from .models import OrganizationReport, RepositoryResult, Summary

app = typer.Typer()

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
    base_workdir.mkdir(exist_ok=True)
    
    for repo_info in repos_data:
        repo_name = repo_info["name"]
        repo_url = repo_info["clone_url"]
        gh_lang = repo_info.get("language")
        
        typer.echo(f"Procesando: {repo_name}...")
        
        repo_dir = base_workdir / repo_name
        db_dir = base_workdir / f"{repo_name}_db"
        sarif_file = base_workdir / f"{repo_name}.sarif"
        
        repo_result = RepositoryResult(name=repo_name, url=repo_url, status="pending")
        
        # 1. Clonar
        if not clone_repository(repo_url, repo_dir):
            repo_result.status = "clone_failed"
            report.summary.failed += 1
            report.repositories.append(repo_result)
            continue
        
        # 2. Detección y validación de lenguaje
        if not gh_lang or gh_lang.lower() not in LANGUAGE_MAPPING:
            repo_result.status = "unsupported"
            report.summary.unsupported += 1
            report.repositories.append(repo_result)
            shutil.rmtree(repo_dir, ignore_errors=True)
            continue
            
        detected_language = LANGUAGE_MAPPING[gh_lang.lower()]
        repo_result.languages.append(detected_language)
        
        # 3. Crear Base de Datos CodeQL
        if not create_database(repo_dir, db_dir, detected_language):
            repo_result.status = "db_failed"
            report.summary.failed += 1
            report.repositories.append(repo_result)
            shutil.rmtree(repo_dir, ignore_errors=True)
            shutil.rmtree(db_dir, ignore_errors=True)
            continue
        
        # 4. Analizar Base de Datos
        if not analyze_database(db_dir, sarif_file):
            repo_result.status = "analyze_failed"
            report.summary.failed += 1
            report.repositories.append(repo_result)
            shutil.rmtree(repo_dir, ignore_errors=True)
            shutil.rmtree(db_dir, ignore_errors=True)
            continue
        
        # 5. Parsear Resultados
        findings = parse_sarif(sarif_file)
        
        # Ordenar hallazgos (archivo, linea, regla) para reproducibilidad
        findings.sort(key=lambda f: (f.file, f.start_line or 0, f.rule_id))
        
        repo_result.status = "analyzed"
        repo_result.findings = findings
        report.summary.analyzed += 1
        report.summary.findings += len(findings)
        
        report.repositories.append(repo_result)
        
        # Limpieza temporal
        shutil.rmtree(repo_dir, ignore_errors=True)
        shutil.rmtree(db_dir, ignore_errors=True)
        sarif_file.unlink(missing_ok=True)
    
    # Guardar JSON usando Pydantic
    with open(output, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))
    
    typer.secho(f"\nEscaneo completado. Resultados guardados en {output}", fg=typer.colors.GREEN)

if __name__ == "__main__":
    app()
