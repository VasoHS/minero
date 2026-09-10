# GitHub CodeQL Miner

Herramienta automatizada en Python para realizar análisis de vulnerabilidades utilizando CodeQL CLI sobre los repositorios de una organización de GitHub.

## Instalación

1. Clonar el repositorio y acceder a la carpeta del proyecto.
2. Crear y activar un entorno virtual:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # En Linux/macOS
   # o .venv\Scripts\activate en Windows
   ```
3. Instalar la herramienta en modo editable con dependencias de desarrollo:
   ```bash
   pip install -e .[dev]
   ```

## Configuración del Token de GitHub

Copia el archivo de ejemplo `.env.example` a `.env` y configura tu token personal de GitHub con permisos para leer repositorios:

```bash
cp .env.example .env
```
Edita `.env` y añade tu token:
```env
GITHUB_TOKEN=ghp_tu_token_aqui
```

## Ejecución

Puedes ejecutar el miner usando el comando configurado mediante Typer:

```bash
export $(grep GITHUB_TOKEN .env)
miner scan --organization nombre-organizacion --output results.json
```

## Pruebas

Para ejecutar las pruebas automatizadas con `pytest`:

```bash
pytest
```
