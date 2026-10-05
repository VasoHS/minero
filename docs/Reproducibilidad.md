# Reproducibilidad con Dev Containers

Esta guía detalla el **Dev Container** del proyecto: un entorno de desarrollo
completo y reproducible que incluye la CLI `miner`, los notebooks del Analyzer y
las pruebas, sin instalar nada en el anfitrión. Complementa la sección
**Reproducibilidad con Dev Containers** del [`README.md`](../README.md) y el
[`.devcontainer/README.md`](../.devcontainer/README.md).

## Dos vías Docker

El repositorio tiene dos formas de usar Docker, con objetivos distintos:

| Vía | Archivos | Objetivo | Qué incluye |
| --- | --- | --- | --- |
| **Imagen de runtime** | [`Dockerfile`](../Dockerfile), [`docker-compose.yml`](../docker-compose.yml) | Ejecutar **solo la CLI `miner`** (`scan`, `sbom`, `vuln`) | Python 3.12, `git`, CodeQL, Syft y Grype |
| **Dev Container** | [`.devcontainer/`](../.devcontainer) | **Entorno de desarrollo completo**: CLI, notebooks, tests y Analyzer/Visualizer | Todo lo anterior + Node.js/npm, extras `[dev,analyzer]` y puerto Jupyter |

La imagen de runtime es la opción ligera para escanear; el Dev Container es la
opción para desarrollar y ejecutar el flujo de análisis completo (notebooks,
figuras, CSV y tablero). Ambas comparten la base `python:3.12-slim-bookworm` y las
mismas versiones fijadas de las herramientas externas.

## Componentes del entorno

| Componente | Versión / origen | Para qué |
| --- | --- | --- |
| Python | 3.12 (`python:3.12-slim-bookworm`) | La CLI `miner` requiere Python ≥ 3.10 (ver [`pyproject.toml`](../pyproject.toml)). |
| Node.js / npm | Incluidos en el Dev Container | Herramientas del entorno de desarrollo y la CLI `devcontainer`. |
| `git` | Paquete del sistema | Clonado superficial de repositorios (`git clone --depth 1`). |
| CodeQL CLI | `2.27.1` | Creación y análisis de bases de datos CodeQL. |
| Syft | `1.51.0` | Generación del SBOM (CycloneDX JSON). |
| Grype | `0.120.0` | Detección de vulnerabilidades conocidas. |
| Extras Python | `[dev,analyzer]` | `pytest`, `jsonschema` (dev) y `pandas`, `matplotlib`, `nbformat`, `nbclient`, `ipykernel` (analyzer). |
| Usuario | `vscode`, con `sudo` | Trabajar sin `root` pero con permisos para instalar dependencias puntuales. |

### Por qué se fijan las versiones

Las versiones de **CodeQL `2.27.1`**, **Syft `1.51.0`** y **Grype `0.120.0`** están
fijadas para que el entorno sea **reproducible**: evitan que una actualización
introduzca cambios en los query packs, en el formato del SBOM o en la base de
vulnerabilidades entre ejecuciones. Son las mismas versiones que fija la imagen de
runtime mediante los argumentos `CODEQL_VERSION`, `SYFT_VERSION` y
`GRYPE_VERSION` (ver [`Dockerfile`](../Dockerfile)), de modo que una ejecución en
el Dev Container y una en la imagen de runtime usan el mismo *toolchain*.

El `postCreateCommand` del contenedor instala el paquete en modo editable con
ambos extras:

```bash
pip install -e ".[dev,analyzer]"
```

## Requisitos

- **Docker** en el anfitrión.
- **VS Code** con la extensión **Dev Containers**, o la **CLI `devcontainer`**
  (`npm install -g @devcontainers/cli`).

## Pasos de apertura

### VS Code

1. Abre la carpeta del proyecto.
2. Paleta de comandos → **Dev Containers: Reopen in Container**.
3. La primera vez se construye la imagen (`.devcontainer/Dockerfile`) y se ejecuta
   `post-create.sh` (instala los extras `[dev,analyzer]`).
4. Para reconstruir tras cambiar `.devcontainer/`, usa **Dev Containers: Rebuild
   Container**.

### CLI `devcontainer`

```bash
devcontainer up --workspace-folder .
```

Para reconstruir la imagen:

```bash
devcontainer up --workspace-folder . --remove-existing-container --build-no-cache
```

## Gestión de secretos

El token de GitHub **nunca** se guarda en el repositorio ni se hornea en la
imagen. El Dev Container admite dos vías:

1. **Variable de entorno del anfitrión.** El contenedor la reenvía con `remoteEnv`
   (`${localEnv:GITHUB_TOKEN}`). Expórtala antes de abrir o reconstruir el
   contenedor:
   ```bash
   export GITHUB_TOKEN=ghp_tu_token_aqui
   ```
2. **Archivo `.env` local.** Créalo a partir de `.env.example`:
   ```bash
   cp .env.example .env
   # Edita .env y define GITHUB_TOKEN=ghp_tu_token_aqui
   ```

`.env` está en [`.gitignore`](../.gitignore) y no se versiona; `.env.example` solo
contiene la clave vacía (`GITHUB_TOKEN=`). Como `.env` **no se carga
automáticamente**, expórtalo en la shell del contenedor antes de ejecutar el
Miner:

```bash
export $(grep GITHUB_TOKEN .env)
```

El token se lee del entorno y **nunca se imprime**: la orquestación
([`analysis/orchestrator.py`](../analysis/orchestrator.py)) solo comprueba su
presencia (`github_token_present`) y lo hereda el subproceso del Miner.

## Ejecución del proceso completo

Dentro del contenedor, desde la raíz del proyecto, el flujo es
**extracción → análisis → visualización → reporte**:

```bash
# 1. Extracción: CodeQL + SBOM + vulnerabilidades
miner scan --organization nombre-organizacion --output results.json

# 2. Análisis + visualización + reporte (notebook maestro 00)
python notebooks/execute.py

# 3. Alternativa: solo el tablero, desde el documento del Analyzer
miner visualize --input analysis/outputs/analyzer_output.json \
  --output analysis/outputs/visualizer.html
```

`python notebooks/execute.py` ejecuta `00_pipeline_completo.ipynb`
(Miner opcional → Analyzer → Visualizer) y escribe:

```
analysis/outputs/
├── analyzer_output.json      # contrato validado para el Visualizer
├── visualizer.html           # tablero autocontenido y offline
├── csv/                      # un CSV por dataset tabular
└── figures/                  # figuras PNG
```

El notebook maestro decide si ejecuta el Miner con las variables `MINER_MODE`
(`auto`, `force`, `off`), `MINER_ORGANIZATION` y `MINER_LIMIT`; y permite fijar la
marca temporal con `GENERATED_AT` para reproducibilidad exacta. Para forzar el
Miner con un límite:

```bash
export $(grep GITHUB_TOKEN .env)
MINER_MODE=force MINER_ORGANIZATION=nombre-organizacion MINER_LIMIT=5 \
  python notebooks/execute.py
```

Para ejecutar las pruebas con `pytest`:

```bash
pytest
```

## Reejecutar `post-create.sh`

Si el contenedor ya existe pero quieres reinstalar las dependencias Python (por
ejemplo tras cambiar los extras en `pyproject.toml`), ejecuta el script de
creación desde la raíz del proyecto:

```bash
bash .devcontainer/post-create.sh
```

También puedes reconstruir el contenedor completo (**Dev Containers: Rebuild
Container** en VS Code, o `devcontainer up` con `--remove-existing-container`).

## Limitaciones

- **Toolchains de lenguajes compilados ausentes.** La creación de bases CodeQL
  para C/C++, Go, Java, C#, Swift requiere sus compiladores, que **no** se
  incluyen para mantener el entorno ligero. Esos repositorios pueden quedar como
  `db_failed` (ver **Solución de problemas** del [`README.md`](../README.md)). Los
  lenguajes interpretados (Python, JavaScript, Ruby, etc.) funcionan sin
  herramientas adicionales.
- **Red necesaria.** La primera ejecución necesita conexión para:
  - clonar los repositorios desde GitHub;
  - descargar los *query packs* de CodeQL desde `ghcr.io` si no están en la caché;
  - descargar la base de vulnerabilidades de Grype.
- **Puerto Jupyter.** El puerto **8888** está expuesto para Jupyter; si usas la
  CLI `devcontainer` fuera de VS Code, reenvíalo o publícalo según tu configuración.
- **Persistencia.** Los clones (`workdir/`), SBOM (`sboms/`), vulnerabilidades
  (`vulns/`) y salidas (`analysis/outputs/`) se escriben en el espacio de trabajo
  montado, por lo que persisten en el anfitrión entre reinicios del contenedor.

## Referencias

- [`.devcontainer/README.md`](../.devcontainer/README.md) — detalle del Dev Container.
- [`README.md`](../README.md) — instalación, CLI, Analyzer y Visualizer.
- [`analysis/README.md`](../analysis/README.md) — guía del Analyzer.
- [`docs/Visualizer.md`](Visualizer.md) — guía del tablero.
