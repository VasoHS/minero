# Dev Container — GitHub CodeQL Miner

Entorno de desarrollo **reproducible** para el GitHub CodeQL Miner. Al abrir el
repositorio en un Dev Container se obtiene todo lo necesario para ejecutar el
flujo completo (extracción → análisis → visualización → reporte) sin instalar
nada a mano en el anfitrión.

> Esta configuración es **independiente** del `Dockerfile` y del
> `docker-compose.yml` de runtime que viven en la raíz del repositorio; no los
> modifica ni los sustituye.

## Qué incluye

| Componente | Detalle |
| --- | --- |
| Base | `python:3.12-slim-bookworm` (misma que el runtime) |
| Python | 3.12 con las dependencias del proyecto: `.[dev,analyzer]` (pytest, jsonschema, pandas, matplotlib, nbformat, nbclient, ipykernel) |
| Node.js / npm | Para el análisis CodeQL de JavaScript/TypeScript |
| CodeQL CLI | `2.27.1`, en `/opt/codeql` y en el `PATH` |
| Syft | `1.51.0`, en `/usr/local/bin` |
| Grype | `0.120.0`, en `/usr/local/bin` |
| Sistema | `git`, `curl`, `unzip`, `sudo`, `procps`, `less`, `nodejs`, `npm` |
| Usuario | `vscode` (UID/GID 1000) con `sudo` sin contraseña |

Las versiones de CodeQL, Syft y Grype se fijan con `ARG` en
`.devcontainer/Dockerfile` y se pasan desde `devcontainer.json`
(`build.args`). Para actualizarlas, cambia el valor en **ambos** sitios y
reconstruye. No se usa `latest`.

## Requisitos en el anfitrión

- Docker con el daemon en marcha.
- Una de estas dos opciones:
  - **VS Code** con la extensión [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers).
  - **Dev Container CLI** (`npm install -g @devcontainers/cli`).

La primera construcción descarga CodeQL (~500 MB), así que puede tardar unos
minutos. Después, el contenedor ya trae las herramientas y solo se necesita red
para clonar repositorios y descargar la base de Grype / los query packs.

## Cómo abrir y reconstruir

**VS Code**

1. Abre la carpeta del repositorio.
2. `F1` → **Dev Containers: Reopen in Container** (o **Rebuild and Reopen in
   Container** si ya existe).

**Dev Container CLI**

```bash
# Construir y ejecutar el postCreateCommand
devcontainer up --workspace-folder .

# Abrir una shell dentro del contenedor
devcontainer exec --workspace-folder . bash
```

Reconstruye cuando cambies `.devcontainer/Dockerfile` o las versiones:

- VS Code: `F1` → **Dev Containers: Rebuild Container**.
- CLI: repite `devcontainer up --workspace-folder .`.

El `postCreateCommand` (`bash .devcontainer/post-create.sh`) actualiza pip,
instala el proyecto en modo editable (`python -m pip install -e ".[dev,analyzer]"`),
registra el kernel `python3` de Jupyter y comprueba que `python`, `git`, `node`,
`npm`, `codeql`, `syft` y `grype` estén disponibles. Es **idempotente**: puedes
reejecutarlo con `bash .devcontainer/post-create.sh` sin romper nada.

## Cómo proporcionar `GITHUB_TOKEN`

El token **nunca** se hornea en la imagen ni se escribe en archivos versionados.
Hay dos formas admitidas:

1. **Variable de entorno del anfitrión** (recomendada). `devcontainer.json` la
   inyecta con:

   ```json
   "remoteEnv": { "GITHUB_TOKEN": "${localEnv:GITHUB_TOKEN}" }
   ```

   Defínela antes de abrir el contenedor, por ejemplo leyéndola de tu gestor de
   secretos o de un archivo local:

   ```bash
   export GITHUB_TOKEN=$(cat ~/.config/miner/github_token)
   ```

   Si no está definida, la variable llega vacía y `miner scan` fallará con un
   mensaje claro (no con un error confuso).

2. **Archivo `.env` local** (ignorado por git). Cópialo desde el ejemplo y
   rellénalo:

   ```bash
   cp .env.example .env
   # edita .env y asigna tu token a la clave GITHUB_TOKEN
   ```

   El contenedor monta el repositorio, así que `.env` está disponible dentro.
   Cárgalo en la shell del contenedor antes de lanzar el Miner:

   ```bash
   export $(grep GITHUB_TOKEN .env)
   ```

   `.env` está en `.gitignore`; no lo añadas nunca al control de versiones.

## Puerto 8888 (Jupyter)

El puerto `8888` está reenviado (`forwardPorts`) para Jupyter. Si abres un
notebook desde VS Code no necesitas nada más. Para lanzar Jupyter manualmente:

```bash
jupyter notebook --no-browser --ip 0.0.0.0 --port 8888
```

## Flujo completo: extracción → análisis → visualización → reporte

Todos los comandos se ejecutan **dentro del contenedor**, en la raíz del
repositorio (el `workspaceFolder`).

### 1. Extracción (Miner)

Analiza los repositorios de una organización y genera `results.json` (además de
los SBOM en `sboms/` y los reportes de Grype en `vulns/`):

```bash
miner scan --organization <org> --output results.json
```

Opciones útiles: `--limit N` para procesar solo los primeros N repositorios,
`--no-sbom` / `--no-vuln` para omitir esas fases, `--query-suite` para elegir la
suite de CodeQL.

### 2. Análisis + visualización + reporte (Analyzer → Visualizer)

El notebook maestro ejecuta el Analyzer y el Visualizer. Si no hay reportes del
Miner, puede lanzarlo antes:

```bash
# Reutiliza reportes existentes y solo ejecuta el Miner si faltan
python notebooks/execute.py

# Fuerza la extracción antes del análisis
MINER_MODE=force MINER_ORGANIZATION=<org> python notebooks/execute.py

# Ejecuta todos los notebooks (00–04) en orden
python notebooks/execute.py --all
```

Salidas generadas:

- `analysis/outputs/analyzer_output.json` — contrato validado para el Visualizer.
- `analysis/outputs/visualizer.html` — tablero HTML autocontenido y offline.

También puedes generar el tablero por separado con la CLI:

```bash
miner visualize \
  --input analysis/outputs/analyzer_output.json \
  --output analysis/outputs/visualizer.html
```

### 3. Verificación

```bash
python -m pytest -q
```

## Variables de entorno del pipeline de notebooks

| Variable | Valores | Descripción |
| --- | --- | --- |
| `MINER_MODE` | `auto` (por defecto), `force`, `off` | `auto` reutiliza reportes y solo ejecuta el Miner si faltan; `force` siempre extrae; `off` nunca extrae. |
| `MINER_ORGANIZATION` | — | Organización de GitHub; obligatoria solo si se ejecuta el Miner. |
| `GITHUB_TOKEN` | — | Token de GitHub; se lee del entorno y nunca se imprime. |

## Limitaciones

- **Toolchains de lenguajes compilados fuera de alcance.** Solo se incluyen
  Node.js (JavaScript/TypeScript) y el soporte de Python. No se instalan
  toolchains de C/C++, Java, Go, C# ni Swift, por lo que los repositorios de
  esos lenguajes pueden quedar como `db_failed` al crear la base de datos
  CodeQL. Instálalos en el contenedor (o extiende el `Dockerfile`) si los
  necesitas.
- **Base de Grype y query packs.** Grype y CodeQL descargan sus bases/paquetes
  la primera vez que se ejecutan; requieren red en ese momento.
- **Datos de vulnerabilidades.** Grype descarga su base desde el anfitrión de
  Anchore; sin red, el escaneo de vulnerabilidades puede fallar aunque el SBOM
  sí se genere.
- **Arquitecturas.** El `Dockerfile` soporta `amd64` y `arm64` para CodeQL,
  Syft y Grype.

## Archivos de esta configuración

```
.devcontainer/
├── devcontainer.json   # Configuración del Dev Container (build, usuario, extensiones)
├── Dockerfile          # Imagen de desarrollo con las herramientas fijadas
├── post-create.sh      # Instalación editable + verificación de herramientas
└── README.md           # Este documento
```
