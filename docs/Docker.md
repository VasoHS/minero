# Uso de Docker en GitHub CodeQL Miner

Guía **centralizada** para ejecutar el GitHub CodeQL Miner con Docker. Reúne las
dos vías Docker del proyecto (imagen de runtime y Dev Container), su construcción,
ejecución, gestión del token, flujo de trabajo y solución de problemas.

Para la instalación local (sin Docker) y la referencia completa de la CLI
(`scan`, `sbom`, `vuln`, `visualize`) consulta el [`README.md`](../README.md).

## Dos vías Docker

El repositorio ofrece dos formas de usar Docker, pensadas para usos diferentes:

| Vía | Archivos | Para qué sirve | Qué incluye |
| --- | --- | --- | --- |
| **Imagen de runtime** | [`Dockerfile`](../Dockerfile), [`docker-compose.yml`](../docker-compose.yml) | Ejecutar **solo la CLI `miner`** (`scan`, `sbom`, `vuln`) | Python 3.12, `git`, CodeQL, Syft y Grype |
| **Dev Container** | [`.devcontainer/`](../.devcontainer) | **Entorno de desarrollo completo**: CLI, notebooks, tests y Analyzer/Visualizer | Todo lo anterior + Node.js/npm, los extras `[dev,analyzer]` y el puerto de Jupyter |

La imagen de runtime es la opción ligera para escanear; el Dev Container es la
opción para desarrollar y ejecutar el flujo de análisis completo (notebooks,
figuras, CSV y tablero). Ambas comparten la base `python:3.12-slim-bookworm` y las
mismas versiones fijadas de las herramientas externas.

## Requisitos

- **Docker** con el daemon en marcha.
- **Conexión a Internet.** La primera ejecución necesita red para:
  - clonar los repositorios desde GitHub;
  - descargar los *query packs* de CodeQL desde `ghcr.io` si no están en la caché;
  - descargar la base de vulnerabilidades de Grype.
- **Solo para el Dev Container**, una de estas dos opciones:
  - **VS Code** con la extensión [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers);
  - **Dev Container CLI** (`npm install -g @devcontainers/cli`).

## Imagen de runtime

La imagen incluye Python, `git`, CodeQL CLI, Syft y Grype. No hace falta instalar
nada en el anfitrión salvo Docker.

### Construcción

Construye la imagen desde la raíz del proyecto:

```bash
docker build -t github-codeql-miner .
```

Las versiones de las herramientas están fijadas en el `Dockerfile`
(`CODEQL_VERSION`, `SYFT_VERSION`, `GRYPE_VERSION`) y se pueden sobrescribir en la
construcción:

```bash
docker build --build-arg GRYPE_VERSION=0.120.0 -t github-codeql-miner .
```

### Ejecución

El directorio del proyecto se monta en `/data`, que es el directorio de trabajo
de la imagen, de modo que los clones (`workdir/`), los SBOM (`sboms/`), las
vulnerabilidades (`vulns/`) y el reporte (`--output`) se escriben en el anfitrión.
El token se pasa como variable de entorno:

```bash
# Opción 1: leer el token desde .env (recomendado)
docker run --rm --env-file .env -v "$PWD:/data" github-codeql-miner \
  scan --organization nombre-organizacion --output results.json

# Opción 2: pasar el token directamente
docker run --rm -e GITHUB_TOKEN="$GITHUB_TOKEN" -v "$PWD:/data" \
  github-codeql-miner scan --organization nombre-organizacion --output results.json
```

El comando por defecto de la imagen es `miner --help`. Puedes encadenar cualquier
subcomando de la CLI (`scan`, `sbom`, `vuln`) igual que en una instalación local:

```bash
docker run --rm -v "$PWD:/data" github-codeql-miner \
  sbom --repos-dir ./workdir --sbom-dir ./sboms --output results-sbom.json

docker run --rm -v "$PWD:/data" github-codeql-miner \
  vuln --sbom-dir ./sboms --vuln-dir ./vulns --output results-vuln.json
```

### Docker Compose

El archivo [`docker-compose.yml`](../docker-compose.yml) automatiza el montaje del
directorio y la carga del token desde `.env`:

```bash
cp .env.example .env      # y define GITHUB_TOKEN
docker compose build
docker compose run --rm miner scan --organization nombre-organizacion --output results.json
```

### Notas sobre la imagen

- La imagen se construye para la arquitectura del anfitrión (`amd64` o `arm64`);
  las herramientas se descargan desde los releases oficiales de GitHub.
- El escaneo se ejecuta como el usuario sin privilegios `miner` (UID 1000). Si tu
  UID no es 1000, añade `--user "$(id -u):$(id -g)"` para que los archivos
  generados te pertenezcan:

  ```bash
  docker run --rm --user "$(id -u):$(id -g)" --env-file .env -v "$PWD:/data" \
    github-codeql-miner scan --organization nombre-organizacion --output results.json
  ```

- La creación de bases CodeQL para lenguajes compilados (C/C++, Go, Java, C#,
  Swift) requiere sus compiladores, que **no** se incluyen para mantener la imagen
  ligera; esos repositorios pueden quedar como `db_failed` (ver **Solución de
  problemas**). Los lenguajes interpretados (Python, JavaScript, Ruby, etc.)
  funcionan sin herramientas adicionales.
- La primera ejecución necesita red para clonar repositorios, descargar los query
  packs de CodeQL (`ghcr.io`) y la base de vulnerabilidades de Grype.

## Dev Container

Entorno de desarrollo **reproducible** para el GitHub CodeQL Miner. Al abrir el
repositorio en un Dev Container se obtiene todo lo necesario para ejecutar el
flujo completo (extracción → análisis → visualización → reporte) sin instalar
nada a mano en el anfitrión.

> Esta configuración es **independiente** del `Dockerfile` y del
> `docker-compose.yml` de runtime de la raíz; no los modifica ni los sustituye.

### Qué incluye

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
[`.devcontainer/Dockerfile`](../.devcontainer/Dockerfile) y se pasan desde
`devcontainer.json` (`build.args`). Para actualizarlas, cambia el valor en **ambos**
sitios y reconstruye. No se usa `latest`.

### Abrir y reconstruir

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
- CLI: `devcontainer up --workspace-folder . --remove-existing-container --build-no-cache`.

El `postCreateCommand` (`bash .devcontainer/post-create.sh`) actualiza pip,
instala el proyecto en modo editable (`python -m pip install -e ".[dev,analyzer]"`),
registra el kernel `python3` de Jupyter y comprueba que `python`, `git`, `node`,
`npm`, `codeql`, `syft` y `grype` estén disponibles. Es **idempotente**: puedes
reejecutarlo con `bash .devcontainer/post-create.sh` sin romper nada.

La primera construcción descarga CodeQL (~500 MB), así que puede tardar unos
minutos. Después, el contenedor ya trae las herramientas y solo se necesita red
para clonar repositorios y descargar la base de Grype / los query packs.

### Proporcionar `GITHUB_TOKEN`

El token **nunca** se guarda en el repositorio ni se hornea en la imagen. El Dev
Container admite dos vías:

1. **Variable de entorno del anfitrión** (recomendada). `devcontainer.json` la
   inyecta con:

   ```json
   "remoteEnv": { "GITHUB_TOKEN": "${localEnv:GITHUB_TOKEN}" }
   ```

   Expórtala antes de abrir o reconstruir el contenedor:

   ```bash
   export GITHUB_TOKEN=ghp_tu_token_aqui
   ```

2. **Archivo `.env` local** (ignorado por git). Créalo a partir de `.env.example`
   y define el token:

   ```bash
   cp .env.example .env
   # Edita .env y define GITHUB_TOKEN=ghp_tu_token_aqui
   ```

   Como `.env` **no se carga automáticamente**, expórtalo en la shell del
   contenedor antes de ejecutar el Miner:

   ```bash
   export $(grep GITHUB_TOKEN .env)
   ```

`.env` está en [`.gitignore`](../.gitignore); no lo añadas nunca al control de
versiones. El token se lee del entorno y **nunca se imprime**.

### Flujo completo

Dentro del contenedor, desde la raíz del proyecto (el `workspaceFolder`):

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

Para ejecutar las pruebas:

```bash
pytest
```

### Reejecutar `post-create.sh`

Si el contenedor ya existe pero quieres reinstalar las dependencias Python (por
ejemplo tras cambiar los extras en `pyproject.toml`), ejecuta el script de
creación desde la raíz del proyecto:

```bash
bash .devcontainer/post-create.sh
```

También puedes reconstruir el contenedor completo (**Dev Containers: Rebuild
Container** en VS Code, o `devcontainer up` con `--remove-existing-container`).

### Puerto 8888 (Jupyter)

El puerto `8888` está reenviado (`forwardPorts`) para Jupyter. Si abres un
notebook desde VS Code no necesitas nada más. Para lanzar Jupyter manualmente:

```bash
jupyter notebook --no-browser --ip 0.0.0.0 --port 8888
```

### Limitaciones del Dev Container

- **Toolchains de lenguajes compilados ausentes.** Solo se incluyen Node.js
  (JavaScript/TypeScript) y el soporte de Python. No se instalan toolchains de
  C/C++, Java, Go, C# ni Swift, por lo que los repositorios de esos lenguajes
  pueden quedar como `db_failed` al crear la base de datos CodeQL. Instálalos en
  el contenedor (o extiende el `Dockerfile`) si los necesitas.
- **Red necesaria.** CodeQL y Grype descargan sus query packs y su base de
  vulnerabilidades la primera vez que se ejecutan.
- **Persistencia.** Los clones (`workdir/`), SBOM (`sboms/`), vulnerabilidades
  (`vulns/`) y salidas (`analysis/outputs/`) se escriben en el espacio de trabajo
  montado, por lo que persisten en el anfitrión entre reinicios del contenedor.

## Gestión del token

El token de GitHub **nunca** se versiona ni se imprime. Las vías admitidas son:

| Vía | Cómo se pasa | Cuándo usarla |
| --- | --- | --- |
| `.env` + `--env-file` | `docker run --rm --env-file .env ...` | Imagen de runtime (recomendado). |
| `.env` + Compose | `docker compose run ...` (lee `env_file: .env`) | Imagen de runtime con Compose. |
| `-e GITHUB_TOKEN=...` | `docker run --rm -e GITHUB_TOKEN="$GITHUB_TOKEN" ...` | Si ya está exportado en la shell. |
| `remoteEnv` | `${localEnv:GITHUB_TOKEN}` en `devcontainer.json` | Dev Container (recomendado). |
| `.env` exportado | `export $(grep GITHUB_TOKEN .env)` dentro del contenedor | Dev Container con archivo `.env`. |

Copia siempre el ejemplo y edita el archivo local:

```bash
cp .env.example .env
# Edita .env y define GITHUB_TOKEN=ghp_tu_token_aqui
```

## Solución de problemas

- **Token ausente:** si `GITHUB_TOKEN` no está configurado, `miner scan` termina
  con código `1` y el mensaje `La variable de entorno GITHUB_TOKEN no está
  configurada.`. Usa `--env-file .env`, `-e GITHUB_TOKEN=...` o expórtalo dentro
  del contenedor con `export $(grep GITHUB_TOKEN .env)`.
- **Archivos generados que pertenecen a `root` o a UID 1000:** la imagen de
  runtime se ejecuta como el usuario `miner` (UID 1000). Si tu UID no es 1000,
  añade `--user "$(id -u):$(id -g)"` al `docker run`.
- **Repositorios `db_failed` por falta de compiladores:** la imagen de runtime y
  el Dev Container no incluyen toolchains de C/C++, Java, Go, C# ni Swift. Usa un
  lenguaje interpretado, instala el toolchain en una imagen extendida o revisa el
  campo `error` de la entrada.
- **Análisis `analyze_failed`:** suele deberse a que no se pudieron descargar los
  query packs (falta de red o de acceso a `ghcr.io`) o a un `--query-suite` no
  disponible en la versión de CodeQL instalada. Comprueba la conexión o prueba
  `--query-suite code-scanning`.
- **Vulnerabilidades `failed`:** la primera ejecución de Grype descarga su base de
  vulnerabilidades; sin red el escaneo falla. Verifica la conexión y reintenta.
- **No encuentro el contenedor o la imagen:** reconstruye con
  `docker build -t github-codeql-miner .` o `docker compose build`, y comprueba
  que Docker esté en marcha.
- **El Dev Container no encuentra el token:** expórtalo antes de abrirlo
  (`export GITHUB_TOKEN=...`) o cárgalo dentro con `export $(grep GITHUB_TOKEN .env)`.

## Referencias

- [`README.md`](../README.md) — descripción general, instalación local y CLI.
- [`Dockerfile`](../Dockerfile) — imagen de runtime.
- [`docker-compose.yml`](../docker-compose.yml) — orquestación de la imagen de runtime.
- [`.devcontainer/README.md`](../.devcontainer/README.md) — detalle del Dev Container.
- [`docs/SBOM.md`](SBOM.md) — referencia del SBOM (Syft).
- [`docs/Vulnerabilidades.md`](Vulnerabilidades.md) — referencia del escaneo (Grype).
- [`docs/Visualizer.md`](Visualizer.md) — guía del tablero HTML.
