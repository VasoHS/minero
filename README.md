# GitHub CodeQL Miner

Herramienta automatizada en Python para realizar análisis de vulnerabilidades con **CodeQL** sobre los repositorios de una organización de GitHub, generar un **SBOM** (Software Bill of Materials) en formato **CycloneDX JSON** por repositorio con **Syft** y detectar vulnerabilidades conocidas con **Grype**.

Para cada repositorio la herramienta:

1. Lo clona de forma superficial (`git clone --depth 1`).
2. Genera su SBOM con Syft.
3. Escanea vulnerabilidades con Grype (reutilizando el SBOM o el propio repositorio).
4. Detecta el lenguaje y, si está soportado por CodeQL, crea la base de datos y la analiza.
5. Registra los hallazgos, el resultado del SBOM y las vulnerabilidades en un informe JSON.

La generación del SBOM y el escaneo de vulnerabilidades son independientes del lenguaje y de CodeQL: se ejecutan aunque el repositorio no sea analizable.

## Requisitos previos

- Python 3.10 o superior.
- **git** disponible en el `PATH` (clonado de los repositorios).
- **CodeQL CLI** disponible en el `PATH` (creación y análisis de bases de datos).
- **Syft** disponible en el `PATH` (generación de SBOM; solo es necesario si no usas `--no-sbom`).
- **Grype** disponible en el `PATH` (detección de vulnerabilidades; solo es necesario si no usas `--no-vuln`).

Si prefieres no instalar nada de esto en tu equipo, usa la [imagen de Docker](#ejecución-con-docker), que incluye Python, `git`, CodeQL CLI, Syft y Grype.

Comprueba que los cuatro binarios están accesibles:

```bash
git --version
codeql version
syft version
grype version
```

### Instalación de Syft

Puedes instalar Syft por cualquiera de estas vías (de la más recomendada según tu sistema a las alternativas genéricas):

**Arch / CachyOS (paquete oficial):**

```bash
sudo pacman -S syft
# o, con un ayudante de AUR:
yay -S syft
```

**Homebrew (macOS/Linux con `brew`):**

```bash
brew install syft
```

**Script oficial (Linux/macOS):**

El script descarga el binario y lo copia al directorio indicado con `-b`. Si eliges `/usr/local/bin` (propiedad de `root`) necesitas `sudo`; de lo contrario falla con `Permiso denegado`:

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
```

Si prefieres no usar `root`, instálalo en un directorio de usuario y agrégalo al `PATH`. Por ejemplo, `~/.local/bin`:

```bash
mkdir -p ~/.local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin
```

Añade `~/.local/bin` al `PATH` según tu shell. En **fish**:

```fish
fish_add_path ~/.local/bin
```

En **bash/zsh** (añádelo a `~/.bashrc` o `~/.zshrc`):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

**Go:**

`go install` deja el binario en `$(go env GOPATH)/bin` (por defecto, `~/go/bin`), que puede no estar en el `PATH`; añádelo si es el caso.

```bash
go install github.com/anchore/syft/cmd/syft@latest
```

Confirma que quedó disponible en el `PATH`:

```bash
syft version
```

> Si Syft no está instalado, el escaneo no se detiene: se muestra una advertencia y cada repositorio queda con `sbom.status = "failed"`. Para omitir el SBOM por completo usa `--no-sbom`.

### Instalación de Grype

Puedes instalar Grype por cualquiera de estas vías (de la más recomendada según tu sistema a las alternativas genéricas):

**Arch / CachyOS (paquete oficial):**

```bash
sudo pacman -S grype
# o, con un ayudante de AUR:
yay -S grype
```

**Homebrew (macOS/Linux con `brew`):**

```bash
brew install grype
```

**Script oficial (Linux/macOS):**

El script descarga el binario y lo copia al directorio indicado con `-b`. Si eliges `/usr/local/bin` (propiedad de `root`) necesitas `sudo`; de lo contrario falla con `Permiso denegado`:

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
```

Si prefieres no usar `root`, instálalo en un directorio de usuario y agrégalo al `PATH`. Por ejemplo, `~/.local/bin`:

```bash
mkdir -p ~/.local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/.local/bin
```

Añade `~/.local/bin` al `PATH` según tu shell. En **fish**:

```fish
fish_add_path ~/.local/bin
```

En **bash/zsh** (añádelo a `~/.bashrc` o `~/.zshrc`):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

**Go:**

`go install` deja el binario en `$(go env GOPATH)/bin` (por defecto, `~/go/bin`), que puede no estar en el `PATH`; añádelo si es el caso.

```bash
go install github.com/anchore/grype/cmd/grype@latest
```

Confirma que quedó disponible en el `PATH`:

```bash
grype version
```

> Grype reutiliza una base de datos de vulnerabilidades; la primera ejecución puede descargarla, por lo que necesita conexión a Internet. Si Grype no está instalado, el escaneo no se detiene: se muestra una advertencia y cada repositorio queda con `vulnerabilities.status = "failed"`. Para omitir el escaneo por completo usa `--no-vuln`.

### Instalación de CodeQL

La herramienta usa el **CodeQL CLI** (no la extensión de VS Code) para crear y analizar las bases de datos. Descarga el *bundle* oficial —incluye la CLI y los query packs estándar— desde [github/codeql-cli-binaries](https://github.com/github/codeql-cli-binaries/releases), descomprímelo y añade su directorio al `PATH`:

```bash
# Ejemplo (ajusta la versión y la ruta a tu sistema)
unzip codeql-linux64.zip -d ~/codeql
export PATH="$HOME/codeql:$PATH"
codeql version
```

El análisis descarga los query packs (`codeql/<lenguaje>-queries`) desde `ghcr.io` si no están en la caché local, por lo que necesita conexión a Internet. Si `codeql` no está en el `PATH`, el escaneo no se detiene: se muestra una advertencia y cada repositorio soportado queda como `db_failed`, con el motivo en el campo `error`.

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

## Ejecución con Docker

Si prefieres no instalar Python, `git`, CodeQL, Syft ni Grype en el anfitrión, el repositorio ofrece **dos vías Docker** con objetivos distintos:

| Vía | Archivos | Para qué sirve | Qué incluye |
| --- | --- | --- | --- |
| **Imagen de runtime** | `Dockerfile`, `docker-compose.yml` | Ejecutar **solo la CLI `miner`** (`scan`, `sbom`, `vuln`) | Python, `git`, CodeQL, Syft y Grype |
| **Dev Container** | `.devcontainer/` | **Entorno de desarrollo completo**: CLI, notebooks, tests y Analyzer/Visualizer | Lo anterior + Node.js/npm, los extras `[dev,analyzer]` y el puerto de Jupyter |

La guía completa y centralizada de ambas vías está en **[`docs/Docker.md`](docs/Docker.md)**: construcción, ejecución, Docker Compose, gestión del token, flujo del Dev Container, versiones fijadas y solución de problemas.

### Imagen de runtime

Solo necesitas **Docker** y conexión a Internet. Construye la imagen desde la raíz del proyecto:

```bash
docker build -t github-codeql-miner .
```

El directorio del proyecto se monta en `/data`, que es el directorio de trabajo de la imagen, de modo que los clones (`workdir/`), los SBOM (`sboms/`), las vulnerabilidades (`vulns/`) y el reporte (`--output`) se escriben en el anfitrión. El token se pasa como variable de entorno:

```bash
# Opción 1: leer el token desde .env (recomendado)
docker run --rm --env-file .env -v "$PWD:/data" github-codeql-miner \
  scan --organization nombre-organizacion --output results.json

# Opción 2: pasar el token directamente
docker run --rm -e GITHUB_TOKEN="$GITHUB_TOKEN" -v "$PWD:/data" \
  github-codeql-miner scan --organization nombre-organizacion --output results.json
```

El comando por defecto de la imagen es `miner --help`; puedes encadenar cualquier subcomando de la CLI (`scan`, `sbom`, `vuln`) igual que en una instalación local.

### Docker Compose

El archivo `docker-compose.yml` automatiza el montaje del directorio y la carga del token desde `.env`:

```bash
cp .env.example .env      # y define GITHUB_TOKEN
docker compose build
docker compose run --rm miner scan --organization nombre-organizacion --output results.json
```

### Dev Container

Para el entorno de desarrollo completo (CLI, notebooks, tests y Analyzer/Visualizer), abre el repositorio en un Dev Container con VS Code (**Dev Containers: Reopen in Container**) o la CLI:

```bash
devcontainer up --workspace-folder .
```

Dentro del contenedor, desde la raíz del proyecto:

```bash
miner scan --organization nombre-organizacion --output results.json
python notebooks/execute.py
pytest
```

Consulta **[`docs/Docker.md`](docs/Docker.md)** para los requisitos, las versiones fijadas, la gestión del token, la reejecución de `post-create.sh` y las limitaciones (por ejemplo, los *toolchains* de lenguajes compilados que no se incluyen).

## Configuración del Token de GitHub

Copia el archivo de ejemplo `.env.example` a `.env` y configura tu token personal de GitHub con permisos para leer repositorios:

```bash
cp .env.example .env
```
Edita `.env` y añade tu token:
```env
GITHUB_TOKEN=ghp_tu_token_aqui
```

## Uso

La CLI dispone de cinco comandos: `miner scan` (CodeQL + SBOM + vulnerabilidades), `miner sbom` (solo SBOM, reutilizando repositorios ya clonados), `miner vuln` (solo vulnerabilidades, reutilizando SBOM ya generados), `miner visualize` (genera el tablero HTML a partir del documento del Analyzer) y `miner report` (audita la seguridad de este repositorio).

### `miner scan`

Analiza los repositorios de una organización, genera un SBOM por repositorio y escanea sus vulnerabilidades.

| Opción | Obligatoria | Valor por defecto | Descripción |
| --- | --- | --- | --- |
| `--organization TEXT` | Sí | — | Nombre de la organización de GitHub. |
| `--output PATH` | Sí | — | Archivo JSON de salida. |
| `--limit INTEGER` | No | sin límite | Máximo de repositorios a analizar: toma los primeros N en el orden en que GitHub los muestra (actualizados más recientemente primero). |
| `--repos-dir PATH` | No | `./workdir` | Directorio donde se clonan los repositorios. |
| `--sbom-dir PATH` | No | `./sboms` | Directorio de salida de los SBOM (CycloneDX JSON). |
| `--sbom / --no-sbom` | No | `--sbom` | Generar un SBOM con Syft por cada repositorio. |
| `--vuln / --no-vuln` | No | `--vuln` | Escanear vulnerabilidades con Grype (usa el SBOM o el propio repositorio). |
| `--vuln-dir PATH` | No | `./vulns` | Directorio de salida de los reportes de Grype (JSON). |
| `--progress / --no-progress` | No | auto (solo si la salida es una terminal) | Mostrar el avance de Grype en tiempo real. `--no-progress` lo silencia, pero los errores se siguen guardando en el log. |
| `--error-log PATH` | No | `<vuln-dir>/errores.log` | Archivo de log de errores de Grype. Cada ejecución lo trunca al empezar. |
| `--query-suite TEXT` | No | `security-extended` | Suite de consultas CodeQL a ejecutar: `security-extended`, `security-and-quality` o `code-scanning`. Un valor no válido termina con código `1`. |
| `--keep-repos / --cleanup-repos` | No | `--keep-repos` | Conservar los repositorios clonados al finalizar. |

```bash
export $(grep GITHUB_TOKEN .env)
miner scan --organization nombre-organizacion --output results.json
```

Para limitar cuántos repositorios se analizan (útil en una pipeline o en pruebas), usa `--limit N`:

```bash
export $(grep GITHUB_TOKEN .env)
miner scan --organization nombre-organizacion --output results.json --limit 5
```

El límite se aplica sobre el **orden en que GitHub muestra los repositorios** de la organización, que por defecto son los **actualizados más recientemente primero** (la API se consulta con `sort=updated&direction=desc`, igual que la página *Repositories* de la organización). Así, `--limit N` analiza los **primeros N** de esa lista, es decir, los N repositorios con actividad más reciente, sin reordenarlos alfabéticamente. Si `N` es mayor o igual al total de repositorios, se analizan todos. `--limit 0` es válido y no analiza ninguno (el informe queda con `summary.repositories = 0` y la lista `repositories` vacía), mientras que un valor negativo se rechaza con código de salida `1`. Cuando el límite recorta la lista, se imprime `Límite aplicado: se procesarán N de TOTAL repositorios.`

El orden de operaciones por repositorio es: validación del nombre → limpieza de restos → clonado → **SBOM** → **Grype** → detección de lenguaje → base de datos CodeQL → análisis → parseo. Por eso un repositorio no soportado (`unsupported`) aún puede tener SBOM y vulnerabilidades si el clonado fue correcto.

Si hay un SBOM válido, Grype escanea `sbom:<ruta.cdx.json>`; si no (sin SBOM o SBOM fallido), escanea `dir:<repositorio>`. Como el escaneo se ejecuta antes de validar el lenguaje, un repositorio `unsupported` también tiene vulnerabilidades.

#### Análisis CodeQL

La detección de lenguaje usa primero el lenguaje primario que reporta GitHub y, si falta o no está soportado, inspecciona los archivos clonados para elegir el lenguaje soportado con más archivos (desempate alfabético). Esto cubre casos como `C++` (GitHub lo escribe así, no `cpp`) o repositorios cuyo lenguaje primario es una plantilla (`Smarty`) pero contienen código analizable.

La base de datos se crea con `codeql database create`; en los lenguajes que lo admiten se intenta primero sin compilar (`--build-mode none`) y, si falla, se reintenta con el modo por defecto (autobuild). Para el análisis se ejecuta explícitamente el paquete estándar de GitHub `codeql/<lenguaje>-queries` con la suite seleccionada (por defecto `security-extended`) y `--download`, de modo que los query packs se descargan si no están en la caché local:

```bash
codeql database analyze <db> \
  codeql/<lenguaje>-queries:codeql-suites/<lenguaje>-security-extended.qls \
  --download --format=sarif-latest --output=<repo>.sarif --threads=8
```

Si la suite seleccionada no se puede resolver, se reintenta con la suite por defecto del paquete (`codeql/<lenguaje>-queries`). Los motivos de fallo de CodeQL se guardan en el campo `error` de cada repositorio para facilitar el diagnóstico.

Todas las operaciones de CodeQL (la fase más pesada del Miner) se ejecutan con un tope de **8 hilos** para no saturar la máquina anfitriona: tanto al crear la base como al analizarla se pasa `--threads=8`. El valor se define en un único lugar (`miner/codeql_runner.py`, constante `MAX_THREADS`).

### `miner sbom`

Genera un SBOM por repositorio reutilizando los repositorios ya clonados, **sin volver a ejecutar CodeQL**. Recorre los subdirectorios de `--repos-dir` que contienen una carpeta `.git`.

| Opción | Obligatoria | Valor por defecto | Descripción |
| --- | --- | --- | --- |
| `--repos-dir PATH` | No | `./workdir` | Directorio con los repositorios ya clonados. |
| `--sbom-dir PATH` | No | `./sboms` | Directorio de salida de los SBOM (CycloneDX JSON). |
| `--output PATH` | No | (ninguno) | Archivo JSON del reporte (opcional). Si se omite, solo se escriben los SBOM. |
| `--organization TEXT` | No | `local` | Nombre de organización para el reporte. |

```bash
miner sbom --repos-dir ./workdir --sbom-dir ./sboms --output results-sbom.json
```

Si `--repos-dir` no existe o no contiene repositorios clonados, el comando termina con código de salida `1` y un mensaje en rojo/amarillo.

### `miner vuln`

Escanea con Grype los SBOM ya generados, **sin clonar repositorios ni ejecutar CodeQL**. Recorre los archivos `*.cdx.json` de `--sbom-dir` y escribe un reporte de Grype por cada uno.

| Opción | Obligatoria | Valor por defecto | Descripción |
| --- | --- | --- | --- |
| `--sbom-dir PATH` | No | `./sboms` | Directorio con los SBOM (CycloneDX JSON) a escanear. |
| `--vuln-dir PATH` | No | `./vulns` | Directorio de salida de los reportes de Grype (JSON). |
| `--output PATH` | No | (ninguno) | Archivo JSON del reporte (opcional). Si se omite, solo se escriben los reportes de Grype. |
| `--progress / --no-progress` | No | auto (solo si la salida es una terminal) | Mostrar el avance de Grype en tiempo real. `--no-progress` lo silencia, pero los errores se siguen guardando en el log. |
| `--error-log PATH` | No | `<vuln-dir>/errores.log` | Archivo de log de errores de Grype. Cada ejecución lo trunca al empezar. |
| `--organization TEXT` | No | `local` | Nombre de organización para el reporte. |

```bash
miner vuln --sbom-dir ./sboms --vuln-dir ./vulns --output results-vuln.json
```

Si `--sbom-dir` no existe o no contiene archivos `*.cdx.json`, el comando termina con código de salida `1` y un mensaje en rojo/amarillo.

Cada entrada del reporte queda con `status = "scanned"` (estado exclusivo de este comando) y su objeto `vulnerabilities` con el resultado del escaneo.

### Seguimiento de Grype (`--progress` y `--error-log`)

Tanto `miner scan` (cuando el escaneo de vulnerabilidades está activo, es decir, sin `--no-vuln`) como `miner vuln` muestran el avance de Grype en tiempo real, línea a línea y prefijado con el nombre del repositorio:

```bash
Procesando: demo-app...
  [demo-app]  ✔ Vulnerability DB                [no update available]
  [demo-app]  ✔ Cataloged packages              [12 packages]
  [demo-app] [0000]  WARN no explicit name provided for directory source
  [demo-app]  ✔ Scanned image                   [2 vulnerabilities]
```

Las líneas que parecen un error o una advertencia (`error`, `fatal`, `panic`, `warning`/`warn`, `failed`) se muestran en rojo y se registran en el log; el resto se muestra como avance normal.

El flag `--progress / --no-progress` controla la salida en pantalla. Por defecto es automático: el avance se muestra solo si la salida es una terminal (TTY). Con `--no-progress` no se imprime el avance, pero los errores **siguen guardándose** en el log.

Los errores se guardan en un archivo de log con marca temporal UTC en formato ISO 8601. La ruta por defecto es `<vuln-dir>/errores.log` (es decir, `vulns/errores.log`) y se puede cambiar con `--error-log RUTA`. Cada ejecución **trunca** el log al empezar.

Al terminar cada comando se imprime una sección final:

- Si no hubo errores: `Sin errores durante la evaluación de Grype.`
- Si hubo: `Errores durante la evaluación (N):`, la lista de mensajes (`  - <mensaje>`) y `Log completo: <ruta>`.

El resultado del escaneo en el informe JSON **no cambia**: esta salida es solo informativa y no agrega campos al reporte.

```bash
miner vuln --sbom-dir ./sboms --vuln-dir ./vulns --output results-vuln.json \
  --progress --error-log ./vulns/errores.log
```

### Flujo recomendado

Para no repetir el análisis CodeQL (que es la parte más costosa) cuando quieres regenerar los SBOM o los escaneos de vulnerabilidades:

```bash
# 1. Escaneo completo (CodeQL + SBOM + vulnerabilidades) conservando los clones en ./workdir
miner scan --organization nombre-organizacion --output results.json --keep-repos

# 2. Regenerar solo los SBOM a partir de los clones existentes
miner sbom --repos-dir ./workdir --sbom-dir ./sboms \
  --organization nombre-organizacion --output results-sbom.json

# 3. Volver a escanear vulnerabilidades a partir de los SBOM existentes
miner vuln --sbom-dir ./sboms --vuln-dir ./vulns \
  --organization nombre-organizacion --output results-vuln.json
```

Recuerda que `--keep-repos` es el valor por defecto. Si usas `--cleanup-repos`, los repositorios se eliminan al terminar y `miner sbom` ya no tendrá nada que procesar.

## Archivos de salida

### Informe JSON (`--output`)

El reporte tiene tres bloques: `organization`, `summary` y `repositories`.

En `summary` se acumulan los contadores globales:

| Campo | Significado |
| --- | --- |
| `repositories` | Repositorios procesados. |
| `analyzed` | Repositorios analizados correctamente con CodeQL. |
| `failed` | Repositorios que fallaron en alguna etapa de CodeQL (`clone_failed`, `db_failed`, `analyze_failed`, `invalid_name`). |
| `unsupported` | Repositorios cuyo lenguaje no está soportado. |
| `findings` | Hallazgos totales. |
| `sboms_generated` | Ejecuciones **exitosas** de Syft (incluye `generated` y `no_components`). |
| `sboms_failed` | Ejecuciones de Syft con error (`failed`). |
| `components` | Componentes totales sumados de todos los SBOM exitosos. |
| `vulns_scanned` | Escaneos de Grype **exitosos** (incluye `scanned` y `no_vulnerabilities`). |
| `vulns_failed` | Escaneos de Grype con error (`failed`). |
| `vulnerabilities` | Vulnerabilidades totales sumadas de todos los escaneos exitosos. |
| `vulns_critical` | Vulnerabilidades de severidad `Critical`. |
| `vulns_high` | Vulnerabilidades de severidad `High`. |
| `vulns_medium` | Vulnerabilidades de severidad `Medium`. |
| `vulns_low` | Vulnerabilidades de severidad `Low`. |

Cada entrada de `repositories` incluye, además de los campos ya existentes, `full_name`, `commit` y los objetos `sbom` y `vulnerabilities`:

| Campo | Descripción |
| --- | --- |
| `name` | Nombre del repositorio. |
| `full_name` | `propietario/repositorio`. |
| `url` | URL de clonado. |
| `commit` | SHA del commit analizado (HEAD del clon). |
| `status` | Estado del análisis CodeQL. |
| `error` | Motivo del fallo de CodeQL (`db_failed` o `analyze_failed`); `null` si no hubo error. |
| `languages` | Lenguajes CodeQL detectados. |
| `findings` | Hallazgos del análisis. |
| `sbom` | Resultado del SBOM (ver abajo). |
| `vulnerabilities` | Resultado del escaneo de Grype (ver abajo). |

Estados posibles de `status`:

- `analyzed`: análisis CodeQL completado.
- `clone_failed`: no se pudo clonar el repositorio.
- `unsupported`: lenguaje ausente o no soportado por CodeQL.
- `db_failed`: falló la creación de la base de datos CodeQL.
- `analyze_failed`: falló el análisis de la base de datos CodeQL.
- `invalid_name`: el nombre del repositorio no es seguro (protección contra *path traversal*).
- `cloned`: solo aparece en el reporte de `miner sbom` (no se ejecutó CodeQL).
- `scanned`: solo aparece en el reporte de `miner vuln` (no se ejecutó CodeQL).

Lenguajes soportados: Python, JavaScript, TypeScript (se tratan como JavaScript), Java, Kotlin (se trata como Java), C, C++ (se tratan como C++), C#, Go, Ruby, Swift y Rust. Un repositorio sin lenguaje de GitHub pero con archivos de estos lenguajes se detecta igualmente por extensión.

### SBOM individuales (`--sbom-dir`)

Por cada repositorio se escribe un archivo CycloneDX JSON:

```
sboms/
├── demo-app.cdx.json
└── otro-repositorio.cdx.json
```

El objeto `sbom` de cada repositorio tiene estos campos:

| Campo | Descripción |
| --- | --- |
| `status` | Estado de la generación (ver tabla inferior). |
| `components` | Número de componentes detectados. |
| `syft_version` | Versión de Syft usada, o `null` si no se pudo determinar. |
| `generated_at` | Marca temporal UTC en formato ISO 8601. |
| `file` | Ruta del archivo SBOM generado. |

Estados del SBOM:

| Estado | Significado |
| --- | --- |
| `generated` | Syft terminó correctamente y detectó uno o más componentes. |
| `no_components` | Syft terminó **correctamente** pero no encontró componentes. |
| `failed` | Syft falló (binario no encontrado, error de ejecución o de escritura). |
| `skipped` | No se solicitó el SBOM (`--no-sbom`); es el estado por defecto. |

> **Importante:** `no_components` es una ejecución exitosa sin componentes, no un error. Solo `failed` indica un problema con Syft. Por eso `summary.sboms_generated` cuenta tanto `generated` como `no_components`.

Consulta [`docs/SBOM.md`](docs/SBOM.md) para la referencia detallada del SBOM y las diferencias observadas en pruebas reales sobre repositorios públicos.

### Vulnerabilidades individuales (`--vuln-dir`)

Por cada repositorio se escribe un reporte JSON crudo de Grype:

```
vulns/
├── demo-app.grype.json
├── otro-repositorio.grype.json
└── errores.log
```

El archivo `errores.log` lo genera el seguimiento de Grype (ver **Seguimiento de Grype**); su nombre y ubicación se cambian con `--error-log`.

El objeto `vulnerabilities` de cada repositorio tiene estos campos:

| Campo | Descripción |
| --- | --- |
| `status` | Estado del escaneo (ver tabla inferior). |
| `total` | Número de vulnerabilidades detectadas. |
| `by_severity` | Conteo por severidad (`Critical`, `High`, `Medium`, `Low`, `Negligible`, `Unknown`). |
| `vulnerabilities` | Lista de hallazgos (ver abajo). |
| `grype_version` | Versión de Grype usada, o `null` si no se pudo determinar. |
| `generated_at` | Marca temporal UTC en formato ISO 8601. |
| `file` | Ruta del reporte de Grype generado. |

Cada hallazgo de la lista `vulnerabilities` incluye:

| Campo | Descripción |
| --- | --- |
| `id` | Identificador de la vulnerabilidad (p. ej. `CVE-2021-44228`). |
| `severity` | Severidad normalizada (ver abajo). |
| `package` | Nombre del paquete afectado. |
| `version` | Versión del paquete detectada. |
| `type` | Tipo de paquete reportado por Grype (p. ej. `deb`, `python`). |
| `fixed_version` | Primera versión con corrección, o `null` si no hay. |
| `namespace` | Espacio de nombres de la fuente (p. ej. `debian:11`). |

Estados del escaneo:

| Estado | Significado |
| --- | --- |
| `scanned` | Grype terminó correctamente y encontró una o más vulnerabilidades. |
| `no_vulnerabilities` | Grype terminó **correctamente** pero no encontró vulnerabilidades. |
| `failed` | Grype falló (binario no encontrado, error de ejecución o de lectura/escritura). |
| `skipped` | No se solicitó el escaneo (`--no-vuln`); es el estado por defecto. |

> **Importante:** `no_vulnerabilities` es una ejecución exitosa sin hallazgos, no un error. Solo `failed` indica un problema con Grype. Por eso `summary.vulns_scanned` cuenta tanto `scanned` como `no_vulnerabilities`.

Las severidades se normalizan a `Critical`, `High`, `Medium`, `Low`, `Negligible` o `Unknown` (comparación sin distinguir mayúsculas); cualquier valor no reconocido pasa a `Unknown`. Los hallazgos se ordenan de forma determinista por severidad (Critical primero), luego por paquete y por último por `id`.

Consulta [`docs/Vulnerabilidades.md`](docs/Vulnerabilidades.md) para la referencia detallada de Grype.

## Analyzer

El **Analyzer** convierte los reportes JSON del Miner en información lista para
el **Visualizer**. No vuelve a ejecutar CodeQL, Syft ni Grype: carga la evidencia
ya generada (`results.json`, `results-vuln.json` o `results-sbom.json`) y, cuando
recibe **varios** reportes, los **fusiona por repositorio** (por ejemplo, los
componentes del SBOM con las vulnerabilidades de Grype) antes de calcular
métricas, generar observaciones respaldadas por cifras y escribir un documento
estructurado y versionado (`schema_version` `1.1`).

Entre sus métricas incluye una **nota de vulnerabilidad 1-10** (gravedad media
con pesos fijos por severidad, no volumen), el **ranking de repositorios** por
gravedad con su densidad de vulnerabilidades y un **resumen global de riesgo**
con los hotspots `Critical`. Se exponen en los datasets `repository_risk` y
`risk_summary` y en la relación `severity_by_language` (versión 1.1, aditiva
sobre 1.0).

El núcleo del Analyzer solo usa la librería estándar y funciona con la
instalación base. Para ejecutar los notebooks y exportar CSV y figuras instala el
extra `[analyzer]`:

```bash
pip install -e .[analyzer]
```

### Ejecución con un solo Jupyter

El **notebook maestro** `notebooks/00_pipeline_completo.ipynb` es el punto de
entrada recomendado: ejecuta el flujo completo **Miner (opcional) → Analyzer →
Visualizer** y muestra el tablero inline en el propio notebook (mediante un
`IFrame`), sin cambiar de herramienta. La orquestación vive en
`analysis/orchestrator.py`.

```bash
source .venv/bin/activate
python notebooks/execute.py                                      # por defecto: solo el notebook maestro (00)
python notebooks/execute.py --all                                # 00-04 en orden
python notebooks/execute.py --notebook 02_analisis_vulnerabilidades
```

`notebooks/execute.py` usa el kernel `python3`, fija el directorio de trabajo en
la raíz del repositorio y devuelve un código de salida distinto de `0` si algún
notebook falla:

| Invocación | Qué ejecuta |
| --- | --- |
| `python notebooks/execute.py` | Solo `00_pipeline_completo.ipynb` (el maestro). Si no existiera, todos los `*.ipynb`. |
| `python notebooks/execute.py --all` | `00`, `01`, `02`, `03` y `04` en orden alfabético. |
| `python notebooks/execute.py --notebook <nombre>` | Un único notebook, por nombre o sin la extensión `.ipynb`. |

El notebook maestro decide si ejecuta el Miner leyendo variables de entorno:

| Variable | Por defecto | Descripción |
| --- | --- | --- |
| `MINER_MODE` | `auto` | `auto`: reutiliza los reportes existentes y **solo ejecuta el Miner si faltan**. `force`: ejecuta siempre el Miner. `off`: nunca ejecuta el Miner (exige reportes existentes). |
| `MINER_ORGANIZATION` | — | Organización de GitHub. **Obligatoria solo si se ejecuta el Miner**. |
| `MINER_LIMIT` | sin límite | Máximo de repositorios a analizar (`--limit` del Miner). Opcional. |
| `GENERATED_AT` | hora real | Marca temporal ISO-8601 que fija `meta.generated_at` del Analyzer para reproducibilidad exacta. |
| `GITHUB_TOKEN` | — | Token de GitHub. Se lee del entorno y **nunca se imprime**; el Miner lo usa al ejecutarse. |

El Miner se invoca con `miner scan` a través de `subprocess` (`python -m
miner.cli scan`), heredando el entorno para que `GITHUB_TOKEN` esté disponible
sin exponerlo. Ejemplo forzando el Miner:

```bash
export $(grep GITHUB_TOKEN .env)
MINER_MODE=force MINER_ORGANIZATION=nombre-organizacion MINER_LIMIT=5 \
  python notebooks/execute.py
```

> El Miner **solo se ejecuta si faltan reportes** (modo `auto`) y el token
> **nunca se imprime**: solo se comprueba su presencia en el entorno.

Los notebooks `01`-`04` quedan como **exploración opcional** del pipeline (carga y
calidad, análisis de vulnerabilidades, síntesis/exportación y Visualizer). No son
necesarios para el flujo end-to-end del notebook maestro.

Cada notebook resuelve su lista `INPUT_PATHS`: usa `results.json` (`scan`) si
existe; en caso contrario, fusiona los que existan de `results-sbom.json` y
`results-vuln.json`. Con `GENERATED_AT` se fija `meta.generated_at` para
reproducibilidad exacta.

| Notebook | Qué hace | Escribe en disco | ¿Opcional? |
| --- | --- | --- | --- |
| `00_pipeline_completo.ipynb` | Ejecuta Miner (opcional) → Analyzer → Visualizer y muestra el tablero inline. | Sí (documento del Analyzer y tablero HTML) | No (entry point) |
| `01_carga_y_calidad.ipynb` | Carga los reportes, los fusiona, mide la cobertura y audita la calidad de los datos. | No | Sí |
| `02_analisis_vulnerabilidades.ipynb` | Analiza severidad, CVE/GHSA, paquetes, concentración y relaciones. | No | Sí |
| `03_sintesis_visualizer.ipynb` | Ejecuta el pipeline, valida el contrato y exporta las salidas. | Sí | Sí |
| `04_visualizer.ipynb` | Genera el tablero HTML a partir del documento del Analyzer. | Sí | Sí |

Las salidas quedan en `analysis/outputs/` (ignorado por git):

```
analysis/outputs/
├── analyzer_output.json      # contrato validado para el Visualizer
├── csv/                      # un CSV por dataset tabular
└── figures/                  # figuras PNG (severidad, paquetes, CVE, repos y riesgo)
```

También puedes ejecutar el pipeline desde Python:

```python
from analysis.pipeline import run_analysis

# Una ruta: analiza ese reporte. Varias: se fusionan por repositorio.
document = run_analysis(
    ["results-sbom.json", "results-vuln.json"],
    "analysis/outputs/analyzer_output.json",
)
```

Consulta [`analysis/README.md`](analysis/README.md) para la guía completa del
Analyzer; el contrato de salida está en
[`analysis/contracts/README.md`](analysis/contracts/README.md) y las métricas en
[`analysis/METRICAS.md`](analysis/METRICAS.md).

## Visualizer

El **Visualizer** convierte el documento del Analyzer
(`analysis/outputs/analyzer_output.json`, contrato `schema_version` `1.1`) en un
**tablero HTML autocontenido y offline**: un único archivo `.html` con los datos,
el CSS y el JavaScript embebidos, sin CDN ni peticiones de red. No recalcula
métricas derivadas: muestra tal cual lo que produjo el Analyzer. Los filtros
(repositorio, severidad, tipo y lenguaje) solo restringen los repositorios de las
vistas por repositorio; los indicadores y rankings globales no cambian.

Genera el tablero desde la CLI:

```bash
miner visualize --input analysis/outputs/analyzer_output.json \
  --output analysis/outputs/visualizer.html
```

También puedes generarlo con el notebook `04_visualizer.ipynb` (por ejemplo,
`python notebooks/execute.py --notebook 04_visualizer`) o desde Python:

```python
from miner.visualizer import build_visualizer

build_visualizer(
    "analysis/outputs/analyzer_output.json",
    "analysis/outputs/visualizer.html",
)
```

El Visualizer vive dentro del paquete `miner` (`src/miner/visualizer/`) y se
instala con `pip install -e .`; a diferencia del Analyzer, cuyo directorio
top-level `analysis/` no forma parte del paquete instalado.

Consulta [`docs/Visualizer.md`](docs/Visualizer.md) para la estructura de vistas,
la personalización del título y la solución de problemas.

## Reporter

El **Reporter** audita la seguridad de **este repositorio** (código,
dependencias, configuración y workflows) en lugar de los repositorios de una
organización externa: no reutiliza los reportes del Miner ni del Analyzer.
Un recolector determinista detecta hallazgos con evidencia (archivo, línea,
fragmento) y un modelo de lenguaje, consultado a través de
**[OpenRouter](https://openrouter.ai)**, los redacta y prioriza; un validador
posterior comprueba que toda cita del modelo exista entre los hallazgos
reales. El resultado es un reporte en Markdown con hallazgos, evidencia,
cobertura del análisis y recomendaciones de mitigación.

Configura la key antes de usarlo:

```bash
cp .env.example .env
# Edita .env y define OPENROUTER_API_KEY=sk-or-tu-key-aqui
export $(grep OPENROUTER_API_KEY .env)
```

Genera el reporte con la CLI:

```bash
miner report --output reports/security-report.md
```

Con `--no-llm` se genera solo con la evidencia recolectada, sin usar el
modelo de lenguaje:

```bash
miner report --no-llm --output reports/security-report.md
```

Se ejecuta automáticamente mediante
[`.github/workflows/security-report.yml`](.github/workflows/security-report.yml)
(diario y manual desde la pestaña **Actions**), publicando el resultado en el
resumen del job y como artefacto descargable.

Consulta [`docs/Reporter.md`](docs/Reporter.md) para la arquitectura completa,
las reglas implementadas y las garantías de trazabilidad frente a
alucinaciones del modelo.

## Ejemplo de uso completo

```bash
# 1. Configurar el token
cp .env.example .env
# Edita .env y define GITHUB_TOKEN=ghp_tu_token_aqui
export $(grep GITHUB_TOKEN .env)

# 2. Escaneo completo (CodeQL + SBOM + vulnerabilidades), conservando los clones
miner scan --organization nombre-organizacion --output results.json --keep-repos

# 3. Regenerar solo los SBOM reutilizando los clones
miner sbom --repos-dir ./workdir --sbom-dir ./sboms \
  --organization nombre-organizacion --output results-sbom.json

# 4. Volver a escanear vulnerabilidades reutilizando los SBOM
miner vuln --sbom-dir ./sboms --vuln-dir ./vulns \
  --organization nombre-organizacion --output results-vuln.json
```

Fragmento del `results.json` generado por `scan`:

```json
{
  "organization": "nombre-organizacion",
  "summary": {
    "repositories": 1,
    "analyzed": 1,
    "failed": 0,
    "unsupported": 0,
    "findings": 0,
    "sboms_generated": 1,
    "sboms_failed": 0,
    "components": 7,
    "vulns_scanned": 1,
    "vulns_failed": 0,
    "vulnerabilities": 2,
    "vulns_critical": 1,
    "vulns_high": 1,
    "vulns_medium": 0,
    "vulns_low": 0
  },
  "repositories": [
    {
      "name": "demo-app",
      "full_name": "nombre-organizacion/demo-app",
      "url": "https://github.com/nombre-organizacion/demo-app.git",
      "commit": "3f2a1c9e5b7d4f0a1c2d3e4f5a6b7c8d9e0f1a2b",
      "status": "analyzed",
      "languages": [
        "python"
      ],
      "findings": [],
      "sbom": {
        "status": "generated",
        "components": 7,
        "syft_version": "1.52.0",
        "generated_at": "2026-09-25T12:34:56.789012+00:00",
        "file": "sboms/demo-app.cdx.json"
      },
      "vulnerabilities": {
        "status": "scanned",
        "total": 2,
        "by_severity": {
          "Critical": 1,
          "High": 1,
          "Medium": 0,
          "Low": 0,
          "Negligible": 0,
          "Unknown": 0
        },
        "vulnerabilities": [
          {
            "id": "CVE-2021-44228",
            "severity": "Critical",
            "package": "log4j-core",
            "version": "2.14.1",
            "type": "java-archive",
            "fixed_version": "2.15.0",
            "namespace": "nvd"
          },
          {
            "id": "CVE-2023-32681",
            "severity": "High",
            "package": "requests",
            "version": "2.30.0",
            "type": "python",
            "fixed_version": "2.31.0",
            "namespace": "nvd"
          }
        ],
        "grype_version": "0.87.0",
        "generated_at": "2026-09-25T12:35:10.123456+00:00",
        "file": "vulns/demo-app.grype.json"
      }
    }
  ]
}
```

Contenido de las carpetas `sboms/` y `vulns/`:

```
sboms/
└── demo-app.cdx.json

vulns/
├── demo-app.grype.json
└── errores.log
```

## Pruebas

Para ejecutar las pruebas automatizadas con `pytest`:

```bash
pytest
```

## Solución de problemas

- **Token ausente:** si `GITHUB_TOKEN` no está configurado, `get_organization_repos` lanza `La variable de entorno GITHUB_TOKEN no está configurada.` y `miner scan` termina con código `1`. Exporta la variable (por ejemplo `export $(grep GITHUB_TOKEN .env)`) o revisa tu `.env`.
- **`codeql` no encontrado:** si el binario no está en el `PATH`, se muestra `Advertencia: no se pudo determinar la versión de CodeQL...` y cada repositorio soportado queda como `db_failed` con `error = "no se encontró el ejecutable 'codeql' en el PATH"`. Verifica con `codeql version` e instala/añade CodeQL CLI al `PATH`.
- **Repositorios no soportados:** si GitHub no informa lenguaje y tampoco se detecta ninguno por extensión, el repositorio queda como `unsupported` (igual se intenta generar su SBOM si el clonado tuvo éxito).
- **Bases de datos que fallan (`db_failed`):** revisa el campo `error` de la entrada. Si menciona dependencias de compilación, instálalas o usa un lenguaje interpretado; el runner ya reintenta sin compilar (`--build-mode none`) antes de recurrir a autobuild.
- **Análisis que fallan (`analyze_failed`):** revisa el campo `error`. Suele deberse a que no se pudieron descargar los query packs (falta de red o de acceso a `ghcr.io`) o a un `--query-suite` no disponible en la versión de CodeQL instalada. Prueba `--query-suite code-scanning` o descarga los packs con `codeql pack download codeql/<lenguaje>-queries`.
- **`--limit` negativo o inesperado:** un valor negativo termina con código `1` y el mensaje `El límite de repositorios (--limit) no puede ser negativo.`; `--limit 0` es válido y produce un informe con `summary.repositories = 0` y la lista `repositories` vacía. El límite se aplica sobre el orden en que GitHub muestra los repositorios (actualizados más recientemente primero), por lo que se analizan los primeros N de esa lista, no los N más relevantes por otro criterio.
- **`syft` no encontrado:** se muestra `Advertencia: no se pudo determinar la versión de Syft...` y los SBOM quedan como `failed`. Instala Syft y comprueba con `syft version`, o usa `--no-sbom` para omitirlos.
- **SBOM sin componentes (`no_components`):** no es un error; significa que Syft no identificó dependencias. Revisa que el repositorio tenga archivos de dependencias que Syft sepa interpretar (por ejemplo, en npm hace falta un archivo de bloqueo como `package-lock.json`, ya que `package.json` por sí solo da 0 componentes; en Python basta `requirements.txt`).
- **`grype` no encontrado:** se muestra `Advertencia: no se pudo determinar la versión de Grype...` y los escaneos quedan como `failed`. Instala Grype (consulta la sección **Instalación de Grype**) y comprueba con `grype version`, o usa `--no-vuln` para omitirlos.
- **Base de datos de Grype no descargable:** la primera ejecución necesita descargar la base de vulnerabilidades. Si no hay red o falla la descarga, el escaneo queda como `failed`. Comprueba la conexión y vuelve a intentarlo; puedes forzar la actualización con `grype db update`.
- **Sin vulnerabilidades (`no_vulnerabilities`):** no es un error; significa que Grype no encontró coincidencias. Puede deberse a que el SBOM no incluye versiones resueltas (por ejemplo, npm sin archivo de bloqueo) o a que la base de datos no conoce esos paquetes.
- **Omitir el escaneo de vulnerabilidades (`--no-vuln`):** el objeto `vulnerabilities` queda en `skipped` y no afecta a ninguno de los contadores `vulns_*`.
- **Errores o advertencias de Grype durante el escaneo:** las líneas que contienen `error`, `fatal`, `panic`, `warning`/`warn` o `failed` se muestran en rojo, se resumen al final del comando y se guardan en `vulns/errores.log` (o en la ruta indicada con `--error-log`). El log se trunca al empezar cada ejecución; con `--no-progress` no se imprime el avance, pero el log se sigue escribiendo.
- **`OPENROUTER_API_KEY` ausente:** `miner report` termina con código `1` y el mensaje `Error: OPENROUTER_API_KEY no está configurada.`. Exporta la variable desde tu `.env` o usa `--no-llm` para generar el reporte solo con evidencia, sin consultar el modelo.
- **El reporte advierte "IDs que no existen":** significa que el modelo citó un hallazgo inexistente en su respuesta. Revisa manualmente esa sección del reporte; el apéndice de evidencia es la fuente de verdad.

Para más detalle sobre el SBOM, consulta [`docs/SBOM.md`](docs/SBOM.md); para el escaneo de vulnerabilidades, [`docs/Vulnerabilidades.md`](docs/Vulnerabilidades.md).
