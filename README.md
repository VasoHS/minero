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

## Uso

La CLI dispone de tres comandos: `miner scan` (CodeQL + SBOM + vulnerabilidades), `miner sbom` (solo SBOM, reutilizando repositorios ya clonados) y `miner vuln` (solo vulnerabilidades, reutilizando SBOM ya generados).

### `miner scan`

Analiza los repositorios de una organización, genera un SBOM por repositorio y escanea sus vulnerabilidades.

| Opción | Obligatoria | Valor por defecto | Descripción |
| --- | --- | --- | --- |
| `--organization TEXT` | Sí | — | Nombre de la organización de GitHub. |
| `--output PATH` | Sí | — | Archivo JSON de salida. |
| `--repos-dir PATH` | No | `./workdir` | Directorio donde se clonan los repositorios. |
| `--sbom-dir PATH` | No | `./sboms` | Directorio de salida de los SBOM (CycloneDX JSON). |
| `--sbom / --no-sbom` | No | `--sbom` | Generar un SBOM con Syft por cada repositorio. |
| `--vuln / --no-vuln` | No | `--vuln` | Escanear vulnerabilidades con Grype (usa el SBOM o el propio repositorio). |
| `--vuln-dir PATH` | No | `./vulns` | Directorio de salida de los reportes de Grype (JSON). |
| `--progress / --no-progress` | No | auto (solo si la salida es una terminal) | Mostrar el avance de Grype en tiempo real. `--no-progress` lo silencia, pero los errores se siguen guardando en el log. |
| `--error-log PATH` | No | `<vuln-dir>/errores.log` | Archivo de log de errores de Grype. Cada ejecución lo trunca al empezar. |
| `--keep-repos / --cleanup-repos` | No | `--keep-repos` | Conservar los repositorios clonados al finalizar. |

```bash
export $(grep GITHUB_TOKEN .env)
miner scan --organization nombre-organizacion --output results.json
```

El orden de operaciones por repositorio es: validación del nombre → limpieza de restos → clonado → **SBOM** → **Grype** → detección de lenguaje → base de datos CodeQL → análisis → parseo. Por eso un repositorio no soportado (`unsupported`) aún puede tener SBOM y vulnerabilidades si el clonado fue correcto.

Si hay un SBOM válido, Grype escanea `sbom:<ruta.cdx.json>`; si no (sin SBOM o SBOM fallido), escanea `dir:<repositorio>`. Como el escaneo se ejecuta antes de validar el lenguaje, un repositorio `unsupported` también tiene vulnerabilidades.

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

Lenguajes soportados: Python, JavaScript, TypeScript (se tratan como JavaScript), Java, C, C++ (se tratan como C++), C#, Go, Ruby y Swift.

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
- **`codeql` no encontrado:** si el binario no está en el `PATH`, la creación de la base de datos falla y el repositorio queda como `db_failed`. Verifica con `codeql version` e instala/añade CodeQL CLI al `PATH`.
- **Repositorios no soportados:** si GitHub no informa lenguaje o este no está en el mapeo, el repositorio queda como `unsupported` (igual se intenta generar su SBOM si el clonado tuvo éxito).
- **Bases de datos que fallan:** un `db_failed` suele deberse a dependencias de compilación ausentes para el lenguaje; `analyze_failed` indica un fallo al analizar una base ya creada.
- **`syft` no encontrado:** se muestra `Advertencia: no se pudo determinar la versión de Syft...` y los SBOM quedan como `failed`. Instala Syft y comprueba con `syft version`, o usa `--no-sbom` para omitirlos.
- **SBOM sin componentes (`no_components`):** no es un error; significa que Syft no identificó dependencias. Revisa que el repositorio tenga archivos de dependencias que Syft sepa interpretar (por ejemplo, en npm hace falta un archivo de bloqueo como `package-lock.json`, ya que `package.json` por sí solo da 0 componentes; en Python basta `requirements.txt`).
- **`grype` no encontrado:** se muestra `Advertencia: no se pudo determinar la versión de Grype...` y los escaneos quedan como `failed`. Instala Grype (consulta la sección **Instalación de Grype**) y comprueba con `grype version`, o usa `--no-vuln` para omitirlos.
- **Base de datos de Grype no descargable:** la primera ejecución necesita descargar la base de vulnerabilidades. Si no hay red o falla la descarga, el escaneo queda como `failed`. Comprueba la conexión y vuelve a intentarlo; puedes forzar la actualización con `grype db update`.
- **Sin vulnerabilidades (`no_vulnerabilities`):** no es un error; significa que Grype no encontró coincidencias. Puede deberse a que el SBOM no incluye versiones resueltas (por ejemplo, npm sin archivo de bloqueo) o a que la base de datos no conoce esos paquetes.
- **Omitir el escaneo de vulnerabilidades (`--no-vuln`):** el objeto `vulnerabilities` queda en `skipped` y no afecta a ninguno de los contadores `vulns_*`.
- **Errores o advertencias de Grype durante el escaneo:** las líneas que contienen `error`, `fatal`, `panic`, `warning`/`warn` o `failed` se muestran en rojo, se resumen al final del comando y se guardan en `vulns/errores.log` (o en la ruta indicada con `--error-log`). El log se trunca al empezar cada ejecución; con `--no-progress` no se imprime el avance, pero el log se sigue escribiendo.

Para más detalle sobre el SBOM, consulta [`docs/SBOM.md`](docs/SBOM.md); para el escaneo de vulnerabilidades, [`docs/Vulnerabilidades.md`](docs/Vulnerabilidades.md).
