# GitHub CodeQL Miner

Herramienta automatizada en Python para realizar análisis de vulnerabilidades con **CodeQL** sobre los repositorios de una organización de GitHub y generar un **SBOM** (Software Bill of Materials) en formato **CycloneDX JSON** por repositorio usando **Syft**.

Para cada repositorio la herramienta:

1. Lo clona de forma superficial (`git clone --depth 1`).
2. Genera su SBOM con Syft.
3. Detecta el lenguaje y, si está soportado por CodeQL, crea la base de datos y la analiza.
4. Registra los hallazgos y el resultado del SBOM en un informe JSON.

La generación del SBOM es independiente del lenguaje y de CodeQL: se ejecuta aunque el repositorio no sea analizable.

## Requisitos previos

- Python 3.10 o superior.
- **git** disponible en el `PATH` (clonado de los repositorios).
- **CodeQL CLI** disponible en el `PATH` (creación y análisis de bases de datos).
- **Syft** disponible en el `PATH` (generación de SBOM; solo es necesario si no usas `--no-sbom`).

Comprueba que los tres binarios están accesibles:

```bash
git --version
codeql version
syft version
```

### Instalación de Syft

Puedes instalar Syft por cualquiera de estas vías:

```bash
# Script oficial (Linux/macOS)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Homebrew (macOS/Linux)
brew install syft

# Go
go install github.com/anchore/syft/cmd/syft@latest
```

Confirma que quedó disponible en el `PATH`:

```bash
syft version
```

> Si Syft no está instalado, el escaneo no se detiene: se muestra una advertencia y cada repositorio queda con `sbom.status = "failed"`. Para omitir el SBOM por completo usa `--no-sbom`.

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

La CLI dispone de dos comandos: `miner scan` (CodeQL + SBOM) y `miner sbom` (solo SBOM, reutilizando repositorios ya clonados).

### `miner scan`

Analiza los repositorios de una organización y genera un SBOM por repositorio.

| Opción | Obligatoria | Valor por defecto | Descripción |
| --- | --- | --- | --- |
| `--organization TEXT` | Sí | — | Nombre de la organización de GitHub. |
| `--output PATH` | Sí | — | Archivo JSON de salida. |
| `--repos-dir PATH` | No | `./workdir` | Directorio donde se clonan los repositorios. |
| `--sbom-dir PATH` | No | `./sboms` | Directorio de salida de los SBOM (CycloneDX JSON). |
| `--sbom / --no-sbom` | No | `--sbom` | Generar un SBOM con Syft por cada repositorio. |
| `--keep-repos / --cleanup-repos` | No | `--keep-repos` | Conservar los repositorios clonados al finalizar. |

```bash
export $(grep GITHUB_TOKEN .env)
miner scan --organization nombre-organizacion --output results.json
```

El orden de operaciones por repositorio es: validación del nombre → limpieza de restos → clonado → **SBOM** → detección de lenguaje → base de datos CodeQL → análisis → parseo. Por eso un repositorio no soportado (`unsupported`) aún puede tener SBOM si el clonado fue correcto.

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

### Flujo recomendado

Para no repetir el análisis CodeQL (que es la parte más costosa) cuando quieres regenerar los SBOM:

```bash
# 1. Escaneo completo conservando los clones en ./workdir
miner scan --organization nombre-organizacion --output results.json --keep-repos

# 2. Regenerar solo los SBOM a partir de los clones existentes
miner sbom --repos-dir ./workdir --sbom-dir ./sboms \
  --organization nombre-organizacion --output results-sbom.json
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

Cada entrada de `repositories` incluye, además de los campos ya existentes, `full_name`, `commit` y el objeto `sbom`:

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

Estados posibles de `status`:

- `analyzed`: análisis CodeQL completado.
- `clone_failed`: no se pudo clonar el repositorio.
- `unsupported`: lenguaje ausente o no soportado por CodeQL.
- `db_failed`: falló la creación de la base de datos CodeQL.
- `analyze_failed`: falló el análisis de la base de datos CodeQL.
- `invalid_name`: el nombre del repositorio no es seguro (protección contra *path traversal*).
- `cloned`: solo aparece en el reporte de `miner sbom` (no se ejecutó CodeQL).

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

## Ejemplo de uso completo

```bash
# 1. Configurar el token
cp .env.example .env
# Edita .env y define GITHUB_TOKEN=ghp_tu_token_aqui
export $(grep GITHUB_TOKEN .env)

# 2. Escaneo completo (CodeQL + SBOM), conservando los clones
miner scan --organization nombre-organizacion --output results.json --keep-repos

# 3. Regenerar solo los SBOM reutilizando los clones
miner sbom --repos-dir ./workdir --sbom-dir ./sboms \
  --organization nombre-organizacion --output results-sbom.json
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
    "components": 7
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
      }
    }
  ]
}
```

Contenido de la carpeta `sboms/`:

```
sboms/
└── demo-app.cdx.json
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

Para más detalle sobre el SBOM, consulta [`docs/SBOM.md`](docs/SBOM.md).
