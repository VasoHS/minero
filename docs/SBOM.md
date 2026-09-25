# SBOM en GitHub CodeQL Miner

Referencia detallada de la generación de **SBOM** (Software Bill of Materials) con **Syft**. Para la descripción general, instalación y uso de la CLI consulta el [`README.md`](../README.md).

## Cómo funciona

Al procesar cada repositorio, la herramienta ejecuta internamente:

```bash
syft dir:<repositorio> -o cyclonedx-json=<sboms/repositorio>.cdx.json
```

Además consulta la versión instalada con:

```bash
syft version -o json
```

La generación del SBOM es **independiente de CodeQL y del lenguaje**: se ejecuta justo después del clonado, antes de la detección de lenguaje. Un repositorio `unsupported` (o cuyo análisis CodeQL falle) puede tener igualmente un SBOM válido.

## Ubicación de los archivos

Los SBOM se escriben en `--sbom-dir` (por defecto `./sboms`), un archivo CycloneDX JSON por repositorio:

```
sboms/
├── demo-app.cdx.json
└── otro-repositorio.cdx.json
```

## Campos del objeto `sbom`

En cada entrada de `repositories` del informe JSON:

| Campo | Tipo | Descripción |
| --- | --- | --- |
| `status` | string | Estado de la generación (ver tabla inferior). |
| `components` | int | Número de componentes (`components[]` del SBOM). |
| `syft_version` | string \| null | Versión de Syft usada, o `null` si no se pudo determinar. |
| `generated_at` | string | Marca temporal UTC en ISO 8601, p. ej. `2026-09-25T12:34:56.789012+00:00`. |
| `file` | string | Ruta del archivo SBOM generado. |

## Estados del SBOM

| Estado | ¿Éxito? | Significado |
| --- | --- | --- |
| `generated` | Sí | Syft terminó correctamente y detectó uno o más componentes. |
| `no_components` | Sí | Syft terminó correctamente pero no encontró componentes. |
| `failed` | No | Syft falló (binario no encontrado, error de ejecución o de escritura del archivo). |
| `skipped` | — | No se solicitó el SBOM (`--no-sbom`); es el estado por defecto. |

Es fundamental distinguir **ejecución fallida** (`failed`) de **ejecución exitosa sin componentes** (`no_components`):

- `failed` implica un problema con Syft; el inventario no es fiable y conviene revisar la instalación (`syft version`).
- `no_components` indica que Syft funcionó pero no identificó dependencias en el repositorio; no es un error.

## Contadores en `summary`

| Campo | Se incrementa cuando... |
| --- | --- |
| `sboms_generated` | El SBOM termina con `generated` **o** `no_components` (ejecución exitosa). |
| `sboms_failed` | El SBOM termina con `failed`. |
| `components` | Suma de componentes de todos los SBOM exitosos. |

Con `--no-sbom`, los SBOM quedan en `skipped` y no afectan a ninguno de estos contadores.

## Verificación / diferencias observadas

Los resultados de esta sección provienen de **ejecuciones reales de `miner sbom`** sobre repositorios públicos con archivos de declaración y de bloqueo de dependencias, usando **Syft 1.52.0** en Linux. Los repositorios A y B terminaron con `sbom.status = "generated"`; el caso mínimo incluye además un escenario sin lockfile que da `no_components` (ver más abajo).

### Repositorio A: `mangowm/mangowm-settings` (JavaScript/Tauri)

| Aspecto | Resultado |
| --- | --- |
| Archivos de dependencias | `package.json` (23 `dependencies` + 15 `devDependencies` = **38 declaradas**), `pnpm-lock.yaml` y, en `src-tauri/`, `Cargo.toml` y `Cargo.lock`. |
| Estado del SBOM | `generated` |
| Componentes | **1070** |

- Las **38 dependencias declaradas aparecen todas** (p. ej. `@tauri-apps/api`, `react`, `vite`, `typescript`).
- Las **~1032 restantes son dependencias transitivas** que Syft resuelve a partir de `pnpm-lock.yaml` (paquetes npm como `@babel/*`) y de `Cargo.lock` (crates de Rust).
- Además, Syft reporta como componentes los propios archivos de bloqueo (`pnpm-lock.yaml`, `Cargo.lock`) y el workflow `.github/workflows/ci.yml`.

### Repositorio B: `pallets/click` (Python)

| Aspecto | Resultado |
| --- | --- |
| Archivos de dependencias | `pyproject.toml`, `uv.lock` y workflows en `.github/workflows/*.yaml`. |
| Estado del SBOM | `generated` |
| Componentes | **108** |

- **~100 paquetes Python con versiones resueltas** desde `uv.lock` (p. ej. `pytest 9.0.2`, `ruff 0.15.9`, `mypy 1.20.0`, `sphinx`).
- **Acciones de GitHub Actions** extraídas de los workflows (p. ej. `actions/checkout v7.0.1`, `actions/setup-python v7.0.0`).
- El propio `uv.lock` aparece como un componente más.
- **Componentes duplicados:** una misma acción puede repetirse en varios workflows y un mismo paquete puede aparecer con varias versiones (p. ej. `sphinx` 8.1.3, 9.0.4 y 9.1.0) cuando el lockfile lo requiere en grupos distintos.

### Casos mínimos

**a) npm con `package-lock.json`**

Directorio con `package.json` (`express ^4.18.2`, `lodash 4.17.21`) **+ `package-lock.json`** + `requirements.txt` (`requests==2.31.0`, `flask==3.0.0`): **7 componentes**.

| Componente | Origen |
| --- | --- |
| `demo-app` | El propio proyecto. |
| `express 4.18.2` | Dependencia directa resuelta por el `package-lock.json`. |
| `lodash 4.17.21` | Dependencia directa resuelta por el `package-lock.json`. |
| `flask 3.0.0` | Dependencia directa declarada en `requirements.txt`. |
| `requests 2.31.0` | Dependencia directa declarada en `requirements.txt`. |
| `package-lock.json` | Archivo de bloqueo, listado como componente. |
| `requirements.txt` | Archivo de manifiesto, listado como componente. |

**b) npm sin lockfile**

Directorio con **solo `package.json`** (`express ^4.18.2`, `lodash 4.17.21`), **sin** ningún archivo de bloqueo: Syft reporta **0 componentes** y el estado es `sbom.status = "no_components"`. Para el ecosistema **npm, Syft necesita un archivo de bloqueo** (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) para identificar dependencias; las declaraciones de `package.json` por sí solas no bastan.

**c) Python con `requirements.txt` (sin lockfile)**

Directorio con **solo `requirements.txt`** (`requests==2.31.0`): **2 componentes**: `requests 2.31.0` y el propio archivo `requirements.txt`. En **Python**, el catalogador de `requirements.txt` sí identifica las dependencias directas **sin necesidad de lockfile**.

### Diferencias a tener en cuenta

- **El inventario depende de qué archivos de dependencias existan y de qué catalogadores de Syft los interpreten.** Sin archivos de dependencias el resultado puede ser `no_components`.
- **Dependencias transitivas:** solo aparecen si existe un **lockfile** (`pnpm-lock.yaml`, `uv.lock`, `package-lock.json`, `poetry.lock`, etc.).
- **El comportamiento sin lockfile depende del ecosistema:** en **npm**, un `package.json` sin archivo de bloqueo produce **0 componentes** (Syft no infiere las dependencias declaradas); en **Python**, `requirements.txt` sí identifica las dependencias directas **sin lockfile**.
- **Rangos vs. versiones resueltas:** rangos como `^` o `>=` se resuelven a una versión concreta **solo si hay lockfile**; en npm sin lockfile no se resuelve ninguna versión (0 componentes) y en Python la versión declarada se usa tal cual.
- **El proyecto aparece como componente**, además de los archivos de manifiesto/bloqueo y de las **acciones de CI** extraídas de los workflows.
- **Pueden aparecer duplicados:** la misma acción en varios workflows o varias versiones de un paquete cuando el lockfile las requiere en grupos distintos.
- **Licencias:** pueden venir vacías (`{}`) aunque el componente tenga nombre y versión; no todas las dependencias declaran licencia y Syft no siempre puede inferirla.

## Solución de problemas de SBOM

- **`syft` no encontrado** (estado `failed` y advertencia `Advertencia: no se pudo determinar la versión de Syft...`): instala Syft y verifica con `syft version`. Para omitir el SBOM usa `--no-sbom`.
- **Ningún componente (`no_components`)**: no es un error; comprueba que el repositorio incluya archivos de dependencias que el catalogador correspondiente sepa interpretar (en npm se requiere un archivo de bloqueo; `requirements.txt` basta en Python) y, para dependencias transitivas, un lockfile.
- **No se generan SBOM**: asegúrate de no haber pasado `--no-sbom` y de que `miner scan` haya podido clonar el repositorio.
- **`miner sbom` no encuentra repositorios**: `--repos-dir` debe existir y contener subdirectorios con `.git`. Recuerda ejecutar antes `miner scan` con `--keep-repos` (valor por defecto).
