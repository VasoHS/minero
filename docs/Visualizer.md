# Visualizer

El **Visualizer** convierte el documento del Analyzer
(`analysis/outputs/analyzer_output.json`, contrato `schema_version` `1.1`) en un
**tablero HTML autocontenido y offline**. No vuelve a ejecutar CodeQL, Syft ni
Grype y **no recalcula métricas derivadas**: presenta tal cual lo que ya calculó
el Analyzer.

Para la descripción general, instalación y uso de la CLI consulta el
[`README.md`](../README.md). El contrato de entrada se detalla en
[`../analysis/contracts/README.md`](../analysis/contracts/README.md) y las
métricas en [`../analysis/METRICAS.md`](../analysis/METRICAS.md).

## Propósito y relación con el Miner y el Analyzer

```
Miner (CLI)                        Analyzer                          Visualizer
────────────                       ────────                          ──────────
miner scan  ─► results.json ─┐
miner sbom  ─► results-*.json ┼─► analyzer_output.json ───────────► visualizer.html
miner vuln  ─► results-*.json ┘   (contrato 1.1, sin red)           (un único HTML)
```

- El **Miner** produce los reportes crudos (`results.json`,
  `results-sbom.json`, `results-vuln.json`).
- El **Analyzer** los fusiona, calcula las métricas y escribe el documento
  `analyzer_output.json` validado contra el contrato 1.1.
- El **Visualizer** consume ese documento y solo lo presenta: es la última etapa
  del flujo y no modifica ni añade datos.

## Qué consume

El Visualizer lee el **documento del Analyzer** (`schema_version` `1.1`). Del
nivel superior usa `meta`, `coverage`, `schema_version`, `observations` y
`limitations`. De `datasets` usa `repositories`, `repository_distribution`,
`repository_risk`, `vulnerabilities`, `findings`, `severity_distribution`,
`top_packages`, `top_cves`, `top_rules`, `risk_summary` y `concentration`; de
`relations` usa `components_vs_vulnerabilities`, `fixed_version_available_share`,
`severity_by_package_type`, `findings_by_language` y `severity_by_language`. No
lee `summary`: los indicadores globales se toman de `risk_summary`, `coverage` y
`severity_distribution`.

Reglas de consumo:

- **Fidelidad estricta.** El tablero **no recalcula métricas derivadas**: muestra
  tal cual vienen del documento la nota `score`, `severity_weighted_average`,
  `severity_median`, `mean_repository_score`, `max_repository_score`, el
  coeficiente de Pearson, el HHI, `fixed_version_share` y `vulns_per_component`.
- **Filtros de alcance.** Los filtros (repositorio, severidad, tipo de paquete y
  lenguaje) solo deciden qué repositorios entran en las vistas **por
  repositorio** (tabla de riesgo, barras por repositorio, dispersión y
  drill-down). Los indicadores y rankings globales se presentan precalculados y
  **no cambian** con los filtros; cuando hay filtros activos se muestra una nota
  aclaratoria.
- **Tolerante a vacíos.** Si un dataset o una relación no existe (por ejemplo, un
  documento de origen `sbom` sin vulnerabilidades), la sección correspondiente se
  omite o muestra un mensaje, sin fallar.
- **Sin red.** El documento se embebe en el HTML junto con el CSS y el
  JavaScript; no hay CDN, fuentes remotas ni peticiones al abrir el archivo.

El Visualizer no valida el contrato completo (esa es responsabilidad del
Analyzer); si el documento está incompleto, algunas secciones quedarán vacías.

## Cómo generarlo

Requisito: la herramienta instalada en modo editable:

```bash
pip install -e .
```

El Visualizer forma parte del paquete `miner` (`src/miner/visualizer/`) y sus
assets CSS/JS viajan con él; **no** depende del directorio top-level `analysis/`,
que no se instala.

### CLI

```bash
miner visualize --input analysis/outputs/analyzer_output.json \
  --output analysis/outputs/visualizer.html
```

| Opción | Obligatoria | Valor por defecto | Descripción |
| --- | --- | --- | --- |
| `--input PATH` | Sí | — | Documento JSON del Analyzer (`analyzer_output.json`). |
| `--output PATH` | Sí | — | Archivo HTML de salida. |
| `--title TEXT` | No | `Visualizer · <organización>` | Título del tablero. |

El directorio de `--output` se crea si no existe. Consulta la ayuda con
`miner visualize --help`.

Si el documento de entrada no existe, el comando termina con código de salida `1`
y el mensaje `No existe el documento de entrada: <ruta>`; si no es JSON válido,
`Error al generar el Visualizer: ...`.

### Notebook

`notebooks/04_visualizer.ipynb` genera el tablero a partir del documento del
Analyzer. Se ejecuta junto con el resto de notebooks:

```bash
source .venv/bin/activate
pip install -e .[analyzer]     # nbformat, nbclient e ipykernel
python notebooks/execute.py
```

`notebooks/execute.py` recorre `notebooks/*.ipynb` en orden alfabético y fija el
directorio de trabajo en la raíz del repositorio; `04` se ejecuta después de
`03_sintesis_visualizer.ipynb`, que escribe `analyzer_output.json`. La salida
queda en `analysis/outputs/visualizer.html` (ignorado por git).

### Python

```python
from miner.visualizer import build_visualizer

build_visualizer(
    "analysis/outputs/analyzer_output.json",
    "analysis/outputs/visualizer.html",
)

# Con título propio:
build_visualizer(
    "analysis/outputs/analyzer_output.json",
    "analysis/outputs/visualizer.html",
    title="Seguridad · nombre-organizacion",
)
```

`build_visualizer(input_path, output_path, *, title=None)` devuelve la ruta del
HTML escrito. Lanza `FileNotFoundError` si el documento no existe y `ValueError`
si no es un objeto JSON válido. También puedes usar `render_html(document)` para
obtener el HTML como cadena.

Alternativa sin Typer: `python -m miner.visualizer --input ... --output ...`
(acepta `-i`, `-o` y `-t`).

## Estructura del tablero

El tablero agrupa las vistas en secciones, todas alimentadas por el documento:

| Sección | Qué muestra | Fuente |
| --- | --- | --- |
| Cabecera y avisos | Organización, origen, fecha, esquema y advertencias de `meta.warnings`. | `meta`, `schema_version` |
| KPIs | Repositorios, vulnerabilidades, Critical, High, nota global 1-10, cobertura y hotspots. | `meta`, `coverage`, `risk_summary`, `severity_distribution` |
| Distribución de severidad | Reparto global de vulnerabilidades por severidad. | `severity_distribution` |
| Riesgo por repositorio | Tabla **ordenable** con nota, gravedad media/mediana, peor severidad, conteos, densidad y reparabilidad. | `repository_risk` |
| Vulnerabilidades por repositorio | Volumen de vulnerabilidades por repositorio, coloreado por peor severidad. | `repository_risk` |
| Dispersión componentes vs vulnerabilidades | Diagrama de dispersión con el coeficiente de Pearson y el aviso «correlación ≠ causalidad». | `relations.components_vs_vulnerabilities` |
| Top paquetes | Paquetes más afectados y su peor severidad. | `top_packages` |
| Top CVEs / GHSA | Identificadores más repetidos. | `top_cves` |
| Severidad por tipo de paquete | Barras apiladas por severidad y tipo. | `relations.severity_by_package_type` |
| Severidad por lenguaje | Barras apiladas por severidad y lenguaje. | `relations.severity_by_language` |
| Top reglas CodeQL | Reglas con más hallazgos. | `top_rules` |
| Concentración y reparabilidad | Repos con vulnerabilidades, cuota top-N y decil superior, HHI, notas media/máxima por repo y corrección disponible. | `concentration`, `risk_summary`, `relations.fixed_version_available_share` |
| Observaciones y limitaciones | Afirmaciones del Analyzer y sus condiciones. | `observations`, `limitations` |

Si `repository_risk` no está presente pero sí `repository_distribution`, las
vistas por repositorio usan esa distribución como respaldo (sin nota ni medias).

Interacción:

- **Filtros combinables** por repositorio, severidad, tipo de paquete y lenguaje.
  Restringen qué repositorios aparecen en las vistas **por repositorio** (tabla
  de riesgo, barras por repositorio, dispersión y drill-down). Los indicadores y
  rankings globales (KPIs, nota global, distribución de severidad, top paquetes,
  top CVEs, severidad por tipo/lenguaje, top reglas, concentración y
  observaciones) se muestran precalculados y **no se filtran**; con filtros
  activos se muestra una nota aclaratoria.
- **Drill-down** por repositorio: al seleccionar un repositorio se muestran su
  resumen, sus vulnerabilidades y sus hallazgos CodeQL.
- **Tooltips** con la explicación de cada métrica, columna o punto.

## Características

- **Autocontenido y offline.** Un único archivo `.html` con datos, CSS y JS
  embebidos; se abre con doble clic, sin servidor ni conexión.
- **Determinismo.** El render es determinista: el mismo documento produce el
  mismo HTML. El único valor no determinista es el que ya traiga el documento
  (por ejemplo `meta.generated_at`).
- **Tolerancia a vacíos.** Las secciones sin datos no rompen el tablero: se
  omiten o muestran un mensaje.
- **Accesibilidad.** Idioma `es`, enlace «Saltar al contenido», contraste
  orientado a AA, `role="group"` en los filtros y en los gráficos SVG, `<title>`
  en los SVG, `aria-label`/`aria-sort` en controles y cabeceras, tablas con
  `caption` para lectores de pantalla, foco visible y respeto por
  `prefers-reduced-motion`.

## Personalización del título

Por defecto el título es `Visualizer · <organización>`; si el documento no trae
organización, `Visualizer · GitHub CodeQL Miner`. Puedes cambiarlo con `--title`
(CLI) o el argumento `title` (Python):

```bash
miner visualize --input analysis/outputs/analyzer_output.json \
  --output analysis/outputs/visualizer.html \
  --title "Postura de seguridad · nombre-organizacion"
```

## Regeneración cuando cambian los datos

El tablero es una **instantánea**: no se actualiza solo. Vuelve a generarlo
cuando cambie el documento del Analyzer (por ejemplo, tras un nuevo `miner scan`
o tras reejecutar el Analyzer):

```bash
# 1. Regenerar el documento del Analyzer
python notebooks/execute.py          # o run_analysis(...)

# 2. Volver a renderizar el tablero (sobrescribe el HTML)
miner visualize --input analysis/outputs/analyzer_output.json \
  --output analysis/outputs/visualizer.html
```

El Visualizer sobrescribe `--output`; no guarda estado ni historial.

## Limitaciones y buenas prácticas

- **Depende del contrato.** Si `analyzer_output.json` no corresponde al contrato
  1.1 o está incompleto, faltarán secciones. Regenera el documento con el
  Analyzer antes de renderizar.
- **Secciones sin datos.** Un documento de origen `sbom` no trae
  vulnerabilidades y uno de origen `vuln` no trae hallazgos ni SBOM; las vistas de
  cada dimensión solo aparecen si el documento las incluye.
- **Los filtros no rehacen los globales.** Al filtrar, los indicadores y rankings
  globales siguen mostrando los valores del documento completo; solo cambia el
  conjunto de repositorios de las vistas por repositorio.
- **No sustituye la revisión de seguridad.** El tablero presenta la evidencia del
  Analyzer; interpretarlo exige revisar `coverage`, `observations` y
  `limitations`, sobre todo con cobertura parcial o muestras pequeñas.
- **Correlación ≠ causalidad.** La dispersión componentes↔vulnerabilidades es
  exploratoria: un repositorio con más componentes no «causa» más
  vulnerabilidades.

## Solución de problemas

- **No existe el documento de entrada:** `miner visualize` termina con código `1`
  y `No existe el documento de entrada: <ruta>`. Genera primero
  `analysis/outputs/analyzer_output.json` con el Analyzer.
- **JSON inválido o que no es un objeto:** el comando muestra
  `Error al generar el Visualizer: ...` y termina con código `1`. Revisa que la
  ruta apunte al documento del Analyzer y que el archivo esté completo.
- **Secciones vacías:** comprueba el `schema_version` (debe ser `1.1`), el origen
  (`meta.source_kind`) y que el reporte de entrada tuviera datos para esa
  dimensión.
- **El tablero no se ve o aparece sin estilos:** reinstala la herramienta
  (`pip install -e .`) para recuperar los assets CSS/JS empaquetados.
- **`miner: command not found`:** activa el entorno virtual donde instalaste el
  paquete o usa `python -m miner.visualizer`.
