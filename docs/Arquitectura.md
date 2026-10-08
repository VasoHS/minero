# Arquitectura del Proyecto P1

Este documento describe la arquitectura de la solución, las responsabilidades de
cada componente, los flujos de datos y las principales decisiones de diseño.

## Vista general

La solución tiene **dos propósitos distintos** y, por lo tanto, **dos flujos**:

```
                         ┌──────────────────────────────────────────────┐
                         │  Flujo 1: análisis de software EXTERNO       │
                         │                                              │
  GitHub (organización)  │   Miner ──► Analyzer ──► Visualizer          │
  ──────────────────────►│  (evidencia) (métricas)   (tablero HTML)     │
                         └──────────────────────────────────────────────┘

                         ┌──────────────────────────────────────────────┐
                         │  Flujo 2: autoevaluación del PROPIO repo     │
                         │                                              │
  Este repositorio       │   Reporter ──► reports/security-report.md    │
  ──────────────────────►│  (recolector + LLM)                          │
                         └──────────────────────────────────────────────┘
```

Los flujos son **independientes**: el Reporter no consume la evidencia del Miner
ni del Analyzer.

## Componentes y responsabilidades

| Componente | Responsabilidad | Entrada | Salida | Implementación |
| --- | --- | --- | --- | --- |
| **Miner** | Obtener evidencia de seguridad de la organización | GitHub API | `results.json` / `results-sbom.json` / `results-vuln.json`, `sboms/`, `vulns/` | `src/miner/` (CLI Python) |
| **Analyzer** | Transformar la evidencia en métricas y observaciones | reportes del Miner | `analysis/outputs/analyzer_output.json` (contrato) | `analysis/` (notebooks) |
| **Visualizer** | Explorar y comunicar los resultados | `analyzer_output.json` | `analysis/outputs/visualizer.html` (offline) | `src/miner/visualizer/` (JS/HTML/CSS) |
| **Reporter** | Auditar la seguridad de **este** repositorio | el propio repositorio | `reports/security-report.md` | `src/miner/reporter/` (Python + LLM) |

## Contratos de datos

La comunicación entre Miner, Analyzer y Visualizer se realiza **mediante
archivos**, no mediante imports entre paquetes:

- **Miner → Analyzer**: reportes JSON del Miner (`results*.json`).
- **Analyzer → Visualizer**: documento versionado (`schema_version` `1.1`)
  definido en `analysis/contracts/analyzer_output.schema.json` y validado por
  `analysis/contract.py`.
- **Reporter**: no usa ningún contrato del flujo 1; produce Markdown.

El contrato del Analyzer es la frontera estable: el Visualizer depende de ese
documento y no del código de los notebooks.

## Separación de componentes

- **Analyzer** vive en un directorio top-level (`analysis/`).
- **Miner**, **Visualizer** y **Reporter** viven como **subpaquetes separados**
  dentro del paquete `miner` (`src/miner/`, `src/miner/visualizer/`,
  `src/miner/reporter/`), cada uno con su propia responsabilidad y **sin imports
  cruzados** con `analysis/`.
- El **Reporter es independiente en propósito e insumo**: no lee los resultados
  del Miner/Analyzer. Reutiliza únicamente utilidades de bajo nivel del paquete
  (`sbom_runner`, `grype_runner`) para ejecutar Syft/Grype sobre el propio
  repositorio; no reutiliza su evidencia.

## Decisiones de diseño

1. **Evidencia primero, LLM después (Reporter).** Un recolector determinista
   detecta hallazgos con evidencia (`archivo:línea`) y el modelo solo redacta y
   prioriza. Un validador comprueba que cada cita `[ID]` del modelo exista entre
   los hallazgos reales, evitando alucinaciones.
2. **Datos redactados hacia el LLM.** El prompt nunca incluye el contenido de
   `.env` ni secretos: las coincidencias se reemplazan por `[REDACTED]` y solo se
   envían los hallazgos estructurados, no el código completo.
3. **Herramientas fijadas por versión.** CodeQL, Syft, Grype y Node.js se fijan
   por versión en `.devcontainer/Dockerfile` y en el `Dockerfile` de runtime. El
   lockfile `requirements.lock.txt` fija las dependencias de Python.
4. **Ejecución sistemática y aislada (Miner).** El Miner recorre todos los
   repositorios, aísla los fallos por repositorio, aplica *timeouts* a los
   subprocesos y permite reanudar (`miner sbom` / `miner vuln` reutilizan
   clones/SBOM).
5. **Visualizer autocontenido.** El tablero es un único HTML con CSS/JS
   embebidos, sin CDN, para que funcione offline y pueda regenerarse al
   reprocesar los datos.
6. **Dos vías de contenedor.** El Dev Container ofrece el entorno completo de
   desarrollo; la imagen de runtime empaqueta solo la CLI del Miner.

## Cómo se ejecuta

Consulta `README.md` y `docs/Docker.md`. Resumen:

```bash
# Flujo 1
miner scan --organization <org> --output results.json
python notebooks/execute.py
miner visualize --input analysis/outputs/analyzer_output.json \
  --output analysis/outputs/visualizer.html

# Flujo 2 (autoevaluación)
miner report --output reports/security-report.md
```
