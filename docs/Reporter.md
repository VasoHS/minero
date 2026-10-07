# Reporter

## Qué es y qué no es

El Reporter es el cuarto componente de la solución. A diferencia del Miner y el
Analyzer, **no analiza los repositorios de la organización** ni usa los
resultados (`results.json`, `results-vuln.json`, `results-sbom.json`) que ellos
generan. Su objeto de análisis es **este mismo repositorio**: el código,
dependencias, configuración y workflows del proyecto `github-codeql-miner`.

Se ejecuta automáticamente (GitHub Actions) y produce un informe en Markdown
con los hallazgos, su evidencia y recomendaciones de mitigación.

## Referencia de diseño

Como referencia se usó el workflow
[`daily-action-setup-security-audit`](https://github.com/githubnext/gh-aw) de
GitHub Agentic Workflows: un agente que inspecciona un repositorio
periódicamente y reporta hallazgos de seguridad apoyado en un LLM.

El Reporter **no reproduce** ese workflow. Toma de él la idea general (ejecución
periódica, auditoría del propio repositorio, reporte legible) pero cambia el
mecanismo de fondo: en vez de dejar que el LLM explore el repositorio e infiera
hallazgos directamente, el Reporter separa la detección de la redacción:

```
repositorio → collector (determinista) → findings + cobertura → LLM → validador de citas → Markdown
```

Esta separación existe por un requisito explícito del proyecto: **las
afirmaciones deben tener trazabilidad con evidencia observable y no deben
presentarse como confirmadas situaciones sin respaldo**. Dejar que un LLM
reporte hallazgos sin una capa determinista previa hace casi imposible
garantizar esa trazabilidad y abre la puerta a alucinaciones (archivos, líneas
o CVEs inventados). Por eso:

- El **collector** (reglas deterministas en Python, sin LLM) es la única
  fuente de hallazgos. Cada uno tiene un ID estable, archivo, línea (cuando
  aplica) y evidencia textual.
- El **LLM** (vía OpenRouter) solo recibe esos hallazgos ya extraídos. Su
  trabajo es explicarlos, priorizarlos y proponer mitigaciones — no descubrir
  hallazgos nuevos por su cuenta.
- Un **validador de citas** posterior a la respuesta del LLM comprueba que
  todo ID que el modelo cita en su narrativa exista realmente entre los
  hallazgos. Si cita uno que no existe, el reporte final incluye una
  advertencia visible en vez de dejarlo pasar en silencio.
- Una tabla de **cobertura** indica qué verificaciones se ejecutaron, cuáles
  se omitieron (por ejemplo, por falta de Syft/Grype en el entorno) y cuáles
  no fueron concluyentes. Esto evita el error simétrico: que la ausencia de
  hallazgos en un área se lea como "está todo bien" cuando en realidad esa
  área no se pudo verificar.

## Arquitectura

```
src/miner/reporter/
├── __init__.py
├── collector.py   # reglas deterministas + ejecución de Syft/Grype sobre el propio repo
├── prompts.py      # instrucciones del sistema para el LLM
├── llm.py          # cliente HTTP de OpenRouter
└── report.py       # orquesta collector → LLM → validación → Markdown
```

Comando de CLI: `miner report` (definido en `src/miner/cli.py`, junto a `scan`,
`sbom`, `vuln` y `visualize`).

## Reglas implementadas

Cada hallazgo tiene un ID con prefijo por categoría, una severidad
(`high`/`medium`/`low`/`info`, o la severidad normalizada de Grype para
vulnerabilidades) y evidencia (archivo, línea cuando aplica, fragmento).

| Prefijo | Categoría | Qué detecta | Por qué importa |
|---|---|---|---|
| `SEC` | Secretos | Patrones de tokens de GitHub, keys de OpenRouter, keys de AWS y claves privadas, **solo en archivos que git versiona o versionaría** (se excluyen los ignorados, como `.env`) | Un secreto en un archivo versionado es recuperable por cualquiera con acceso de lectura al repositorio |
| `WF` | Workflows | Ausencia de bloque `permissions:`; acciones (`uses:`) no fijadas a un SHA de commit; uso de `pull_request_target`; `curl \| sh` o `wget \| sh` dentro de un `run:` | Permisos amplios por defecto, acciones mutables y scripts remotos sin verificar son vectores de *supply chain* conocidos en Actions |
| `DK` | Docker | Ausencia de instrucción `USER`; imagen base sin tag fijo o con `latest`; `curl \| sh` en una instrucción `RUN` | Contenedores que corren como root y bases no reproducibles amplían el impacto de una imagen comprometida |
| `HY` | Higiene | `.env` ausente de `.gitignore` | Sin esa entrada, un `git add .` accidental versiona secretos |
| `TR` | Archivos versionados | `.env`, claves (`.pem`/`.key`/`.p12`) o artefactos generados (`.zip`, `results*.json`) que están versionados | Expone datos sensibles o infla el repositorio con artefactos que deberían regenerarse, no versionarse |
| `DEP` | Dependencias | Ausencia de lockfile (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements*.txt`) cuando existe `pyproject.toml` | Sin versiones resueltas, los builds no son reproducibles y Syft/Grype no pueden resolver versiones exactas para buscar CVEs |
| `VUL` | Vulnerabilidades conocidas | CVEs de severidad `Critical`/`High` encontrados por Grype sobre un SBOM generado con Syft a partir de los archivos versionados del propio repositorio | Vulnerabilidades conocidas en las dependencias reales del proyecto |

El escaneo de secretos y de archivos versionados usa `git ls-files` (más, para
secretos, los archivos no rastreados pero no ignorados) en vez de recorrer todo
el disco, para no reportar como hallazgo algo que `.gitignore` ya protege (como
el propio `.env` local de quien ejecuta el Reporter).

## Garantías de trazabilidad

- **Nunca se guarda el valor real de un secreto.** El campo `evidence` de un
  hallazgo `SEC` siempre es `[REDACTED]`; solo se registra el archivo, la
  línea y el tipo de patrón que coincidió.
- **Todo hallazgo tiene un ID único y aparece en el apéndice** del reporte con
  su archivo, línea, regla y evidencia textual — la misma tabla que se envía
  al LLM.
- **El LLM debe citar el ID** de cada hallazgo que comente (`[SEC-001]`, por
  ejemplo). El reporte final valida esas citas contra los IDs reales:
  - Si el modelo cita un ID que no existe, se agrega una advertencia visible
    al inicio del reporte.
  - Si quedan hallazgos sin citar, se avisa también, para que no se pierdan
    silenciosamente.
- **El prompt del sistema prohíbe presentar indicios como confirmados**: un
  posible secreto se describe como "posible", nunca como "confirmado", y el
  modelo no puede inventar archivos, líneas o CVEs que no estén en el JSON de
  entrada.
- **La cobertura es explícita.** Si Syft o Grype no están disponibles, o si el
  SBOM resultante tiene 0 componentes, la tabla de cobertura lo indica como
  `omitido` o `no concluyente`, y el prompt instruye al modelo a no afirmar
  que esa área está libre de problemas en esos casos.

## Configuración

### Variables de entorno

| Variable | Obligatoria | Descripción |
|---|---|---|
| `OPENROUTER_API_KEY` | Sí (salvo con `--no-llm`) | Key de OpenRouter. Se lee del entorno y nunca se imprime ni se incluye en el reporte. |
| `OPENROUTER_MODEL` | No | Modelo a usar en OpenRouter (por ejemplo `openai/gpt-4o-mini`). Si no está definida, se usa un valor por defecto. |

### Local

```bash
cp .env.example .env
# edita .env y define OPENROUTER_API_KEY y, opcionalmente, OPENROUTER_MODEL
```

En PowerShell, carga las variables en la sesión actual antes de ejecutar el
comando:

```powershell
Get-Content .env | ForEach-Object {
  if ($_ -match '^\s*([^#=]+)=(.*)$') {
    [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
  }
}
```

### GitHub Actions

El secret `OPENROUTER_API_KEY` se configura en
**Settings → Secrets and variables → Actions → New repository secret**. El
workflow (`.github/workflows/security-report.yml`) lo inyecta como variable de
entorno al ejecutar `miner report`; nunca aparece en los logs del job.

## Uso

```bash
# Reporte completo, con LLM (requiere OPENROUTER_API_KEY)
miner report

# Solo evidencia, sin gastar créditos de LLM
miner report --no-llm

# Rutas personalizadas
miner report --root . --output reports/security-report.md
```

| Opción | Por defecto | Descripción |
|---|---|---|
| `--root` | `.` | Raíz del repositorio a auditar |
| `--output` | `reports/security-report.md` | Archivo Markdown de salida |
| `--llm / --no-llm` | `--llm` | Usar o no el modelo de lenguaje para redactar el reporte |

El resultado incluye: un resumen de hallazgos por severidad redactado por el
LLM (o un marcador cuando se usa `--no-llm`), la tabla de cobertura y el
apéndice completo de evidencia.

## Ejecución automática

`.github/workflows/security-report.yml` ejecuta el Reporter:

- Diariamente (`schedule`), y
- Manualmente desde la pestaña **Actions** (`workflow_dispatch`).

El job instala Syft y Grype (para que la verificación `DEP`/`VUL` se ejecute
en el runner y no quede `omitido`), corre `miner report`, publica el
contenido en el resumen del job (`GITHUB_STEP_SUMMARY`), sube el archivo como
artefacto descargable y hace commit del reporte actualizado en
`reports/security-report.md`.

## Limitaciones conocidas

- **Las reglas son heurísticas**, no un analizador semántico. Pueden producir
  falsos positivos (por ejemplo, un patrón que coincide con un secreto de
  prueba en un test) y no cubren todas las formas posibles de mala
  configuración.
- **El escaneo de dependencias depende de un lockfile.** Sin versiones
  resueltas, Syft genera menos componentes (o ninguno) y Grype tiene menos
  base para encontrar CVEs; el hallazgo `DEP-001` existe precisamente para
  señalar esta limitación cuando ocurre.
- **El LLM puede seguir equivocándose** en matices de severidad o redacción
  aunque no pueda inventar hallazgos nuevos citables; por eso el apéndice de
  evidencia siempre acompaña al reporte y es la fuente de verdad final.
- **No reemplaza una auditoría manual o herramientas dedicadas** (por ejemplo,
  GitHub Advanced Security, Dependabot o un pentest). Es un mecanismo de
  revisión continua y liviano, pensado para este proyecto académico.

## Diferencias con el workflow de referencia

| `daily-action-setup-security-audit` (gh-aw) | Reporter de este proyecto |
|---|---|
| Un agente LLM explora el repositorio y decide qué reportar | Un collector determinista decide los hallazgos; el LLM solo los redacta |
| Pensado como agente autónomo con herramientas de GitHub | CLI propia (`miner report`) integrada al resto del Miner/Analyzer/Visualizer |
| Sin validación explícita de que las citas del LLM existan | Validación de citas obligatoria contra los IDs de evidencia real |
| — | Tabla de cobertura que distingue "sin hallazgos" de "no verificado" |
