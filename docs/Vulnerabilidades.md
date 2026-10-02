# Vulnerabilidades en GitHub CodeQL Miner

Referencia detallada del escaneo de vulnerabilidades con **Grype** (Anchore). Para la descripción general, instalación y uso de la CLI consulta el [`README.md`](../README.md).

## Cómo funciona

Al procesar cada repositorio, la herramienta ejecuta internamente:

```bash
grype sbom:<sboms/repositorio>.cdx.json -o json --file <vulns/repositorio>.grype.json
```

Si no hay un SBOM válido (no se generó o falló), Grype cataloga directamente el directorio del repositorio:

```bash
grype dir:<repositorio> -o json --file <vulns/repositorio>.grype.json
```

Además consulta la versión instalada con:

```bash
grype version -o json
```

El escaneo es **independiente de CodeQL y del lenguaje**: se ejecuta justo después del SBOM y antes de la detección de lenguaje. Un repositorio `unsupported` (o cuyo análisis CodeQL falle) puede tener igualmente vulnerabilidades.

En `miner scan`, el orden por repositorio es: clonado → **SBOM** → **Grype** → lenguaje → CodeQL. El comando `miner vuln` reutiliza los SBOM ya generados y no clona repositorios ni ejecuta CodeQL.

## Relación con el SBOM

Grype reutiliza el SBOM de Syft: si existe un SBOM válido (`sbom.status` es `generated` o `no_components`), escanea `sbom:<ruta.cdx.json>`. Si no hay SBOM válido (por ejemplo, con `--no-sbom`, o si Syft falló), escanea el propio directorio con `dir:<repositorio>`, ya que Grype incorpora el catalogador de Syft.

Esto implica que la calidad del inventario afecta al escaneo:

- Un SBOM con versiones resueltas (con lockfile) permite a Grype identificar paquetes y versiones concretas.
- Un SBOM sin componentes (`no_components`) o un escaneo del directorio pueden producir menos hallazgos si no se resuelven las versiones (p. ej. npm sin archivo de bloqueo).

## Ubicación de los archivos

Los reportes crudos de Grype se escriben en `--vuln-dir` (por defecto `./vulns`), un archivo JSON por repositorio:

```
vulns/
├── demo-app.grype.json
├── otro-repositorio.grype.json
└── errores.log
```

El archivo `errores.log` es el log del seguimiento de Grype (ver **Seguimiento en tiempo real y log de errores**).

## Seguimiento en tiempo real y log de errores

Tanto `miner scan` (cuando el escaneo de vulnerabilidades está activo, es decir, sin `--no-vuln`) como `miner vuln` pueden mostrar el avance de Grype en tiempo real, línea a línea, prefijado con el nombre del repositorio:

```bash
Procesando: demo-app...
  [demo-app]  ✔ Vulnerability DB                [no update available]
  [demo-app]  ✔ Cataloged packages              [12 packages]
  [demo-app] [0000]  WARN no explicit name provided for directory source
  [demo-app]  ✔ Scanned image                   [2 vulnerabilities]
```

Cuando el seguimiento está activo, Grype se ejecuta con `Popen` fusionando `stdout` y `stderr` (Grype escribe el JSON en `--file` y el progreso en `stderr`), de modo que cada línea se procesa a medida que se emite. El resultado del escaneo no depende de esto: el JSON se sigue escribiendo en `--vuln-dir`.

### Flag `--progress / --no-progress`

| Opción | Valor por defecto | Comportamiento |
| --- | --- | --- |
| `--progress` | auto | Fuerza la salida del avance en tiempo real. |
| `--no-progress` | — | No imprime el avance en pantalla. Los errores siguen registrándose en el log. |
| (ninguno) | auto | Muestra el avance solo si la salida es una terminal (TTY). |

En `miner scan`, el seguimiento solo existe si el escaneo de vulnerabilidades está activo; con `--no-vuln` no se muestra ni la sección final de errores. En `miner vuln` siempre está activo.

### Clasificación de líneas

Cada línea emitida por Grype se clasifica con una expresión regular que ignora mayúsculas y busca palabras completas `error`, `fatal`, `panic`, `warn`/`warning` o `failed`:

- Si coincide, se considera un error o advertencia: se muestra en rojo y se añade al log.
- Si no coincide, se muestra como avance normal.

La distinción es solo de presentación: no altera el estado del escaneo ni los hallazgos.

### Archivo de log de errores

| Aspecto | Detalle |
| --- | --- |
| Ruta por defecto | `<vuln-dir>/errores.log` (por defecto `vulns/errores.log`). |
| Opción | `--error-log RUTA`. |
| Formato | Una línea por error, con marca temporal UTC en ISO 8601: `<timestamp> <mensaje>`. |
| Duración | Cada ejecución **trunca** el archivo al empezar. |
| Con `--no-progress` | El log se sigue escribiendo. |

Además de las líneas detectadas en la salida de Grype, el log incluye los errores que reporta el propio ejecutor (por ejemplo, no poder preparar o leer el reporte de Grype).

### Sección final de errores

Al terminar el comando se imprime un resumen:

- Sin errores: `Sin errores durante la evaluación de Grype.`
- Con errores: `Errores durante la evaluación (N):`, la lista de mensajes (`  - <mensaje>`) y `Log completo: <ruta>`.

> **El informe JSON no cambia:** el seguimiento y el log son solo informativos. No se agregan campos al reporte ni se modifican los estados `scanned`/`no_vulnerabilities`/`failed` ni los contadores de `summary`.

## Campos del objeto `vulnerabilities`

En cada entrada de `repositories` del informe JSON:

| Campo | Tipo | Descripción |
| --- | --- | --- |
| `status` | string | Estado del escaneo (ver tabla inferior). |
| `total` | int | Número de vulnerabilidades detectadas. |
| `by_severity` | object | Conteo por severidad, incluyendo los ceros (`Critical`, `High`, `Medium`, `Low`, `Negligible`, `Unknown`). |
| `vulnerabilities` | array | Lista de hallazgos (ver abajo). |
| `grype_version` | string \| null | Versión de Grype usada, o `null` si no se pudo determinar. |
| `generated_at` | string | Marca temporal UTC en ISO 8601, p. ej. `2026-09-25T12:35:10.123456+00:00`. |
| `file` | string | Ruta del reporte de Grype generado. |

### Hallazgos (`vulnerabilities[]`)

| Campo | Tipo | Descripción |
| --- | --- | --- |
| `id` | string | Identificador de la vulnerabilidad (p. ej. `CVE-2021-44228`); `unknown` si Grype no lo informa. |
| `severity` | string | Severidad normalizada (ver abajo). |
| `package` | string | Nombre del paquete afectado; `unknown` si no se informa. |
| `version` | string \| null | Versión del paquete detectada. |
| `type` | string \| null | Tipo de paquete reportado por Grype (p. ej. `deb`, `python`, `java-archive`). |
| `fixed_version` | string \| null | Primera versión con corrección disponible, o `null` si no hay. |
| `namespace` | string \| null | Espacio de nombres de la fuente de datos (p. ej. `debian:11`, `nvd`). |

## Estados del escaneo

| Estado | ¿Éxito? | Significado |
| --- | --- | --- |
| `scanned` | Sí | Grype terminó correctamente y encontró una o más vulnerabilidades. |
| `no_vulnerabilities` | Sí | Grype terminó correctamente pero no encontró vulnerabilidades. |
| `failed` | No | Grype falló (binario no encontrado, error de ejecución o de lectura/escritura del reporte). |
| `skipped` | — | No se solicitó el escaneo (`--no-vuln`); es el estado por defecto. |

Es fundamental distinguir **ejecución fallida** (`failed`) de **ejecución exitosa sin hallazgos** (`no_vulnerabilities`):

- `failed` implica un problema con Grype (o con su base de datos); el resultado no es fiable y conviene revisar la instalación (`grype version`).
- `no_vulnerabilities` indica que Grype funcionó correctamente pero no encontró coincidencias; no es un error.

> **Estado de repositorio `scanned`:** además del estado de cada `vulnerabilities.status`, el comando `miner vuln` marca cada entrada de `repositories` con `status = "scanned"`, que solo aparece en ese reporte.

## Normalización de severidades y orden

Grype informa severidades que la herramienta normaliza a uno de estos valores canónicos:

`Critical`, `High`, `Medium`, `Low`, `Negligible`, `Unknown`.

La comparación **ignora mayúsculas y espacios**; cualquier valor no reconocido se clasifica como `Unknown`. En `by_severity` siempre aparecen las seis claves, con `0` cuando no hay hallazgos de esa severidad.

Los hallazgos se ordenan de forma **determinista**: primero por severidad (Critical primero, `Unknown` al final), luego por nombre de paquete y por último por `id`. Así, dos ejecuciones sobre el mismo inventario producen el mismo orden.

## Contadores en `summary`

| Campo | Se incrementa cuando... |
| --- | --- |
| `vulns_scanned` | El escaneo termina con `scanned` **o** `no_vulnerabilities` (ejecución exitosa). |
| `vulns_failed` | El escaneo termina con `failed`. |
| `vulnerabilities` | Suma de vulnerabilidades de todos los escaneos exitosos. |
| `vulns_critical` | Suma de vulnerabilidades con severidad `Critical`. |
| `vulns_high` | Suma de vulnerabilidades con severidad `High`. |
| `vulns_medium` | Suma de vulnerabilidades con severidad `Medium`. |
| `vulns_low` | Suma de vulnerabilidades con severidad `Low`. |

Con `--no-vuln`, los escaneos quedan en `skipped` y no afectan a ninguno de estos contadores.

## Ejemplo

Fragmento de un informe generado por `miner scan` para `demo-app`:

```json
{
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
```

## Solución de problemas de Grype

- **`grype` no encontrado** (estado `failed` y advertencia `Advertencia: no se pudo determinar la versión de Grype...`): instala Grype (consulta la sección **Instalación de Grype** del [`README.md`](../README.md)) y verifica con `grype version`. Para omitir el escaneo usa `--no-vuln`.
- **Base de datos de vulnerabilidades no descargable**: la primera ejecución descarga la base de Grype y necesita conexión a Internet. Si falla, el escaneo queda como `failed`; comprueba la red o el proxy y reintenta. Puedes forzar la actualización con `grype db update`.
- **Ninguna vulnerabilidad (`no_vulnerabilities`)**: no es un error. Comprueba que el SBOM incluya versiones resueltas (en npm hace falta un archivo de bloqueo) o que la base de datos conozca los paquetes del inventario.
- **No se generan reportes de Grype**: asegúrate de no haber pasado `--no-vuln` y de que `miner scan` haya podido clonar el repositorio. En `miner vuln`, `--sbom-dir` debe existir y contener archivos `*.cdx.json`.
- **`miner vuln` no encuentra SBOM**: `--sbom-dir` debe existir y contener archivos `*.cdx.json`. Ejecuta antes `miner scan` o `miner sbom` (con `--keep-repos`, valor por defecto, si necesitas reutilizar los clones).
- **Advertencias o errores visibles durante el escaneo**: las líneas con `error`, `fatal`, `panic`, `warning`/`warn` o `failed` se muestran en rojo, se resumen al final y quedan en `vulns/errores.log` (o en `--error-log RUTA`). Un mensaje de advertencia no implica necesariamente que el escaneo haya fallado: revisa el `vulnerabilities.status` y el log completo. El log se trunca en cada ejecución y, con `--no-progress`, no se imprime el avance pero sí se escribe el log.
