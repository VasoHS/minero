"""Render del tablero HTML autocontenido del Visualizer.

Toma el documento del Analyzer y produce un único HTML con:

- el documento embebido en ``<script id="analyzer-data" type="application/json">``;
- el CSS y el JS del tablero embebidos (leídos de ``assets/``).

No hay dependencias externas ni peticiones de red: el archivo resultante se abre
con doble clic. El render es determinista salvo por los valores ya presentes en
el documento (p. ej. ``meta.generated_at``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

__all__ = ["render_html", "ASSETS_DIR"]

#: Directorio con los assets del tablero (``dashboard.css`` y ``dashboard.js``).
ASSETS_DIR = Path(__file__).resolve().parent / "assets"

#: Plantilla HTML. Los marcadores se sustituyen sin escapar (el JSON se escapa
#: aparte para no romper el ``<script>``).
_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="generator" content="github-codeql-miner visualizer">
<meta name="color-scheme" content="light dark">
<style>
{css}
</style>
</head>
<body>
<a class="skip-link" href="#app">Saltar al contenido</a>
<div id="app" role="main"></div>
<script id="analyzer-data" type="application/json">{data}</script>
<script>
{js}
</script>
</body>
</html>
"""


def _read_asset(name: str) -> str:
    """Lee un asset del tablero; lanza ``FileNotFoundError`` si no existe."""
    return (ASSETS_DIR / name).read_text(encoding="utf-8")


def _json_default(value: Any) -> Any:
    """Convierte escalares no nativos (p. ej. NumPy) a tipos JSON nativos."""
    item = getattr(value, "item", None)
    if callable(item):
        return item()
    raise TypeError(f"Tipo no serializable en JSON: {type(value).__name__}")


def _embed_json(document: Any) -> str:
    """Serializa el documento para embeberlo en un ``<script>`` de forma segura.

    Se escapan ``<``, ``>`` y los separadores de línea U+2028/U+2029 como
    secuencias ``\\uXXXX``, de modo que ninguna cadena del documento pueda cerrar
    el bloque ``<script>`` ni activar los estados de *script data escaped*
    (``</script>``, ``<!--<script>``). ``JSON.parse`` reconstruye el valor
    original.
    """
    text = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        default=_json_default,
    )
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _default_title(document: Dict[str, Any]) -> str:
    """Título por defecto a partir de la organización del documento."""
    organization = ""
    meta = document.get("meta")
    if isinstance(meta, dict):
        organization = str(meta.get("organization") or "").strip()
    if organization:
        return f"Visualizer · {organization}"
    return "Visualizer · GitHub CodeQL Miner"


def render_html(
    document: Union[Dict[str, Any], str, Path],
    *,
    title: Optional[str] = None,
) -> str:
    """Genera el HTML del tablero a partir del documento del Analyzer.

    Parámetros
    ----------
    document:
        Documento del Analyzer como ``dict``, o ruta a un JSON (``str``/``Path``).
        Cuando es una ruta se carga con :func:`miner.visualizer.build.load_document`.
    title:
        Título del documento HTML. Si es ``None`` se usa
        ``"Visualizer · <organización>"``.

    Devuelve una cadena HTML autocontenida. Lanza ``TypeError`` si ``document``
    no es un objeto JSON.
    """
    if isinstance(document, (str, Path)):
        # Import diferido para evitar el ciclo render <-> build.
        from .build import load_document

        document = load_document(document)

    if not isinstance(document, dict):
        raise TypeError("El documento del Analyzer debe ser un objeto JSON (dict).")

    resolved_title = title.strip() if isinstance(title, str) and title.strip() else None
    return _TEMPLATE.format(
        title=_escape_html(resolved_title or _default_title(document)),
        css=_read_asset("dashboard.css"),
        data=_embed_json(document),
        js=_read_asset("dashboard.js"),
    )


def _escape_html(text: str) -> str:
    """Escapa el texto que se interpola en el HTML (título)."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
