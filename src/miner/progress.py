"""Seguimiento en tiempo real del escaneo de vulnerabilidades con Grype.

Este módulo concentra la presentación del avance de Grype y el registro de
los posibles errores que aparezcan durante la evaluación. La salida es
secuencial (una línea por evento) y no depende de un TTY, por lo que también
sirve para CI. Además de mostrarlos, los errores se anexan a un archivo de log
para su revisión posterior.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import typer

# Líneas de Grype que merecen registrarse como error o advertencia.
# Cubre singular/plural (error/errors, warning/warnings, failed/failure...).
_ERROR_PATTERN = re.compile(
    r"(?i)\b(errors?|fatal|panic|warn(?:ing)?s?|fail(?:ed|ures?)?)\b"
)


class VulnProgress:
    """Muestra el avance de Grype y guarda los errores en un log.

    Parámetros
    ----------
    log_file:
        Ruta del archivo donde se anexan los errores. Si es ``None`` no se
        escribe ningún log.
    enabled:
        Si es ``False`` no se imprime en pantalla (útil para CI o cuando se
        pasa ``--no-progress``), pero el log sigue escribiéndose.
    """

    def __init__(self, log_file: Optional[Path] = None, enabled: bool = True):
        self.enabled = enabled
        self.errors: List[str] = []
        self._label: Optional[str] = None
        self.log_file = log_file
        if log_file is not None:
            try:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                # Cada ejecución comienza con un log limpio.
                log_file.write_text("", encoding="utf-8")
            except OSError:
                # Un log no escribible no debe interrumpir el escaneo.
                self.log_file = None

    def set_label(self, label: Optional[str]) -> None:
        """Fija el repositorio actual para prefijar los mensajes."""
        self._label = label

    def info(self, message: str) -> None:
        """Muestra una línea de avance normal."""
        if self.enabled:
            typer.echo(self._format(message))

    def error(self, message: str, prefix: bool = True) -> None:
        """Muestra y registra un error (o advertencia) de la evaluación."""
        self.errors.append(message)
        self._write_log(message)
        if self.enabled:
            text = f"ERROR: {message}" if prefix else message
            typer.secho(self._format(text), fg=typer.colors.RED)

    def line(self, message: str) -> None:
        """Procesa una línea emitida por Grype en tiempo real.

        Las líneas con pinta de error o advertencia se muestran en rojo y se
        registran en el log; el resto se muestra como avance normal.
        """
        if self._looks_like_error(message):
            self.error(message, prefix=False)
        else:
            self.info(message)

    @staticmethod
    def _looks_like_error(line: str) -> bool:
        """Indica si una línea de Grype parece un error o una advertencia."""
        return bool(_ERROR_PATTERN.search(line))

    def _format(self, message: str) -> str:
        if self._label:
            return f"  [{self._label}] {message}"
        return f"  {message}"

    def _write_log(self, message: str) -> None:
        if self.log_file is None:
            return
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            with open(self.log_file, "a", encoding="utf-8") as handle:
                handle.write(f"{timestamp} {message}\n")
        except OSError:
            pass
