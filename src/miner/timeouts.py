"""Tiempos máximos configurables para los subprocesos externos del Miner.

Los valores se pueden sobrescribir con variables de entorno para adaptar el
análisis a repositorios o máquinas más lentas sin tocar el código.
"""

import os

# Tope por defecto (segundos) para clone, Syft y Grype.
DEFAULT_SUBPROCESS_TIMEOUT = 1800
# Tope por defecto (segundos) para las operaciones de CodeQL, más costosas.
DEFAULT_CODEQL_TIMEOUT = 7200


def _env_seconds(name: str, default: int) -> int:
    """Lee un entero positivo de una variable de entorno, o usa el valor por defecto."""
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


SUBPROCESS_TIMEOUT = _env_seconds("MINER_TIMEOUT", DEFAULT_SUBPROCESS_TIMEOUT)
CODEQL_TIMEOUT = _env_seconds("MINER_CODEQL_TIMEOUT", DEFAULT_CODEQL_TIMEOUT)
