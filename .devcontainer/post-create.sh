#!/usr/bin/env bash
#
# postCreateCommand del Dev Container del GitHub CodeQL Miner.
#
# Instala el proyecto en modo editable (extras [dev,analyzer]) y verifica que
# todas las herramientas externas estén disponibles. Es idempotente: puede
# reejecutarse sin romper nada (pip install -e y el registro del kernel
# sobrescriben sin problema).
#
# Uso:  bash .devcontainer/post-create.sh
#
set -euo pipefail

# Raíz del repositorio = directorio padre de este script (.devcontainer/).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo "==> Raíz del repositorio: ${REPO_ROOT}"

echo "==> Actualizando pip"
python -m pip install --upgrade pip

echo "==> Instalando el proyecto en modo editable con extras [dev,analyzer]"
python -m pip install -e ".[dev,analyzer]"

# Registra el kernel "python3" que usan notebooks/execute.py y Jupyter.
# Idempotente: reinstalar el kernelspec del mismo nombre lo sobrescribe.
echo "==> Registrando el kernel de Jupyter 'python3'"
python -m ipykernel install --user --name python3 --display-name "Python 3 (miner)"

# Comprueba que cada comando exista en el PATH; si falta, falla con un mensaje
# claro en lugar de dejar el contenedor a medias.
check_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: la herramienta '${cmd}' no está instalada o no está en el PATH." >&2
    echo "       Reconstruye el Dev Container (Dev Containers: Rebuild Container)." >&2
    exit 1
  fi
}

echo "==> Verificando herramientas"
check_cmd python; python --version
check_cmd git;    git --version
check_cmd node;   node --version
check_cmd npm;    npm --version
check_cmd codeql; codeql version
check_cmd syft;   syft version
check_cmd grype;  grype version

echo "==> Entorno listo. Prueba rápida:  python -m pytest -q"
