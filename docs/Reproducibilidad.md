# Reproducibilidad con Docker

La documentación de las vías Docker del proyecto está **centralizada** en
[`Docker.md`](Docker.md). Este documento se conserva como punto de entrada para
enlaces existentes.

- **Imagen de runtime** ([`Dockerfile`](../Dockerfile),
  [`docker-compose.yml`](../docker-compose.yml)): ejecutar **solo la CLI `miner`**
  (`scan`, `sbom`, `vuln`). Incluye Python 3.12, `git`, CodeQL, Syft y Grype.
- **Dev Container** ([`.devcontainer/`](../.devcontainer)): **entorno de
  desarrollo completo** con CLI, notebooks, tests y Analyzer/Visualizer. Añade
  Node.js/npm, los extras `[dev,analyzer]` y el puerto Jupyter.

Ambas comparten la base `python:3.12-slim-bookworm` y las mismas versiones fijadas
de las herramientas externas, de modo que una ejecución en el Dev Container y una
en la imagen de runtime usan el mismo *toolchain*.

Consulta [`Docker.md`](Docker.md) para la guía completa: construcción, ejecución,
Docker Compose, gestión del token, flujo del Dev Container, reejecución de
`post-create.sh`, limitaciones y solución de problemas. Para el detalle del
entorno de desarrollo, consulta también
[`.devcontainer/README.md`](../.devcontainer/README.md).
