# syntax=docker/dockerfile:1
#
# Imagen del Dev Container del GitHub CodeQL Miner.
#
# A diferencia del Dockerfile de runtime (que empaqueta el Miner y arranca la
# CLI), esta imagen solo prepara el *entorno de desarrollo*: Python 3.12, Node.js
# y las herramientas externas (CodeQL CLI, Syft y Grype) con versiones fijadas.
# El repositorio se monta desde el anfitrión y se instala en modo editable en el
# postCreateCommand, de modo que los cambios se reflejan sin reconstruir.
#
# Construcción (contexto = raíz del repositorio):
#   docker build -f .devcontainer/Dockerfile -t miner-devcontainer .
#
# Las versiones se fijan con build args para que la imagen sea reproducible.

FROM python:3.12-slim-bookworm

# Versiones de las herramientas externas. Deben coincidir con el Dockerfile de
# runtime (raíz del repositorio); se pueden sobrescribir con --build-arg.
ARG CODEQL_VERSION=2.27.1
ARG SYFT_VERSION=1.51.0
ARG GRYPE_VERSION=0.120.0

LABEL org.opencontainers.image.title="GitHub CodeQL Miner (Dev Container)" \
      org.opencontainers.image.description="Entorno de desarrollo reproducible: Python 3.12, Node.js, CodeQL, Syft y Grype"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/codeql:${PATH}"

# Dependencias del sistema: git (clonado), curl y unzip (descarga de las
# herramientas), ca-certificates (HTTPS), Node.js/npm (análisis CodeQL de
# JavaScript/TypeScript) y utilidades básicas de desarrollo.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      unzip \
      sudo \
      procps \
      less \
      nodejs \
      npm \
 && rm -rf /var/lib/apt/lists/*

# CodeQL CLI: bundle oficial que incluye la CLI y los query packs estándar.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64) codeql_asset="codeql-linux64.zip" ;; \
      arm64) codeql_asset="codeql-linux-arm64.zip" ;; \
      *) echo "Arquitectura no soportada para CodeQL: ${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/codeql.zip \
      "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/${codeql_asset}"; \
    unzip -q /tmp/codeql.zip -d /opt; \
    rm /tmp/codeql.zip; \
    codeql version

# Los shells de login (p. ej. `bash -lc` de VS Code) reconstruyen el PATH desde
# /etc/profile y descartan el ENV de la imagen; este snippet garantiza que
# /opt/codeql siga en el PATH también en esos casos.
RUN printf '%s\n' 'export PATH="/opt/codeql:${PATH}"' > /etc/profile.d/codeql-path.sh \
 && chmod 0644 /etc/profile.d/codeql-path.sh

# Syft (SBOM) y Grype (vulnerabilidades) desde sus releases oficiales.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64 | arm64) : ;; \
      *) echo "Arquitectura no soportada: ${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/syft.tar.gz \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${arch}.tar.gz"; \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft; \
    rm /tmp/syft.tar.gz; \
    curl -fsSL -o /tmp/grype.tar.gz \
      "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${arch}.tar.gz"; \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype; \
    rm /tmp/grype.tar.gz; \
    syft version; \
    grype version

# Usuario sin privilegios (convención de Dev Containers): UID/GID 1000 y sudo
# sin contraseña. Crear de forma defensiva por si el GID ya existiera.
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=1000
RUN set -eux; \
    if ! getent group "${USER_GID}" >/dev/null; then \
      groupadd --gid "${USER_GID}" "${USERNAME}"; \
    fi; \
    if ! id -u "${USERNAME}" >/dev/null 2>&1; then \
      useradd --uid "${USER_UID}" --gid "${USER_GID}" --create-home --shell /bin/bash "${USERNAME}"; \
    fi; \
    echo "${USERNAME} ALL=(root) NOPASSWD:ALL" > "/etc/sudoers.d/${USERNAME}"; \
    chmod 0440 "/etc/sudoers.d/${USERNAME}"; \
    # El intérprete y pip viven en /usr/local: se ceden a vscode para que el
    # postCreateCommand pueda instalar el proyecto sin sudo.
    chown -R "${USERNAME}:${USER_GID}" /usr/local

USER ${USERNAME}

WORKDIR /workspaces
