# syntax=docker/dockerfile:1
#
# Imagen del GitHub CodeQL Miner.
#
# Incluye todo lo necesario para ejecutar la CLI sin instalar nada en el
# anfitrión: Python, git, CodeQL CLI, Syft y Grype. Las herramientas externas se
# fijan por versión con build args para que la imagen sea reproducible.
#
# Construcción:
#   docker build -t github-codeql-miner .
#
# Uso (los resultados se escriben en el directorio actual):
#   docker run --rm --env-file .env -v "$PWD:/data" github-codeql-miner \
#     scan --organization <org> --output results.json

FROM python:3.12-slim-bookworm

# Versiones de las herramientas externas. Se pueden sobrescribir en la
# construcción con --build-arg.
ARG CODEQL_VERSION=2.27.1
ARG SYFT_VERSION=1.51.0
ARG GRYPE_VERSION=0.120.0

LABEL org.opencontainers.image.title="GitHub CodeQL Miner" \
      org.opencontainers.image.description="Miner de vulnerabilidades con CodeQL, Syft y Grype"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/codeql:${PATH}"

# Dependencias del sistema: git (clonado), curl y unzip (descarga de las
# herramientas) y ca-certificates (HTTPS hacia GitHub y ghcr.io).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      unzip \
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

# Usuario sin privilegios para ejecutar el escaneo.
RUN useradd --create-home --uid 1000 --shell /bin/bash miner

# Paquete del Miner y sus dependencias Python.
WORKDIR /opt/miner
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install .

# Directorio de trabajo: aquí se clonan los repositorios y se escriben los
# reportes. Se recomienda montar el directorio del anfitrión sobre /data.
WORKDIR /data
RUN mkdir -p /data && chown -R miner:miner /data

USER miner

ENTRYPOINT ["miner"]
CMD ["--help"]
