FROM python:3.11-slim AS base
RUN apt-get update && apt-get install -y \
    gcc \
    ca-certificates \
    git \
    curl \
    unzip \
    gzip \
    && rm -rf /var/lib/apt/lists/*

# Stage: Install FRP binaries
FROM base AS frp-bin
# Explicit CI-only 0.71.1 candidate selection; existing builds remain on 0.71.0.
ARG SMITE_FRP_CANDIDATE_VERSION=v0.71.0
RUN set -eux; \
    ARCH_RAW="$(uname -m)"; \
    case "$ARCH_RAW" in \
        x86_64) ARCH="amd64" ;; \
        aarch64) ARCH="arm64" ;; \
        *) echo "Unsupported architecture: $ARCH_RAW" >&2; exit 1 ;; \
    esac; \
    echo "Fetching verified FRP release"; \
    FRP_VERSION="${SMITE_FRP_CANDIDATE_VERSION}"; \
    case "$FRP_VERSION:$ARCH" in \
        v0.71.0:amd64) FRP_SHA256="84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716" ;; \
        v0.71.0:arm64) FRP_SHA256="f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266" ;; \
        v0.71.1:amd64) FRP_SHA256="1d9875210972a5d1a62b2dc4c48df45ab0af05d3ca1b5e494a014428259df803" ;; \
        v0.71.1:arm64) FRP_SHA256="8edf590b0c396fa42f9c147121a76af83cfc2002b08f5aef0ea1008c43482019" ;; \
        *) echo "HOLD: Unsupported FRP version or architecture" >&2; exit 1 ;; \
    esac; \
    FRP_VERSION_NO_V="${FRP_VERSION#v}"; \
    FRP_URL="https://github.com/fatedier/frp/releases/download/${FRP_VERSION}/frp_${FRP_VERSION_NO_V}_linux_${ARCH}.tar.gz"; \
    FRP_TMP="$(mktemp -d)"; \
    curl -fsSL "$FRP_URL" -o "$FRP_TMP/frp.tar.gz"; \
    echo "$FRP_SHA256  $FRP_TMP/frp.tar.gz" | sha256sum -c -; \
    tar -xzf "$FRP_TMP/frp.tar.gz" -C "$FRP_TMP"; \
    install -Dm755 "$FRP_TMP/frp_${FRP_VERSION_NO_V}_linux_${ARCH}/frps" /usr/local/bin/frps; \
    test "$(/usr/local/bin/frps --version)" = "$FRP_VERSION_NO_V"; \
    rm -rf "$FRP_TMP"; \
    /usr/local/bin/frps --version || true

FROM node:18-alpine AS frontend-build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    if [ -f package-lock.json ]; then \
        npm ci --prefer-offline --no-audit --no-fund; \
    else \
        npm install --prefer-offline --no-audit --no-fund; \
    fi
COPY frontend ./
RUN npm run build

FROM base AS deps
WORKDIR /app
COPY panel/requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir -r requirements.txt

FROM base
WORKDIR /app

ARG SMITE_VERSION=latest
ARG SMITE_SOURCE_SHA=unverified
LABEL org.opencontainers.image.version="${SMITE_VERSION}"
LABEL org.opencontainers.image.revision="${SMITE_SOURCE_SHA}"
LABEL smite.role="panel"
LABEL smite.version="${SMITE_VERSION}"
ENV SMITE_VERSION="${SMITE_VERSION}"
RUN echo "${SMITE_VERSION}" > /app/VERSION

# Copy FRP binary from frp-bin stage
COPY --from=frp-bin /usr/local/bin/frps /usr/local/bin/frps

COPY --from=deps /usr/local /usr/local
COPY --from=frontend-build /app/dist ./static
COPY panel .
# Note: .git is excluded in .dockerignore, so git tag extraction at runtime won't work in Docker
# Version is set via SMITE_VERSION build arg (extract with: git describe --tags --abbrev=0)

EXPOSE 8000 443/tcp 443/udp

RUN echo '#!/bin/sh' > /app/start.sh && \
    echo 'set -e' >> /app/start.sh && \
    echo 'exec uvicorn main:app --host "${PANEL_HOST:-0.0.0.0}" --port "${PANEL_PORT:-8000}"' >> /app/start.sh && \
    chmod +x /app/start.sh

CMD ["/bin/sh", "/app/start.sh"]
