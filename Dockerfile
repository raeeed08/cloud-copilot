# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------- 1. frontend
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build -- --outDir /web/dist

# ---------------------------------------------------------------------------- 2. python build
FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
# dependency layer first: cached until uv.lock changes
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project --extra azure --extra postgres --extra otel
COPY src/ src/
COPY knowledge/ knowledge/
COPY --from=web /web/dist/ src/cloud_copilot/web/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --extra azure --extra postgres --extra otel

# ---------------------------------------------------------------------------- 3. runtime
FROM python:3.12-slim AS runtime
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="cloud-copilot" \
      org.opencontainers.image.description="Multi-cloud security & cost posture copilot" \
      org.opencontainers.image.source="https://github.com/raeeed08/cloud-copilot" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="MIT"
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --home /app app \
    && apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build --chown=app:app /app/.venv /app/.venv
COPY --chown=app:app knowledge/ /app/knowledge/
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    KNOWLEDGE_DIR=/app/knowledge \
    DATABASE_URL=sqlite:////app/data/cloud_copilot.db \
    LOG_JSON=true
RUN mkdir -p /app/data && chown app:app /app/data
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=2).status==200 else 1)"
ENTRYPOINT ["cloud-copilot"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
