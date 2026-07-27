# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: build de assets (Tailwind CSS + JS via esbuild). Node não é
# necessário em produção — só nesta etapa de build.
# ---------------------------------------------------------------------------
FROM node:20-slim AS assets

WORKDIR /build

COPY package.json ./
RUN npm install

COPY tailwind.config.js postcss.config.js ./
COPY scripts/build-js.mjs ./scripts/build-js.mjs
COPY app/templates ./app/templates
COPY app/static/src ./app/static/src

RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: dependências Python isoladas, para reduzir a imagem final.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS python-deps

WORKDIR /wheels

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip wheel --no-cache-dir --wheel-dir /wheels/dist -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 3: imagem de runtime, sem Node e sem toolchain de build.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 analisa \
    && useradd --uid 1000 --gid analisa --shell /bin/bash --create-home analisa

WORKDIR /app

COPY --from=python-deps /wheels/dist /wheels/dist
COPY requirements.txt ./
RUN pip install --no-cache-dir --no-index --find-links=/wheels/dist -r requirements.txt \
    && rm -rf /wheels

COPY --chown=analisa:analisa . .
COPY --from=assets --chown=analisa:analisa /build/app/static/dist ./app/static/dist

RUN mkdir -p /data/generated-pages /data/sitemaps /app/logs /app/backups \
    && chown -R analisa:analisa /data /app/logs /app/backups

USER analisa

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:5000/healthz || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--worker-class", "gthread", \
     "--workers", "2", "--threads", "4", "--timeout", "60", \
     "--access-logfile", "-", "--error-logfile", "-", "wsgi:app"]
