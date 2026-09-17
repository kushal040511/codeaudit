# syntax=docker/dockerfile:1.7
# API, Celery worker, beat, egress proxy and migrations share this image
# (build context: ./backend). Analyzers never run in it: they run in separate,
# locked-down sandbox containers started by the worker (see README "Sandboxing").

# ---------------------------------------------------------------- build stage
FROM python:3.12-slim-bookworm AS build

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /bin/uv

# Dependencies only, exactly as locked; no compilers or uv in the runtime image.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    uv sync --frozen --no-dev --no-install-project

# -------------------------------------------------------------- runtime stage
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# git: GitHub-URL sources and patch validation. tini: signal forwarding for graceful
# shutdown (SIGTERM reaches uvicorn/celery, zombies are reaped).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin codeaudit \
    && mkdir -p /var/lib/codeaudit/workspace /tmp/codeaudit-metrics \
    && chown codeaudit:codeaudit /var/lib/codeaudit/workspace /tmp/codeaudit-metrics

COPY --from=build /opt/venv /opt/venv
WORKDIR /app
# Code is owned by root and read-only to the service user.
COPY alembic.ini pyproject.toml ./
COPY alembic ./alembic
COPY app ./app

USER codeaudit
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
