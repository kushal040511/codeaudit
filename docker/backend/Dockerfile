# syntax=docker/dockerfile:1.7
# Image for the API and the Celery worker (build context: ./backend).
# NOTE: this is NOT the sandbox image. Analyzers must eventually run against
# untrusted code in a separate, locked-down container (see README "Sandboxing").
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /uvx /bin/

# git: GitHub-URL sources and semgrep's git-aware file targeting.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first (cached layer), exactly as locked in uv.lock.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    uv sync --frozen --no-dev --no-install-project

COPY . .

RUN useradd --create-home --uid 10001 codeaudit \
    && mkdir -p /var/lib/codeaudit/workspace \
    && chown -R codeaudit:codeaudit /var/lib/codeaudit
USER codeaudit

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
