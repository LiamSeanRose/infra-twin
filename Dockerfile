# syntax=docker/dockerfile:1
# Multi-stage build for the infra-twin FastAPI query surface.
# Stage 1 — builder: installs the uv workspace with all member sources.
# Stage 2 — runtime: copies the entire /app tree (venv + sources) so editable
#            .pth entries resolve at import time.

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app

# uv is the package manager; pin to a released version.
ENV UV_VERSION=0.7.12

RUN pip install --no-cache-dir "uv==${UV_VERSION}"

# Reproducible build settings:
#   UV_COMPILE_BYTECODE  — precompile .py to .pyc in the venv.
#   UV_LINK_MODE=copy    — copy files instead of hard-linking (works across
#                          layer boundaries in multi-stage builds).
#   UV_PROJECT_ENVIRONMENT — place the virtualenv inside /app so we can
#                            copy the whole tree to the runtime stage at the
#                            same path, which is required for editable installs.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

# Layer-cache optimisation: copy only manifests first so that a source-only
# change does not invalidate the dependency-install layer.
COPY pyproject.toml uv.lock ./

# Copy every member pyproject.toml preserving workspace-relative paths.
COPY packages/connector-sdk/pyproject.toml packages/connector-sdk/pyproject.toml
COPY packages/core-model/pyproject.toml     packages/core-model/pyproject.toml
COPY packages/db/pyproject.toml             packages/db/pyproject.toml
COPY packages/onboarding/pyproject.toml     packages/onboarding/pyproject.toml
COPY services/collectors/pyproject.toml     services/collectors/pyproject.toml
COPY services/query/pyproject.toml          services/query/pyproject.toml
COPY services/reconciliation/pyproject.toml services/reconciliation/pyproject.toml
COPY apps/api/pyproject.toml                apps/api/pyproject.toml
COPY apps/cli/pyproject.toml                apps/cli/pyproject.toml

# Install all dependencies (frozen against uv.lock, production deps only).
# --no-install-project skips installing the root workspace (which has no
# package = true) and defers editable member installs until after sources
# are present.
RUN uv sync --frozen --no-dev --no-install-project

# Copy all workspace member sources into /app at their workspace-relative
# paths. apps/web is excluded (npm project, not a uv member).
COPY packages/ packages/
COPY services/ services/
COPY apps/api   apps/api
COPY apps/cli   apps/cli

# Final sync: install the editable members now that their src/ trees exist.
RUN uv sync --frozen --no-dev

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

# Create a non-root user for the running process.
RUN useradd --create-home --uid 10001 appuser

WORKDIR /app

# Copy the entire /app tree from the builder stage:
#   /app/.venv     — the fully installed virtualenv
#   /app/packages  — editable member sources referenced by .pth entries
#   /app/services  — editable member sources referenced by .pth entries
#   /app/apps      — editable member sources referenced by .pth entries
# Without the sources the editable .pth entries would point at non-existent
# directories and every `import infra_twin.*` would fail (edge case E1).
COPY --from=builder --chown=appuser:appuser /app /app

# Put the virtualenv's bin/ first on PATH so `uvicorn` and Python packages
# from the venv are found without activation.
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# Switch to the non-root user before the process starts.
USER appuser

# Production entrypoint: no --reload, explicit host+port binding.
CMD ["uvicorn", "infra_twin.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
