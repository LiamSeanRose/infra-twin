"""Environment-driven configuration for the access layer and migration runner."""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_APP_DSN = "postgresql://app:app@localhost:5433/infra_twin"
DEFAULT_ADMIN_DSN = "postgresql://postgres:postgres@localhost:5433/infra_twin"


def app_dsn() -> str:
    """DSN for the non-superuser application role (RLS enforced)."""
    return os.environ.get("DATABASE_URL", DEFAULT_APP_DSN)


def admin_dsn() -> str:
    """DSN for the superuser role used only by migrations."""
    return os.environ.get("ADMIN_DATABASE_URL", DEFAULT_ADMIN_DSN)


def migrations_dir() -> Path:
    """Directory holding numbered ``*.sql`` migration files."""
    return Path(os.environ.get("MIGRATIONS_DIR", "migrations"))
