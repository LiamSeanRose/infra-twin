"""Connection pool factory."""

from __future__ import annotations

from psycopg_pool import ConnectionPool

from infra_twin.db.config import app_dsn


def make_pool(dsn: str | None = None, **kwargs) -> ConnectionPool:
    """Open a connection pool for the application role.

    Defaults to the app DSN (RLS-enforced role). Callers own the returned pool's lifetime.
    """
    return ConnectionPool(dsn or app_dsn(), open=True, **kwargs)
