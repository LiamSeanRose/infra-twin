"""Tenant-scoped sessions.

Every read or write goes through :func:`tenant_session`, which opens a transaction and
sets the ``app.tenant_id`` GUC locally. Postgres Row-Level Security keys off that GUC, so
tenant isolation is enforced by the database — callers cannot pass a different tenant_id to
widen their access.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator
from uuid import UUID

import psycopg
from psycopg_pool import ConnectionPool


@contextmanager
def tenant_session(pool: ConnectionPool, tenant_id: UUID) -> Iterator[psycopg.Connection]:
    """Yield a connection bound to ``tenant_id`` for the duration of one transaction."""
    with pool.connection() as conn:
        with conn.transaction():
            # SET LOCAL via set_config(..., is_local => true): scoped to this transaction.
            conn.execute("SELECT set_config('app.tenant_id', %s, true)", (str(tenant_id),))
            yield conn
