"""Minimal Apache AGE plumbing.

The relational tables are the source of truth; the ``infra_twin`` AGE graph is a derived
projection used later for traversal queries (blast radius, paths). This module provides just
enough to run cypher against that graph from an app-role connection. Full CI/edge projection
lands with the discovery/reconciliation tranche.
"""

from __future__ import annotations

import psycopg

GRAPH_NAME = "infra_twin"


def ensure_age(conn: psycopg.Connection) -> None:
    """Put ag_catalog on the search path for this session.

    The ``age`` library itself is auto-loaded by ``session_preload_libraries`` (set on the
    database in the migration), so the non-superuser app role does not — and may not —
    ``LOAD`` it explicitly.
    """
    conn.execute('SET LOCAL search_path = ag_catalog, "$user", public')


def cypher(
    conn: psycopg.Connection,
    query: str,
    columns: str = "(v agtype)",
) -> list[tuple]:
    """Run a cypher ``query`` against the ``infra_twin`` graph and return the rows.

    ``query`` is the cypher body (without the wrapping ``cypher(...)`` call). ``columns`` is
    the AS-clause column definition list AGE requires.
    """
    ensure_age(conn)
    return conn.execute(
        f"SELECT * FROM ag_catalog.cypher('{GRAPH_NAME}', $cypher$ {query} $cypher$) AS {columns}"
    ).fetchall()
