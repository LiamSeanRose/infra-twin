"""Tenant-scoped connector registry: Pydantic model and repository.

The registry tracks which connectors are configured for each tenant.  It is an
operational / configuration concern, not a versioned graph fact, so the table
is mutable in place (no valid_from/valid_to) — mirroring ``connector_runs``.

Naming note: ``infra_twin.connector_sdk.Connector`` is the live-connector
Protocol.  The registry record defined here is ``Connector`` within this
module, exported from ``infra_twin.db`` under the alias ``RegisteredConnector``
to keep the two unambiguous at import sites.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from pydantic import BaseModel


class Connector(BaseModel):
    """A registry record for a tenant-scoped connector (NOT the connector_sdk Protocol)."""

    connector_id: UUID
    tenant_id: UUID
    type: str
    display_name: str
    config: dict[str, Any]
    enabled: bool
    created_at: datetime


def _row_to_connector(row: dict) -> Connector:
    return Connector(
        connector_id=row["connector_id"],
        tenant_id=row["tenant_id"],
        type=row["type"],
        display_name=row["display_name"],
        config=row["config"],
        enabled=row["enabled"],
        created_at=row["created_at"],
    )


_COLUMNS = "connector_id, tenant_id, type, display_name, config, enabled, created_at"


class ConnectorRegistry:
    """Registry of connectors, scoped to one tenant.

    Constructed with an open ``psycopg.Connection`` that has already had the
    ``app.tenant_id`` GUC set via :func:`infra_twin.db.session.tenant_session`.
    Row-Level Security scopes every statement to the tenant; ``tenant_id`` is
    only used to stamp inserts, never as a query filter.
    """

    def __init__(self, conn: psycopg.Connection, tenant_id: UUID) -> None:
        self._conn = conn
        self._tenant_id = tenant_id

    def _cur(self):
        return self._conn.cursor(row_factory=dict_row)

    def register(
        self,
        type: str,
        display_name: str,
        config: dict[str, Any] | None = None,
        enabled: bool = True,
    ) -> Connector:
        """Idempotent upsert keyed on (tenant_id, type, display_name).

        If a row with the same (type, display_name) already exists for this
        tenant, return it UNCHANGED (do not overwrite config/enabled).
        Otherwise insert a new row with a fresh connector_id and
        created_at=now().  ``config`` defaults to ``{}`` when ``None``.
        """
        effective_config: dict[str, Any] = config if config is not None else {}

        with self._cur() as cur:
            existing = cur.execute(
                f"SELECT {_COLUMNS} FROM connectors "
                "WHERE type = %s AND display_name = %s",
                (type, display_name),
            ).fetchone()

            if existing is not None:
                return _row_to_connector(existing)

            row = cur.execute(
                f"INSERT INTO connectors (tenant_id, type, display_name, config, enabled) "
                f"VALUES (%s, %s, %s, %s, %s) RETURNING {_COLUMNS}",
                (
                    self._tenant_id,
                    type,
                    display_name,
                    Jsonb(effective_config),
                    enabled,
                ),
            ).fetchone()
            return _row_to_connector(row)

    def list(self) -> list[Connector]:
        """All connectors visible to the tenant (RLS-scoped), ordered by type then display_name."""
        with self._cur() as cur:
            rows = cur.execute(
                f"SELECT {_COLUMNS} FROM connectors ORDER BY type, display_name"
            ).fetchall()
        return [_row_to_connector(r) for r in rows]

    def get(self, connector_id: UUID) -> Connector | None:
        """Single connector by id, or None if not visible to this tenant."""
        with self._cur() as cur:
            row = cur.execute(
                f"SELECT {_COLUMNS} FROM connectors WHERE connector_id = %s",
                (connector_id,),
            ).fetchone()
        return _row_to_connector(row) if row is not None else None

    def resolve_or_register(self, type: str, display_name: str) -> Connector:
        """Return the existing connector for (type, display_name), or register a new one.

        The new one is created with empty config and enabled=True.
        Used by ``discover_and_reconcile`` to stamp connector_id on runs and facts.
        """
        return self.register(type=type, display_name=display_name, config=None, enabled=True)

    def set_enabled(self, connector_id: UUID, enabled: bool) -> Connector | None:
        """Set enabled to the given value; return the updated Connector.

        Returns ``None`` when the id is not visible to this tenant (RLS hides
        other tenants' rows, so zero rows are updated for a cross-tenant id).
        """
        with self._cur() as cur:
            row = cur.execute(
                f"UPDATE connectors SET enabled = %s WHERE connector_id = %s "
                f"RETURNING {_COLUMNS}",
                (enabled, connector_id),
            ).fetchone()
        return _row_to_connector(row) if row is not None else None
