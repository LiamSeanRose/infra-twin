"""Event-driven delta intake for AWS CloudTrail/EventBridge events.

Resolves (or registers) an ``aws-events`` connector for the tenant, then
delegates to :func:`infra_twin.reconciliation.apply_delta` to persist the
parsed delta bitemporally.

The parse step (raw record -> ConnectorDelta) is NOT performed here; callers
supply a pre-parsed delta.  This avoids a forbidden service->service import
(``services/reconciliation`` must not import ``services/collectors``).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from psycopg_pool import ConnectionPool

from infra_twin.connector_sdk import ConnectorDelta
from infra_twin.db.connectors import ConnectorRegistry
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation.reconcile import DeltaResult, apply_delta

EVENT_SOURCE: str = "aws-events"


def apply_event_delta(
    pool: ConnectionPool,
    tenant_id: UUID,
    delta: ConnectorDelta,
    *,
    observed_at: datetime,
    source: str = EVENT_SOURCE,
) -> DeltaResult:
    """Resolve-or-register the event connector, then apply *delta* via :func:`apply_delta`.

    Parameters
    ----------
    pool:
        A tenant-capable connection pool (``DATABASE_URL``-backed, with RLS).
    tenant_id:
        The owning tenant.
    delta:
        A pre-parsed :class:`~infra_twin.connector_sdk.ConnectorDelta`.
    observed_at:
        The observation timestamp stamped on ``connector_runs`` and ``raw_facts``.
    source:
        Connector type/display_name used for ``resolve_or_register``.
        Defaults to ``"aws-events"``.

    Returns
    -------
    DeltaResult
        Counters from :func:`apply_delta`, returned unchanged.
    """
    with tenant_session(pool, tenant_id) as conn:
        registered = ConnectorRegistry(conn, tenant_id).resolve_or_register(
            type=source, display_name=source
        )
        connector_id = registered.connector_id

    return apply_delta(pool, tenant_id, connector_id, delta, observed_at)
