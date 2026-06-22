"""Orchestration: drive a connector and reconcile its output.

Discovery (which makes live, slow, fallible provider calls) runs first and is fully
materialized; only then is a single tenant-scoped transaction opened to reconcile the batch
atomically. The connector is injected, so this same wiring is exercised in tests with a
moto-backed connector and in production with a real assume-role session.

Lifecycle:
  A. A 'partial' connector_runs row is committed before any provider calls.
  B. Discovery runs (connector.discover is materialized).
  C. A single transaction writes raw facts, reconciles the graph, and marks the run 'ok'.
  D. On any failure in B or C, a separate transaction marks the run 'error' and then
     re-raises the original exception so the caller sees the real failure.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from psycopg_pool import ConnectionPool

from infra_twin.connector_sdk import Connector, DiscoveredCI, DiscoveredEdge
from infra_twin.db.connector_health import ConnectorRunRepository, RawFactRepository
from infra_twin.db.connectors import ConnectorRegistry
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation.reconcile import ReconcileResult, reconcile

_MAX_ERROR_LEN = 4000


def discover_and_reconcile(
    pool: ConnectionPool, tenant_id: UUID, connector: Connector
) -> ReconcileResult:
    # A. Resolve-or-register the connector and record the run start in a committed
    #    transaction before slow provider calls.  Both the connectors row and the
    #    partial run row commit together here so a failure in discovery still leaves
    #    a traceable run stamped with the connector_id.
    with tenant_session(pool, tenant_id) as conn:
        registered = ConnectorRegistry(conn, tenant_id).resolve_or_register(
            type=connector.source, display_name=connector.source
        )
        connector_id = registered.connector_id
        run_id = ConnectorRunRepository(conn, tenant_id).start(
            connector.source, connector_id=connector_id
        )

    try:
        # B. Run discovery — materialized before opening the reconcile transaction.
        events = list(connector.discover())

        # C. Capture a single observation timestamp for this entire batch.
        observed_at = datetime.now(timezone.utc)

        # D. Persist raw facts, reconcile the graph, and mark the run ok — all atomic.
        with tenant_session(pool, tenant_id) as conn:
            payloads = [
                {
                    "kind": "ci" if isinstance(event, DiscoveredCI) else "edge",
                    "event": event.model_dump(mode="json"),
                }
                for event in events
            ]
            RawFactRepository(conn, tenant_id).record(
                connector.source, observed_at, payloads, connector_id=connector_id
            )
            result = reconcile(
                conn,
                tenant_id,
                events,
                source=connector.source,
                ci_types=connector.ci_types,
                edge_types=connector.edge_types,
            )
            ConnectorRunRepository(conn, tenant_id).finish_ok(run_id)

        return result

    except Exception as exc:
        # F. Record the failure in a NEW session so a rollback doesn't discard the error row.
        error_text = str(exc) or type(exc).__name__
        error_text = error_text[:_MAX_ERROR_LEN]
        try:
            with tenant_session(pool, tenant_id) as conn:
                ConnectorRunRepository(conn, tenant_id).finish_error(run_id, error_text)
        except Exception:
            # finish_error failing must not mask the original exception.
            pass
        raise
