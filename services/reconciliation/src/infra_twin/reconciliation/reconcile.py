"""Reconcile a batch of discovery events into the versioned graph.

A reconcile call is the diff engine: it resolves provider identities to internal CIs, opens
or versions CIs/edges via the bitemporal repositories, closes anything in scope that the run
no longer observed, and projects the result into the AGE graph — all inside the caller's
tenant-scoped transaction, so one discovery run lands atomically.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg_pool import ConnectionPool

from infra_twin.connector_sdk import (
    ConnectorDelta,
    DiscoveredCI,
    DiscoveredEdge,
    DiscoveryEvent,
)
from infra_twin.core_model import CI, CIType, Edge, EdgeType
from infra_twin.db.connector_health import ConnectorRunRepository, RawFactRepository
from infra_twin.db.connectors import ConnectorRegistry
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation.projection import project


@dataclass
class ReconcileResult:
    """What one reconcile run changed."""

    cis_created: int = 0
    cis_updated: int = 0
    cis_unchanged: int = 0
    cis_closed: int = 0
    edges_written: int = 0
    edges_closed: int = 0


def _bind_source_key(
    conn: psycopg.Connection, tenant_id: UUID, source: str, native_id: str, ci_id: UUID
) -> None:
    conn.execute(
        "INSERT INTO source_keys (tenant_id, source, native_id, ci_id, observed_at) "
        "VALUES (%s, %s, %s, %s, now()) "
        "ON CONFLICT (tenant_id, source, native_id) "
        "DO UPDATE SET ci_id = EXCLUDED.ci_id, observed_at = now()",
        (tenant_id, source, native_id, ci_id),
    )


def _register_alias_keys(
    conn: psycopg.Connection,
    tenant_id: UUID,
    alias_keys: list[str],
    ci_id: UUID,
    ci_type: str,
    source: str,
) -> None:
    """Idempotently bind each alias key to the canonical CI id.

    Uses ON CONFLICT DO UPDATE so a re-discovery is a no-op at the CI level and
    simply refreshes observed_at.  Never deletes.
    """
    for k in alias_keys:
        conn.execute(
            "INSERT INTO ci_alias_keys "
            "    (tenant_id, alias_key, ci_id, ci_type, source, observed_at) "
            "VALUES (%s, %s, %s, %s, %s, now()) "
            "ON CONFLICT (tenant_id, alias_key) "
            "DO UPDATE SET ci_id = EXCLUDED.ci_id, ci_type = EXCLUDED.ci_type, "
            "              source = EXCLUDED.source, observed_at = now()",
            (tenant_id, k, ci_id, ci_type, source),
        )


def _record_merge(
    conn: psycopg.Connection,
    tenant_id: UUID,
    canonical_ci_id: UUID,
    merged_source: str,
    merged_external_id: str,
    matched_alias_key: str,
    evidence: str,
) -> None:
    """Append one merge-provenance row.  Append-only: never updates or deletes."""
    conn.execute(
        "INSERT INTO ci_merges "
        "    (tenant_id, canonical_ci_id, merged_source, merged_external_id, "
        "     matched_alias_key, evidence) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (
            tenant_id,
            canonical_ci_id,
            merged_source,
            merged_external_id,
            matched_alias_key,
            evidence,
        ),
    )


def _resolve_canonical_ci(
    conn: psycopg.Connection,
    ci_repo: CIRepository,
    tenant_id: UUID,
    dci: DiscoveredCI,
    source: str,
) -> tuple[CI | None, str | None]:
    """Return (canonical_ci, matched_alias_key) when a deterministic cross-source merge
    applies, else (None, None).  Read-only: performs lookups, writes nothing.

    Merge conditions (ALL must hold):
    - dci.alias_keys is non-empty.
    - At least one alias key matches a ci_alias_keys row of the same ci_type and a
      DIFFERENT source.
    - Exactly ONE distinct ci_id satisfies the above (ambiguous >= 2 -> no merge).
    - That ci_id still maps to a current open CI of the same type.
    """
    if not dci.alias_keys:
        return None, None

    rows = conn.execute(
        "SELECT alias_key, ci_id, ci_type, source "
        "FROM ci_alias_keys "
        "WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid "
        "  AND alias_key = ANY(%s)",
        (list(dci.alias_keys),),
    ).fetchall()

    # Filter: same type, different source.
    candidates: dict[UUID, str] = {}  # ci_id -> (first) matched alias_key
    for alias_key, ci_id, ci_type, row_source in rows:
        if ci_type != dci.type.value:
            continue
        if row_source == source:
            continue
        if ci_id not in candidates:
            candidates[ci_id] = alias_key

    if len(candidates) != 1:
        # Zero candidates -> new CI; >=2 -> ambiguous, no merge.
        return None, None

    canonical_ci_id, tentative_key = next(iter(candidates.items()))

    # Confirm the candidate is still a current open CI of the same type.
    canonical = ci_repo.get_current_by_id(canonical_ci_id)
    if canonical is None or canonical.type != dci.type:
        return None, None

    # Choose lexicographically smallest matched alias key for determinism.
    matched_keys = sorted(
        alias_key
        for alias_key, ci_id, ci_type, row_source in rows
        if ci_id == canonical_ci_id
        and ci_type == dci.type.value
        and row_source != source
    )
    matched_alias_key = matched_keys[0] if matched_keys else tentative_key

    return canonical, matched_alias_key


def reconcile(
    conn: psycopg.Connection,
    tenant_id: UUID,
    events: list[DiscoveryEvent],
    *,
    source: str,
    ci_types: frozenset[CIType],
    edge_types: frozenset[EdgeType],
) -> ReconcileResult:
    ci_repo = CIRepository(conn, tenant_id)
    edge_repo = EdgeRepository(conn, tenant_id)
    result = ReconcileResult()

    discovered_cis = [e for e in events if isinstance(e, DiscoveredCI)]
    discovered_edges = [e for e in events if isinstance(e, DiscoveredEdge)]

    id_by_key: dict[tuple[CIType, str], UUID] = {}
    seen_ci_keys: set[tuple[CIType, str]] = set()
    current_cis: list[CI] = []

    # 1. Upsert observed CIs and bind their provider identity.
    for dci in discovered_cis:
        key = (dci.type, dci.external_id)
        existing = ci_repo.get_current(type=dci.type, external_id=dci.external_id)

        if existing:
            # Native-id match: upsert normally, register alias keys, no merge row.
            stored = ci_repo.upsert(
                CI(
                    tenant_id=tenant_id,
                    type=dci.type,
                    external_id=dci.external_id,
                    name=dci.name,
                    attributes=dci.attributes,
                )
            )
            _bind_source_key(conn, tenant_id, source, dci.external_id, stored.id)
            _register_alias_keys(conn, tenant_id, dci.alias_keys, stored.id, dci.type.value, source)
            id_by_key[key] = stored.id
            seen_ci_keys.add(key)
            current_cis.append(stored)

            if existing[0].valid_from != stored.valid_from:
                result.cis_updated += 1
            else:
                result.cis_unchanged += 1
        else:
            # No native match: attempt deterministic alias merge.
            canonical, matched_alias_key = _resolve_canonical_ci(
                conn, ci_repo, tenant_id, dci, source
            )

            if canonical is not None and matched_alias_key is not None:
                # Single unambiguous cross-source match: merge into the canonical CI.
                stored = ci_repo.upsert(
                    CI(
                        id=canonical.id,
                        tenant_id=tenant_id,
                        type=dci.type,
                        external_id=canonical.external_id,
                        name=dci.name,
                        attributes=dci.attributes,
                    )
                )
                _bind_source_key(conn, tenant_id, source, dci.external_id, canonical.id)
                _register_alias_keys(
                    conn, tenant_id, dci.alias_keys, canonical.id, dci.type.value, source
                )
                evidence_text = (
                    f"merged {source}:{dci.external_id} into canonical "
                    f"{canonical.id} via alias_key={matched_alias_key}"
                )
                _record_merge(
                    conn,
                    tenant_id,
                    canonical.id,
                    source,
                    dci.external_id,
                    matched_alias_key,
                    evidence_text,
                )
                canonical_key = (dci.type, canonical.external_id)
                id_by_key[key] = canonical.id
                id_by_key[canonical_key] = canonical.id
                seen_ci_keys.add(canonical_key)
                current_cis.append(stored)

                if canonical.valid_from != stored.valid_from:
                    result.cis_updated += 1
                else:
                    result.cis_unchanged += 1
            else:
                # Zero candidates or ambiguous: insert new CI, register alias keys, no merge.
                stored = ci_repo.upsert(
                    CI(
                        tenant_id=tenant_id,
                        type=dci.type,
                        external_id=dci.external_id,
                        name=dci.name,
                        attributes=dci.attributes,
                    )
                )
                _bind_source_key(conn, tenant_id, source, dci.external_id, stored.id)
                _register_alias_keys(
                    conn, tenant_id, dci.alias_keys, stored.id, dci.type.value, source
                )
                id_by_key[key] = stored.id
                seen_ci_keys.add(key)
                current_cis.append(stored)
                result.cis_created += 1

    # 2. Close CIs in scope that this authoritative run did not observe.
    #    Only close CIs that this source previously created or claimed (i.e., have a
    #    source_key binding for the current source).  CIs created by a different source
    #    are not closed, so multi-source reconciliation does not erroneously retire facts
    #    it was never authoritative for.
    source_owned_ids: set[UUID] = {
        row[0]
        for row in conn.execute(
            "SELECT ci_id FROM source_keys "
            "WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid "
            "  AND source = %s",
            (source,),
        ).fetchall()
    }
    closed_cis: list[CI] = []
    for ci_type in ci_types:
        for current in ci_repo.get_current(type=ci_type):
            if (ci_type, current.external_id) not in seen_ci_keys and current.id in source_owned_ids:
                ci_repo.close(ci_type, current.external_id)
                closed_cis.append(current)
                result.cis_closed += 1

    def _resolve(ref_type: CIType, external_id: str) -> UUID | None:
        # Check in-run cache first.
        cached = id_by_key.get((ref_type, external_id))
        if cached is not None:
            return cached
        # Look up current CI by (type, external_id).
        existing = ci_repo.get_current(type=ref_type, external_id=external_id)
        if existing:
            return existing[0].id
        # Fall back to source_keys so edges from a merged-away source identity resolve to
        # the canonical CI id — only if that canonical CI is still current.
        row = conn.execute(
            "SELECT ci_id FROM source_keys "
            "WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid "
            "  AND native_id = %s",
            (external_id,),
        ).fetchone()
        if row is not None:
            canonical = ci_repo.get_current_by_id(row[0])
            if canonical is not None:
                return canonical.id
        return None

    # 3. Upsert observed edges between resolved endpoints.
    seen_edge_keys: set[tuple[EdgeType, UUID, UUID, str]] = set()
    current_edges: list[Edge] = []
    for de in discovered_edges:
        from_id = _resolve(de.from_ref.type, de.from_ref.external_id)
        to_id = _resolve(de.to_ref.type, de.to_ref.external_id)
        if from_id is None or to_id is None:
            continue  # endpoint not in scope; skip rather than assert a phantom edge
        stored = edge_repo.upsert(
            Edge(
                tenant_id=tenant_id,
                type=de.type,
                from_id=from_id,
                to_id=to_id,
                edge_key=de.edge_key,
                source=de.source,
                confidence=de.confidence,
                evidence=de.evidence,
            )
        )
        seen_edge_keys.add((de.type, from_id, to_id, de.edge_key))
        current_edges.append(stored)
        result.edges_written += 1

    # 4. Close edges in scope that this run did not observe.
    closed_edges: list[Edge] = []
    for current in edge_repo.get_current():
        if current.type in edge_types and (
            current.type,
            current.from_id,
            current.to_id,
            current.edge_key,
        ) not in seen_edge_keys:
            edge_repo.close(current.type, current.from_id, current.to_id, current.edge_key)
            closed_edges.append(current)
            result.edges_closed += 1

    # 5. Project current state into the graph (and remove what was closed).
    project(
        conn,
        current_cis=current_cis,
        current_edges=current_edges,
        closed_cis=closed_cis,
        closed_edges=closed_edges,
    )
    return result


@dataclass
class DeltaResult:
    """What one apply_delta call changed."""

    cis_created: int = 0
    cis_updated: int = 0
    cis_unchanged: int = 0
    cis_closed: int = 0
    edges_written: int = 0
    edges_closed: int = 0
    connector_run_id: UUID | None = None


def apply_delta(
    pool: ConnectionPool,
    tenant_id: UUID,
    connector_id: UUID,
    delta: ConnectorDelta,
    observed_at: datetime,
) -> DeltaResult:
    """Apply an explicit incremental delta bitemporally inside one tenant-scoped transaction.

    Unlike ``reconcile``, which closes facts absent from the observed set, ``apply_delta``
    only upserts/closes the facts named in the delta.  Untouched CIs/edges are never
    re-projected or closed.  The entire delta lands atomically; on any failure the
    transaction rolls back and no persistent state is written.
    """
    with tenant_session(pool, tenant_id) as conn:
        # Step 2: Resolve and validate the connector.
        registered = ConnectorRegistry(conn, tenant_id).get(connector_id)
        if registered is None:
            raise ValueError("connector_id not found for tenant")
        source = registered.type

        ci_repo = CIRepository(conn, tenant_id)
        edge_repo = EdgeRepository(conn, tenant_id)
        result = DeltaResult()

        # Step 3: Record run start (status='partial'; marked 'ok' in step 9).
        run_id = ConnectorRunRepository(conn, tenant_id).start(source, connector_id=connector_id)
        result.connector_run_id = run_id

        # Step 4: Build raw-fact payloads and record them.
        payloads: list[dict] = []
        for event in delta.upserts:
            if isinstance(event, DiscoveredCI):
                payloads.append({"kind": "ci", "event": event.model_dump(mode="json")})
            else:
                payloads.append({"kind": "edge", "event": event.model_dump(mode="json")})
        for ref in delta.removed_cis:
            payloads.append({"kind": "removed_ci", "event": ref.model_dump(mode="json")})
        for ref in delta.removed_edges:
            payloads.append({"kind": "removed_edge", "event": ref.model_dump(mode="json")})
        RawFactRepository(conn, tenant_id).record(source, observed_at, payloads, connector_id=connector_id)

        # Shared resolve helper: check id_by_key (built during CI upserts) then the DB,
        # then source_keys for merged-away identities.
        id_by_key: dict[tuple[CIType, str], UUID] = {}

        def _resolve(ref_type: CIType, external_id: str) -> UUID | None:
            cached = id_by_key.get((ref_type, external_id))
            if cached is not None:
                return cached
            existing = ci_repo.get_current(type=ref_type, external_id=external_id)
            if existing:
                return existing[0].id
            # Fall back to source_keys so edges from a merged-away source identity resolve
            # to the canonical CI id — only if that canonical CI is still current.
            row = conn.execute(
                "SELECT ci_id FROM source_keys "
                "WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid "
                "  AND native_id = %s",
                (external_id,),
            ).fetchone()
            if row is not None:
                canonical = ci_repo.get_current_by_id(row[0])
                if canonical is not None:
                    return canonical.id
            return None

        # Step 5: Upsert named CIs.
        current_cis: list[CI] = []
        for event in delta.upserts:
            if not isinstance(event, DiscoveredCI):
                continue
            dci = event
            key = (dci.type, dci.external_id)
            existing = ci_repo.get_current(type=dci.type, external_id=dci.external_id)

            if existing:
                # Native-id match: upsert normally, register alias keys, no merge row.
                stored = ci_repo.upsert(
                    CI(
                        tenant_id=tenant_id,
                        type=dci.type,
                        external_id=dci.external_id,
                        name=dci.name,
                        attributes=dci.attributes,
                    )
                )
                _bind_source_key(conn, tenant_id, source, dci.external_id, stored.id)
                _register_alias_keys(
                    conn, tenant_id, dci.alias_keys, stored.id, dci.type.value, source
                )
                id_by_key[key] = stored.id
                current_cis.append(stored)

                if existing[0].valid_from != stored.valid_from:
                    result.cis_updated += 1
                else:
                    result.cis_unchanged += 1
            else:
                # No native match: attempt deterministic alias merge.
                canonical, matched_alias_key = _resolve_canonical_ci(
                    conn, ci_repo, tenant_id, dci, source
                )

                if canonical is not None and matched_alias_key is not None:
                    # Single unambiguous cross-source match: merge into the canonical CI.
                    stored = ci_repo.upsert(
                        CI(
                            id=canonical.id,
                            tenant_id=tenant_id,
                            type=dci.type,
                            external_id=canonical.external_id,
                            name=dci.name,
                            attributes=dci.attributes,
                        )
                    )
                    _bind_source_key(conn, tenant_id, source, dci.external_id, canonical.id)
                    _register_alias_keys(
                        conn, tenant_id, dci.alias_keys, canonical.id, dci.type.value, source
                    )
                    evidence_text = (
                        f"merged {source}:{dci.external_id} into canonical "
                        f"{canonical.id} via alias_key={matched_alias_key}"
                    )
                    _record_merge(
                        conn,
                        tenant_id,
                        canonical.id,
                        source,
                        dci.external_id,
                        matched_alias_key,
                        evidence_text,
                    )
                    canonical_key = (dci.type, canonical.external_id)
                    id_by_key[key] = canonical.id
                    id_by_key[canonical_key] = canonical.id
                    current_cis.append(stored)

                    if canonical.valid_from != stored.valid_from:
                        result.cis_updated += 1
                    else:
                        result.cis_unchanged += 1
                else:
                    # Zero candidates or ambiguous: insert new CI, register alias keys, no merge.
                    stored = ci_repo.upsert(
                        CI(
                            tenant_id=tenant_id,
                            type=dci.type,
                            external_id=dci.external_id,
                            name=dci.name,
                            attributes=dci.attributes,
                        )
                    )
                    _bind_source_key(conn, tenant_id, source, dci.external_id, stored.id)
                    _register_alias_keys(
                        conn, tenant_id, dci.alias_keys, stored.id, dci.type.value, source
                    )
                    id_by_key[key] = stored.id
                    current_cis.append(stored)
                    result.cis_created += 1

        # Step 6: Upsert named edges.
        current_edges: list[Edge] = []
        for event in delta.upserts:
            if not isinstance(event, DiscoveredEdge):
                continue
            de = event
            from_id = _resolve(de.from_ref.type, de.from_ref.external_id)
            to_id = _resolve(de.to_ref.type, de.to_ref.external_id)
            if from_id is None:
                raise ValueError(
                    f"unresolved edge endpoint: {de.from_ref.type.value}/{de.from_ref.external_id}"
                )
            if to_id is None:
                raise ValueError(
                    f"unresolved edge endpoint: {de.to_ref.type.value}/{de.to_ref.external_id}"
                )
            stored_edge = edge_repo.upsert(
                Edge(
                    tenant_id=tenant_id,
                    type=de.type,
                    from_id=from_id,
                    to_id=to_id,
                    edge_key=de.edge_key,
                    source=de.source,
                    confidence=de.confidence,
                    evidence=de.evidence,
                )
            )
            current_edges.append(stored_edge)
            result.edges_written += 1

        # Step 7: Close only explicitly-removed CIs.
        closed_cis: list[CI] = []
        for ref in delta.removed_cis:
            before = ci_repo.get_current(type=ref.type, external_id=ref.external_id)
            was_open = ci_repo.close(ref.type, ref.external_id)
            if was_open and before:
                closed_cis.append(before[0])
                result.cis_closed += 1

        # Step 8: Close only explicitly-removed edges.
        closed_edges: list[Edge] = []
        for ref in delta.removed_edges:
            from_id = _resolve(ref.from_ref.type, ref.from_ref.external_id)
            to_id = _resolve(ref.to_ref.type, ref.to_ref.external_id)
            if from_id is None or to_id is None:
                # Endpoint already gone -> edge cannot exist; no-op (E7).
                continue
            # Find the matching current edge to record what was closed.
            matching: Edge | None = None
            for e in edge_repo.get_current(from_id=from_id):
                if e.type == ref.type and e.to_id == to_id:
                    matching = e
                    break
            was_open = edge_repo.close(ref.type, from_id, to_id)
            if was_open and matching is not None:
                closed_edges.append(matching)
                result.edges_closed += 1

        # Step 9: Mark run ok.
        ConnectorRunRepository(conn, tenant_id).finish_ok(run_id)

        # Step 10: Project only touched facts into AGE.
        project(
            conn,
            current_cis=current_cis,
            current_edges=current_edges,
            closed_cis=closed_cis,
            closed_edges=closed_edges,
        )

    return result
