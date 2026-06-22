"""Bitemporal, tenant-scoped repositories for CIs and edges.

Both repositories operate on a connection already bound to a tenant by
:func:`infra_twin.db.session.tenant_session`; Row-Level Security scopes every statement, so
these methods never accept a tenant_id from the caller as a query filter.

Bitemporal rule: a change never overwrites or deletes a fact. It closes the current version
(sets ``valid_to``) and opens a new version that shares the same ``id``. ``now()`` is the
transaction timestamp, so a closed version's ``valid_to`` exactly equals the new version's
``valid_from``.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from infra_twin.core_model import (
    CI,
    CIType,
    Edge,
    EdgeSource,
    EdgeType,
    Evidence,
    INFERRED_BASELINE_CONFIDENCE,
    confidence_for_observations,
)

# ---------------------------------------------------------------------------
# Accessor: last_observed_at from the reserved count-marker Evidence entry
# ---------------------------------------------------------------------------


def last_observed_at_of(evidence: list[Evidence]) -> datetime | None:
    """Return the observed_at of the reserved count-marker Evidence entry, or None
    if no count marker is present (pre-feature / declared edges)."""
    for ev in evidence:
        if ev.source == FLOWLOG_COUNT_EVIDENCE_SOURCE:
            return ev.observed_at
    return None

# Reserved Evidence.source for the accumulated observation-count marker.
# Stored as evidence[0] of every re-observable inferred edge.
FLOWLOG_COUNT_EVIDENCE_SOURCE: str = "aws-flowlogs-count"

# Maximum number of individual observation Evidence rows retained per edge.
# The count marker (evidence[0]) is not counted against this cap; the count
# itself always reflects the true number of observations, regardless of how
# many Evidence rows are retained.
EVIDENCE_WINDOW_CAP: int = 20

_CI_COLUMNS = (
    "id, tenant_id, type, external_id, name, attributes, confidence, "
    "first_seen, last_seen, valid_from, valid_to"
)
_EDGE_COLUMNS = (
    "id, tenant_id, type, from_id, to_id, edge_key, source, confidence, evidence, valid_from, valid_to"
)


def _row_to_ci(row: dict) -> CI:
    return CI(
        id=row["id"],
        tenant_id=row["tenant_id"],
        type=CIType(row["type"]),
        external_id=row["external_id"],
        name=row["name"],
        attributes=row["attributes"],
        confidence=row["confidence"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        valid_from=row["valid_from"],
        valid_to=row["valid_to"],
    )


def _row_to_edge(row: dict) -> Edge:
    return Edge(
        id=row["id"],
        tenant_id=row["tenant_id"],
        type=EdgeType(row["type"]),
        from_id=row["from_id"],
        to_id=row["to_id"],
        edge_key=row["edge_key"],
        source=EdgeSource(row["source"]),
        confidence=row["confidence"],
        evidence=[Evidence(**e) for e in row["evidence"]],
        valid_from=row["valid_from"],
        valid_to=row["valid_to"],
    )


class CIRepository:
    """Bitemporal store for Configuration Items, scoped to one tenant."""

    def __init__(self, conn: psycopg.Connection, tenant_id: UUID) -> None:
        self._conn = conn
        self._tenant_id = tenant_id

    def _cur(self):
        return self._conn.cursor(row_factory=dict_row)

    def upsert(self, ci: CI) -> CI:
        """Insert, version, or touch a CI keyed on (type, external_id) within the tenant."""
        if ci.tenant_id != self._tenant_id:
            raise ValueError("CI.tenant_id does not match the session tenant")

        with self._cur() as cur:
            current = cur.execute(
                f"SELECT {_CI_COLUMNS} FROM cis "
                "WHERE type = %s AND external_id = %s AND valid_to IS NULL",
                (ci.type.value, ci.external_id),
            ).fetchone()

            if current is None:
                row = cur.execute(
                    f"INSERT INTO cis ({_CI_COLUMNS}) VALUES "
                    "(%s, %s, %s, %s, %s, %s, %s, now(), now(), now(), NULL) "
                    f"RETURNING {_CI_COLUMNS}",
                    (
                        ci.id,
                        self._tenant_id,
                        ci.type.value,
                        ci.external_id,
                        ci.name,
                        Jsonb(ci.attributes),
                        ci.confidence,
                    ),
                ).fetchone()
                return _row_to_ci(row)

            if not _ci_changed(current, ci):
                row = cur.execute(
                    f"UPDATE cis SET last_seen = now() WHERE id = %s AND valid_to IS NULL "
                    f"RETURNING {_CI_COLUMNS}",
                    (current["id"],),
                ).fetchone()
                return _row_to_ci(row)

            cur.execute(
                "UPDATE cis SET valid_to = now() WHERE id = %s AND valid_to IS NULL",
                (current["id"],),
            )
            row = cur.execute(
                f"INSERT INTO cis ({_CI_COLUMNS}) VALUES "
                "(%s, %s, %s, %s, %s, %s, %s, %s, now(), now(), NULL) "
                f"RETURNING {_CI_COLUMNS}",
                (
                    current["id"],
                    self._tenant_id,
                    ci.type.value,
                    ci.external_id,
                    ci.name,
                    Jsonb(ci.attributes),
                    ci.confidence,
                    current["first_seen"],
                ),
            ).fetchone()
            return _row_to_ci(row)

    def get_current(
        self, type: CIType | None = None, external_id: str | None = None
    ) -> list[CI]:
        """Return current (open) CIs, optionally filtered by type and/or external_id."""
        clauses = ["valid_to IS NULL"]
        params: list[object] = []
        if type is not None:
            clauses.append("type = %s")
            params.append(type.value)
        if external_id is not None:
            clauses.append("external_id = %s")
            params.append(external_id)
        with self._cur() as cur:
            rows = cur.execute(
                f"SELECT {_CI_COLUMNS} FROM cis WHERE {' AND '.join(clauses)} "
                "ORDER BY type, external_id",
                params,
            ).fetchall()
        return [_row_to_ci(r) for r in rows]

    def get_current_by_id(self, ci_id: UUID) -> CI | None:
        with self._cur() as cur:
            row = cur.execute(
                f"SELECT {_CI_COLUMNS} FROM cis WHERE id = %s AND valid_to IS NULL",
                (ci_id,),
            ).fetchone()
        return _row_to_ci(row) if row else None

    def as_of(self, ts: datetime, type: CIType | None = None) -> list[CI]:
        """Return CIs valid at ``ts`` (valid_from <= ts < valid_to or still open)."""
        clauses = ["valid_from <= %s", "(valid_to IS NULL OR valid_to > %s)"]
        params: list[object] = [ts, ts]
        if type is not None:
            clauses.append("type = %s")
            params.append(type.value)
        with self._cur() as cur:
            rows = cur.execute(
                f"SELECT {_CI_COLUMNS} FROM cis WHERE {' AND '.join(clauses)}",
                params,
            ).fetchall()
        return [_row_to_ci(r) for r in rows]

    def history(self, ci_id: UUID) -> list[CI]:
        """All versions of a CI, oldest first."""
        with self._cur() as cur:
            rows = cur.execute(
                f"SELECT {_CI_COLUMNS} FROM cis WHERE id = %s ORDER BY valid_from",
                (ci_id,),
            ).fetchall()
        return [_row_to_ci(r) for r in rows]

    def close(self, type: CIType, external_id: str) -> bool:
        """Close the current version of a CI (set valid_to). Never deletes. Returns True if one was open."""
        with self._cur() as cur:
            row = cur.execute(
                "UPDATE cis SET valid_to = now() "
                "WHERE type = %s AND external_id = %s AND valid_to IS NULL RETURNING id",
                (type.value, external_id),
            ).fetchone()
        return row is not None


class EdgeRepository:
    """Bitemporal store for edges, scoped to one tenant. Provenance is mandatory."""

    def __init__(self, conn: psycopg.Connection, tenant_id: UUID) -> None:
        self._conn = conn
        self._tenant_id = tenant_id

    def _cur(self):
        return self._conn.cursor(row_factory=dict_row)

    def upsert(self, edge: Edge) -> Edge:
        """Insert, version, or no-op an edge keyed on (type, from_id, to_id) within the tenant.

        Re-observation (inferred -> inferred) branch
        -----------------------------------------------
        When BOTH the current open version and the incoming edge are ``source == inferred``,
        this method aggregates the observation count and raises confidence via
        ``confidence_for_observations``.  It ALWAYS produces a new bitemporal version
        (close current row, open new row with the same id) rather than performing an
        in-place mutation or hard-delete.

        All other combinations (new pair, declared current, declared incoming) use the
        existing insert / _edge_changed / version semantics with the incoming
        source/confidence/evidence written verbatim.
        """
        if edge.tenant_id != self._tenant_id:
            raise ValueError("Edge.tenant_id does not match the session tenant")
        if not edge.evidence:
            raise ValueError("edge requires non-empty evidence")

        with self._cur() as cur:
            current = cur.execute(
                f"SELECT {_EDGE_COLUMNS} FROM edges "
                "WHERE type = %s AND from_id = %s AND to_id = %s AND edge_key = %s AND valid_to IS NULL",
                (edge.type.value, edge.from_id, edge.to_id, edge.edge_key),
            ).fetchone()

            # --- Case 1: no open version (first sight of this ordered pair) ---
            if current is None:
                if edge.source == EdgeSource.inferred:
                    # First inferred observation: prepend the count marker (count=1) so
                    # every stored inferred edge row carries the cumulative count.  The
                    # incoming confidence (0.6 == INFERRED_BASELINE_CONFIDENCE) is used
                    # verbatim; on subsequent re-observations it is recomputed.
                    newest_obs_at = max(
                        (ev.observed_at for ev in edge.evidence), default=None
                    )
                    count_marker = Evidence(
                        source=FLOWLOG_COUNT_EVIDENCE_SOURCE,
                        detail="1",
                        observed_at=newest_obs_at or edge.evidence[0].observed_at,
                    )
                    final_evidence: list[Evidence] = [count_marker] + list(edge.evidence)
                    final_confidence = edge.confidence  # 0.6 for first sight
                else:
                    # Declared edge (or any non-inferred source): store verbatim.
                    final_evidence = list(edge.evidence)
                    final_confidence = edge.confidence

                evidence_json = Jsonb([e.model_dump(mode="json") for e in final_evidence])
                row = cur.execute(
                    f"INSERT INTO edges ({_EDGE_COLUMNS}) VALUES "
                    "(%s, %s, %s, %s, %s, %s, %s, %s, %s, now(), NULL) "
                    f"RETURNING {_EDGE_COLUMNS}",
                    (
                        edge.id,
                        self._tenant_id,
                        edge.type.value,
                        edge.from_id,
                        edge.to_id,
                        edge.edge_key,
                        edge.source.value,
                        final_confidence,
                        evidence_json,
                    ),
                ).fetchone()
                return _row_to_edge(row)

            # --- Case 2: re-observation (both current and incoming are inferred) ---
            if (
                current["source"] == EdgeSource.inferred.value
                and edge.source == EdgeSource.inferred
            ):
                # Read the prior observation count from the reserved count-marker Evidence
                # entry.  One batch = exactly +1 to the count, regardless of how many
                # ACCEPT records for this pair appeared in the batch (the parser deduplicates
                # within a batch, so the incoming edge always represents exactly one new
                # observation).
                prior_count = 1  # defensive default: covers pre-feature edges without marker
                for ev in current["evidence"]:
                    if ev.get("source") == FLOWLOG_COUNT_EVIDENCE_SOURCE:
                        try:
                            prior_count = int(ev["detail"])
                        except (TypeError, ValueError, KeyError):
                            prior_count = 1  # unparsable: treat as 1 (edge case 13)
                        break

                new_count = prior_count + 1
                new_confidence = confidence_for_observations(new_count)

                # Build combined observation evidence list (excluding the count marker
                # from the prior row) + the incoming observation rows, capped at
                # EVIDENCE_WINDOW_CAP most-recent entries.
                prior_obs = [
                    ev for ev in current["evidence"]
                    if ev.get("source") != FLOWLOG_COUNT_EVIDENCE_SOURCE
                ]
                incoming_obs = [
                    ev.model_dump(mode="json") for ev in edge.evidence
                    if ev.source != FLOWLOG_COUNT_EVIDENCE_SOURCE
                ]
                combined_obs = (prior_obs + incoming_obs)[-EVIDENCE_WINDOW_CAP:]

                # Determine the timestamp for the new count marker.
                newest_obs_at_new: datetime | None = None
                for ev in reversed(combined_obs):
                    ts = ev.get("observed_at")
                    if ts is not None:
                        # observed_at may be a datetime or an ISO string depending on
                        # whether it came from a raw DB dict or a model_dump.
                        if isinstance(ts, datetime):
                            newest_obs_at_new = ts
                        else:
                            try:
                                newest_obs_at_new = datetime.fromisoformat(ts)
                            except (TypeError, ValueError):
                                pass
                        break
                if newest_obs_at_new is None:
                    newest_obs_at_new = edge.evidence[0].observed_at

                new_count_marker = {
                    "source": FLOWLOG_COUNT_EVIDENCE_SOURCE,
                    "detail": str(new_count),
                    "observed_at": (
                        newest_obs_at_new.isoformat()
                        if isinstance(newest_obs_at_new, datetime)
                        else newest_obs_at_new
                    ),
                }
                new_evidence_raw = [new_count_marker] + combined_obs

                # Always version: close the prior open row, open a new one sharing the
                # same id.  new_confidence != current confidence by construction
                # (confidence_for_observations is strictly increasing), so the new
                # bitemporal version always differs.
                cur.execute(
                    "UPDATE edges SET valid_to = now() WHERE id = %s AND valid_to IS NULL",
                    (current["id"],),
                )
                row = cur.execute(
                    f"INSERT INTO edges ({_EDGE_COLUMNS}) VALUES "
                    "(%s, %s, %s, %s, %s, %s, %s, %s, %s, now(), NULL) "
                    f"RETURNING {_EDGE_COLUMNS}",
                    (
                        current["id"],
                        self._tenant_id,
                        edge.type.value,
                        edge.from_id,
                        edge.to_id,
                        edge.edge_key,
                        edge.source.value,
                        new_confidence,
                        Jsonb(new_evidence_raw),
                    ),
                ).fetchone()
                return _row_to_edge(row)

            # --- Case 3: declared current, or declared incoming, or mixed ---
            # Not aggregated.  If incoming is DECLARED and current was INFERRED, the
            # declared edge overwrites via normal versioning and the count marker is
            # dropped (the new row carries the incoming declared evidence only).
            # If current is DECLARED, any incoming edge (declared or inferred) follows
            # the standard no-op / version path.
            evidence_json = Jsonb([e.model_dump(mode="json") for e in edge.evidence])

            if not _edge_changed(current, edge):
                return _row_to_edge(current)

            cur.execute(
                "UPDATE edges SET valid_to = now() WHERE id = %s AND valid_to IS NULL",
                (current["id"],),
            )
            row = cur.execute(
                f"INSERT INTO edges ({_EDGE_COLUMNS}) VALUES "
                "(%s, %s, %s, %s, %s, %s, %s, %s, %s, now(), NULL) "
                f"RETURNING {_EDGE_COLUMNS}",
                (
                    current["id"],
                    self._tenant_id,
                    edge.type.value,
                    edge.from_id,
                    edge.to_id,
                    edge.edge_key,
                    edge.source.value,
                    edge.confidence,
                    evidence_json,
                ),
            ).fetchone()
            return _row_to_edge(row)

    def get_current(self, from_id: UUID | None = None) -> list[Edge]:
        clauses = ["valid_to IS NULL"]
        params: list[object] = []
        if from_id is not None:
            clauses.append("from_id = %s")
            params.append(from_id)
        with self._cur() as cur:
            rows = cur.execute(
                f"SELECT {_EDGE_COLUMNS} FROM edges WHERE {' AND '.join(clauses)}",
                params,
            ).fetchall()
        return [_row_to_edge(r) for r in rows]

    def as_of(self, ts: datetime) -> list[Edge]:
        with self._cur() as cur:
            rows = cur.execute(
                f"SELECT {_EDGE_COLUMNS} FROM edges "
                "WHERE valid_from <= %s AND (valid_to IS NULL OR valid_to > %s)",
                (ts, ts),
            ).fetchall()
        return [_row_to_edge(r) for r in rows]

    def close(self, edge_type: EdgeType, from_id: UUID, to_id: UUID, edge_key: str = "") -> bool:
        with self._cur() as cur:
            row = cur.execute(
                "UPDATE edges SET valid_to = now() "
                "WHERE type = %s AND from_id = %s AND to_id = %s AND edge_key = %s AND valid_to IS NULL "
                "RETURNING id",
                (edge_type.value, from_id, to_id, edge_key),
            ).fetchone()
        return row is not None

    def write_decayed_version(
        self, current: Edge, new_confidence: float, *, decay_evidence: Evidence
    ) -> Edge:
        """Write a lower-confidence bitemporal version of an inferred edge.

        Used exclusively by the aging sweep to record a linear-decay step.  The
        method enforces the invariants that the sweep must never violate:

        - ``current.source`` must be ``inferred``  (no declared edges are ever decayed).
        - ``new_confidence`` must be strictly < ``current.confidence``  (never raises).

        Raises ``ValueError`` on violation.

        Behaviour:
        1. Close the current open row (``UPDATE … valid_to = now()``).
        2. Insert a new row sharing the same ``id``, ``type``, ``from_id``, ``to_id``,
           and ``source``, with ``confidence = new_confidence`` and the existing evidence
           list (count marker + observation rows) with ``decay_evidence`` appended.
           The count-marker entry is NOT modified, so ``last_observed_at`` is preserved.
        3. Return the new open ``Edge``.
        """
        if current.source != EdgeSource.inferred:
            raise ValueError(
                f"write_decayed_version only accepts inferred edges; "
                f"got source={current.source!r}"
            )
        if new_confidence >= current.confidence:
            raise ValueError(
                f"new_confidence ({new_confidence}) must be strictly less than "
                f"current.confidence ({current.confidence})"
            )

        # Build the new evidence list: carry all existing entries (count marker +
        # observation rows) and append the decay audit entry.
        new_evidence: list[Evidence] = list(current.evidence) + [decay_evidence]

        with self._cur() as cur:
            cur.execute(
                "UPDATE edges SET valid_to = now() WHERE id = %s AND valid_to IS NULL",
                (current.id,),
            )
            row = cur.execute(
                f"INSERT INTO edges ({_EDGE_COLUMNS}) VALUES "
                "(%s, %s, %s, %s, %s, %s, %s, %s, %s, now(), NULL) "
                f"RETURNING {_EDGE_COLUMNS}",
                (
                    current.id,
                    current.tenant_id,
                    current.type.value,
                    current.from_id,
                    current.to_id,
                    current.edge_key,
                    current.source.value,
                    new_confidence,
                    Jsonb([e.model_dump(mode="json") for e in new_evidence]),
                ),
            ).fetchone()
        return _row_to_edge(row)


def _ci_changed(current: dict, ci: CI) -> bool:
    return (
        current["name"] != ci.name
        or current["attributes"] != ci.attributes
        or abs(current["confidence"] - ci.confidence) > 1e-6
    )


def _edge_changed(current: dict, edge: Edge) -> bool:
    incoming_evidence = [e.model_dump(mode="json") for e in edge.evidence]
    return (
        current["source"] != edge.source.value
        or abs(current["confidence"] - edge.confidence) > 1e-6
        or current["evidence"] != incoming_evidence
    )