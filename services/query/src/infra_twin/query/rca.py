"""Root-cause analysis by change/topology correlation.

Given a suspected-impacted CI and an incident timestamp, this module correlates recent
change events in that CI's upstream topological neighborhood and returns a ranked,
evidence-grounded list of candidate root causes.

The algorithm composes the existing change_feed (bitemporal window diff) and blast_radius
(graph traversal), walking topology in the UPSTREAM direction — the inverse of blast-radius.

Upstream direction semantics (mirror + invert blast_radius constants):
  - CONTAINS edges: blast_radius walks (a)-[CONTAINS]->(b) to find downstream impact.
    Upstream RCA inverts this: (a)<-[CONTAINS]-(b), i.e. the container of the target
    is upstream.
  - DEPENDS_ON / RUNS_ON / ROUTES_TO / EXPOSES: blast_radius walks (a)<-[r]-(b) to find
    things that depend on a failing node. Upstream RCA inverts: (a)-[r]->(b), i.e. the
    things the target depends on / runs on / routes to / is exposed-via are upstream.

Scoring formula (deterministic, pure — no now(), no random):
  Let e = a ChangeEvent, d = graph distance of subject CI from target (target=0).
  Only events with since <= e.at < incident_at are candidates (half-open window + guard).

  proximity  = 1.0 / (1.0 + d)
      d=0 → 1.0, d=1 → 0.5, d=2 → 0.333…

  age_seconds = (incident_at - e.at).total_seconds()   # always > 0 for candidates
  lookback_seconds = lookback.total_seconds()
  recency = lookback_seconds / (lookback_seconds + age_seconds)
      Just-before-incident → near 1.0; near far edge of window → near 0.5.

  kind_weight:
      edge removed  → 3.0   (removed dependency edge: strong signal)
      ci   removed  → 3.0
      ci   updated  → 2.0
      edge updated  → 2.0
      ci   created  → 1.0
      edge created  → 1.0

  score = kind_weight * (proximity + recency)

Ranking: candidates sorted by score DESC. Tie-break key:
  (-score, distance, age_seconds, entity, str(id))
  This yields: closer first, then older-within-tie deterministically by age, then entity
  type alphabetically, then UUID string to guarantee identical ordering across repeated calls.

Limitation on removed CI events: the neighborhood is built from the current CI snapshot
(valid_to IS NULL). A CI that was removed before the incident will not appear in the
current snapshot; therefore a "removed" CI change event for such a CI will be excluded by
the membership filter (§4.4). This is documented honestly: to include removed-CI events the
neighborhood would need to be built from the bitemporal state at incident_at, which is a
future enhancement.

Findings corroboration: deferred (future enhancement).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

import psycopg

from infra_twin.db.graph import cypher
from infra_twin.query.blast_radius import INCOMING_IMPACT, OUTGOING_IMPACT, _scalar
from infra_twin.query.change_feed import ChangeEvent, change_feed

# Edge types walked upstream from target.
# Mirrors blast_radius direction constants but inverted:
#   blast_radius OUTGOING  (a)-[CONTAINS]->(b)  downstream
#   upstream RCA           (a)<-[CONTAINS]-(b)   → container is upstream
#
#   blast_radius INCOMING  (a)<-[DEPENDS_ON|...]-( b)  downstream (dependents)
#   upstream RCA           (a)-[DEPENDS_ON|...]->( b)  → what target depends on

_UPSTREAM_REVERSE = OUTGOING_IMPACT   # walk <-[r]- for these
_UPSTREAM_FORWARD = INCOMING_IMPACT   # walk -[r]-> for these

_KIND_WEIGHT: dict[tuple[str, str], float] = {
    ("edge", "removed"): 3.0,
    ("ci", "removed"): 3.0,
    ("ci", "updated"): 2.0,
    ("edge", "updated"): 2.0,
    ("ci", "created"): 1.0,
    ("edge", "created"): 1.0,
}


@dataclass
class NeighborhoodCI:
    id: UUID
    type: str
    name: str | None
    distance: int  # graph hops upstream from target; target itself is 0


@dataclass
class CandidateCause:
    event: ChangeEvent       # the underlying change_feed.ChangeEvent, unmodified
    distance: int            # graph distance of the subject CI (or nearest edge endpoint)
    score: float             # deterministic numeric score; higher = more likely root cause
    evidence: str            # human-readable, cites real queried data


@dataclass
class RcaResult:
    target_id: UUID
    incident_at: datetime
    since: datetime           # incident_at - lookback
    until: datetime           # == incident_at (exclusive upper bound)
    max_depth: int
    candidates: list[CandidateCause]   # ranked, highest score first


def _upstream_neighbors(
    conn: psycopg.Connection,
    tenant_id: UUID,
    ci_id: str,
    min_confidence: float = 0.0,
) -> list[str]:
    """Return the upstream neighbor ci_ids of ``ci_id`` in the AGE graph.

    Upstream = inverse of blast_radius direction:
      CONTAINS-type edges: walk (ci_id)<-[r]-(b)  → container is upstream
      DEPENDS_ON/RUNS_ON/ROUTES_TO/EXPOSES: walk (ci_id)-[r]->(b) → dependency is upstream
    """
    tenant = str(tenant_id)
    conf = float(min_confidence)
    rev_types = ", ".join(f"'{t}'" for t in _UPSTREAM_REVERSE)
    fwd_types = ", ".join(f"'{t}'" for t in _UPSTREAM_FORWARD)

    # Walk (ci_id)<-[r]-(b) for CONTAINS-like edges (container is upstream)
    rows = cypher(
        conn,
        f"MATCH (a {{ci_id: '{ci_id}'}})<-[r]-(b) "
        f"WHERE type(r) IN [{rev_types}] AND r.tenant_id = '{tenant}' "
        f"AND r.confidence >= {conf} RETURN b.ci_id",
        "(ci_id agtype)",
    )
    # Walk (ci_id)-[r]->(b) for DEPENDS_ON/RUNS_ON/ROUTES_TO/EXPOSES (what target depends on)
    rows += cypher(
        conn,
        f"MATCH (a {{ci_id: '{ci_id}'}})-[r]->(b) "
        f"WHERE type(r) IN [{fwd_types}] AND r.tenant_id = '{tenant}' "
        f"AND r.confidence >= {conf} RETURN b.ci_id",
        "(ci_id agtype)",
    )
    return [_scalar(row[0]) for row in rows]


def _build_neighborhood(
    conn: psycopg.Connection,
    tenant_id: UUID,
    target_id: UUID,
    max_depth: int,
    min_confidence: float = 0.0,
) -> dict[UUID, int]:
    """BFS upstream from target_id up to max_depth hops.

    Returns a mapping {ci_id: distance} where distance is the number of graph hops from
    target_id. target_id itself is always at distance 0.

    Mirrors the BFS loop in blast_radius.blast_radius exactly, but uses upstream neighbors.
    Cycles are handled by the ``visited`` set (same guard as blast_radius).
    """
    source = str(target_id)
    visited: dict[str, int] = {source: 0}
    frontier = [source]
    discovered: list[tuple[str, int]] = []

    for depth in range(1, max_depth + 1):
        next_frontier: list[str] = []
        for node in frontier:
            neighbors = list(dict.fromkeys(
                _upstream_neighbors(conn, tenant_id, node, min_confidence)
            ))
            for neighbor in neighbors:
                if neighbor not in visited:
                    visited[neighbor] = depth
                    next_frontier.append(neighbor)
                    discovered.append((neighbor, depth))
        frontier = next_frontier
        if not frontier:
            break

    # Resolve discovered CIs from the relational store (RLS-scoped) for current type/name.
    # (target_id is already in visited at distance 0.)
    neighbor_distance: dict[UUID, int] = {target_id: 0}
    if discovered:
        ids = [UUID(node) for node, _ in discovered]
        rows = conn.execute(
            "SELECT id, type, name FROM cis WHERE id = ANY(%s) AND valid_to IS NULL",
            (ids,),
        ).fetchall()
        present = {r[0] for r in rows}  # only currently-present CIs
        for node, distance in discovered:
            uid = UUID(node)
            if uid in present:
                neighbor_distance[uid] = distance

    return neighbor_distance


def _score_event(
    e: ChangeEvent,
    distance: int,
    incident_at: datetime,
    lookback: timedelta,
) -> float:
    """Compute the deterministic score for a candidate event.

    See module docstring for the full formula. Pure: no now(), no random.
    """
    proximity = 1.0 / (1.0 + distance)
    age_seconds = (incident_at - e.at).total_seconds()
    lookback_seconds = lookback.total_seconds()
    recency = lookback_seconds / (lookback_seconds + age_seconds)
    kind_weight = _KIND_WEIGHT.get((e.entity, e.kind), 1.0)
    return kind_weight * (proximity + recency)


def _build_evidence(
    e: ChangeEvent,
    distance: int,
    incident_at: datetime,
) -> str:
    """Build a human-readable evidence sentence for a candidate cause.

    Requirements: must contain event kind, entity type, and integer distance.
    """
    age = incident_at - e.at
    # Strip sub-second precision for readability.
    age_str = str(age).split(".")[0]
    if e.entity == "ci":
        name_part = f" '{e.name}'" if e.name else ""
        return (
            f"{e.type}{name_part} was {e.kind} {age_str} before the incident, "
            f"{distance} hop{'s' if distance != 1 else ''} upstream of the target"
        )
    else:
        from_part = str(e.from_id) if e.from_id else "?"
        to_part = str(e.to_id) if e.to_id else "?"
        return (
            f"{e.type} edge ({from_part} -> {to_part}) was {e.kind} {age_str} "
            f"before the incident, "
            f"{distance} hop{'s' if distance != 1 else ''} upstream of the target"
        )


def root_cause(
    conn: psycopg.Connection,
    tenant_id: UUID,
    *,
    target_id: UUID,
    incident_at: datetime,
    lookback: timedelta = timedelta(hours=24),
    max_depth: int = 3,
) -> RcaResult:
    """Correlate recent change events in the upstream topology neighborhood of target_id.

    Algorithm:
    1. Define the change window: since = incident_at - lookback; until = incident_at.
       Window is half-open [since, until) — change_feed already enforces >= since AND
       < until; additionally guard e.at < incident_at defensively.

    2. Build upstream neighborhood via bounded-depth BFS (inverted blast_radius direction),
       collecting {ci_id: distance}. target_id is always at distance 0.

    3. Pull change events via change_feed(conn, tenant_id, since=since, until=until).
       Never re-implements the window SQL.

    4. Filter to neighborhood membership (§4.4 rules) and exclude events at/after
       incident_at.

    5. Score each remaining event deterministically (see module docstring for formula).

    6. Build evidence string and assemble CandidateCause list.

    7. Sort by (-score, distance, age_seconds, entity, str(id)) — highest score first with
       deterministic tie-break: closer first, then older-within-tie by age, then entity
       type alphabetically, then UUID string.

    Confidence filter: min_confidence=0.0 (all edges included) — acceptable for v1.
    Findings corroboration: deferred to a future cycle.
    """
    since = incident_at - lookback
    until = incident_at

    # Step 2: upstream neighborhood
    neighbor_distance = _build_neighborhood(
        conn, tenant_id, target_id, max_depth, min_confidence=0.0
    )
    neighborhood_ids: set[UUID] = set(neighbor_distance.keys())

    # Step 3: change feed (half-open [since, until))
    events = change_feed(conn, tenant_id, since=since, until=until)

    # Steps 4–6: filter, score, build candidates
    candidates: list[CandidateCause] = []
    for e in events:
        # Defensive guard: exclude events at or after incident_at (cause cannot post-date effect)
        if e.at >= incident_at:
            continue

        if e.entity == "ci":
            if e.id not in neighborhood_ids:
                continue
            distance = neighbor_distance[e.id]
        else:
            # edge event
            endpoints_in = [
                ep for ep in (e.from_id, e.to_id)
                if ep is not None and ep in neighborhood_ids
            ]
            if not endpoints_in:
                continue
            distance = min(neighbor_distance[ep] for ep in endpoints_in)

        score = _score_event(e, distance, incident_at, lookback)
        evidence = _build_evidence(e, distance, incident_at)

        candidates.append(CandidateCause(
            event=e,
            distance=distance,
            score=score,
            evidence=evidence,
        ))

    # Step 7: sort by (-score, distance, age_seconds, entity, str(id))
    def _sort_key(c: CandidateCause) -> tuple:
        age_seconds = (incident_at - c.event.at).total_seconds()
        return (-c.score, c.distance, age_seconds, c.event.entity, str(c.event.id))

    candidates.sort(key=_sort_key)

    return RcaResult(
        target_id=target_id,
        incident_at=incident_at,
        since=since,
        until=until,
        max_depth=max_depth,
        candidates=candidates,
    )
