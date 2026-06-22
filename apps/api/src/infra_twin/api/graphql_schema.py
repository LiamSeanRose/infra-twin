"""Strawberry GraphQL schema: read-only projection of the infra-twin query surface.

Exposes four query fields that mirror the matching REST read endpoints:
  graph         -> GET /graph          (topology)
  blastRadius   -> GET /cis/{id}/blast-radius
  changes       -> GET /changes
  findings      -> GET /findings

All data access happens inside tenant_session(pool, tenant_id) so Postgres
Row-Level Security scopes every statement to the caller's tenant.  The tenant
UUID and pool are read from info.context; they are placed there by the
context_getter wired in app.py, which declares Depends(require_permission("read"))
so the full auth/RBAC/metering/audit path runs before any resolver executes.

There is NO Mutation type.  The schema is query-only.
"""

from __future__ import annotations

from typing import Optional
from uuid import UUID

import strawberry
from strawberry.scalars import JSON

from infra_twin.db.findings import FindingRepository
from infra_twin.db.repositories import CIRepository
from infra_twin.db.session import tenant_session
from infra_twin.query import blast_radius, change_feed, topology


# ---------------------------------------------------------------------------
# GraphQL object types
# ---------------------------------------------------------------------------


@strawberry.type
class CINode:
    id: strawberry.ID
    type: str
    external_id: str = strawberry.field(name="externalId")
    name: Optional[str]


@strawberry.type
class Edge:
    id: strawberry.ID
    type: str
    from_id: strawberry.ID = strawberry.field(name="fromId")
    to_id: strawberry.ID = strawberry.field(name="toId")
    source: str
    confidence: float


@strawberry.type
class Graph:
    nodes: list[CINode]
    edges: list[Edge]


@strawberry.type
class ImpactedCI:
    id: strawberry.ID
    type: str
    name: Optional[str]
    distance: int


@strawberry.type
class Supernode:
    id: strawberry.ID
    degree: int
    depth: int


@strawberry.type
class BlastRadius:
    source_id: strawberry.ID = strawberry.field(name="sourceId")
    max_depth: int = strawberry.field(name="maxDepth")
    impacted: list[ImpactedCI]
    truncated_supernodes: list[Supernode] = strawberry.field(name="truncatedSupernodes")


@strawberry.type
class ChangeEvent:
    entity: str
    kind: str
    at: str
    id: strawberry.ID
    type: str
    name: Optional[str]
    from_id: Optional[strawberry.ID] = strawberry.field(name="fromId")
    to_id: Optional[strawberry.ID] = strawberry.field(name="toId")


@strawberry.type
class Finding:
    id: strawberry.ID
    rule_id: str = strawberry.field(name="ruleId")
    severity: str
    subject_ci_id: strawberry.ID = strawberry.field(name="subjectCiId")
    subject_ci_type: Optional[str] = strawberry.field(name="subjectCiType")
    subject_ci_name: Optional[str] = strawberry.field(name="subjectCiName")
    title: str
    description: str
    evidence: JSON
    status: str
    detected_at: str = strawberry.field(name="detectedAt")


# ---------------------------------------------------------------------------
# Query root
# ---------------------------------------------------------------------------


@strawberry.type
class Query:

    @strawberry.field
    def graph(self, info: strawberry.types.Info, limit: int = 500) -> Graph:
        tenant_id: UUID = info.context["tenant_id"]
        pool = info.context["pool"]
        with tenant_session(pool, tenant_id) as conn:
            topo = topology(conn, tenant_id, limit=limit)
        nodes = [
            CINode(
                id=strawberry.ID(str(n.id)),
                type=n.type,
                external_id=n.external_id,
                name=n.name,
            )
            for n in topo.nodes
        ]
        edges = [
            Edge(
                id=strawberry.ID(str(e.id)),
                type=e.type,
                from_id=strawberry.ID(str(e.from_id)),
                to_id=strawberry.ID(str(e.to_id)),
                source=e.source,
                confidence=e.confidence,
            )
            for e in topo.edges
        ]
        return Graph(nodes=nodes, edges=edges)

    @strawberry.field
    def blast_radius(
        self,
        info: strawberry.types.Info,
        ci_id: strawberry.ID,
        max_depth: int = 4,
        min_confidence: float = 0.0,
        max_fanout: int = 1000,
    ) -> Optional[BlastRadius]:
        tenant_id: UUID = info.context["tenant_id"]
        pool = info.context["pool"]
        # Validate UUID format: ValueError propagates as a GraphQL error (HTTP 200,
        # errors array), not a 500.
        ci_uuid = UUID(str(ci_id))
        with tenant_session(pool, tenant_id) as conn:
            if CIRepository(conn, tenant_id).get_current_by_id(ci_uuid) is None:
                return None
            result = blast_radius(
                conn,
                tenant_id,
                ci_uuid,
                max_depth=max_depth,
                min_confidence=min_confidence,
                max_fanout=max_fanout,
            )
        impacted = [
            ImpactedCI(
                id=strawberry.ID(str(i.id)),
                type=i.type,
                name=i.name,
                distance=i.distance,
            )
            for i in result.impacted
        ]
        truncated = [
            Supernode(
                id=strawberry.ID(str(s.id)),
                degree=s.degree,
                depth=s.depth,
            )
            for s in result.truncated_supernodes
        ]
        return BlastRadius(
            source_id=strawberry.ID(str(result.source_id)),
            max_depth=result.max_depth,
            impacted=impacted,
            truncated_supernodes=truncated,
        )

    @strawberry.field
    def changes(self, info: strawberry.types.Info, days: int = 7) -> list[ChangeEvent]:
        tenant_id: UUID = info.context["tenant_id"]
        pool = info.context["pool"]
        with tenant_session(pool, tenant_id) as conn:
            events = change_feed(conn, tenant_id, days=days)
        return [
            ChangeEvent(
                entity=e.entity,
                kind=e.kind,
                at=e.at.isoformat(),
                id=strawberry.ID(str(e.id)),
                type=e.type,
                name=e.name,
                from_id=strawberry.ID(str(e.from_id)) if e.from_id else None,
                to_id=strawberry.ID(str(e.to_id)) if e.to_id else None,
            )
            for e in events
        ]

    @strawberry.field
    def findings(self, info: strawberry.types.Info) -> list[Finding]:
        tenant_id: UUID = info.context["tenant_id"]
        pool = info.context["pool"]
        with tenant_session(pool, tenant_id) as conn:
            repo = FindingRepository(conn, tenant_id)
            raw_findings = repo.get_open()
            ci_repo = CIRepository(conn, tenant_id)
            out: list[Finding] = []
            for f in raw_findings:
                ci = ci_repo.get_current_by_id(f.subject_ci_id)
                out.append(
                    Finding(
                        id=strawberry.ID(str(f.id)),
                        rule_id=f.rule_id,
                        severity=f.severity,
                        subject_ci_id=strawberry.ID(str(f.subject_ci_id)),
                        subject_ci_type=ci.type.value if ci else None,
                        subject_ci_name=ci.name if ci else None,
                        title=f.title,
                        description=f.description,
                        evidence=f.evidence,
                        status=f.status,
                        detected_at=f.detected_at.isoformat(),
                    )
                )
        return out


# Module-level schema (query-only, no mutation).
schema = strawberry.Schema(query=Query)
