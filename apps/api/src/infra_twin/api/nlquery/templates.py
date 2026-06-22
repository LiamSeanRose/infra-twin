"""The whitelist of query templates the NL layer is allowed to run.

Each template pairs a typed Pydantic parameter model (validated before execution) with a
handler that calls the platform's existing tenant-scoped repositories / query functions. The
LLM may only choose a template name and supply arguments for these models — it can never emit
a query string. Each template also carries a deterministic ``summarize`` so the natural-language
answer is generated from the actual result, not from the model's imagination.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

import psycopg
from pydantic import BaseModel, Field

from infra_twin.core_model import CIType
from infra_twin.db.repositories import CIRepository
from infra_twin.query import blast_radius, change_feed, reachability


# -- parameter models ------------------------------------------------------------

class InventoryParams(BaseModel):
    """Filter for listing current CIs."""

    type: CIType | None = Field(
        default=None, description="Restrict to a single CI type, or omit for all types."
    )


class CountByTypeParams(BaseModel):
    """No parameters — counts all current CIs grouped by type."""


class BlastRadiusParams(BaseModel):
    """Identify the resource to fail by its provider-native id."""

    external_id: str = Field(
        description="Provider id of the resource (instance id, vpc id, ARN, bucket name, ...)."
    )
    max_depth: int = Field(default=4, ge=1, le=10, description="Traversal depth bound.")


class RecentChangesParams(BaseModel):
    """Time window for the change feed."""

    days: int = Field(default=7, ge=1, le=30, description="Look back this many days.")


class ReachabilityParams(BaseModel):
    """Identify the target resource to test for inbound reachability by its provider-native id."""

    external_id: str = Field(
        description="Provider id of the target resource (instance id, sg id, ARN, bucket name, ...)."
    )
    max_depth: int = Field(default=6, ge=1, le=10, description="Traversal depth bound.")
    internet_only: bool = Field(
        default=False,
        description="If true, answer only whether the internet can reach the target.",
    )


# -- template definition ---------------------------------------------------------

@dataclass(frozen=True)
class Template:
    name: str
    description: str
    params_model: type[BaseModel]
    handler: Callable[[psycopg.Connection, UUID, BaseModel], dict]
    summarize: Callable[[BaseModel, dict], str]


# -- handlers + summaries --------------------------------------------------------

def _inventory(conn: psycopg.Connection, tenant_id: UUID, params: InventoryParams) -> dict:
    cis = CIRepository(conn, tenant_id).get_current(type=params.type)
    return {
        "cis": [
            {"id": str(c.id), "type": c.type.value, "external_id": c.external_id, "name": c.name}
            for c in cis
        ]
    }


def _inventory_summary(params: InventoryParams, data: dict) -> str:
    n = len(data["cis"])
    scope = f" of type {params.type.value}" if params.type else ""
    return f"Found {n} configuration item{'' if n == 1 else 's'}{scope}."


def _count_by_type(conn: psycopg.Connection, tenant_id: UUID, params: CountByTypeParams) -> dict:
    rows = conn.execute(
        "SELECT type, count(*) FROM cis WHERE valid_to IS NULL GROUP BY type ORDER BY type"
    ).fetchall()
    return {"counts": {r[0]: r[1] for r in rows}}


def _count_summary(params: CountByTypeParams, data: dict) -> str:
    counts = data["counts"]
    return f"{sum(counts.values())} configuration items across {len(counts)} type(s)."


def _blast(conn: psycopg.Connection, tenant_id: UUID, params: BlastRadiusParams) -> dict:
    row = conn.execute(
        "SELECT id FROM cis WHERE external_id = %s AND valid_to IS NULL LIMIT 1",
        (params.external_id,),
    ).fetchone()
    if row is None:
        return {"found": False, "external_id": params.external_id, "impacted": []}
    result = blast_radius(conn, tenant_id, row[0], max_depth=params.max_depth)
    return {
        "found": True,
        "external_id": params.external_id,
        "impacted": [
            {"id": str(i.id), "type": i.type, "name": i.name, "distance": i.distance}
            for i in result.impacted
        ],
        "truncated_supernodes": [
            {"id": str(s.id), "degree": s.degree} for s in result.truncated_supernodes
        ],
    }


def _blast_summary(params: BlastRadiusParams, data: dict) -> str:
    if not data["found"]:
        return f"No configuration item found with id '{params.external_id}'."
    n = len(data["impacted"])
    return f"{n} resource{'' if n == 1 else 's'} would be impacted if '{params.external_id}' failed."


def _changes(conn: psycopg.Connection, tenant_id: UUID, params: RecentChangesParams) -> dict:
    events = change_feed(conn, tenant_id, days=params.days)
    return {
        "days": params.days,
        "events": [
            {
                "entity": e.entity,
                "kind": e.kind,
                "type": e.type,
                "name": e.name,
                "at": e.at.isoformat(),
            }
            for e in events
        ],
    }


def _changes_summary(params: RecentChangesParams, data: dict) -> str:
    n = len(data["events"])
    return f"{n} change{'' if n == 1 else 's'} in the last {params.days} days."


def _reachability(conn: psycopg.Connection, tenant_id: UUID, params: ReachabilityParams) -> dict:
    row = conn.execute(
        "SELECT id FROM cis WHERE external_id = %s AND valid_to IS NULL LIMIT 1",
        (params.external_id,),
    ).fetchone()
    if row is None:
        return {
            "found": False,
            "external_id": params.external_id,
            "reached_by_internet": False,
            "sources": [],
        }
    result = reachability(conn, tenant_id, row[0], max_depth=params.max_depth)
    reached_by_internet = result.reached_by_internet
    sources = result.sources
    if params.internet_only:
        sources = [s for s in sources if s.is_internet]
    return {
        "found": True,
        "external_id": params.external_id,
        "reached_by_internet": reached_by_internet,
        "internet_only": params.internet_only,
        "sources": [
            {
                "id": str(s.id),
                "type": s.type,
                "name": s.name,
                "distance": s.distance,
                "is_internet": s.is_internet,
                "path": [
                    {
                        "from_id": str(h.from_id),
                        "to_id": str(h.to_id),
                        "edge_type": h.edge_type,
                        "evidence": h.evidence,
                    }
                    for h in s.path
                ],
            }
            for s in sources
        ],
    }


def _reachability_summary(params: ReachabilityParams, data: dict) -> str:
    if not data["found"]:
        return f"No configuration item found with id '{params.external_id}'."
    reached_by_internet = data["reached_by_internet"]
    if params.internet_only:
        if reached_by_internet:
            return f"The internet can reach '{params.external_id}'."
        return f"The internet cannot reach '{params.external_id}'."
    n = len(data["sources"])
    return f"{n} source{'' if n == 1 else 's'} can reach '{params.external_id}'."


REGISTRY: dict[str, Template] = {
    "inventory": Template(
        name="inventory",
        description=(
            "List current configuration items, optionally filtered to a single CI type. "
            "Use for questions like 'what EC2 instances do I have' or 'list my VPCs'."
        ),
        params_model=InventoryParams,
        handler=_inventory,
        summarize=_inventory_summary,
    ),
    "count_by_type": Template(
        name="count_by_type",
        description=(
            "Count current configuration items grouped by type. Use for 'how many of each "
            "resource do I have' or 'give me an inventory summary'."
        ),
        params_model=CountByTypeParams,
        handler=_count_by_type,
        summarize=_count_summary,
    ),
    "blast_radius": Template(
        name="blast_radius",
        description=(
            "Find what would be impacted if a specific resource failed, given its provider id "
            "(an instance id, vpc id, ARN, or bucket name). Use for 'what breaks if vpc-123 "
            "goes down'."
        ),
        params_model=BlastRadiusParams,
        handler=_blast,
        summarize=_blast_summary,
    ),
    "recent_changes": Template(
        name="recent_changes",
        description=(
            "List infrastructure changes (created/updated/removed) within the last N days "
            "(default 7). Use for 'what changed this week'."
        ),
        params_model=RecentChangesParams,
        handler=_changes,
        summarize=_changes_summary,
    ),
    "reachability": Template(
        name="reachability",
        description=(
            "Find which sources (including the internet) can reach a specific resource via "
            "network access paths, given its provider id. Use for questions like 'can the "
            "internet reach this resource', 'what can reach this instance', or 'is sg-123 "
            "publicly accessible'."
        ),
        params_model=ReachabilityParams,
        handler=_reachability,
        summarize=_reachability_summary,
    ),
}
