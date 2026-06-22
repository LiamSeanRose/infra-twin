"""Canonical discovery events and the Connector protocol.

A connector emits :class:`DiscoveredCI` and :class:`DiscoveredEdge` objects. These reference
resources by provider-native identity (``type`` + ``external_id``) only — a connector never
knows or assigns internal CI ids; reconciliation does that.
"""

from __future__ import annotations

from typing import Any, Iterator, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence


class DiscoveredCI(BaseModel):
    """A CI observed by a connector, keyed by provider-native (type, external_id)."""

    type: CIType
    external_id: str
    name: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    alias_keys: list[str] = Field(default_factory=list)  # cross-source join keys


class CIRef(BaseModel):
    """A reference to a CI by its provider-native identity."""

    type: CIType
    external_id: str


class DiscoveredEdge(BaseModel):
    """A relationship observed by a connector. Provenance is mandatory, as for all edges."""

    type: EdgeType
    from_ref: CIRef
    to_ref: CIRef
    source: EdgeSource = EdgeSource.declared
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: list[Evidence] = Field(min_length=1)
    edge_key: str = ""


DiscoveryEvent = DiscoveredCI | DiscoveredEdge


class EdgeEndpointRef(BaseModel):
    """Identifies an edge to remove by its type and provider-native endpoints."""

    type: EdgeType
    from_ref: CIRef
    to_ref: CIRef


class ConnectorDelta(BaseModel):
    """An explicit incremental change set emitted by a connector.

    Unlike a full discovery batch, a delta names exactly which facts changed.
    Reconciliation upserts only ``upserts`` and closes only ``removed_cis`` /
    ``removed_edges``; it never closes facts merely because they are absent.
    """

    upserts: list[DiscoveryEvent] = Field(default_factory=list)
    removed_cis: list[CIRef] = Field(default_factory=list)
    removed_edges: list[EdgeEndpointRef] = Field(default_factory=list)


@runtime_checkable
class Connector(Protocol):
    """What every connector implements.

    ``ci_types`` / ``edge_types`` declare the scope the connector is authoritative for, so
    reconciliation knows which existing facts a full run is allowed to close when absent.
    """

    source: str
    ci_types: frozenset[CIType]
    edge_types: frozenset[EdgeType]

    def discover(self) -> Iterator[DiscoveryEvent]: ...
