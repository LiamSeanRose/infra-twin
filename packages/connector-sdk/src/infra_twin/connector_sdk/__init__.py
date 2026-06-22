"""The connector contract.

Connectors are dumb: they fetch from a provider and emit normalized discovery events keyed
by provider-native identifiers. All intelligence (entity resolution, versioning, inference)
lives in reconciliation, never in a connector.
"""

from infra_twin.connector_sdk.events import (
    CIRef,
    Connector,
    ConnectorDelta,
    DiscoveredCI,
    DiscoveredEdge,
    DiscoveryEvent,
    EdgeEndpointRef,
)

__all__ = [
    "CIRef",
    "Connector",
    "ConnectorDelta",
    "DiscoveredCI",
    "DiscoveredEdge",
    "DiscoveryEvent",
    "EdgeEndpointRef",
]
