"""Read-only GCP discovery connector.

Discovers a representative GCP resource set (project, VPC network, subnetwork, firewall
rule, Compute Engine VM instance) via an injected GcpClient and emits canonical discovery
events.

The connector holds no internal ids, never mutates the project, and never raises on
missing optional keys — all accesses use .get() chains.

A ``GcpClient`` is injected so the same code runs against a real Google Cloud SDK adapter
(in the CLI) and against an in-memory fake in tests.
"""

from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable

from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge, DiscoveryEvent
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence


@runtime_checkable
class GcpClient(Protocol):
    """Minimal read-only GCP API surface required by GcpConnector.

    Each method returns a list of plain dicts with the normalized GCP resource shape.
    Production implementations wrap the Google Cloud SDK; test fakes return in-memory
    fixtures.
    """

    def list_networks(self) -> list[dict]: ...        # VPC networks
    def list_subnetworks(self) -> list[dict]: ...     # subnetworks (subnets)
    def list_firewalls(self) -> list[dict]: ...       # firewall rules
    def list_instances(self) -> list[dict]: ...       # Compute Engine VM instances


_CI_TYPES: frozenset[CIType] = frozenset(
    {
        CIType.gcp_project,
        CIType.gcp_network,
        CIType.gcp_subnetwork,
        CIType.gcp_firewall,
        CIType.gcp_instance,
    }
)

_EDGE_TYPES: frozenset[EdgeType] = frozenset(
    {
        EdgeType.CONTAINS,
        EdgeType.RUNS_ON,
        EdgeType.CONNECTS_TO,
    }
)


def _self_link_name(self_link: str | None) -> str | None:
    """Extract the trailing path segment of a GCP selfLink/URL.

    Returns None when the argument is absent or has no path segments.
    """
    if not self_link:
        return None
    parts = self_link.rstrip("/").split("/")
    if parts:
        return parts[-1] or None
    return None


def _firewall_rule_label(firewall: dict) -> str:
    """Render the protocol/ports of a firewall's ``allowed`` entries as a stable label.

    Returns a human-readable summary of the allowed protocol/port combinations, e.g.
    ``tcp/80,443`` or ``all``. Falls back to ``all`` when no entries are present.
    """
    allowed: list[dict] = firewall.get("allowed") or []
    if not allowed:
        return "all"
    parts: list[str] = []
    for entry in allowed:
        if not isinstance(entry, dict):
            continue
        proto = entry.get("IPProtocol") or "all"
        ports: list[str] = entry.get("ports") or []
        if ports:
            parts.append(f"{proto}/{','.join(ports)}")
        else:
            parts.append(proto)
    return ",".join(parts) if parts else "all"


class GcpConnector:
    """Discovers a representative GCP resource set from a single project."""

    source: str = "gcp"
    ci_types: frozenset[CIType] = _CI_TYPES
    edge_types: frozenset[EdgeType] = _EDGE_TYPES

    def __init__(
        self,
        client: GcpClient,
        project_id: str,
        project_name: str | None = None,
    ) -> None:
        self._client = client
        self._project_id = project_id
        self._project_name = project_name

    # -- helpers -----------------------------------------------------------------

    def _evidence(self, detail: str) -> list[Evidence]:
        return [Evidence(source="gcp", detail=detail)]

    def _edge(
        self,
        etype: EdgeType,
        from_ref: CIRef,
        to_ref: CIRef,
        detail: str,
    ) -> DiscoveredEdge:
        return DiscoveredEdge(
            type=etype,
            from_ref=from_ref,
            to_ref=to_ref,
            source=EdgeSource.declared,
            confidence=1.0,
            evidence=self._evidence(detail),
        )

    # -- discovery ---------------------------------------------------------------

    def discover(self) -> Iterator[DiscoveryEvent]:
        project_id = self._project_id
        project_name = self._project_name or project_id
        project_ref = CIRef(type=CIType.gcp_project, external_id=project_id)

        # 1. Project CI — always emitted exactly once.
        yield DiscoveredCI(
            type=CIType.gcp_project,
            external_id=project_id,
            name=project_name,
            attributes={"project_id": project_id},
        )

        # 2. Networks — build network_ids set and emit CIs + CONTAINS project->network.
        network_ids: set[str] = set()
        for net in self._client.list_networks():
            net_id: str | None = net.get("selfLink")
            if not net_id:
                continue
            net_name: str = net.get("name") or net_id
            routing_config = net.get("routingConfig") or {}
            yield DiscoveredCI(
                type=CIType.gcp_network,
                external_id=net_id,
                name=net_name,
                attributes={
                    "auto_create_subnetworks": net.get("autoCreateSubnetworks"),
                    "routing_mode": routing_config.get("routingMode"),
                },
            )
            yield self._edge(
                EdgeType.CONTAINS,
                project_ref,
                CIRef(type=CIType.gcp_network, external_id=net_id),
                "gcp:project:network",
            )
            network_ids.add(net_id)

        # 3. Subnetworks — emit CIs and CONTAINS network->subnetwork when parent resolves.
        discovered_subnetwork_ids: set[str] = set()
        # Track subnetwork -> parent network selfLink for firewall targeting.
        subnetwork_network: dict[str, str] = {}
        for sn in self._client.list_subnetworks():
            sn_id: str | None = sn.get("selfLink")
            if not sn_id:
                continue
            sn_name: str = sn.get("name") or sn_id
            parent_network: str | None = sn.get("network")
            region_raw: str | None = sn.get("region")
            yield DiscoveredCI(
                type=CIType.gcp_subnetwork,
                external_id=sn_id,
                name=sn_name,
                attributes={
                    "ip_cidr_range": sn.get("ipCidrRange"),
                    "region": _self_link_name(region_raw) or region_raw,
                    "network": parent_network,
                },
            )
            if parent_network and parent_network in network_ids:
                yield self._edge(
                    EdgeType.CONTAINS,
                    CIRef(type=CIType.gcp_network, external_id=parent_network),
                    CIRef(type=CIType.gcp_subnetwork, external_id=sn_id),
                    "gcp:network:subnetwork",
                )
            discovered_subnetwork_ids.add(sn_id)
            if parent_network:
                subnetwork_network[sn_id] = parent_network

        # 4. Firewalls — emit CIs and stash for deferred CONNECTS_TO.
        firewalls: list[dict] = []
        for fw in self._client.list_firewalls():
            fw_id: str | None = fw.get("selfLink")
            if not fw_id:
                continue
            yield DiscoveredCI(
                type=CIType.gcp_firewall,
                external_id=fw_id,
                name=fw.get("name") or fw_id,
                attributes={
                    "network": fw.get("network"),
                    "direction": fw.get("direction"),
                    "disabled": fw.get("disabled"),
                },
            )
            firewalls.append(fw)

        # 5. Instances — emit CIs, CONTAINS project->instance, RUNS_ON instance->subnetwork.
        #    Track instances_in_subnetwork and instance_tags for firewall targeting (step 6).
        instances_in_subnetwork: dict[str, set[str]] = {}
        instance_tags: dict[str, set[str]] = {}
        for inst in self._client.list_instances():
            inst_id: str | None = inst.get("selfLink")
            if not inst_id:
                continue
            inst_name: str = inst.get("name") or inst_id
            tags_obj = inst.get("tags") or {}
            tag_items: list[str] = tags_obj.get("items") or []
            yield DiscoveredCI(
                type=CIType.gcp_instance,
                external_id=inst_id,
                name=inst_name,
                attributes={
                    "machine_type": _self_link_name(inst.get("machineType")) or inst.get("machineType"),
                    "zone": _self_link_name(inst.get("zone")) or inst.get("zone"),
                    "tags": tag_items,
                },
            )
            inst_ref = CIRef(type=CIType.gcp_instance, external_id=inst_id)

            # CONTAINS project -> instance (always — project always resolves).
            yield self._edge(
                EdgeType.CONTAINS,
                project_ref,
                inst_ref,
                "gcp:project:instance",
            )

            # RUNS_ON instance -> subnetwork via first matching NIC.
            nics: list[dict] = inst.get("networkInterfaces") or []
            primary_subnet_id: str | None = None
            for nic in nics:
                candidate: str | None = nic.get("subnetwork") if isinstance(nic, dict) else None
                if candidate and candidate in discovered_subnetwork_ids:
                    primary_subnet_id = candidate
                    break

            if primary_subnet_id:
                yield self._edge(
                    EdgeType.RUNS_ON,
                    inst_ref,
                    CIRef(type=CIType.gcp_subnetwork, external_id=primary_subnet_id),
                    "gcp:instance:nic:subnetwork",
                )
                instances_in_subnetwork.setdefault(primary_subnet_id, set()).add(inst_id)

            # Track instance tags and subnetwork membership for firewall targeting.
            instance_tags[inst_id] = set(tag_items)
            # Also track for subnetworks via any NIC (not just primary) for firewall targeting.
            for nic in nics:
                if not isinstance(nic, dict):
                    continue
                nic_sn: str | None = nic.get("subnetwork")
                if nic_sn and nic_sn in discovered_subnetwork_ids:
                    instances_in_subnetwork.setdefault(nic_sn, set()).add(inst_id)

        # 6. Firewall-derived CONNECTS_TO (deferred; now instances are known).
        for fw in firewalls:
            fw_id = fw.get("selfLink")
            if not fw_id:
                continue

            # Only ingress allow rules that are not disabled with non-empty allowed entries.
            direction = (fw.get("direction") or "INGRESS").upper()
            if direction != "INGRESS":
                continue
            if fw.get("disabled"):
                continue
            allowed_entries: list[dict] = fw.get("allowed") or []
            if not allowed_entries:
                continue

            fw_name: str = fw.get("name") or "<unnamed>"
            fw_network: str | None = fw.get("network")
            target_tags: list[str] = fw.get("targetTags") or []
            source_ranges: list[str] = fw.get("sourceRanges") or []
            source_tags: list[str] = fw.get("sourceTags") or []

            # Derive source string for evidence.
            if source_ranges:
                src_str = ",".join(sorted(source_ranges))
            elif source_tags:
                src_str = "tag:" + ",".join(sorted(source_tags))
            else:
                src_str = "*"

            rule_label = _firewall_rule_label(fw)
            rule_detail = f"gcp:firewall:rule:{fw_name} allows {rule_label} from {src_str}"

            fw_ref = CIRef(type=CIType.gcp_firewall, external_id=fw_id)

            # Resolve target subnetworks.
            for sn_id in sorted(discovered_subnetwork_ids):
                # Check subnetwork's parent network matches firewall's network (when declared).
                if fw_network:
                    sn_parent = subnetwork_network.get(sn_id)
                    if sn_parent != fw_network:
                        continue

                # Check at least one instance in this subnetwork matches the firewall.
                inst_ids_in_sn = instances_in_subnetwork.get(sn_id, set())
                if not inst_ids_in_sn:
                    continue

                if target_tags:
                    # Firewall applies only to instances with matching tags.
                    matched = any(
                        instance_tags.get(iid, set()) & set(target_tags)
                        for iid in inst_ids_in_sn
                    )
                    if not matched:
                        continue
                # else: no target tags = applies to all instances in the network.

                yield DiscoveredEdge(
                    type=EdgeType.CONNECTS_TO,
                    from_ref=fw_ref,
                    to_ref=CIRef(type=CIType.gcp_subnetwork, external_id=sn_id),
                    source=EdgeSource.declared,
                    confidence=1.0,
                    evidence=[Evidence(source="gcp", detail=rule_detail)],
                )
