"""Read-only Azure discovery connector.

Discovers a representative Azure resource set (subscription, resource groups, virtual
networks + subnets, network security groups, virtual machines) via an injected AzureClient
and emits canonical discovery events.

The connector holds no internal ids, never mutates the subscription, and never raises on
missing optional keys — all accesses use .get() chains.

An ``AzureClient`` is injected so the same code runs against a real Azure SDK adapter (in
the CLI) and against an in-memory fake in tests.
"""

from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable

from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge, DiscoveryEvent
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence


@runtime_checkable
class AzureClient(Protocol):
    """Minimal read-only Azure API surface required by AzureConnector.

    Each method returns a list of plain dicts with the normalized Azure resource shape.
    Production implementations wrap the Azure SDK; test fakes return in-memory fixtures.
    """

    def list_resource_groups(self) -> list[dict]: ...
    def list_virtual_networks(self) -> list[dict]: ...
    def list_network_security_groups(self) -> list[dict]: ...
    def list_virtual_machines(self) -> list[dict]: ...


_CI_TYPES: frozenset[CIType] = frozenset(
    {
        CIType.azure_subscription,
        CIType.azure_resource_group,
        CIType.azure_vnet,
        CIType.azure_subnet,
        CIType.azure_nsg,
        CIType.azure_vm,
    }
)

_EDGE_TYPES: frozenset[EdgeType] = frozenset(
    {
        EdgeType.CONTAINS,
        EdgeType.RUNS_ON,
        EdgeType.CONNECTS_TO,
    }
)


def _rg_name_from_id(resource_id: str) -> str | None:
    """Extract the resource group name from an Azure resource id string.

    Azure resource ids follow the pattern:
    /subscriptions/<sub>/resourceGroups/<rg>/...
    Returns the <rg> segment, or None if the id does not contain one.
    """
    parts = resource_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return None


def _nsg_rule_label(rule_props: dict) -> str:
    """Render an NSG security rule as a stable evidence fragment.

    Format: ``<proto>/<destinationPortRange> from <sourceAddressPrefix>``
    Falls back to ``all`` for missing fields.
    """
    proto = rule_props.get("protocol") or "all"
    port_range = rule_props.get("destinationPortRange") or "all"
    src = rule_props.get("sourceAddressPrefix") or "*"
    return f"{proto}/{port_range} from {src}"


class AzureConnector:
    """Discovers a representative Azure resource set from a single subscription."""

    source: str = "azure"
    ci_types: frozenset[CIType] = _CI_TYPES
    edge_types: frozenset[EdgeType] = _EDGE_TYPES

    def __init__(
        self,
        client: AzureClient,
        subscription_id: str,
        subscription_name: str | None = None,
    ) -> None:
        self._client = client
        self._subscription_id = subscription_id
        self._subscription_name = subscription_name

    # -- helpers -----------------------------------------------------------------

    def _evidence(self, detail: str) -> list[Evidence]:
        return [Evidence(source="azure", detail=detail)]

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
        sub_id = self._subscription_id
        sub_name = self._subscription_name or sub_id
        sub_ref = CIRef(type=CIType.azure_subscription, external_id=sub_id)

        # 1. Subscription CI — always emitted exactly once.
        yield DiscoveredCI(
            type=CIType.azure_subscription,
            external_id=sub_id,
            name=sub_name,
            attributes={"subscription_id": sub_id},
        )

        # 2. Resource groups — build rg_id_by_name index.
        rg_id_by_name: dict[str, str] = {}
        for rg in self._client.list_resource_groups():
            rg_id: str | None = rg.get("id")
            if not rg_id:
                continue
            rg_name: str = rg.get("name") or rg_id
            rg_id_by_name[rg_name] = rg_id
            rg_ref = CIRef(type=CIType.azure_resource_group, external_id=rg_id)
            yield DiscoveredCI(
                type=CIType.azure_resource_group,
                external_id=rg_id,
                name=rg_name,
                attributes={"location": rg.get("location")},
            )
            yield self._edge(
                EdgeType.CONTAINS,
                sub_ref,
                rg_ref,
                "azure:subscription:resource_group",
            )

        # 3. NSGs — build indexes for later CONNECTS_TO emission.
        #    nsg_by_id: nsg resource id -> nsg dict
        #    subnet_ids_by_nsg_id: nsg id -> set of subnet ids associated with it
        nsg_by_id: dict[str, dict] = {}
        subnet_ids_by_nsg_id: dict[str, set[str]] = {}
        for nsg in self._client.list_network_security_groups():
            nsg_id: str | None = nsg.get("id")
            if not nsg_id:
                continue
            nsg_props = nsg.get("properties") or {}
            nsg_name: str = nsg.get("name") or nsg_id
            nsg_rg_name: str | None = _rg_name_from_id(nsg_id)
            yield DiscoveredCI(
                type=CIType.azure_nsg,
                external_id=nsg_id,
                name=nsg_name,
                attributes={
                    "location": nsg.get("location"),
                    "resource_group": nsg_rg_name,
                },
            )
            nsg_by_id[nsg_id] = nsg
            for subnet_assoc in nsg_props.get("subnets") or []:
                s_id: str | None = subnet_assoc.get("id") if isinstance(subnet_assoc, dict) else None
                if s_id:
                    subnet_ids_by_nsg_id.setdefault(nsg_id, set()).add(s_id)

        # 4. Virtual networks + subnets — build discovered_subnet_ids set.
        discovered_subnet_ids: set[str] = set()
        for vnet in self._client.list_virtual_networks():
            vnet_id: str | None = vnet.get("id")
            if not vnet_id:
                continue
            vnet_name: str = vnet.get("name") or vnet_id
            vnet_props = vnet.get("properties") or {}
            addr_space = (vnet_props.get("addressSpace") or {}).get("addressPrefixes")
            vnet_rg_name: str | None = _rg_name_from_id(vnet_id)
            yield DiscoveredCI(
                type=CIType.azure_vnet,
                external_id=vnet_id,
                name=vnet_name,
                attributes={
                    "location": vnet.get("location"),
                    "address_space": addr_space,
                    "resource_group": vnet_rg_name,
                },
            )
            vnet_ref = CIRef(type=CIType.azure_vnet, external_id=vnet_id)

            # CONTAINS RG -> vnet (only if RG resolves).
            if vnet_rg_name:
                rg_id_for_vnet = rg_id_by_name.get(vnet_rg_name)
                if rg_id_for_vnet:
                    yield self._edge(
                        EdgeType.CONTAINS,
                        CIRef(type=CIType.azure_resource_group, external_id=rg_id_for_vnet),
                        vnet_ref,
                        "azure:resource_group:vnet",
                    )

            # Subnets inline under the vnet.
            for subnet in (vnet_props.get("subnets") or []):
                subnet_id: str | None = subnet.get("id") if isinstance(subnet, dict) else None
                if not subnet_id:
                    continue
                subnet_name: str = subnet.get("name") or subnet_id
                subnet_props = subnet.get("properties") or {}
                yield DiscoveredCI(
                    type=CIType.azure_subnet,
                    external_id=subnet_id,
                    name=subnet_name,
                    attributes={
                        "address_prefix": subnet_props.get("addressPrefix"),
                        "vnet": vnet_id,
                    },
                )
                yield self._edge(
                    EdgeType.CONTAINS,
                    vnet_ref,
                    CIRef(type=CIType.azure_subnet, external_id=subnet_id),
                    "azure:vnet:subnet",
                )
                discovered_subnet_ids.add(subnet_id)

        # 5. NSG CONNECTS_TO emission (deferred until subnets are known).
        for nsg_id, nsg in nsg_by_id.items():
            nsg_ref = CIRef(type=CIType.azure_nsg, external_id=nsg_id)
            nsg_props = nsg.get("properties") or {}
            security_rules: list[dict] = nsg_props.get("securityRules") or []

            # Collect inbound Allow rules.
            allow_inbound: list[dict] = []
            for rule in security_rules:
                rule_props = rule.get("properties") or {}
                if (
                    (rule_props.get("access") or "").lower() == "allow"
                    and (rule_props.get("direction") or "").lower() == "inbound"
                ):
                    allow_inbound.append(rule)

            if not allow_inbound:
                continue

            # For each associated subnet that is discovered, emit one collapsed CONNECTS_TO.
            associated_subnet_ids = subnet_ids_by_nsg_id.get(nsg_id, set())
            for subnet_id in sorted(associated_subnet_ids):
                if subnet_id not in discovered_subnet_ids:
                    continue
                # Build one Evidence entry per contributing rule, deduped and sorted.
                seen_details: set[str] = set()
                evidence: list[Evidence] = []
                for rule in sorted(allow_inbound, key=lambda r: r.get("name") or ""):
                    rule_name: str = rule.get("name") or "<unnamed>"
                    rule_props = rule.get("properties") or {}
                    rule_fragment = _nsg_rule_label(rule_props)
                    detail = (
                        f"azure:nsg:rule:{rule_name} allows {rule_fragment}"
                    )
                    if detail not in seen_details:
                        seen_details.add(detail)
                        evidence.append(Evidence(source="azure", detail=detail))
                if evidence:
                    yield DiscoveredEdge(
                        type=EdgeType.CONNECTS_TO,
                        from_ref=nsg_ref,
                        to_ref=CIRef(type=CIType.azure_subnet, external_id=subnet_id),
                        source=EdgeSource.declared,
                        confidence=1.0,
                        evidence=evidence,
                    )

        # 6. Virtual machines.
        for vm in self._client.list_virtual_machines():
            vm_id: str | None = vm.get("id")
            if not vm_id:
                continue
            vm_name: str = vm.get("name") or vm_id
            vm_props = vm.get("properties") or {}
            vm_rg_name: str | None = _rg_name_from_id(vm_id)
            hw_profile = vm_props.get("hardwareProfile") or {}
            yield DiscoveredCI(
                type=CIType.azure_vm,
                external_id=vm_id,
                name=vm_name,
                attributes={
                    "location": vm.get("location"),
                    "vm_size": hw_profile.get("vmSize"),
                    "resource_group": vm_rg_name,
                },
            )
            vm_ref = CIRef(type=CIType.azure_vm, external_id=vm_id)

            # CONTAINS RG -> VM (only if RG resolves).
            if vm_rg_name:
                rg_id_for_vm = rg_id_by_name.get(vm_rg_name)
                if rg_id_for_vm:
                    yield self._edge(
                        EdgeType.CONTAINS,
                        CIRef(type=CIType.azure_resource_group, external_id=rg_id_for_vm),
                        vm_ref,
                        "azure:resource_group:vm",
                    )

            # RUNS_ON VM -> subnet (via primary NIC ipConfiguration subnet id).
            network_profile = vm_props.get("networkProfile") or {}
            nics = network_profile.get("networkInterfaces") or []
            primary_subnet_id: str | None = None
            for nic in nics:
                nic_props = nic.get("properties") or {}
                ip_configs = nic_props.get("ipConfigurations") or []
                for ip_config in ip_configs:
                    ip_props = ip_config.get("properties") or {}
                    subnet_ref_obj = ip_props.get("subnet") or {}
                    candidate = subnet_ref_obj.get("id") if isinstance(subnet_ref_obj, dict) else None
                    if candidate:
                        primary_subnet_id = candidate
                        break
                if primary_subnet_id:
                    break

            if primary_subnet_id and primary_subnet_id in discovered_subnet_ids:
                yield self._edge(
                    EdgeType.RUNS_ON,
                    vm_ref,
                    CIRef(type=CIType.azure_subnet, external_id=primary_subnet_id),
                    "azure:vm:nic:subnet",
                )
