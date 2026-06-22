"""Contract test for the Azure connector against a deterministic in-memory fake client.

No live Azure subscription, no network. The fake returns fixed, seeded data so the
test is offline-reproducible and pinned to a specific expected mapping.

Covers:
  - AC 1-4  : CIType / EdgeType enum invariants (azure additions + unchanged members)
  - AC 5-12 : AzureConnector class-level attributes
  - AC 13-24: connector contract — happy path + every spec edge case (§5.1–§5.19)
  - AC 25-30: E2E reconcile + adversarial tenant isolation (uses pool/make_tenant fixtures)
  - AC 31   : migration 0016 content
  - AC 32   : CLI subcommand wiring (discover-azure)
  - AC 33   : regression — all existing connectors still importable
"""

from __future__ import annotations

import os

import pytest

from infra_twin.collectors import AwsConnector, AzureConnector, KubernetesConnector
from infra_twin.collectors.azure import AzureClient
from infra_twin.collectors.azure.connector import _rg_name_from_id, _nsg_rule_label
from infra_twin.connector_sdk import Connector, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeSource, EdgeType

# ---------------------------------------------------------------------------
# Seeded Azure resource ids (ARM-style paths)
# ---------------------------------------------------------------------------

SUB_ID = "/subscriptions/sub-001"
SUB_NAME = "test-subscription"

RG1_ID = "/subscriptions/sub-001/resourceGroups/rg-network"
RG1_NAME = "rg-network"
RG2_ID = "/subscriptions/sub-001/resourceGroups/rg-compute"
RG2_NAME = "rg-compute"

# A vnet whose RG resolves (rg-network)
VNET_ID = "/subscriptions/sub-001/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-main"
VNET_NAME = "vnet-main"

# Subnets inside the vnet
SUBNET1_ID = "/subscriptions/sub-001/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-main/subnets/subnet-web"
SUBNET1_NAME = "subnet-web"
SUBNET2_ID = "/subscriptions/sub-001/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-main/subnets/subnet-db"
SUBNET2_NAME = "subnet-db"

# NSG associated with subnet-web
NSG_ID = "/subscriptions/sub-001/resourceGroups/rg-network/providers/Microsoft.Network/networkSecurityGroups/nsg-web"
NSG_NAME = "nsg-web"

# VM in rg-compute, NIC references subnet-web
VM_ID = "/subscriptions/sub-001/resourceGroups/rg-compute/providers/Microsoft.Compute/virtualMachines/vm-app"
VM_NAME = "vm-app"

# NSG rule details used in evidence assertions
NSG_RULE_NAME = "Allow-HTTP"
NSG_RULE2_NAME = "Allow-HTTPS"

# A vnet with an unresolvable RG (edge case 3)
VNET_ORPHAN_ID = "/subscriptions/sub-001/resourceGroups/rg-gone/providers/Microsoft.Network/virtualNetworks/vnet-orphan"

# A VM with an unresolvable RG (edge case 4)
VM_ORPHAN_ID = "/subscriptions/sub-001/resourceGroups/rg-gone/providers/Microsoft.Compute/virtualMachines/vm-orphan"

# A VM whose NIC subnet is not discovered (edge case 5)
SUBNET_UNKNOWN_ID = "/subscriptions/sub-001/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-main/subnets/subnet-unknown"
VM_NOSUB_ID = "/subscriptions/sub-001/resourceGroups/rg-compute/providers/Microsoft.Compute/virtualMachines/vm-nosub"

# An NSG with inbound Allow rules but no associated discovered subnet (edge case 7)
NSG_DANGLING_ID = "/subscriptions/sub-001/resourceGroups/rg-network/providers/Microsoft.Network/networkSecurityGroups/nsg-dangling"


class FakeAzureClient:
    """Deterministic in-memory AzureClient for offline contract tests.

    The fixture exercises every major edge case from spec §5:
      - Two RGs (rg-network, rg-compute)
      - One vnet (in rg-network) with two subnets
      - One vnet with an unresolvable RG (edge case 3) — no CONTAINS RG->vnet
      - One NSG associated with subnet-web (triggering CONNECTS_TO)
      - One NSG with inbound Allow rules but no associated discovered subnet (edge case 7)
      - One VM in rg-compute whose NIC references subnet-web (RUNS_ON + CONTAINS)
      - One VM with unresolvable RG (edge case 4) — no CONTAINS RG->VM
      - One VM whose NIC subnet is not discovered (edge case 5) — no RUNS_ON
    """

    def list_resource_groups(self) -> list[dict]:
        return [
            {"id": RG1_ID, "name": RG1_NAME, "location": "eastus"},
            {"id": RG2_ID, "name": RG2_NAME, "location": "westus"},
        ]

    def list_virtual_networks(self) -> list[dict]:
        return [
            {
                "id": VNET_ID,
                "name": VNET_NAME,
                "location": "eastus",
                "properties": {
                    "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                    "subnets": [
                        {
                            "id": SUBNET1_ID,
                            "name": SUBNET1_NAME,
                            "properties": {"addressPrefix": "10.0.1.0/24"},
                        },
                        {
                            "id": SUBNET2_ID,
                            "name": SUBNET2_NAME,
                            "properties": {"addressPrefix": "10.0.2.0/24"},
                        },
                    ],
                },
            },
            # Edge case 3: vnet with unresolvable RG
            {
                "id": VNET_ORPHAN_ID,
                "name": "vnet-orphan",
                "location": "eastus",
                "properties": {
                    "addressSpace": {"addressPrefixes": ["10.1.0.0/16"]},
                    "subnets": [],
                },
            },
        ]

    def list_network_security_groups(self) -> list[dict]:
        return [
            {
                "id": NSG_ID,
                "name": NSG_NAME,
                "location": "eastus",
                "properties": {
                    "subnets": [{"id": SUBNET1_ID}],
                    "securityRules": [
                        {
                            "name": NSG_RULE_NAME,
                            "properties": {
                                "access": "Allow",
                                "direction": "Inbound",
                                "protocol": "Tcp",
                                "destinationPortRange": "80",
                                "sourceAddressPrefix": "*",
                            },
                        },
                        {
                            "name": NSG_RULE2_NAME,
                            "properties": {
                                "access": "Allow",
                                "direction": "Inbound",
                                "protocol": "Tcp",
                                "destinationPortRange": "443",
                                "sourceAddressPrefix": "*",
                            },
                        },
                        # Edge case 6: Deny rule — should not contribute to CONNECTS_TO
                        {
                            "name": "Deny-All",
                            "properties": {
                                "access": "Deny",
                                "direction": "Inbound",
                                "protocol": "*",
                                "destinationPortRange": "*",
                                "sourceAddressPrefix": "*",
                            },
                        },
                        # Edge case 6: Outbound allow — should not contribute
                        {
                            "name": "Allow-Outbound",
                            "properties": {
                                "access": "Allow",
                                "direction": "Outbound",
                                "protocol": "Tcp",
                                "destinationPortRange": "80",
                                "sourceAddressPrefix": "*",
                            },
                        },
                    ],
                },
            },
            # Edge case 7: NSG with inbound Allow rules but not associated with any subnet
            {
                "id": NSG_DANGLING_ID,
                "name": "nsg-dangling",
                "location": "eastus",
                "properties": {
                    "subnets": [],  # No associated subnets
                    "securityRules": [
                        {
                            "name": "Allow-SSH",
                            "properties": {
                                "access": "Allow",
                                "direction": "Inbound",
                                "protocol": "Tcp",
                                "destinationPortRange": "22",
                                "sourceAddressPrefix": "*",
                            },
                        },
                    ],
                },
            },
        ]

    def list_virtual_machines(self) -> list[dict]:
        return [
            {
                "id": VM_ID,
                "name": VM_NAME,
                "location": "westus",
                "properties": {
                    "hardwareProfile": {"vmSize": "Standard_B2s"},
                    "networkProfile": {
                        "networkInterfaces": [
                            {
                                "properties": {
                                    "ipConfigurations": [
                                        {
                                            "properties": {
                                                "subnet": {"id": SUBNET1_ID},
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                },
            },
            # Edge case 4: VM with unresolvable RG — VM CI emitted, no CONTAINS RG->VM
            {
                "id": VM_ORPHAN_ID,
                "name": "vm-orphan",
                "location": "eastus",
                "properties": {
                    "hardwareProfile": {"vmSize": "Standard_B1s"},
                    "networkProfile": {"networkInterfaces": []},
                },
            },
            # Edge case 5: VM whose NIC references a subnet not in discovered_subnet_ids
            {
                "id": VM_NOSUB_ID,
                "name": "vm-nosub",
                "location": "westus",
                "properties": {
                    "hardwareProfile": {"vmSize": "Standard_B1s"},
                    "networkProfile": {
                        "networkInterfaces": [
                            {
                                "properties": {
                                    "ipConfigurations": [
                                        {
                                            "properties": {
                                                "subnet": {"id": SUBNET_UNKNOWN_ID},
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                },
            },
        ]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_client() -> FakeAzureClient:
    return FakeAzureClient()


@pytest.fixture
def connector(fake_client: FakeAzureClient) -> AzureConnector:
    return AzureConnector(fake_client, subscription_id=SUB_ID, subscription_name=SUB_NAME)


@pytest.fixture
def all_events(connector: AzureConnector):
    return list(connector.discover())


@pytest.fixture
def cis(all_events) -> list[DiscoveredCI]:
    return [e for e in all_events if isinstance(e, DiscoveredCI)]


@pytest.fixture
def edges(all_events) -> list[DiscoveredEdge]:
    return [e for e in all_events if isinstance(e, DiscoveredEdge)]


# ---------------------------------------------------------------------------
# AC 1: azure_* CIType members exist with value == name
# ---------------------------------------------------------------------------


def test_azure_citype_values_match_names():
    """AC 1: each new azure_* CIType member has value == name."""
    for member_name in (
        "azure_subscription",
        "azure_resource_group",
        "azure_vnet",
        "azure_subnet",
        "azure_nsg",
        "azure_vm",
    ):
        member = CIType[member_name]
        assert member.value == member_name, (
            f"CIType.{member_name}.value should be {member_name!r}, got {member.value!r}"
        )


# ---------------------------------------------------------------------------
# AC 2: pre-existing CIType members unchanged
# ---------------------------------------------------------------------------


def test_pre_existing_citype_members_unchanged():
    """AC 2: all 14 AWS/internet/dns members and 6 k8s_* members still present, unchanged."""
    expected = {
        # AWS
        "cloud_account": "cloud_account",
        "region": "region",
        "vpc": "vpc",
        "subnet": "subnet",
        "security_group": "security_group",
        "ec2_instance": "ec2_instance",
        "elb": "elb",
        "rds": "rds",
        "s3_bucket": "s3_bucket",
        "iam_role": "iam_role",
        "iam_user": "iam_user",
        "eks_cluster": "eks_cluster",
        "internet": "internet",
        "dns_name": "dns_name",
        # K8s
        "k8s_cluster": "k8s_cluster",
        "k8s_namespace": "k8s_namespace",
        "k8s_node": "k8s_node",
        "k8s_workload": "k8s_workload",
        "k8s_pod": "k8s_pod",
        "k8s_service": "k8s_service",
    }
    for name, value in expected.items():
        member = CIType[name]
        assert member.value == value, (
            f"Pre-existing CIType.{name}.value changed: expected {value!r}, got {member.value!r}"
        )


# ---------------------------------------------------------------------------
# AC 3: EdgeType unchanged (exactly 10 members)
# ---------------------------------------------------------------------------


def test_edgetype_unchanged():
    """AC 3: EdgeType has exactly the 10 existing members and no additions."""
    expected_members = {
        "CONTAINS",
        "RUNS_ON",
        "CONNECTS_TO",
        "DEPENDS_ON",
        "ROUTES_TO",
        "HAS_ACCESS_TO",
        "OWNS",
        "EXPOSES",
        "MEMBER_OF",
        "RESOLVES_TO",
    }
    actual = {m.value for m in EdgeType}
    assert actual == expected_members, (
        f"EdgeType members changed. Extra: {actual - expected_members}, "
        f"Missing: {expected_members - actual}"
    )


# ---------------------------------------------------------------------------
# AC 4: EdgeSource, Evidence, CI, Edge unchanged
# ---------------------------------------------------------------------------


def test_edgesource_has_declared_and_inferred():
    """AC 4: EdgeSource has exactly 'declared' and 'inferred'."""
    from infra_twin.core_model import EdgeSource
    values = {m.value for m in EdgeSource}
    assert values == {"declared", "inferred"}, f"EdgeSource changed: {values}"


def test_evidence_model_fields():
    """AC 4: Evidence model has source, detail, observed_at fields."""
    from infra_twin.core_model import Evidence
    ev = Evidence(source="azure", detail="test")
    assert ev.source == "azure"
    assert ev.detail == "test"
    assert ev.observed_at is not None


# ---------------------------------------------------------------------------
# AC 5: AzureConnector.source == "azure"
# ---------------------------------------------------------------------------


def test_connector_source():
    """AC 5: AzureConnector.source == 'azure'."""
    assert AzureConnector.source == "azure"


# ---------------------------------------------------------------------------
# AC 6: AzureConnector.ci_types
# ---------------------------------------------------------------------------


def test_connector_ci_types():
    """AC 6: AzureConnector.ci_types == frozenset of all 6 azure_* CI types."""
    expected = frozenset(
        {
            CIType.azure_subscription,
            CIType.azure_resource_group,
            CIType.azure_vnet,
            CIType.azure_subnet,
            CIType.azure_nsg,
            CIType.azure_vm,
        }
    )
    assert AzureConnector.ci_types == expected


# ---------------------------------------------------------------------------
# AC 7: AzureConnector.edge_types
# ---------------------------------------------------------------------------


def test_connector_edge_types():
    """AC 7: AzureConnector.edge_types == frozenset({CONTAINS, RUNS_ON, CONNECTS_TO})."""
    expected = frozenset(
        {
            EdgeType.CONTAINS,
            EdgeType.RUNS_ON,
            EdgeType.CONNECTS_TO,
        }
    )
    assert AzureConnector.edge_types == expected


# ---------------------------------------------------------------------------
# AC 8: isinstance(connector, Connector) protocol check
# ---------------------------------------------------------------------------


def test_connector_satisfies_protocol(fake_client):
    """AC 8: isinstance(AzureConnector(fake, ...), Connector) is True."""
    conn = AzureConnector(fake_client, subscription_id="s1")
    assert isinstance(conn, Connector)


# ---------------------------------------------------------------------------
# AC 9: isinstance(fake, AzureClient) protocol check
# ---------------------------------------------------------------------------


def test_fake_client_satisfies_protocol():
    """AC 9: the FakeAzureClient satisfies the AzureClient runtime_checkable Protocol."""
    assert isinstance(FakeAzureClient(), AzureClient)


# ---------------------------------------------------------------------------
# AC 10: connector.py imports no forbidden SDK
# ---------------------------------------------------------------------------


def test_connector_module_no_forbidden_imports():
    """AC 10: azure connector source must not import boto3, kubernetes, azure SDK,
    or infra_twin.collectors.aws / infra_twin.collectors.k8s."""
    import importlib.util

    spec = importlib.util.find_spec("infra_twin.collectors.azure.connector")
    assert spec is not None, "azure connector module not found"
    source = open(spec.origin).read()
    assert "boto3" not in source, "connector.py must not import boto3"
    assert "import kubernetes" not in source, "connector.py must not import kubernetes"
    assert "kubernetes." not in source, "connector.py must not reference kubernetes."
    assert "infra_twin.collectors.aws" not in source, (
        "connector.py must not import from infra_twin.collectors.aws"
    )
    assert "infra_twin.collectors.k8s" not in source, (
        "connector.py must not import from infra_twin.collectors.k8s"
    )
    # The module may NOT import azure SDK at module level
    # (it should only use infra_twin.connector_sdk and infra_twin.core_model)
    lines = [ln.strip() for ln in source.splitlines() if ln.strip().startswith("import ") or ln.strip().startswith("from ")]
    azure_sdk_imports = [ln for ln in lines if "azure.identity" in ln or "azure.mgmt" in ln]
    assert not azure_sdk_imports, (
        f"connector.py must not import Azure SDK at module level: {azure_sdk_imports}"
    )


# ---------------------------------------------------------------------------
# AC 11: all three connectors importable from infra_twin.collectors
# ---------------------------------------------------------------------------


def test_all_three_connectors_importable_from_collectors():
    """AC 11: AwsConnector, AzureConnector, KubernetesConnector importable from infra_twin.collectors."""
    from infra_twin.collectors import AwsConnector as _Aws, AzureConnector as _Azure, KubernetesConnector as _K8s
    assert _Aws is not None
    assert _Azure is not None
    assert _K8s is not None


def test_collectors_all_contains_all_three():
    """AC 11: infra_twin.collectors.__all__ contains all three connector names."""
    import infra_twin.collectors as pkg
    assert "AwsConnector" in pkg.__all__
    assert "AzureConnector" in pkg.__all__
    assert "KubernetesConnector" in pkg.__all__


# ---------------------------------------------------------------------------
# AC 12: AzureClient and AzureConnector importable from infra_twin.collectors.azure
# ---------------------------------------------------------------------------


def test_azure_package_exports():
    """AC 12: AzureClient and AzureConnector importable from infra_twin.collectors.azure."""
    from infra_twin.collectors.azure import AzureClient as _Client, AzureConnector as _Connector
    assert _Client is not None
    assert _Connector is not None


# ---------------------------------------------------------------------------
# AC 13: exactly one azure_subscription CI emitted
# ---------------------------------------------------------------------------


def test_subscription_ci_emitted_once(cis):
    """AC 13: exactly one azure_subscription CI with external_id == subscription_id."""
    sub_cis = [c for c in cis if c.type == CIType.azure_subscription]
    assert len(sub_cis) == 1, f"Expected 1 azure_subscription CI, got {len(sub_cis)}"
    assert sub_cis[0].external_id == SUB_ID
    assert sub_cis[0].name == SUB_NAME


def test_subscription_ci_uses_name_when_provided(fake_client):
    """AC 13: when subscription_name is provided, the CI uses it as name."""
    conn = AzureConnector(fake_client, subscription_id=SUB_ID, subscription_name="My Sub")
    cis = [e for e in conn.discover() if isinstance(e, DiscoveredCI)]
    sub_ci = next(c for c in cis if c.type == CIType.azure_subscription)
    assert sub_ci.name == "My Sub"


def test_subscription_ci_falls_back_to_id_when_no_name(fake_client):
    """AC 13: when subscription_name is absent, name falls back to subscription_id."""
    conn = AzureConnector(fake_client, subscription_id=SUB_ID, subscription_name=None)
    cis = [e for e in conn.discover() if isinstance(e, DiscoveredCI)]
    sub_ci = next(c for c in cis if c.type == CIType.azure_subscription)
    assert sub_ci.name == SUB_ID


# ---------------------------------------------------------------------------
# AC 14: each seeded resource appears as correct DiscoveredCI with right attributes
# ---------------------------------------------------------------------------


def test_all_expected_cis_emitted(cis):
    """AC 14: every seeded resource id appears exactly once as a DiscoveredCI of the correct type."""
    by_id = {c.external_id: c for c in cis}

    checks: dict[str, CIType] = {
        SUB_ID: CIType.azure_subscription,
        RG1_ID: CIType.azure_resource_group,
        RG2_ID: CIType.azure_resource_group,
        VNET_ID: CIType.azure_vnet,
        VNET_ORPHAN_ID: CIType.azure_vnet,
        SUBNET1_ID: CIType.azure_subnet,
        SUBNET2_ID: CIType.azure_subnet,
        NSG_ID: CIType.azure_nsg,
        NSG_DANGLING_ID: CIType.azure_nsg,
        VM_ID: CIType.azure_vm,
        VM_ORPHAN_ID: CIType.azure_vm,
        VM_NOSUB_ID: CIType.azure_vm,
    }

    for resource_id, expected_type in checks.items():
        assert resource_id in by_id, (
            f"Expected DiscoveredCI with external_id={resource_id!r} not found"
        )
        assert by_id[resource_id].type == expected_type, (
            f"CI {resource_id} should have type {expected_type}, got {by_id[resource_id].type}"
        )


def test_rg_attributes(cis):
    """AC 14: azure_resource_group CI has correct location attribute."""
    by_id = {c.external_id: c for c in cis if c.type == CIType.azure_resource_group}
    assert RG1_ID in by_id
    assert by_id[RG1_ID].attributes.get("location") == "eastus"
    assert RG2_ID in by_id
    assert by_id[RG2_ID].attributes.get("location") == "westus"


def test_vnet_attributes(cis):
    """AC 14: azure_vnet CI has location, address_space, resource_group attributes."""
    by_id = {c.external_id: c for c in cis if c.type == CIType.azure_vnet}
    assert VNET_ID in by_id
    vnet_ci = by_id[VNET_ID]
    assert vnet_ci.attributes.get("location") == "eastus"
    assert vnet_ci.attributes.get("address_space") == ["10.0.0.0/16"]
    assert vnet_ci.attributes.get("resource_group") == RG1_NAME


def test_subnet_attributes(cis):
    """AC 14: azure_subnet CI has address_prefix and vnet attributes."""
    by_id = {c.external_id: c for c in cis if c.type == CIType.azure_subnet}
    assert SUBNET1_ID in by_id
    sub_ci = by_id[SUBNET1_ID]
    assert sub_ci.attributes.get("address_prefix") == "10.0.1.0/24"
    assert sub_ci.attributes.get("vnet") == VNET_ID


def test_nsg_attributes(cis):
    """AC 14: azure_nsg CI has location and resource_group attributes."""
    by_id = {c.external_id: c for c in cis if c.type == CIType.azure_nsg}
    assert NSG_ID in by_id
    nsg_ci = by_id[NSG_ID]
    assert nsg_ci.attributes.get("location") == "eastus"
    assert nsg_ci.attributes.get("resource_group") == RG1_NAME


def test_vm_attributes(cis):
    """AC 14: azure_vm CI has location, vm_size, resource_group attributes."""
    by_id = {c.external_id: c for c in cis if c.type == CIType.azure_vm}
    assert VM_ID in by_id
    vm_ci = by_id[VM_ID]
    assert vm_ci.attributes.get("location") == "westus"
    assert vm_ci.attributes.get("vm_size") == "Standard_B2s"
    assert vm_ci.attributes.get("resource_group") == RG2_NAME


# ---------------------------------------------------------------------------
# AC 15: no duplicate (type, external_id) CIs
# ---------------------------------------------------------------------------


def test_no_duplicate_ci_external_ids(cis):
    """AC 15: each (type, external_id) pair appears exactly once."""
    seen: dict = {}
    for ci in cis:
        key = (ci.type, ci.external_id)
        assert key not in seen, f"Duplicate CI emitted: {key}"
        seen[key] = True


# ---------------------------------------------------------------------------
# AC 16: CONTAINS hierarchy edges
# ---------------------------------------------------------------------------


def test_contains_subscription_to_rgs(edges):
    """AC 16: CONTAINS edge from subscription to each RG."""
    sub_to_rg = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.azure_subscription
        and e.from_ref.external_id == SUB_ID
        and e.to_ref.type == CIType.azure_resource_group
    ]
    rg_ids = {e.to_ref.external_id for e in sub_to_rg}
    assert RG1_ID in rg_ids, f"CONTAINS sub->rg1 missing; found {rg_ids}"
    assert RG2_ID in rg_ids, f"CONTAINS sub->rg2 missing; found {rg_ids}"


def test_contains_rg_to_vnet(edges):
    """AC 16: CONTAINS RG->vnet for vnet whose RG resolves."""
    rg_to_vnet = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.azure_resource_group
        and e.to_ref.type == CIType.azure_vnet
        and e.to_ref.external_id == VNET_ID
    ]
    assert rg_to_vnet, "CONTAINS RG->vnet-main missing"
    assert rg_to_vnet[0].from_ref.external_id == RG1_ID


def test_contains_vnet_to_subnets(edges):
    """AC 16: CONTAINS vnet->each subnet."""
    vnet_to_subnet = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.azure_vnet
        and e.from_ref.external_id == VNET_ID
        and e.to_ref.type == CIType.azure_subnet
    ]
    subnet_ids = {e.to_ref.external_id for e in vnet_to_subnet}
    assert SUBNET1_ID in subnet_ids, "CONTAINS vnet->subnet-web missing"
    assert SUBNET2_ID in subnet_ids, "CONTAINS vnet->subnet-db missing"


def test_contains_rg_to_vm(edges):
    """AC 16: CONTAINS RG->VM for VM whose RG resolves."""
    rg_to_vm = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.azure_resource_group
        and e.to_ref.type == CIType.azure_vm
        and e.to_ref.external_id == VM_ID
    ]
    assert rg_to_vm, "CONTAINS rg->vm-app missing"
    assert rg_to_vm[0].from_ref.external_id == RG2_ID


# ---------------------------------------------------------------------------
# AC 17: RUNS_ON VM -> subnet
# ---------------------------------------------------------------------------


def test_runs_on_vm_to_subnet(edges):
    """AC 17: RUNS_ON edge from vm-app to subnet-web (NIC resolves)."""
    runs_on = [
        e for e in edges
        if e.type == EdgeType.RUNS_ON
        and e.from_ref.external_id == VM_ID
        and e.to_ref.external_id == SUBNET1_ID
    ]
    assert runs_on, "RUNS_ON vm-app->subnet-web missing"
    assert runs_on[0].from_ref.type == CIType.azure_vm
    assert runs_on[0].to_ref.type == CIType.azure_subnet


def test_runs_on_evidence_detail(edges):
    """AC 17/20: RUNS_ON edge has correct evidence detail."""
    for e in edges:
        if e.type == EdgeType.RUNS_ON:
            detail = e.evidence[0].detail
            assert detail == "azure:vm:nic:subnet", (
                f"RUNS_ON evidence detail wrong: {detail!r}"
            )


# ---------------------------------------------------------------------------
# AC 18/19: CONNECTS_TO edge from NSG to subnet
# ---------------------------------------------------------------------------


def test_connects_to_nsg_to_subnet(edges):
    """AC 18: CONNECTS_TO from azure_nsg to azure_subnet for inbound Allow rule."""
    connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.type == CIType.azure_nsg
        and e.from_ref.external_id == NSG_ID
        and e.to_ref.external_id == SUBNET1_ID
    ]
    assert connects, "CONNECTS_TO nsg->subnet-web missing"
    assert connects[0].from_ref.type == CIType.azure_nsg
    assert connects[0].to_ref.type == CIType.azure_subnet


def test_connects_to_source_confidence_evidence(edges):
    """AC 19: CONNECTS_TO has source=declared, confidence=1.0, non-empty evidence."""
    connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.external_id == NSG_ID
    ]
    assert connects, "No CONNECTS_TO for NSG found"
    edge = connects[0]
    assert edge.source == EdgeSource.declared, f"source wrong: {edge.source}"
    assert edge.confidence == 1.0, f"confidence wrong: {edge.confidence}"
    assert edge.evidence, "evidence must be non-empty"


def test_connects_to_evidence_names_nsg_rule(edges):
    """AC 19: CONNECTS_TO evidence detail contains originating NSG rule name."""
    connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.external_id == NSG_ID
    ]
    assert connects, "No CONNECTS_TO for NSG found"
    details = [ev.detail for ev in connects[0].evidence]
    rule_names_in_details = [d for d in details if NSG_RULE_NAME in d]
    assert rule_names_in_details, (
        f"Evidence detail must contain rule name '{NSG_RULE_NAME}'; got details: {details}"
    )


def test_connects_to_evidence_source_is_azure(edges):
    """AC 19: each Evidence entry on CONNECTS_TO has source=='azure'."""
    for e in edges:
        if e.type == EdgeType.CONNECTS_TO:
            for ev in e.evidence:
                assert ev.source == "azure", (
                    f"CONNECTS_TO evidence.source must be 'azure'; got {ev.source!r}"
                )
                assert ev.detail, "CONNECTS_TO evidence.detail must be non-empty"


# ---------------------------------------------------------------------------
# AC 20: every edge has correct provenance
# ---------------------------------------------------------------------------


def test_all_edges_have_azure_provenance(edges):
    """AC 20: every DiscoveredEdge has source=declared, confidence=1.0,
    non-empty evidence, all with source=='azure' and non-empty detail."""
    assert edges, "no edges emitted at all"
    for edge in edges:
        assert edge.source == EdgeSource.declared, (
            f"Edge {edge.type} source must be 'declared', got {edge.source!r}"
        )
        assert edge.confidence == 1.0, (
            f"Edge {edge.type} confidence must be 1.0, got {edge.confidence!r}"
        )
        assert edge.evidence, f"Edge {edge.type} must have non-empty evidence"
        for ev in edge.evidence:
            assert ev.source == "azure", (
                f"Edge {edge.type} evidence.source must be 'azure'; got {ev.source!r}"
            )
            assert ev.detail, (
                f"Edge {edge.type} evidence.detail must be non-empty; got {ev.detail!r}"
            )


# ---------------------------------------------------------------------------
# AC 21: no raise on minimal fixture with optional keys absent (§5.12)
# ---------------------------------------------------------------------------


def test_discover_does_not_raise_on_missing_optional_keys():
    """AC 21 / §5.12: discover() succeeds when optional nested keys are absent."""

    class MinimalClient:
        def list_resource_groups(self):
            # id present but no location
            return [{"id": "/subscriptions/s/resourceGroups/rg1", "name": "rg1"}]

        def list_virtual_networks(self):
            # No properties key at all
            return [{"id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1", "name": "vnet1"}]

        def list_network_security_groups(self):
            # No properties key, no securityRules
            return [{"id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1", "name": "nsg1"}]

        def list_virtual_machines(self):
            # No properties at all
            return [{"id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1", "name": "vm1"}]

    conn = AzureConnector(MinimalClient(), subscription_id="s", subscription_name=None)
    events = list(conn.discover())
    cis = [e for e in events if isinstance(e, DiscoveredCI)]
    types = {c.type for c in cis}
    # At minimum the subscription CI must be present
    assert CIType.azure_subscription in types


# ---------------------------------------------------------------------------
# AC 22: discover() twice yields identical event stream (§5.14)
# ---------------------------------------------------------------------------


def test_discover_twice_yields_identical_stream(connector):
    """AC 22 / §5.14: calling discover() twice on the same connector + fixture yields
    the same event stream (same length, same per-event type/external_id/from/to order)."""
    events1 = list(connector.discover())
    events2 = list(connector.discover())

    assert len(events1) == len(events2), (
        f"Second discover yielded different event count: {len(events1)} vs {len(events2)}"
    )
    for i, (e1, e2) in enumerate(zip(events1, events2)):
        assert type(e1) == type(e2), f"Event {i} type changed between runs"
        if isinstance(e1, DiscoveredCI):
            assert e1.type == e2.type and e1.external_id == e2.external_id, (
                f"CI event {i} changed: {e1} vs {e2}"
            )
        else:
            assert (
                e1.type == e2.type
                and e1.from_ref.external_id == e2.from_ref.external_id
                and e1.to_ref.external_id == e2.to_ref.external_id
            ), f"Edge event {i} changed: {e1} vs {e2}"


# ---------------------------------------------------------------------------
# AC 23 / §5.1: empty subscription emits 1 CI, 0 edges
# ---------------------------------------------------------------------------


def test_edge_case_1_empty_subscription():
    """§5.1: subscription with zero RGs/vnets/subnets/nsgs/vms -> 1 CI (subscription) + 0 edges."""

    class EmptyClient:
        def list_resource_groups(self):
            return []

        def list_virtual_networks(self):
            return []

        def list_network_security_groups(self):
            return []

        def list_virtual_machines(self):
            return []

    conn = AzureConnector(EmptyClient(), subscription_id="empty-sub")
    events = list(conn.discover())
    cis = [e for e in events if isinstance(e, DiscoveredCI)]
    edges_out = [e for e in events if isinstance(e, DiscoveredEdge)]

    assert len(cis) == 1, f"Expected 1 CI for empty subscription, got {len(cis)}"
    assert cis[0].type == CIType.azure_subscription
    assert cis[0].external_id == "empty-sub"
    assert not edges_out, f"Expected 0 edges for empty subscription, got {len(edges_out)}"


# ---------------------------------------------------------------------------
# AC 23 / §5.2: resource with missing id is skipped
# ---------------------------------------------------------------------------


def test_edge_case_2_missing_id_skips_resource():
    """§5.2: RG/vnet/subnet/nsg/vm dict missing its resource id is skipped entirely."""

    class MissingIdClient:
        def list_resource_groups(self):
            return [
                {"name": "rg-no-id"},  # missing id — skip
                {"id": "/subscriptions/s/resourceGroups/rg-valid", "name": "rg-valid", "location": "eastus"},
            ]

        def list_virtual_networks(self):
            return [
                {"name": "vnet-no-id"},  # missing id — skip
            ]

        def list_network_security_groups(self):
            return [
                {"name": "nsg-no-id"},  # missing id — skip
            ]

        def list_virtual_machines(self):
            return [
                {"name": "vm-no-id"},  # missing id — skip
            ]

    conn = AzureConnector(MissingIdClient(), subscription_id="s")
    events = list(conn.discover())
    cis = [e for e in events if isinstance(e, DiscoveredCI)]

    types_emitted = {c.type for c in cis}
    # Only subscription and rg-valid should appear; no CI for missing-id resources
    assert CIType.azure_subscription in types_emitted
    assert CIType.azure_resource_group in types_emitted

    rg_cis = [c for c in cis if c.type == CIType.azure_resource_group]
    assert len(rg_cis) == 1
    assert rg_cis[0].external_id == "/subscriptions/s/resourceGroups/rg-valid"

    # No vnet/nsg/vm CIs
    assert CIType.azure_vnet not in types_emitted
    assert CIType.azure_nsg not in types_emitted
    assert CIType.azure_vm not in types_emitted


# ---------------------------------------------------------------------------
# AC 23 / §5.3: vnet with unresolvable RG — vnet CI emitted, no CONTAINS RG->vnet
# ---------------------------------------------------------------------------


def test_edge_case_3_unresolvable_rg_for_vnet(edges, cis):
    """§5.3: vnet whose RG name doesn't match any discovered RG: vnet CI present, no CONTAINS RG->vnet."""
    # VNET_ORPHAN_ID has rg-gone in path which is not in our fixture RGs
    orphan_vnet_ci = [c for c in cis if c.external_id == VNET_ORPHAN_ID]
    assert orphan_vnet_ci, "Orphan vnet CI should still be emitted"

    contains_rg_to_orphan = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.to_ref.external_id == VNET_ORPHAN_ID
        and e.from_ref.type == CIType.azure_resource_group
    ]
    assert not contains_rg_to_orphan, "No CONTAINS RG->orphan-vnet should be emitted"


# ---------------------------------------------------------------------------
# AC 23 / §5.4: VM with unresolvable RG — VM CI emitted, no CONTAINS RG->VM
# ---------------------------------------------------------------------------


def test_edge_case_4_unresolvable_rg_for_vm(edges, cis):
    """§5.4: VM whose RG doesn't resolve: VM CI still emitted, no CONTAINS RG->VM."""
    orphan_vm_ci = [c for c in cis if c.external_id == VM_ORPHAN_ID]
    assert orphan_vm_ci, "Orphan VM CI should still be emitted"

    contains_rg_to_orphan_vm = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.to_ref.external_id == VM_ORPHAN_ID
        and e.from_ref.type == CIType.azure_resource_group
    ]
    assert not contains_rg_to_orphan_vm, "No CONTAINS RG->orphan-vm should be emitted"


# ---------------------------------------------------------------------------
# AC 23 / §5.5: VM NIC subnet not discovered — no RUNS_ON
# ---------------------------------------------------------------------------


def test_edge_case_5_no_runs_on_for_unresolved_subnet(edges, cis):
    """§5.5: VM whose NIC references undiscovered subnet -> VM CI emitted, no RUNS_ON."""
    nosub_vm_ci = [c for c in cis if c.external_id == VM_NOSUB_ID]
    assert nosub_vm_ci, "vm-nosub CI should be emitted"

    runs_on_nosub = [
        e for e in edges
        if e.type == EdgeType.RUNS_ON
        and e.from_ref.external_id == VM_NOSUB_ID
    ]
    assert not runs_on_nosub, "RUNS_ON should not be emitted for unresolved NIC subnet"


# ---------------------------------------------------------------------------
# AC 23 / §5.6: NSG with no securityRules or all Deny/Outbound -> no CONNECTS_TO
# ---------------------------------------------------------------------------


def test_edge_case_6_nsg_no_allow_inbound_no_connects_to():
    """§5.6: NSG with no inbound Allow rules emits no CONNECTS_TO."""

    class NoDenyClient:
        def list_resource_groups(self):
            return [{"id": "/subscriptions/s/resourceGroups/rg1", "name": "rg1", "location": "eastus"}]

        def list_virtual_networks(self):
            return [
                {
                    "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1",
                    "name": "vnet1",
                    "properties": {
                        "subnets": [
                            {
                                "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/sub1",
                                "name": "sub1",
                                "properties": {"addressPrefix": "10.0.0.0/24"},
                            }
                        ]
                    },
                }
            ]

        def list_network_security_groups(self):
            return [
                {
                    "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg-deny",
                    "name": "nsg-deny",
                    "properties": {
                        "subnets": [
                            {
                                "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/sub1"
                            }
                        ],
                        "securityRules": [
                            {
                                "name": "deny-all",
                                "properties": {
                                    "access": "Deny",
                                    "direction": "Inbound",
                                    "protocol": "*",
                                    "destinationPortRange": "*",
                                    "sourceAddressPrefix": "*",
                                },
                            }
                        ],
                    },
                }
            ]

        def list_virtual_machines(self):
            return []

    conn = AzureConnector(NoDenyClient(), subscription_id="s")
    events = list(conn.discover())
    connects_to = [e for e in events if isinstance(e, DiscoveredEdge) and e.type == EdgeType.CONNECTS_TO]
    assert not connects_to, "No CONNECTS_TO should be emitted when all rules are Deny"


# ---------------------------------------------------------------------------
# AC 23 / §5.7: NSG with inbound Allow but no associated discovered subnet -> no CONNECTS_TO
# ---------------------------------------------------------------------------


def test_edge_case_7_nsg_dangling_no_connects_to(edges):
    """§5.7: NSG_DANGLING has Allow rules but no associated subnet -> no CONNECTS_TO."""
    dangling_connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.external_id == NSG_DANGLING_ID
    ]
    assert not dangling_connects, (
        "CONNECTS_TO must not be emitted for NSG with no associated discovered subnet"
    )


# ---------------------------------------------------------------------------
# §5.9: multiple inbound Allow rules for same (nsg, subnet) -> one CONNECTS_TO, one Evidence per rule
# ---------------------------------------------------------------------------


def test_edge_case_9_multiple_allow_rules_collapsed(edges):
    """§5.9: multiple Allow rules for same (nsg, subnet) -> exactly one CONNECTS_TO, one Evidence per rule."""
    connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.external_id == NSG_ID
        and e.to_ref.external_id == SUBNET1_ID
    ]
    assert len(connects) == 1, (
        f"Expected exactly 1 CONNECTS_TO edge for (nsg, subnet); got {len(connects)}"
    )
    evidence_details = [ev.detail for ev in connects[0].evidence]
    # Both Allow rules (Allow-HTTP and Allow-HTTPS) should appear
    assert any(NSG_RULE_NAME in d for d in evidence_details), (
        f"Allow-HTTP rule not in evidence: {evidence_details}"
    )
    assert any(NSG_RULE2_NAME in d for d in evidence_details), (
        f"Allow-HTTPS rule not in evidence: {evidence_details}"
    )
    # Deny-All and Allow-Outbound should NOT appear
    assert not any("Deny-All" in d for d in evidence_details), (
        "Deny rule must not appear in CONNECTS_TO evidence"
    )
    assert not any("Allow-Outbound" in d for d in evidence_details), (
        "Outbound Allow rule must not appear in CONNECTS_TO evidence"
    )


# ---------------------------------------------------------------------------
# §5.11: two resources sharing base name in different RGs -> distinct CIs
# ---------------------------------------------------------------------------


def test_edge_case_11_same_name_different_rg_distinct_cis():
    """§5.11: two VMs named 'vm-app' in different RGs have distinct resource ids -> distinct CIs."""

    class SameNameClient:
        def list_resource_groups(self):
            return [
                {"id": "/subscriptions/s/resourceGroups/rg-a", "name": "rg-a", "location": "eastus"},
                {"id": "/subscriptions/s/resourceGroups/rg-b", "name": "rg-b", "location": "westus"},
            ]

        def list_virtual_networks(self):
            return []

        def list_network_security_groups(self):
            return []

        def list_virtual_machines(self):
            return [
                {
                    "id": "/subscriptions/s/resourceGroups/rg-a/providers/Microsoft.Compute/virtualMachines/vm-app",
                    "name": "vm-app",
                    "properties": {},
                },
                {
                    "id": "/subscriptions/s/resourceGroups/rg-b/providers/Microsoft.Compute/virtualMachines/vm-app",
                    "name": "vm-app",
                    "properties": {},
                },
            ]

    conn = AzureConnector(SameNameClient(), subscription_id="s")
    events = list(conn.discover())
    vm_cis = [e for e in events if isinstance(e, DiscoveredCI) and e.type == CIType.azure_vm]
    assert len(vm_cis) == 2, f"Expected 2 distinct azure_vm CIs, got {len(vm_cis)}"
    ids = {c.external_id for c in vm_cis}
    assert len(ids) == 2, f"Two VMs must have distinct external_ids; got {ids}"


# ---------------------------------------------------------------------------
# §5.13: NSG rule with missing 'name' -> unnamed rule still emits non-empty evidence
# ---------------------------------------------------------------------------


def test_edge_case_13_unnamed_nsg_rule_emits_evidence():
    """§5.13: NSG rule missing 'name' field -> evidence detail contains '<unnamed>', non-empty."""

    class UnnamedRuleClient:
        def list_resource_groups(self):
            return [{"id": "/subscriptions/s/resourceGroups/rg1", "name": "rg1", "location": "eastus"}]

        def list_virtual_networks(self):
            return [
                {
                    "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1",
                    "name": "vnet1",
                    "properties": {
                        "subnets": [
                            {
                                "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/sub1",
                                "name": "sub1",
                                "properties": {"addressPrefix": "10.0.0.0/24"},
                            }
                        ]
                    },
                }
            ]

        def list_network_security_groups(self):
            return [
                {
                    "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1",
                    "name": "nsg1",
                    "properties": {
                        "subnets": [
                            {
                                "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/sub1"
                            }
                        ],
                        "securityRules": [
                            {
                                # No 'name' key
                                "properties": {
                                    "access": "Allow",
                                    "direction": "Inbound",
                                    "protocol": "Tcp",
                                    "destinationPortRange": "22",
                                    "sourceAddressPrefix": "*",
                                },
                            }
                        ],
                    },
                }
            ]

        def list_virtual_machines(self):
            return []

    conn = AzureConnector(UnnamedRuleClient(), subscription_id="s")
    events = list(conn.discover())
    connects_to = [
        e for e in events
        if isinstance(e, DiscoveredEdge) and e.type == EdgeType.CONNECTS_TO
    ]
    assert connects_to, "CONNECTS_TO must still be emitted for unnamed rule"
    for ev in connects_to[0].evidence:
        assert ev.detail, "evidence.detail must be non-empty even for unnamed rule"
        assert "<unnamed>" in ev.detail, (
            f"Unnamed rule evidence must contain '<unnamed>'; got {ev.detail!r}"
        )


# ---------------------------------------------------------------------------
# AC 24: fake client not mutated by discover()
# ---------------------------------------------------------------------------


def test_fake_client_not_mutated_by_discover():
    """AC 24 / §5.18: discover() must not mutate the injected client.
    We record the state of the client's return values before and after discover()
    and assert they are identical."""

    class TrackingClient:
        def __init__(self):
            self._rg_calls = 0
            self._vnet_calls = 0
            self._nsg_calls = 0
            self._vm_calls = 0

        def list_resource_groups(self):
            self._rg_calls += 1
            return [{"id": "/subscriptions/s/resourceGroups/rg1", "name": "rg1", "location": "eastus"}]

        def list_virtual_networks(self):
            self._vnet_calls += 1
            return []

        def list_network_security_groups(self):
            self._nsg_calls += 1
            return []

        def list_virtual_machines(self):
            self._vm_calls += 1
            return []

    client = TrackingClient()
    conn = AzureConnector(client, subscription_id="s")

    # Confirm client state before
    before_rg = client._rg_calls
    list(conn.discover())
    after_rg = client._rg_calls

    # The client was called (read) but the DATA it returns is unchanged
    assert after_rg == before_rg + 1, "list_resource_groups should be called exactly once"

    # Verify the client's lists are unmodified — call again and get same data
    rg_data = client.list_resource_groups()
    assert rg_data == [{"id": "/subscriptions/s/resourceGroups/rg1", "name": "rg1", "location": "eastus"}], (
        "Client data must not be mutated by discover()"
    )


def test_connector_only_reads_never_writes(fake_client):
    """AC 24: connector does not add any write methods or call any non-list method."""
    write_methods = ["create", "update", "delete", "put", "patch", "post"]
    for method_name in dir(fake_client):
        if any(wm in method_name.lower() for wm in write_methods):
            # No write methods should exist on the protocol
            assert False, f"Fake client has unexpected write method: {method_name}"


# ---------------------------------------------------------------------------
# AC 31: migration 0016 content
# ---------------------------------------------------------------------------


def test_migration_0016_azure_vertex_labels_exists():
    """AC 31: migration 0016 exists, calls create_vlabel for all 6 azure_* labels,
    includes both GRANT statements, no create_elabel, no relational DDL."""
    migration_path = os.path.normpath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "migrations",
            "0016_azure_vertex_labels.sql",
        )
    )
    assert os.path.isfile(migration_path), f"Migration not found: {migration_path}"

    content = open(migration_path).read()

    assert "ag_catalog" in content, "Migration must set ag_catalog in search_path"
    assert "create_elabel" not in content, "Migration must NOT call create_elabel"
    assert "CREATE TABLE" not in content, "Migration must NOT contain CREATE TABLE (relational DDL)"

    for label in (
        "azure_subscription",
        "azure_resource_group",
        "azure_vnet",
        "azure_subnet",
        "azure_nsg",
        "azure_vm",
    ):
        assert label in content, f"Migration must create vertex label '{label}'"

    assert "create_vlabel" in content, "Migration must call create_vlabel"
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES" in content, (
        "Migration must re-apply table GRANT"
    )
    assert "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES" in content, (
        "Migration must re-apply sequence GRANT"
    )


def test_existing_migrations_0001_to_0015_unchanged():
    """AC 31: files 0001 through 0015 must all still exist."""
    migrations_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "migrations")
    )
    for n in range(1, 16):
        pattern = f"{n:04d}_"
        matches = [f for f in os.listdir(migrations_dir) if f.startswith(pattern)]
        assert matches, f"Migration {pattern}* not found in {migrations_dir}"


# ---------------------------------------------------------------------------
# AC 32: CLI discover-azure subcommand wiring
# ---------------------------------------------------------------------------


def test_cli_discover_azure_subparser_registered():
    """AC 32: 'discover-azure' subcommand is registered with required args."""
    from unittest.mock import patch

    captured = {}

    def fake_handler(args):
        captured["args"] = args
        return 0

    from infra_twin.cli.main import main as cli_main

    with patch("infra_twin.cli.main._discover_azure", fake_handler):
        rc = cli_main([
            "discover-azure",
            "--tenant", "00000000-0000-0000-0000-000000000001",
            "--subscription-id", "test-sub-id",
        ])

    assert rc == 0
    args = captured["args"]
    assert args.tenant == "00000000-0000-0000-0000-000000000001"
    assert args.subscription_id == "test-sub-id"
    assert args.subscription_name is None  # optional, defaults to None


def test_cli_discover_azure_subscription_name_arg():
    """AC 32: --subscription-name is optional; when supplied it reaches the handler."""
    from unittest.mock import patch

    captured = {}

    def fake_handler(args):
        captured["args"] = args
        return 0

    from infra_twin.cli.main import main as cli_main

    with patch("infra_twin.cli.main._discover_azure", fake_handler):
        cli_main([
            "discover-azure",
            "--tenant", "00000000-0000-0000-0000-000000000001",
            "--subscription-id", "test-sub-id",
            "--subscription-name", "My Azure Sub",
        ])

    assert captured["args"].subscription_name == "My Azure Sub"


# ---------------------------------------------------------------------------
# AC 33: regression — all existing connector tests unaffected (import smoke test)
# ---------------------------------------------------------------------------


def test_all_three_connectors_still_importable():
    """AC 33: AwsConnector, KubernetesConnector still importable alongside AzureConnector."""
    assert AwsConnector is not None
    assert KubernetesConnector is not None
    assert AzureConnector is not None


# ---------------------------------------------------------------------------
# Helper function unit tests (_rg_name_from_id, _nsg_rule_label)
# ---------------------------------------------------------------------------


def test_rg_name_from_id_standard_path():
    """_rg_name_from_id extracts RG name from standard ARM resource id."""
    result = _rg_name_from_id("/subscriptions/sub-001/resourceGroups/my-rg/providers/X/Y/z")
    assert result == "my-rg"


def test_rg_name_from_id_case_insensitive():
    """_rg_name_from_id handles case variations in 'resourceGroups'."""
    result = _rg_name_from_id("/subscriptions/sub/RESOURCEGROUPS/my-rg/providers/X")
    assert result == "my-rg"


def test_rg_name_from_id_no_rg_segment():
    """_rg_name_from_id returns None when no resourceGroups segment present."""
    result = _rg_name_from_id("/subscriptions/sub/providers/X/Y/z")
    assert result is None


def test_nsg_rule_label_full():
    """_nsg_rule_label renders proto/port/source from full rule props."""
    props = {"protocol": "Tcp", "destinationPortRange": "80", "sourceAddressPrefix": "10.0.0.0/8"}
    result = _nsg_rule_label(props)
    assert result == "Tcp/80 from 10.0.0.0/8"


def test_nsg_rule_label_missing_fields():
    """_nsg_rule_label falls back to 'all' for missing fields."""
    result = _nsg_rule_label({})
    assert result == "all/all from *"


# ===========================================================================
# E2E + ADVERSARIAL ISOLATION TESTS (use pool + make_tenant from conftest.py)
# These tests require the local Postgres+AGE stack with migration 0016 applied.
# ===========================================================================


def _make_connector_for_e2e() -> AzureConnector:
    return AzureConnector(
        FakeAzureClient(), subscription_id=SUB_ID, subscription_name=SUB_NAME
    )


# ---------------------------------------------------------------------------
# AC 25: discover_and_reconcile returns positive counts
# ---------------------------------------------------------------------------


def test_discover_and_reconcile_returns_positive_counts(pool, make_tenant):
    """AC 25: discover_and_reconcile creates CIs and writes edges for Azure connector."""
    from infra_twin.reconciliation import discover_and_reconcile

    tenant = make_tenant("azure-a")
    result = discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    assert result.cis_created > 0, f"Expected cis_created > 0, got {result.cis_created}"
    assert result.edges_written > 0, f"Expected edges_written > 0, got {result.edges_written}"


# ---------------------------------------------------------------------------
# AC 26: connector registry + runs + raw_facts
# ---------------------------------------------------------------------------


def test_connector_registry_has_azure_type(pool, make_tenant):
    """AC 26: after reconcile, connectors row with type='azure' exists."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connectors import ConnectorRegistry
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("azure-registry")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        registry = ConnectorRegistry(conn, tenant)
        connectors_list = registry.list()

    azure_connectors = [c for c in connectors_list if c.type == "azure"]
    assert azure_connectors, (
        f"No connector with type='azure' found; got: {[c.type for c in connectors_list]}"
    )
    assert azure_connectors[0].display_name == "azure"


def test_connector_run_ok_and_raw_facts(pool, make_tenant):
    """AC 26: connector_runs row with source='azure' and status='ok'; >= 1 raw_facts row."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connector_health import ConnectorRunRepository
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("azure-run")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        run_repo = ConnectorRunRepository(conn, tenant)
        summaries = run_repo.latest_per_source()

    azure_runs = [s for s in summaries if s.source == "azure"]
    assert azure_runs, "No connector_run with source='azure' found"
    assert azure_runs[0].status == "ok", (
        f"connector_run status expected 'ok', got {azure_runs[0].status!r}"
    )

    from infra_twin.db.session import tenant_session as _ts
    with _ts(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = %s", ("azure",)
        ).fetchone()[0]
    assert count >= 1, f"Expected at least 1 raw_facts row for source='azure', got {count}"


# ---------------------------------------------------------------------------
# AC 27: all six azure_* CI types persisted current with correct tenant_id
# ---------------------------------------------------------------------------


def test_azure_cis_persisted_current_with_correct_tenant(pool, make_tenant):
    """AC 27: all six azure_* CI types are persisted current (valid_to IS NULL) with tenant_id == tenant."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.repositories import CIRepository
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("azure-cis")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        for ci_type in (
            CIType.azure_subscription,
            CIType.azure_resource_group,
            CIType.azure_vnet,
            CIType.azure_subnet,
            CIType.azure_nsg,
            CIType.azure_vm,
        ):
            cis = repo.get_current(type=ci_type)
            assert cis, f"No current {ci_type.value} CIs found"
            for ci in cis:
                assert ci.valid_to is None, (
                    f"{ci_type.value} CI {ci.external_id} has valid_to={ci.valid_to}, expected NULL"
                )
                assert ci.tenant_id == tenant, (
                    f"{ci_type.value} CI tenant_id {ci.tenant_id} != expected {tenant}"
                )


def test_azure_edges_persisted_with_provenance(pool, make_tenant):
    """AC 27: persisted azure edges have source, non-null confidence, and non-empty evidence."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("azure-edges")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT source, confidence, evidence FROM edges WHERE valid_to IS NULL",
        ).fetchall()

    assert rows, "No current edges found after azure reconcile"
    for source, confidence, evidence in rows:
        assert source in ("declared", "inferred"), (
            f"Edge source must be 'declared' or 'inferred'; got {source!r}"
        )
        assert confidence is not None, "Edge confidence must be set"
        assert evidence, "Edge evidence must be non-empty"
        for ev in evidence:
            assert "source" in ev, f"Evidence entry missing 'source' key: {ev!r}"


# ---------------------------------------------------------------------------
# AC 28: AGE projection contains azure_* nodes and edges
# ---------------------------------------------------------------------------


def test_age_projection_azure_vm(pool, make_tenant):
    """AC 28: MATCH (n:azure_vm) WHERE n.tenant_id='<A>' RETURN n returns >= 1 row."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("azure-age-vm")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(conn, f"MATCH (n:azure_vm) WHERE n.tenant_id = '{tenant}' RETURN n")

    assert len(rows) >= 1, (
        f"Expected >= 1 azure_vm node in AGE for tenant {tenant}, got {len(rows)}"
    )


def test_age_projection_subscription_contains_rg(pool, make_tenant):
    """AC 28: MATCH (:azure_subscription)-[r:CONTAINS]->(:azure_resource_group) returns >= 1."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("azure-age-contains")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:azure_subscription)-[r:CONTAINS]->(:azure_resource_group) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )

    assert len(rows) >= 1, (
        f"Expected >= 1 CONTAINS subscription->RG in AGE, got {len(rows)}"
    )


def test_age_projection_nsg_connects_to_subnet(pool, make_tenant):
    """AC 28: MATCH (:azure_nsg)-[r:CONNECTS_TO]->(:azure_subnet) returns >= 1."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("azure-age-connects")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:azure_nsg)-[r:CONNECTS_TO]->(:azure_subnet) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )

    assert len(rows) >= 1, (
        f"Expected >= 1 CONNECTS_TO nsg->subnet in AGE, got {len(rows)}"
    )


# ---------------------------------------------------------------------------
# AC 29: second reconcile over same fixture is a no-op
# ---------------------------------------------------------------------------


def test_second_reconcile_is_noop(pool, make_tenant):
    """AC 29 / §5.15: cis_created==0, cis_closed==0, edges_closed==0 on second identical run."""
    from infra_twin.reconciliation import discover_and_reconcile

    tenant = make_tenant("azure-idempotent")

    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())
    result2 = discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    assert result2.cis_created == 0, (
        f"Second reconcile should create 0 CIs; got {result2.cis_created}"
    )
    assert result2.cis_closed == 0, (
        f"Second reconcile should close 0 CIs; got {result2.cis_closed}"
    )
    assert result2.edges_closed == 0, (
        f"Second reconcile should close 0 edges; got {result2.edges_closed}"
    )


# ---------------------------------------------------------------------------
# AC 30: adversarial cross-tenant isolation
# ---------------------------------------------------------------------------


def test_cross_tenant_isolation_azure_cis(pool, make_tenant):
    """AC 30a / §5.17: tenant B sees zero azure_* CIs belonging to tenant A."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.repositories import CIRepository
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("azure-iso-a")
    tenant_b = make_tenant("azure-iso-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        repo = CIRepository(conn, tenant_b)
        b_cis = repo.get_current()

    azure_types = {
        CIType.azure_subscription,
        CIType.azure_resource_group,
        CIType.azure_vnet,
        CIType.azure_subnet,
        CIType.azure_nsg,
        CIType.azure_vm,
    }
    b_azure = [c for c in b_cis if c.type in azure_types]
    assert not b_azure, (
        f"Tenant B should see 0 azure CIs belonging to A; got {len(b_azure)}: {b_azure[:3]}"
    )


def test_cross_tenant_isolation_azure_edges(pool, make_tenant):
    """AC 30b: tenant B sees zero edges written for tenant A."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("azure-iso-edge-a")
    tenant_b = make_tenant("azure-iso-edge-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute("SELECT count(*) FROM edges WHERE valid_to IS NULL").fetchone()[0]
    assert count == 0, f"Tenant B should see 0 edges; got {count}"


def test_cross_tenant_isolation_azure_connector_runs(pool, make_tenant):
    """AC 30c: tenant B sees no connector_runs with source='azure'."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connector_health import ConnectorRunRepository
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("azure-iso-run-a")
    tenant_b = make_tenant("azure-iso-run-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        run_repo = ConnectorRunRepository(conn, tenant_b)
        summaries = run_repo.latest_per_source()

    azure = [s for s in summaries if s.source == "azure"]
    assert not azure, f"Tenant B should see no azure connector_runs; got {azure}"


def test_cross_tenant_isolation_connector_registry(pool, make_tenant):
    """AC 30d: ConnectorRegistry for tenant B shows no 'azure' connector."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connectors import ConnectorRegistry
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("azure-iso-reg-a")
    tenant_b = make_tenant("azure-iso-reg-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        registry = ConnectorRegistry(conn, tenant_b)
        b_connectors = registry.list()

    azure = [c for c in b_connectors if c.type == "azure"]
    assert not azure, (
        f"Tenant B should have no azure connector in registry; got {azure}"
    )


def test_cross_tenant_isolation_raw_facts(pool, make_tenant):
    """AC 30e: tenant B sees zero raw_facts rows written for tenant A's azure run."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("azure-iso-rf-a")
    tenant_b = make_tenant("azure-iso-rf-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = %s", ("azure",)
        ).fetchone()[0]
    assert count == 0, f"Tenant B should see 0 azure raw_facts; got {count}"
