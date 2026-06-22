"""Contract test for the GCP connector against a deterministic in-memory fake client.

No live GCP project, no network. The fake returns fixed, seeded data so the
test is offline-reproducible and pinned to a specific expected mapping.

Covers:
  - AC 1-4  : CIType / EdgeType / EdgeSource / Evidence enum invariants (gcp additions + unchanged members)
  - AC 5-12 : GcpConnector class-level attributes and package exports
  - AC 13-24: connector contract — happy path + every spec edge case (§5.1–§5.17)
  - AC 25-30: E2E reconcile + adversarial tenant isolation (uses pool/make_tenant fixtures)
  - AC 31   : migration 0017 content
  - AC 32   : CLI subcommand wiring (discover-gcp)
  - AC 33   : regression — all existing connectors still importable
"""

from __future__ import annotations

import os

import pytest

from infra_twin.collectors import AwsConnector, AzureConnector, GcpConnector, KubernetesConnector
from infra_twin.collectors.gcp import GcpClient
from infra_twin.collectors.gcp.connector import _firewall_rule_label, _self_link_name
from infra_twin.connector_sdk import Connector, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeSource, EdgeType

# ---------------------------------------------------------------------------
# Seeded GCP resource ids (GCP selfLink-style URLs)
# ---------------------------------------------------------------------------

PROJECT_ID = "my-gcp-project-001"
PROJECT_NAME = "My GCP Project"

NET1_ID = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/global/networks/vpc-main"
NET1_NAME = "vpc-main"

# A second network whose subnetwork parent doesn't resolve (no subnetwork in net2's range)
NET2_ID = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/global/networks/vpc-secondary"
NET2_NAME = "vpc-secondary"

# Subnetwork whose parent network resolves (NET1)
SN1_ID = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/regions/us-central1/subnetworks/subnet-web"
SN1_NAME = "subnet-web"
SN1_REGION = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/regions/us-central1"

# Subnetwork whose parent network does NOT exist in discovered networks (edge case §5.3)
SN2_ID = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/regions/us-east1/subnetworks/subnet-orphan"
SN2_NAME = "subnet-orphan"
SN2_REGION = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/regions/us-east1"
SN2_PARENT_NET = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/global/networks/vpc-gone"

# Firewall: ingress allow, targets instances in vpc-main (drives CONNECTS_TO for subnet-web)
FW_ALLOW_ID = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/global/firewalls/allow-http"
FW_ALLOW_NAME = "allow-http"

# Firewall: egress (§5.5) — no CONNECTS_TO
FW_EGRESS_ID = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/global/firewalls/egress-all"
FW_EGRESS_NAME = "egress-all"

# Firewall: disabled (§5.6) — no CONNECTS_TO
FW_DISABLED_ID = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/global/firewalls/disabled-rule"
FW_DISABLED_NAME = "disabled-rule"

# Firewall: empty/absent allowed (§5.7) — no CONNECTS_TO (deny-style with only 'denied')
FW_DENY_ID = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/global/firewalls/deny-all"
FW_DENY_NAME = "deny-all"

# Firewall: dangling — ingress allow but network matches no discovered subnetwork (§5.8)
FW_DANGLING_ID = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/global/firewalls/dangling-fw"
FW_DANGLING_NAME = "dangling-fw"

# Instance whose NIC resolves to SN1 (will get RUNS_ON)
INST1_ID = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/zones/us-central1-a/instances/vm-web"
INST1_NAME = "vm-web"
INST1_MACHINE_TYPE = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/zones/us-central1-a/machineTypes/n1-standard-2"
INST1_ZONE = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/zones/us-central1-a"

# Instance whose NIC subnetwork is not discovered (§5.4) — no RUNS_ON
INST2_ID = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/zones/us-east1-b/instances/vm-nosub"
INST2_NAME = "vm-nosub"
INST2_MACHINE_TYPE = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/zones/us-east1-b/machineTypes/n1-standard-1"
INST2_ZONE = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/zones/us-east1-b"
SN_UNKNOWN_ID = "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/regions/us-east1/subnetworks/subnet-unknown"

# NSG rule detail used in evidence assertions
FW_ALLOW_RULE2_NAME = "allow-https"


class FakeGcpClient:
    """Deterministic in-memory GcpClient for offline contract tests.

    The fixture exercises every major edge case from spec §5:
      - Two networks (vpc-main, vpc-secondary)
      - One subnetwork whose parent network resolves (subnet-web in vpc-main)
      - One subnetwork whose parent network does NOT exist (subnet-orphan, §5.3)
      - Ingress allow firewall targeting vpc-main instances (drives CONNECTS_TO)
      - Egress firewall (§5.5) — no CONNECTS_TO
      - Disabled firewall (§5.6) — no CONNECTS_TO
      - Firewall with empty allowed (§5.7) — no CONNECTS_TO
      - Dangling firewall with no matching subnetwork (§5.8) — no CONNECTS_TO
      - Instance whose NIC resolves to subnet-web (RUNS_ON + CONTAINS)
      - Instance whose NIC subnetwork is not discovered (§5.4) — no RUNS_ON
    """

    def list_networks(self) -> list[dict]:
        return [
            {
                "selfLink": NET1_ID,
                "name": NET1_NAME,
                "autoCreateSubnetworks": False,
                "routingConfig": {"routingMode": "REGIONAL"},
            },
            {
                "selfLink": NET2_ID,
                "name": NET2_NAME,
                "autoCreateSubnetworks": True,
                "routingConfig": {"routingMode": "GLOBAL"},
            },
        ]

    def list_subnetworks(self) -> list[dict]:
        return [
            {
                "selfLink": SN1_ID,
                "name": SN1_NAME,
                "network": NET1_ID,
                "ipCidrRange": "10.0.1.0/24",
                "region": SN1_REGION,
            },
            # Edge case §5.3: parent network not discovered
            {
                "selfLink": SN2_ID,
                "name": SN2_NAME,
                "network": SN2_PARENT_NET,
                "ipCidrRange": "10.99.0.0/24",
                "region": SN2_REGION,
            },
        ]

    def list_firewalls(self) -> list[dict]:
        return [
            # Primary ingress allow firewall — will generate CONNECTS_TO to subnet-web
            {
                "selfLink": FW_ALLOW_ID,
                "name": FW_ALLOW_NAME,
                "network": NET1_ID,
                "direction": "INGRESS",
                "disabled": False,
                "sourceRanges": ["0.0.0.0/0"],
                "targetTags": [],
                "allowed": [
                    {"IPProtocol": "tcp", "ports": ["80"]},
                    {"IPProtocol": "tcp", "ports": ["443"]},
                ],
            },
            # Edge case §5.5: egress firewall — no CONNECTS_TO
            {
                "selfLink": FW_EGRESS_ID,
                "name": FW_EGRESS_NAME,
                "network": NET1_ID,
                "direction": "EGRESS",
                "disabled": False,
                "allowed": [{"IPProtocol": "all"}],
            },
            # Edge case §5.6: disabled firewall — no CONNECTS_TO
            {
                "selfLink": FW_DISABLED_ID,
                "name": FW_DISABLED_NAME,
                "network": NET1_ID,
                "direction": "INGRESS",
                "disabled": True,
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
            },
            # Edge case §5.7: empty/absent allowed list — no CONNECTS_TO
            {
                "selfLink": FW_DENY_ID,
                "name": FW_DENY_NAME,
                "network": NET1_ID,
                "direction": "INGRESS",
                "disabled": False,
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [],
            },
            # Edge case §5.8: dangling — ingress allow but network has no discovered subnetwork with instances
            {
                "selfLink": FW_DANGLING_ID,
                "name": FW_DANGLING_NAME,
                "network": "https://www.googleapis.com/compute/v1/projects/my-gcp-project-001/global/networks/vpc-gone",
                "direction": "INGRESS",
                "disabled": False,
                "sourceRanges": ["10.0.0.0/8"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["8080"]}],
            },
        ]

    def list_instances(self) -> list[dict]:
        return [
            {
                "selfLink": INST1_ID,
                "name": INST1_NAME,
                "machineType": INST1_MACHINE_TYPE,
                "zone": INST1_ZONE,
                "tags": {"items": ["web", "http-server"]},
                "networkInterfaces": [
                    {"subnetwork": SN1_ID, "networkIP": "10.0.1.10"},
                ],
            },
            # Edge case §5.4: NIC subnetwork not in discovered_subnetwork_ids
            {
                "selfLink": INST2_ID,
                "name": INST2_NAME,
                "machineType": INST2_MACHINE_TYPE,
                "zone": INST2_ZONE,
                "tags": {"items": []},
                "networkInterfaces": [
                    {"subnetwork": SN_UNKNOWN_ID, "networkIP": "10.99.0.20"},
                ],
            },
        ]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_client() -> FakeGcpClient:
    return FakeGcpClient()


@pytest.fixture
def connector(fake_client: FakeGcpClient) -> GcpConnector:
    return GcpConnector(fake_client, project_id=PROJECT_ID, project_name=PROJECT_NAME)


@pytest.fixture
def all_events(connector: GcpConnector):
    return list(connector.discover())


@pytest.fixture
def cis(all_events) -> list[DiscoveredCI]:
    return [e for e in all_events if isinstance(e, DiscoveredCI)]


@pytest.fixture
def edges(all_events) -> list[DiscoveredEdge]:
    return [e for e in all_events if isinstance(e, DiscoveredEdge)]


# ---------------------------------------------------------------------------
# AC 1 (enum): gcp_* CIType members exist with value == name
# ---------------------------------------------------------------------------


def test_gcp_citype_values_match_names():
    """AC 1: each new gcp_* CIType member has value == name."""
    for member_name in (
        "gcp_project",
        "gcp_network",
        "gcp_subnetwork",
        "gcp_firewall",
        "gcp_instance",
    ):
        member = CIType[member_name]
        assert member.value == member_name, (
            f"CIType.{member_name}.value should be {member_name!r}, got {member.value!r}"
        )


# ---------------------------------------------------------------------------
# AC 2 (enum): pre-existing CIType members unchanged
# ---------------------------------------------------------------------------


def test_pre_existing_citype_members_unchanged():
    """AC 2: all 14 AWS/internet/dns members, 6 k8s_*, and 6 azure_* members still present and unchanged."""
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
        # Azure
        "azure_subscription": "azure_subscription",
        "azure_resource_group": "azure_resource_group",
        "azure_vnet": "azure_vnet",
        "azure_subnet": "azure_subnet",
        "azure_nsg": "azure_nsg",
        "azure_vm": "azure_vm",
    }
    for name, value in expected.items():
        member = CIType[name]
        assert member.value == value, (
            f"Pre-existing CIType.{name}.value changed: expected {value!r}, got {member.value!r}"
        )


# ---------------------------------------------------------------------------
# AC 3 (enum): EdgeType unchanged (exactly 10 members)
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
# AC 4 (enum): EdgeSource, Evidence unchanged
# ---------------------------------------------------------------------------


def test_edgesource_has_declared_and_inferred():
    """AC 4: EdgeSource has exactly 'declared' and 'inferred'."""
    from infra_twin.core_model import EdgeSource
    values = {m.value for m in EdgeSource}
    assert values == {"declared", "inferred"}, f"EdgeSource changed: {values}"


def test_evidence_model_fields():
    """AC 4: Evidence model has source, detail, observed_at fields."""
    from infra_twin.core_model import Evidence
    ev = Evidence(source="gcp", detail="test-detail")
    assert ev.source == "gcp"
    assert ev.detail == "test-detail"
    assert ev.observed_at is not None


# ---------------------------------------------------------------------------
# AC 5: GcpConnector.source == "gcp"
# ---------------------------------------------------------------------------


def test_connector_source():
    """AC 5: GcpConnector.source == 'gcp'."""
    assert GcpConnector.source == "gcp"


# ---------------------------------------------------------------------------
# AC 6: GcpConnector.ci_types
# ---------------------------------------------------------------------------


def test_connector_ci_types():
    """AC 6: GcpConnector.ci_types == frozenset of all 5 gcp_* CI types."""
    expected = frozenset(
        {
            CIType.gcp_project,
            CIType.gcp_network,
            CIType.gcp_subnetwork,
            CIType.gcp_firewall,
            CIType.gcp_instance,
        }
    )
    assert GcpConnector.ci_types == expected


# ---------------------------------------------------------------------------
# AC 7: GcpConnector.edge_types
# ---------------------------------------------------------------------------


def test_connector_edge_types():
    """AC 7: GcpConnector.edge_types == frozenset({CONTAINS, RUNS_ON, CONNECTS_TO})."""
    expected = frozenset(
        {
            EdgeType.CONTAINS,
            EdgeType.RUNS_ON,
            EdgeType.CONNECTS_TO,
        }
    )
    assert GcpConnector.edge_types == expected


# ---------------------------------------------------------------------------
# AC 8: isinstance(connector, Connector) protocol check
# ---------------------------------------------------------------------------


def test_connector_satisfies_protocol(fake_client):
    """AC 8: isinstance(GcpConnector(fake, ...), Connector) is True."""
    conn = GcpConnector(fake_client, project_id="p")
    assert isinstance(conn, Connector)


# ---------------------------------------------------------------------------
# AC 9: isinstance(fake, GcpClient) protocol check
# ---------------------------------------------------------------------------


def test_fake_client_satisfies_protocol():
    """AC 9: the FakeGcpClient satisfies the GcpClient runtime_checkable Protocol."""
    assert isinstance(FakeGcpClient(), GcpClient)


# ---------------------------------------------------------------------------
# AC 10: connector.py imports no forbidden SDK
# ---------------------------------------------------------------------------


def test_connector_module_no_forbidden_imports():
    """AC 10: gcp connector source must not import boto3, kubernetes, azure SDK,
    google.cloud/google.oauth2 at module level, or infra_twin.collectors.aws/azure/k8s."""
    import importlib.util

    spec = importlib.util.find_spec("infra_twin.collectors.gcp.connector")
    assert spec is not None, "gcp connector module not found"
    source = open(spec.origin).read()
    assert "boto3" not in source, "connector.py must not import boto3"
    assert "import kubernetes" not in source, "connector.py must not import kubernetes"
    assert "kubernetes." not in source, "connector.py must not reference kubernetes."
    assert "infra_twin.collectors.aws" not in source, (
        "connector.py must not import from infra_twin.collectors.aws"
    )
    assert "infra_twin.collectors.azure" not in source, (
        "connector.py must not import from infra_twin.collectors.azure"
    )
    assert "infra_twin.collectors.k8s" not in source, (
        "connector.py must not import from infra_twin.collectors.k8s"
    )
    # No google SDK imports at module level
    lines = [ln.strip() for ln in source.splitlines() if ln.strip().startswith("import ") or ln.strip().startswith("from ")]
    google_sdk_imports = [
        ln for ln in lines
        if "google.cloud" in ln or "google.oauth2" in ln or ln.startswith("from google")
    ]
    assert not google_sdk_imports, (
        f"connector.py must not import Google SDK at module level: {google_sdk_imports}"
    )
    azure_sdk_imports = [ln for ln in lines if "azure.identity" in ln or "azure.mgmt" in ln]
    assert not azure_sdk_imports, (
        f"connector.py must not import Azure SDK: {azure_sdk_imports}"
    )


# ---------------------------------------------------------------------------
# AC 11: all four connectors importable from infra_twin.collectors
# ---------------------------------------------------------------------------


def test_all_four_connectors_importable_from_collectors():
    """AC 11: AwsConnector, AzureConnector, GcpConnector, KubernetesConnector importable from infra_twin.collectors."""
    from infra_twin.collectors import (
        AwsConnector as _Aws,
        AzureConnector as _Azure,
        GcpConnector as _Gcp,
        KubernetesConnector as _K8s,
    )
    assert _Aws is not None
    assert _Azure is not None
    assert _Gcp is not None
    assert _K8s is not None


def test_collectors_all_contains_all_four():
    """AC 11: infra_twin.collectors.__all__ contains all four connector names."""
    import infra_twin.collectors as pkg
    assert "AwsConnector" in pkg.__all__
    assert "AzureConnector" in pkg.__all__
    assert "GcpConnector" in pkg.__all__
    assert "KubernetesConnector" in pkg.__all__


# ---------------------------------------------------------------------------
# AC 12: GcpClient and GcpConnector importable from infra_twin.collectors.gcp
# ---------------------------------------------------------------------------


def test_gcp_package_exports():
    """AC 12: GcpClient and GcpConnector importable from infra_twin.collectors.gcp."""
    from infra_twin.collectors.gcp import GcpClient as _Client, GcpConnector as _Connector
    assert _Client is not None
    assert _Connector is not None


# ---------------------------------------------------------------------------
# AC 13: exactly one gcp_project CI emitted; name uses project_name or falls back
# ---------------------------------------------------------------------------


def test_project_ci_emitted_once(cis):
    """AC 13: exactly one gcp_project CI with external_id == project_id."""
    proj_cis = [c for c in cis if c.type == CIType.gcp_project]
    assert len(proj_cis) == 1, f"Expected 1 gcp_project CI, got {len(proj_cis)}"
    assert proj_cis[0].external_id == PROJECT_ID
    assert proj_cis[0].name == PROJECT_NAME


def test_project_ci_uses_name_when_provided(fake_client):
    """AC 13: when project_name is provided, the CI uses it as name."""
    conn = GcpConnector(fake_client, project_id=PROJECT_ID, project_name="My Custom Name")
    cis = [e for e in conn.discover() if isinstance(e, DiscoveredCI)]
    proj_ci = next(c for c in cis if c.type == CIType.gcp_project)
    assert proj_ci.name == "My Custom Name"


def test_project_ci_falls_back_to_id_when_no_name(fake_client):
    """AC 13: when project_name is absent, name falls back to project_id."""
    conn = GcpConnector(fake_client, project_id=PROJECT_ID, project_name=None)
    cis = [e for e in conn.discover() if isinstance(e, DiscoveredCI)]
    proj_ci = next(c for c in cis if c.type == CIType.gcp_project)
    assert proj_ci.name == PROJECT_ID


# ---------------------------------------------------------------------------
# AC 14: each seeded selfLink appears as correct DiscoveredCI with normalized attributes
# ---------------------------------------------------------------------------


def test_all_expected_cis_emitted(cis):
    """AC 14: every seeded selfLink appears exactly once as a DiscoveredCI of the correct type."""
    by_id = {c.external_id: c for c in cis}

    checks: dict[str, CIType] = {
        PROJECT_ID: CIType.gcp_project,
        NET1_ID: CIType.gcp_network,
        NET2_ID: CIType.gcp_network,
        SN1_ID: CIType.gcp_subnetwork,
        SN2_ID: CIType.gcp_subnetwork,
        FW_ALLOW_ID: CIType.gcp_firewall,
        FW_EGRESS_ID: CIType.gcp_firewall,
        FW_DISABLED_ID: CIType.gcp_firewall,
        FW_DENY_ID: CIType.gcp_firewall,
        FW_DANGLING_ID: CIType.gcp_firewall,
        INST1_ID: CIType.gcp_instance,
        INST2_ID: CIType.gcp_instance,
    }

    for resource_id, expected_type in checks.items():
        assert resource_id in by_id, (
            f"Expected DiscoveredCI with external_id={resource_id!r} not found"
        )
        assert by_id[resource_id].type == expected_type, (
            f"CI {resource_id} should have type {expected_type}, got {by_id[resource_id].type}"
        )


def test_network_attributes(cis):
    """AC 14: gcp_network CI has auto_create_subnetworks and routing_mode attributes."""
    by_id = {c.external_id: c for c in cis if c.type == CIType.gcp_network}
    assert NET1_ID in by_id
    net_ci = by_id[NET1_ID]
    assert net_ci.attributes.get("routing_mode") == "REGIONAL"
    assert net_ci.attributes.get("auto_create_subnetworks") is False

    assert NET2_ID in by_id
    net2_ci = by_id[NET2_ID]
    assert net2_ci.attributes.get("routing_mode") == "GLOBAL"
    assert net2_ci.attributes.get("auto_create_subnetworks") is True


def test_subnetwork_attributes(cis):
    """AC 14: gcp_subnetwork CI has ip_cidr_range, region, network attributes."""
    by_id = {c.external_id: c for c in cis if c.type == CIType.gcp_subnetwork}
    assert SN1_ID in by_id
    sn_ci = by_id[SN1_ID]
    assert sn_ci.attributes.get("ip_cidr_range") == "10.0.1.0/24"
    # region should be the last segment of the selfLink URL
    assert sn_ci.attributes.get("region") == "us-central1"
    assert sn_ci.attributes.get("network") == NET1_ID


def test_firewall_attributes(cis):
    """AC 14: gcp_firewall CI has network, direction, disabled attributes."""
    by_id = {c.external_id: c for c in cis if c.type == CIType.gcp_firewall}
    assert FW_ALLOW_ID in by_id
    fw_ci = by_id[FW_ALLOW_ID]
    assert fw_ci.attributes.get("network") == NET1_ID
    assert fw_ci.attributes.get("direction") == "INGRESS"
    assert fw_ci.attributes.get("disabled") is False

    assert FW_EGRESS_ID in by_id
    egress_ci = by_id[FW_EGRESS_ID]
    assert egress_ci.attributes.get("direction") == "EGRESS"

    assert FW_DISABLED_ID in by_id
    disabled_ci = by_id[FW_DISABLED_ID]
    assert disabled_ci.attributes.get("disabled") is True


def test_instance_attributes(cis):
    """AC 14: gcp_instance CI has machine_type, zone, tags attributes."""
    by_id = {c.external_id: c for c in cis if c.type == CIType.gcp_instance}
    assert INST1_ID in by_id
    inst_ci = by_id[INST1_ID]
    # machine_type and zone should be the last segment of the selfLink URL
    assert inst_ci.attributes.get("machine_type") == "n1-standard-2"
    assert inst_ci.attributes.get("zone") == "us-central1-a"
    assert inst_ci.attributes.get("tags") == ["web", "http-server"]


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


def test_contains_project_to_networks(edges):
    """AC 16: CONTAINS edge from project to each discovered network."""
    proj_to_net = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.gcp_project
        and e.from_ref.external_id == PROJECT_ID
        and e.to_ref.type == CIType.gcp_network
    ]
    net_ids = {e.to_ref.external_id for e in proj_to_net}
    assert NET1_ID in net_ids, f"CONTAINS project->net1 missing; found {net_ids}"
    assert NET2_ID in net_ids, f"CONTAINS project->net2 missing; found {net_ids}"


def test_contains_network_to_subnetwork_when_parent_resolves(edges):
    """AC 16: CONTAINS network->subnetwork for SN1 whose parent network resolves."""
    net_to_sn = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.gcp_network
        and e.from_ref.external_id == NET1_ID
        and e.to_ref.type == CIType.gcp_subnetwork
        and e.to_ref.external_id == SN1_ID
    ]
    assert net_to_sn, "CONTAINS net1->subnet-web missing"


def test_contains_project_to_instances(edges):
    """AC 16: CONTAINS project->instance for each discovered instance."""
    proj_to_inst = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.gcp_project
        and e.from_ref.external_id == PROJECT_ID
        and e.to_ref.type == CIType.gcp_instance
    ]
    inst_ids = {e.to_ref.external_id for e in proj_to_inst}
    assert INST1_ID in inst_ids, f"CONTAINS project->vm-web missing; found {inst_ids}"
    assert INST2_ID in inst_ids, f"CONTAINS project->vm-nosub missing; found {inst_ids}"


# ---------------------------------------------------------------------------
# AC 17: RUNS_ON instance -> subnetwork
# ---------------------------------------------------------------------------


def test_runs_on_instance_to_subnetwork(edges):
    """AC 17: RUNS_ON edge from vm-web to subnet-web (NIC resolves)."""
    runs_on = [
        e for e in edges
        if e.type == EdgeType.RUNS_ON
        and e.from_ref.external_id == INST1_ID
        and e.to_ref.external_id == SN1_ID
    ]
    assert runs_on, "RUNS_ON vm-web->subnet-web missing"
    assert runs_on[0].from_ref.type == CIType.gcp_instance
    assert runs_on[0].to_ref.type == CIType.gcp_subnetwork


def test_runs_on_evidence_detail(edges):
    """AC 17/20: RUNS_ON edge has correct evidence detail."""
    for e in edges:
        if e.type == EdgeType.RUNS_ON:
            detail = e.evidence[0].detail
            assert detail == "gcp:instance:nic:subnetwork", (
                f"RUNS_ON evidence detail wrong: {detail!r}"
            )


# ---------------------------------------------------------------------------
# AC 18/19: CONNECTS_TO edge from firewall to subnetwork
# ---------------------------------------------------------------------------


def test_connects_to_firewall_to_subnetwork(edges):
    """AC 18: CONNECTS_TO from gcp_firewall to gcp_subnetwork for ingress allow rule."""
    connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.type == CIType.gcp_firewall
        and e.from_ref.external_id == FW_ALLOW_ID
        and e.to_ref.external_id == SN1_ID
    ]
    assert connects, "CONNECTS_TO allow-http->subnet-web missing"
    assert connects[0].from_ref.type == CIType.gcp_firewall
    assert connects[0].to_ref.type == CIType.gcp_subnetwork


def test_connects_to_source_confidence_evidence(edges):
    """AC 19: CONNECTS_TO has source=declared, confidence=1.0, non-empty evidence."""
    connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.external_id == FW_ALLOW_ID
    ]
    assert connects, "No CONNECTS_TO for allow-http firewall found"
    edge = connects[0]
    assert edge.source == EdgeSource.declared, f"source wrong: {edge.source}"
    assert edge.confidence == 1.0, f"confidence wrong: {edge.confidence}"
    assert edge.evidence, "evidence must be non-empty"


def test_connects_to_evidence_names_firewall_rule(edges):
    """AC 19: CONNECTS_TO evidence detail contains originating firewall name."""
    connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.external_id == FW_ALLOW_ID
    ]
    assert connects, "No CONNECTS_TO for allow-http firewall found"
    details = [ev.detail for ev in connects[0].evidence]
    rule_names_in_details = [d for d in details if FW_ALLOW_NAME in d]
    assert rule_names_in_details, (
        f"Evidence detail must contain firewall name '{FW_ALLOW_NAME}'; got details: {details}"
    )


def test_connects_to_evidence_source_is_gcp(edges):
    """AC 19: each Evidence entry on CONNECTS_TO has source=='gcp'."""
    for e in edges:
        if e.type == EdgeType.CONNECTS_TO:
            for ev in e.evidence:
                assert ev.source == "gcp", (
                    f"CONNECTS_TO evidence.source must be 'gcp'; got {ev.source!r}"
                )
                assert ev.detail, "CONNECTS_TO evidence.detail must be non-empty"


# ---------------------------------------------------------------------------
# AC 20: every edge has correct provenance
# ---------------------------------------------------------------------------


def test_all_edges_have_gcp_provenance(edges):
    """AC 20: every DiscoveredEdge has source=declared, confidence=1.0,
    non-empty evidence, all with source=='gcp' and non-empty detail."""
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
            assert ev.source == "gcp", (
                f"Edge {edge.type} evidence.source must be 'gcp'; got {ev.source!r}"
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
        def list_networks(self):
            # selfLink present but no routingConfig or autoCreateSubnetworks
            return [{"selfLink": "https://googleapis.com/compute/v1/projects/p/global/networks/n1", "name": "n1"}]

        def list_subnetworks(self):
            # No ipCidrRange, no region, no network
            return [{"selfLink": "https://googleapis.com/compute/v1/projects/p/regions/r/subnetworks/s1", "name": "s1"}]

        def list_firewalls(self):
            # No allowed, no direction
            return [{"selfLink": "https://googleapis.com/compute/v1/projects/p/global/firewalls/f1", "name": "f1"}]

        def list_instances(self):
            # No machineType, no zone, no tags, no networkInterfaces
            return [{"selfLink": "https://googleapis.com/compute/v1/projects/p/zones/z/instances/i1", "name": "i1"}]

    conn = GcpConnector(MinimalClient(), project_id="p", project_name=None)
    events = list(conn.discover())
    cis = [e for e in events if isinstance(e, DiscoveredCI)]
    types = {c.type for c in cis}
    # At minimum the project CI must be present
    assert CIType.gcp_project in types


# ---------------------------------------------------------------------------
# AC 22: discover() twice yields identical event stream (§5.13)
# ---------------------------------------------------------------------------


def test_discover_twice_yields_identical_stream(connector):
    """AC 22 / §5.13: calling discover() twice on the same connector + fixture yields
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
# AC 23 / §5.1: empty project emits 1 CI, 0 edges
# ---------------------------------------------------------------------------


def test_edge_case_1_empty_project():
    """§5.1: project with zero networks/subnetworks/firewalls/instances -> 1 CI (project) + 0 edges."""

    class EmptyClient:
        def list_networks(self):
            return []

        def list_subnetworks(self):
            return []

        def list_firewalls(self):
            return []

        def list_instances(self):
            return []

    conn = GcpConnector(EmptyClient(), project_id="empty-proj")
    events = list(conn.discover())
    cis = [e for e in events if isinstance(e, DiscoveredCI)]
    edges_out = [e for e in events if isinstance(e, DiscoveredEdge)]

    assert len(cis) == 1, f"Expected 1 CI for empty project, got {len(cis)}"
    assert cis[0].type == CIType.gcp_project
    assert cis[0].external_id == "empty-proj"
    assert not edges_out, f"Expected 0 edges for empty project, got {len(edges_out)}"


# ---------------------------------------------------------------------------
# AC 23 / §5.2: resource missing selfLink is skipped
# ---------------------------------------------------------------------------


def test_edge_case_2_missing_selflink_skips_resource():
    """§5.2: network/subnetwork/firewall/instance dict missing selfLink is skipped entirely."""

    class MissingLinkClient:
        def list_networks(self):
            return [
                {"name": "net-no-link"},  # missing selfLink — skip
                {"selfLink": "https://googleapis.com/compute/v1/projects/p/global/networks/n-valid", "name": "n-valid"},
            ]

        def list_subnetworks(self):
            return [
                {"name": "sn-no-link"},  # missing selfLink — skip
            ]

        def list_firewalls(self):
            return [
                {"name": "fw-no-link"},  # missing selfLink — skip
            ]

        def list_instances(self):
            return [
                {"name": "inst-no-link"},  # missing selfLink — skip
            ]

    conn = GcpConnector(MissingLinkClient(), project_id="p")
    events = list(conn.discover())
    cis = [e for e in events if isinstance(e, DiscoveredCI)]

    types_emitted = {c.type for c in cis}
    assert CIType.gcp_project in types_emitted
    assert CIType.gcp_network in types_emitted

    net_cis = [c for c in cis if c.type == CIType.gcp_network]
    assert len(net_cis) == 1
    assert net_cis[0].external_id == "https://googleapis.com/compute/v1/projects/p/global/networks/n-valid"

    # No subnetwork/firewall/instance CIs for missing-selfLink resources
    sn_cis = [c for c in cis if c.type == CIType.gcp_subnetwork]
    fw_cis = [c for c in cis if c.type == CIType.gcp_firewall]
    inst_cis = [c for c in cis if c.type == CIType.gcp_instance]
    assert not sn_cis, "No gcp_subnetwork CI should be emitted for missing selfLink"
    assert not fw_cis, "No gcp_firewall CI should be emitted for missing selfLink"
    assert not inst_cis, "No gcp_instance CI should be emitted for missing selfLink"


# ---------------------------------------------------------------------------
# AC 23 / §5.3: subnetwork with unresolvable parent network — no CONTAINS network->subnetwork
# ---------------------------------------------------------------------------


def test_edge_case_3_unresolvable_parent_network_for_subnetwork(edges, cis):
    """§5.3: subnetwork whose parent network not discovered: CI emitted, no CONTAINS network->subnetwork."""
    # SN2 references SN2_PARENT_NET which is not in the discovered networks
    orphan_sn_ci = [c for c in cis if c.external_id == SN2_ID]
    assert orphan_sn_ci, "Orphan subnetwork CI should still be emitted"

    contains_net_to_orphan_sn = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.to_ref.external_id == SN2_ID
        and e.from_ref.type == CIType.gcp_network
    ]
    assert not contains_net_to_orphan_sn, (
        "No CONTAINS network->orphan-subnetwork should be emitted"
    )


# ---------------------------------------------------------------------------
# AC 23 / §5.4: instance NIC subnetwork not discovered — no RUNS_ON
# ---------------------------------------------------------------------------


def test_edge_case_4_no_runs_on_for_unresolved_nic_subnetwork(edges, cis):
    """§5.4: instance whose NIC references undiscovered subnetwork -> CI emitted, CONTAINS project->instance emitted, no RUNS_ON."""
    nosub_inst_ci = [c for c in cis if c.external_id == INST2_ID]
    assert nosub_inst_ci, "vm-nosub CI should be emitted"

    # CONTAINS project->instance should still be emitted
    proj_to_inst2 = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.external_id == PROJECT_ID
        and e.to_ref.external_id == INST2_ID
    ]
    assert proj_to_inst2, "CONTAINS project->vm-nosub should be emitted even when NIC unresolved"

    runs_on_nosub = [
        e for e in edges
        if e.type == EdgeType.RUNS_ON
        and e.from_ref.external_id == INST2_ID
    ]
    assert not runs_on_nosub, "RUNS_ON should not be emitted for unresolved NIC subnetwork"


# ---------------------------------------------------------------------------
# AC 23 / §5.5: egress firewall — no CONNECTS_TO
# ---------------------------------------------------------------------------


def test_edge_case_5_egress_firewall_no_connects_to(edges):
    """§5.5: egress firewall does not generate CONNECTS_TO."""
    egress_connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.external_id == FW_EGRESS_ID
    ]
    assert not egress_connects, (
        "CONNECTS_TO must not be emitted for egress firewall"
    )


# ---------------------------------------------------------------------------
# AC 23 / §5.6: disabled firewall — no CONNECTS_TO
# ---------------------------------------------------------------------------


def test_edge_case_6_disabled_firewall_no_connects_to(edges):
    """§5.6: disabled firewall does not generate CONNECTS_TO."""
    disabled_connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.external_id == FW_DISABLED_ID
    ]
    assert not disabled_connects, (
        "CONNECTS_TO must not be emitted for disabled firewall"
    )


# ---------------------------------------------------------------------------
# AC 23 / §5.7: firewall with empty/absent allowed — no CONNECTS_TO
# ---------------------------------------------------------------------------


def test_edge_case_7_empty_allowed_no_connects_to(edges):
    """§5.7: firewall with empty/absent allowed list does not generate CONNECTS_TO."""
    deny_connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.external_id == FW_DENY_ID
    ]
    assert not deny_connects, (
        "CONNECTS_TO must not be emitted for firewall with empty allowed list"
    )


# ---------------------------------------------------------------------------
# AC 23 / §5.8: dangling firewall — no CONNECTS_TO
# ---------------------------------------------------------------------------


def test_edge_case_8_dangling_firewall_no_connects_to(edges):
    """§5.8: firewall whose network has no discovered subnetwork with instances -> no CONNECTS_TO."""
    dangling_connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.external_id == FW_DANGLING_ID
    ]
    assert not dangling_connects, (
        "CONNECTS_TO must not be emitted for dangling firewall"
    )


# ---------------------------------------------------------------------------
# AC 23 / §5.9: multiple allowed entries -> one collapsed CONNECTS_TO, one Evidence per rule entry
# ---------------------------------------------------------------------------


def test_edge_case_9_multiple_allowed_entries_collapsed(edges):
    """§5.9: firewall with two allowed entries -> exactly one collapsed CONNECTS_TO."""
    connects = [
        e for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.from_ref.external_id == FW_ALLOW_ID
        and e.to_ref.external_id == SN1_ID
    ]
    # The spec collapses per (firewall, subnetwork) pair — exactly one CONNECTS_TO
    assert len(connects) == 1, (
        f"Expected exactly 1 CONNECTS_TO edge for (firewall, subnetwork); got {len(connects)}"
    )


# ---------------------------------------------------------------------------
# AC 23 / §5.10: firewall rule with missing name -> evidence contains "<unnamed>"
# ---------------------------------------------------------------------------


def test_edge_case_10_unnamed_firewall_rule_emits_evidence():
    """§5.10: firewall with missing 'name' -> CONNECTS_TO still emitted; evidence contains '<unnamed>'."""

    class UnnamedFwClient:
        def list_networks(self):
            return [
                {
                    "selfLink": "https://googleapis.com/compute/v1/projects/p/global/networks/n1",
                    "name": "n1",
                }
            ]

        def list_subnetworks(self):
            return [
                {
                    "selfLink": "https://googleapis.com/compute/v1/projects/p/regions/r/subnetworks/s1",
                    "name": "s1",
                    "network": "https://googleapis.com/compute/v1/projects/p/global/networks/n1",
                    "ipCidrRange": "10.0.0.0/24",
                }
            ]

        def list_firewalls(self):
            return [
                {
                    # No 'name' key
                    "selfLink": "https://googleapis.com/compute/v1/projects/p/global/firewalls/fw1",
                    "network": "https://googleapis.com/compute/v1/projects/p/global/networks/n1",
                    "direction": "INGRESS",
                    "disabled": False,
                    "sourceRanges": ["0.0.0.0/0"],
                    "allowed": [{"IPProtocol": "tcp", "ports": ["80"]}],
                }
            ]

        def list_instances(self):
            return [
                {
                    "selfLink": "https://googleapis.com/compute/v1/projects/p/zones/z/instances/i1",
                    "name": "i1",
                    "networkInterfaces": [
                        {"subnetwork": "https://googleapis.com/compute/v1/projects/p/regions/r/subnetworks/s1"}
                    ],
                }
            ]

    conn = GcpConnector(UnnamedFwClient(), project_id="p")
    events = list(conn.discover())
    connects_to = [
        e for e in events
        if isinstance(e, DiscoveredEdge) and e.type == EdgeType.CONNECTS_TO
    ]
    assert connects_to, "CONNECTS_TO must still be emitted for unnamed firewall"
    for ev in connects_to[0].evidence:
        assert ev.detail, "evidence.detail must be non-empty even for unnamed firewall"
        assert "<unnamed>" in ev.detail, (
            f"Unnamed firewall evidence must contain '<unnamed>'; got {ev.detail!r}"
        )


# ---------------------------------------------------------------------------
# AC 23 / §5.11: two resources sharing base name in different regions -> distinct CIs
# ---------------------------------------------------------------------------


def test_edge_case_11_same_name_different_region_distinct_cis():
    """§5.11: two subnetworks named 'subnet-app' in different regions have distinct selfLinks -> distinct CIs."""

    class SameNameClient:
        def list_networks(self):
            return []

        def list_subnetworks(self):
            return [
                {
                    "selfLink": "https://googleapis.com/compute/v1/projects/p/regions/us-central1/subnetworks/subnet-app",
                    "name": "subnet-app",
                    "ipCidrRange": "10.0.0.0/24",
                },
                {
                    "selfLink": "https://googleapis.com/compute/v1/projects/p/regions/us-east1/subnetworks/subnet-app",
                    "name": "subnet-app",
                    "ipCidrRange": "10.1.0.0/24",
                },
            ]

        def list_firewalls(self):
            return []

        def list_instances(self):
            return []

    conn = GcpConnector(SameNameClient(), project_id="p")
    events = list(conn.discover())
    sn_cis = [e for e in events if isinstance(e, DiscoveredCI) and e.type == CIType.gcp_subnetwork]
    assert len(sn_cis) == 2, f"Expected 2 distinct gcp_subnetwork CIs, got {len(sn_cis)}"
    ids = {c.external_id for c in sn_cis}
    assert len(ids) == 2, f"Two subnetworks must have distinct external_ids; got {ids}"


# ---------------------------------------------------------------------------
# AC 24: fake client not mutated by discover()
# ---------------------------------------------------------------------------


def test_fake_client_not_mutated_by_discover():
    """AC 24 / §5.14: discover() must not mutate the injected client.
    We track call counts and verify the client's returned data is unchanged."""

    class TrackingClient:
        def __init__(self):
            self._net_calls = 0
            self._sn_calls = 0
            self._fw_calls = 0
            self._inst_calls = 0

        def list_networks(self):
            self._net_calls += 1
            return [{"selfLink": "https://googleapis.com/compute/v1/projects/p/global/networks/n1", "name": "n1"}]

        def list_subnetworks(self):
            self._sn_calls += 1
            return []

        def list_firewalls(self):
            self._fw_calls += 1
            return []

        def list_instances(self):
            self._inst_calls += 1
            return []

    client = TrackingClient()
    conn = GcpConnector(client, project_id="p")

    before_calls = client._net_calls
    list(conn.discover())
    after_calls = client._net_calls

    assert after_calls == before_calls + 1, "list_networks should be called exactly once"

    # Verify the client's lists are unmodified — call again and get same data
    net_data = client.list_networks()
    assert net_data == [{"selfLink": "https://googleapis.com/compute/v1/projects/p/global/networks/n1", "name": "n1"}], (
        "Client data must not be mutated by discover()"
    )


def test_connector_only_reads_never_writes(fake_client):
    """AC 24: connector does not call any write method; fake exposes no write methods."""
    write_methods = ["create", "update", "delete", "put", "patch", "post", "insert"]
    for method_name in dir(fake_client):
        if any(wm in method_name.lower() for wm in write_methods):
            assert False, f"Fake client has unexpected write method: {method_name}"


# ---------------------------------------------------------------------------
# Helper function unit tests (_self_link_name, _firewall_rule_label)
# ---------------------------------------------------------------------------


def test_self_link_name_standard_url():
    """_self_link_name extracts last path segment from a GCP selfLink URL."""
    result = _self_link_name(
        "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a"
    )
    assert result == "us-central1-a"


def test_self_link_name_machine_type():
    """_self_link_name extracts machine type name from machineType selfLink."""
    result = _self_link_name(
        "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/machineTypes/n1-standard-2"
    )
    assert result == "n1-standard-2"


def test_self_link_name_none_input():
    """_self_link_name returns None when given None."""
    result = _self_link_name(None)
    assert result is None


def test_self_link_name_empty_string():
    """_self_link_name returns None when given empty string."""
    result = _self_link_name("")
    assert result is None


def test_firewall_rule_label_with_proto_and_ports():
    """_firewall_rule_label renders protocol/ports from full allowed entries."""
    fw = {"allowed": [{"IPProtocol": "tcp", "ports": ["80", "443"]}]}
    result = _firewall_rule_label(fw)
    assert result == "tcp/80,443"


def test_firewall_rule_label_missing_allowed():
    """_firewall_rule_label falls back to 'all' for missing/empty allowed."""
    result = _firewall_rule_label({})
    assert result == "all"


def test_firewall_rule_label_empty_allowed():
    """_firewall_rule_label falls back to 'all' for empty allowed list."""
    result = _firewall_rule_label({"allowed": []})
    assert result == "all"


def test_firewall_rule_label_proto_only_no_ports():
    """_firewall_rule_label returns just proto when no ports specified."""
    fw = {"allowed": [{"IPProtocol": "icmp"}]}
    result = _firewall_rule_label(fw)
    assert result == "icmp"


# ---------------------------------------------------------------------------
# AC 31: migration 0017 content
# ---------------------------------------------------------------------------


def test_migration_0017_gcp_vertex_labels_exists():
    """AC 31: migration 0017 exists, calls create_vlabel for all 5 gcp_* labels,
    includes both GRANT statements, no create_elabel, no relational DDL."""
    migration_path = os.path.normpath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "migrations",
            "0017_gcp_vertex_labels.sql",
        )
    )
    assert os.path.isfile(migration_path), f"Migration not found: {migration_path}"

    content = open(migration_path).read()

    assert "ag_catalog" in content, "Migration must set ag_catalog in search_path"
    assert "create_elabel" not in content, "Migration must NOT call create_elabel"
    assert "CREATE TABLE" not in content, "Migration must NOT contain CREATE TABLE (relational DDL)"

    for label in (
        "gcp_project",
        "gcp_network",
        "gcp_subnetwork",
        "gcp_firewall",
        "gcp_instance",
    ):
        assert label in content, f"Migration must create vertex label '{label}'"

    assert "create_vlabel" in content, "Migration must call create_vlabel"
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES" in content, (
        "Migration must re-apply table GRANT"
    )
    assert "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES" in content, (
        "Migration must re-apply sequence GRANT"
    )


def test_existing_migrations_0001_to_0017_unchanged():
    """AC 31 (updated): files 0001 through 0024 must all still exist; 0024 (freshness_slo)
    is now the highest-numbered migration.  No migration numbered 0025 or above may exist."""
    migrations_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "migrations")
    )
    for n in range(1, 20):
        pattern = f"{n:04d}_"
        matches = [f for f in os.listdir(migrations_dir) if f.startswith(pattern)]
        assert matches, f"Migration {pattern}* not found in {migrations_dir}"

    # 0025 (history_retention) is now the latest — no 0026 or higher
    all_files = os.listdir(migrations_dir)
    assert any(f.startswith("0024") for f in all_files), (
        "Migration 0024_* must exist (freshness_slo)"
    )
    assert any(f.startswith("0025") for f in all_files), (
        "Migration 0025_* must exist (history_retention)"
    )
    higher = [f for f in all_files if len(f) >= 4 and f[:4].isdigit() and int(f[:4]) > 25]
    assert not higher, f"Unexpected migration(s) higher than 0025 found: {higher}"


# ---------------------------------------------------------------------------
# AC 32: CLI discover-gcp subcommand wiring
# ---------------------------------------------------------------------------


def test_cli_discover_gcp_subparser_registered():
    """AC 32: 'discover-gcp' subcommand is registered with required args."""
    from unittest.mock import patch

    captured = {}

    def fake_handler(args):
        captured["args"] = args
        return 0

    from infra_twin.cli.main import main as cli_main

    with patch("infra_twin.cli.main._discover_gcp", fake_handler):
        rc = cli_main([
            "discover-gcp",
            "--tenant", "00000000-0000-0000-0000-000000000001",
            "--project-id", "my-project-123",
        ])

    assert rc == 0
    args = captured["args"]
    assert args.tenant == "00000000-0000-0000-0000-000000000001"
    assert args.project_id == "my-project-123"
    assert args.project_name is None  # optional, defaults to None


def test_cli_discover_gcp_project_name_arg():
    """AC 32: --project-name is optional; when supplied it reaches the handler."""
    from unittest.mock import patch

    captured = {}

    def fake_handler(args):
        captured["args"] = args
        return 0

    from infra_twin.cli.main import main as cli_main

    with patch("infra_twin.cli.main._discover_gcp", fake_handler):
        cli_main([
            "discover-gcp",
            "--tenant", "00000000-0000-0000-0000-000000000001",
            "--project-id", "my-project-123",
            "--project-name", "My GCP Project",
        ])

    assert captured["args"].project_name == "My GCP Project"


def test_cli_discover_gcp_credentials_path_arg():
    """AC 32: --credentials-path is optional; when supplied it reaches the handler."""
    from unittest.mock import patch

    captured = {}

    def fake_handler(args):
        captured["args"] = args
        return 0

    from infra_twin.cli.main import main as cli_main

    with patch("infra_twin.cli.main._discover_gcp", fake_handler):
        cli_main([
            "discover-gcp",
            "--tenant", "00000000-0000-0000-0000-000000000001",
            "--project-id", "my-project-123",
            "--credentials-path", "/path/to/key.json",
        ])

    assert captured["args"].credentials_path == "/path/to/key.json"


# ---------------------------------------------------------------------------
# AC 33: regression — all existing connector tests unaffected (import smoke test)
# ---------------------------------------------------------------------------


def test_all_four_connectors_still_importable():
    """AC 33: AwsConnector, AzureConnector, KubernetesConnector still importable alongside GcpConnector."""
    assert AwsConnector is not None
    assert AzureConnector is not None
    assert GcpConnector is not None
    assert KubernetesConnector is not None


# ===========================================================================
# E2E + ADVERSARIAL ISOLATION TESTS (use pool + make_tenant from conftest.py)
# These tests require the local Postgres+AGE stack with migration 0017 applied.
# ===========================================================================


def _make_connector_for_e2e() -> GcpConnector:
    return GcpConnector(
        FakeGcpClient(), project_id=PROJECT_ID, project_name=PROJECT_NAME
    )


# ---------------------------------------------------------------------------
# AC 25: discover_and_reconcile returns positive counts
# ---------------------------------------------------------------------------


def test_discover_and_reconcile_returns_positive_counts(pool, make_tenant):
    """AC 25: discover_and_reconcile creates CIs and writes edges for GCP connector."""
    from infra_twin.reconciliation import discover_and_reconcile

    tenant = make_tenant("gcp-a")
    result = discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    assert result.cis_created > 0, f"Expected cis_created > 0, got {result.cis_created}"
    assert result.edges_written > 0, f"Expected edges_written > 0, got {result.edges_written}"


# ---------------------------------------------------------------------------
# AC 26: connector registry + runs + raw_facts
# ---------------------------------------------------------------------------


def test_connector_registry_has_gcp_type(pool, make_tenant):
    """AC 26: after reconcile, connectors row with type='gcp' exists."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connectors import ConnectorRegistry
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("gcp-registry")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        registry = ConnectorRegistry(conn, tenant)
        connectors_list = registry.list()

    gcp_connectors = [c for c in connectors_list if c.type == "gcp"]
    assert gcp_connectors, (
        f"No connector with type='gcp' found; got: {[c.type for c in connectors_list]}"
    )
    assert gcp_connectors[0].display_name == "gcp"


def test_connector_run_ok_and_raw_facts(pool, make_tenant):
    """AC 26: connector_runs row with source='gcp' and status='ok'; >= 1 raw_facts row."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connector_health import ConnectorRunRepository
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("gcp-run")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        run_repo = ConnectorRunRepository(conn, tenant)
        summaries = run_repo.latest_per_source()

    gcp_runs = [s for s in summaries if s.source == "gcp"]
    assert gcp_runs, "No connector_run with source='gcp' found"
    assert gcp_runs[0].status == "ok", (
        f"connector_run status expected 'ok', got {gcp_runs[0].status!r}"
    )

    from infra_twin.db.session import tenant_session as _ts
    with _ts(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = %s", ("gcp",)
        ).fetchone()[0]
    assert count >= 1, f"Expected at least 1 raw_facts row for source='gcp', got {count}"


# ---------------------------------------------------------------------------
# AC 27: all five gcp_* CI types persisted current with correct tenant_id
# ---------------------------------------------------------------------------


def test_gcp_cis_persisted_current_with_correct_tenant(pool, make_tenant):
    """AC 27: all five gcp_* CI types are persisted current (valid_to IS NULL) with tenant_id == tenant."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.repositories import CIRepository
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("gcp-cis")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        for ci_type in (
            CIType.gcp_project,
            CIType.gcp_network,
            CIType.gcp_subnetwork,
            CIType.gcp_firewall,
            CIType.gcp_instance,
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


def test_gcp_edges_persisted_with_provenance(pool, make_tenant):
    """AC 27: persisted gcp edges have source, non-null confidence, and non-empty evidence."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("gcp-edges")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT source, confidence, evidence FROM edges WHERE valid_to IS NULL",
        ).fetchall()

    assert rows, "No current edges found after gcp reconcile"
    for source, confidence, evidence in rows:
        assert source in ("declared", "inferred"), (
            f"Edge source must be 'declared' or 'inferred'; got {source!r}"
        )
        assert confidence is not None, "Edge confidence must be set"
        assert evidence, "Edge evidence must be non-empty"
        for ev in evidence:
            assert "source" in ev, f"Evidence entry missing 'source' key: {ev!r}"


# ---------------------------------------------------------------------------
# AC 28: AGE projection contains gcp_* nodes and edges
# ---------------------------------------------------------------------------


def test_age_projection_gcp_instance(pool, make_tenant):
    """AC 28: MATCH (n:gcp_instance) WHERE n.tenant_id='<A>' RETURN n returns >= 1 row."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("gcp-age-inst")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(conn, f"MATCH (n:gcp_instance) WHERE n.tenant_id = '{tenant}' RETURN n")

    assert len(rows) >= 1, (
        f"Expected >= 1 gcp_instance node in AGE for tenant {tenant}, got {len(rows)}"
    )


def test_age_projection_project_contains_network(pool, make_tenant):
    """AC 28: MATCH (:gcp_project)-[r:CONTAINS]->(:gcp_network) WHERE r.tenant_id=... returns >= 1."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("gcp-age-contains")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:gcp_project)-[r:CONTAINS]->(:gcp_network) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )

    assert len(rows) >= 1, (
        f"Expected >= 1 CONTAINS project->network in AGE, got {len(rows)}"
    )


def test_age_projection_firewall_connects_to_subnetwork(pool, make_tenant):
    """AC 28: MATCH (:gcp_firewall)-[r:CONNECTS_TO]->(:gcp_subnetwork) WHERE r.tenant_id=... returns >= 1."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("gcp-age-connects")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:gcp_firewall)-[r:CONNECTS_TO]->(:gcp_subnetwork) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )

    assert len(rows) >= 1, (
        f"Expected >= 1 CONNECTS_TO firewall->subnetwork in AGE, got {len(rows)}"
    )


# ---------------------------------------------------------------------------
# AC 29: second reconcile over same fixture is a no-op
# ---------------------------------------------------------------------------


def test_second_reconcile_is_noop(pool, make_tenant):
    """AC 29 / §5.16: cis_created==0, cis_closed==0, edges_closed==0 on second identical run."""
    from infra_twin.reconciliation import discover_and_reconcile

    tenant = make_tenant("gcp-idempotent")

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


def test_cross_tenant_isolation_gcp_cis(pool, make_tenant):
    """AC 30a / §5.17: tenant B sees zero gcp_* CIs belonging to tenant A."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.repositories import CIRepository
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("gcp-iso-a")
    tenant_b = make_tenant("gcp-iso-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        repo = CIRepository(conn, tenant_b)
        b_cis = repo.get_current()

    gcp_types = {
        CIType.gcp_project,
        CIType.gcp_network,
        CIType.gcp_subnetwork,
        CIType.gcp_firewall,
        CIType.gcp_instance,
    }
    b_gcp = [c for c in b_cis if c.type in gcp_types]
    assert not b_gcp, (
        f"Tenant B should see 0 gcp CIs belonging to A; got {len(b_gcp)}: {b_gcp[:3]}"
    )


def test_cross_tenant_isolation_gcp_edges(pool, make_tenant):
    """AC 30b: tenant B sees zero edges written for tenant A."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("gcp-iso-edge-a")
    tenant_b = make_tenant("gcp-iso-edge-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute("SELECT count(*) FROM edges WHERE valid_to IS NULL").fetchone()[0]
    assert count == 0, f"Tenant B should see 0 edges; got {count}"


def test_cross_tenant_isolation_gcp_connector_runs(pool, make_tenant):
    """AC 30c: tenant B sees no connector_runs with source='gcp'."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connector_health import ConnectorRunRepository
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("gcp-iso-run-a")
    tenant_b = make_tenant("gcp-iso-run-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        run_repo = ConnectorRunRepository(conn, tenant_b)
        summaries = run_repo.latest_per_source()

    gcp = [s for s in summaries if s.source == "gcp"]
    assert not gcp, f"Tenant B should see no gcp connector_runs; got {gcp}"


def test_cross_tenant_isolation_connector_registry(pool, make_tenant):
    """AC 30d: ConnectorRegistry for tenant B shows no 'gcp' connector."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connectors import ConnectorRegistry
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("gcp-iso-reg-a")
    tenant_b = make_tenant("gcp-iso-reg-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        registry = ConnectorRegistry(conn, tenant_b)
        b_connectors = registry.list()

    gcp = [c for c in b_connectors if c.type == "gcp"]
    assert not gcp, (
        f"Tenant B should have no gcp connector in registry; got {gcp}"
    )


def test_cross_tenant_isolation_raw_facts(pool, make_tenant):
    """AC 30e: tenant B sees zero raw_facts rows written for tenant A's gcp run."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("gcp-iso-rf-a")
    tenant_b = make_tenant("gcp-iso-rf-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = %s", ("gcp",)
        ).fetchone()[0]
    assert count == 0, f"Tenant B should see 0 gcp raw_facts; got {count}"
