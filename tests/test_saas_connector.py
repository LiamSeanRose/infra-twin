"""Contract tests for the SaaS discovery connector against a deterministic in-memory fake.

No live database, no network. The fake returns fixed seeded data so the test is
offline-reproducible and pinned to a specific expected mapping.

Covers:
  - AC 1-2  : saas_* CIType values == names; pre-existing CIType/EdgeType/EdgeSource/Evidence
               enum invariants unchanged
  - AC 3-9  : SaasDiscoveryConnector class attrs, Protocol checks, no-forbidden-imports, exports
  - AC 10-18: connector contract — happy path + every spec edge case (§5.1–§5.20)
  - AC 19   : migration 0020 content
  - AC 20   : migration ordering — 0001..0020 exist; 0020 is highest; none > 0020
  - AC 21   : CLI discover-saas subparser wiring
  - AC 22-27: E2E reconcile + adversarial tenant isolation (uses pool/make_tenant fixtures)
"""

from __future__ import annotations

import importlib.util
import os
from unittest.mock import patch

import pytest

from infra_twin.collectors import (
    AwsConnector,
    AzureConnector,
    DbIntrospectionConnector,
    GcpConnector,
    KubernetesConnector,
    SaasDiscoveryConnector,
)
from infra_twin.collectors.saas import (
    SaasDiscoveryClient,
    SaasDiscoveryConnector as SaasConn,
)
from infra_twin.connector_sdk import Connector, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence

# ---------------------------------------------------------------------------
# Seeded test constants
# ---------------------------------------------------------------------------

ACCOUNT_ID = "acct-12345"

APP1_ID = "app-crm"
APP1_NAME = "CRM Suite"
APP1_VENDOR = "Salesforce"
APP1_CATEGORY = "crm"
APP1_EXT_ID = f"{ACCOUNT_ID}/{APP1_ID}"

APP2_ID = "app-erp"
APP2_NAME = "ERP System"
APP2_VENDOR = "SAP"
APP2_CATEGORY = "erp"
APP2_EXT_ID = f"{ACCOUNT_ID}/{APP2_ID}"

ACC1_ID = "u-alice"
ACC1_EMAIL = "alice@example.com"
ACC1_EXT_ID = f"{ACCOUNT_ID}/{ACC1_ID}"

ACC2_ID = "u-bob"
ACC2_EMAIL = "bob@example.com"
ACC2_EXT_ID = f"{ACCOUNT_ID}/{ACC2_ID}"

# Resource in app-crm with external_handle pointing at res2
RES1_ID = "r-deals"
RES1_EXT_ID = f"{ACCOUNT_ID}/{APP1_ID}/{RES1_ID}"

RES2_ID = "r-contacts"
RES2_EXT_ID = f"{ACCOUNT_ID}/{APP1_ID}/{RES2_ID}"

# Resource in app-erp
RES3_ID = "r-ledger"
RES3_EXT_ID = f"{ACCOUNT_ID}/{APP2_ID}/{RES3_ID}"

# Resource in app-erp with SAME resource_id as res1 (§5.12)
RES4_SAME_ID = RES1_ID  # same id, different app
RES4_EXT_ID = f"{ACCOUNT_ID}/{APP2_ID}/{RES4_SAME_ID}"

# Resource with no external_handle (§5.9)
RES5_ID = "r-noop"
RES5_EXT_ID = f"{ACCOUNT_ID}/{APP1_ID}/{RES5_ID}"

# Resource with external_handle pointing at undiscovered handle (§5.11)
RES6_ID = "r-external-dep"
RES6_HANDLE = "external://warehouse-system"
RES6_EXT_ID = f"{ACCOUNT_ID}/{APP1_ID}/{RES6_ID}"

# Grant g1: alice -> r-deals, read (§5.8 — two parallel grants)
GRANT1_ID = "grant-1"
GRANT1_SCOPE = "read"

# Grant g2: alice -> r-deals, write (§5.8 — same pair, different grant id)
GRANT2_ID = "grant-2"
GRANT2_SCOPE = "write"


class FakeSaasClient:
    """Deterministic in-memory SaasDiscoveryClient for offline contract tests.

    The fixture exercises every major discovery path:
      - Two apps: app-crm, app-erp
      - Two accounts in app-crm (alice, bob); one account with non-discovered app_id (§5.3);
        one account with falsy id (§5.2)
      - Resources: r-deals (has external_handle -> r-contacts), r-contacts, r-ledger (app-erp),
        r-deals clone in app-erp (§5.12), r-noop (no external_handle, §5.9),
        r-external-dep (handle -> undiscovered endpoint, §5.11)
      - Two parallel grants from alice to r-deals with distinct ids (§5.8);
        one grant with non-discovered resource (§5.6); one with non-discovered account (§5.5)
    """

    def list_apps(self) -> list[dict]:
        return [
            {"id": APP1_ID, "name": APP1_NAME, "vendor": APP1_VENDOR, "category": APP1_CATEGORY},
            {"id": APP2_ID, "name": APP2_NAME, "vendor": APP2_VENDOR, "category": APP2_CATEGORY},
        ]

    def list_accounts(self) -> list[dict]:
        return [
            # Valid — linked to app-crm
            {"id": ACC1_ID, "name": "Alice", "email": ACC1_EMAIL, "kind": "user", "app_id": APP1_ID},
            # Valid — linked to app-crm
            {"id": ACC2_ID, "name": "Bob", "email": ACC2_EMAIL, "kind": "user", "app_id": APP1_ID},
            # §5.3: account with non-discovered app_id -> CI emitted, no CONTAINS edge
            {"id": "u-ghost", "name": "Ghost", "email": "ghost@example.com", "kind": "user", "app_id": "app-nonexistent"},
            # §5.2: falsy id -> skipped entirely
            {"id": "", "name": "Nobody", "email": "nobody@example.com", "kind": "user", "app_id": APP1_ID},
        ]

    def list_resources(self) -> list[dict]:
        return [
            # §5.12: same resource_id as r-deals but in app-erp — placed FIRST so that
            # app-crm r-deals (below) overwrites discovered_resources['r-deals'] and wins.
            # This ensures grants referencing RES1_ID resolve to RES1_EXT_ID (app-crm).
            {"id": RES4_SAME_ID, "name": "Deals ERP", "app_id": APP2_ID, "kind": "dataset"},
            # r-deals: external_handle -> r-contacts (intra-graph DEPENDS_ON).
            # Overwrites RES4 in discovered_resources so grants resolve here.
            {"id": RES1_ID, "name": "Deals", "app_id": APP1_ID, "kind": "dataset", "external_handle": RES2_EXT_ID},
            # r-contacts: no external_handle (§5.9 for this one)
            {"id": RES2_ID, "name": "Contacts", "app_id": APP1_ID, "kind": "dataset"},
            # r-ledger in app-erp
            {"id": RES3_ID, "name": "Ledger", "app_id": APP2_ID, "kind": "report"},
            # §5.9: no external_handle -> no DEPENDS_ON
            {"id": RES5_ID, "name": "Noop", "app_id": APP1_ID, "kind": "noop"},
            # §5.11: external_handle -> undiscovered endpoint
            {"id": RES6_ID, "name": "External Dep", "app_id": APP1_ID, "kind": "dataset", "external_handle": RES6_HANDLE},
        ]

    def list_access_grants(self) -> list[dict]:
        return [
            # §5.8: grant-1 and grant-2 are TWO parallel grants between alice -> r-deals
            {"id": GRANT1_ID, "account_id": ACC1_ID, "resource_id": RES1_ID, "scope": GRANT1_SCOPE},
            {"id": GRANT2_ID, "account_id": ACC1_ID, "resource_id": RES1_ID, "scope": GRANT2_SCOPE},
            # §5.6: grant to non-discovered resource -> no HAS_ACCESS_TO
            {"id": "grant-bad-res", "account_id": ACC1_ID, "resource_id": "r-does-not-exist"},
            # §5.5: grant to non-discovered account -> no HAS_ACCESS_TO
            {"id": "grant-bad-acct", "account_id": "u-does-not-exist", "resource_id": RES1_ID},
        ]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_client() -> FakeSaasClient:
    return FakeSaasClient()


@pytest.fixture
def connector(fake_client: FakeSaasClient) -> SaasDiscoveryConnector:
    return SaasDiscoveryConnector(fake_client, account_id=ACCOUNT_ID, account_name="Test SaaS Acct")


@pytest.fixture
def all_events(connector: SaasDiscoveryConnector):
    return list(connector.discover())


@pytest.fixture
def cis(all_events) -> list[DiscoveredCI]:
    return [e for e in all_events if isinstance(e, DiscoveredCI)]


@pytest.fixture
def edges(all_events) -> list[DiscoveredEdge]:
    return [e for e in all_events if isinstance(e, DiscoveredEdge)]


# ===========================================================================
# AC 1: saas_* CIType members exist with value == name
# ===========================================================================


def test_saas_citype_values_match_names():
    """AC 1: each new saas_* CIType member has value == name."""
    for member_name in ("saas_app", "saas_account", "saas_resource"):
        member = CIType[member_name]
        assert member.value == member_name, (
            f"CIType.{member_name}.value should be {member_name!r}, got {member.value!r}"
        )


# ===========================================================================
# AC 2: pre-existing CIType / EdgeType / EdgeSource / Evidence unchanged
# ===========================================================================


def test_pre_existing_citype_members_unchanged():
    """AC 2: all AWS, k8s_*, azure_*, gcp_*, and db_* members still present unchanged."""
    expected = {
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
        "k8s_cluster": "k8s_cluster",
        "k8s_namespace": "k8s_namespace",
        "k8s_node": "k8s_node",
        "k8s_workload": "k8s_workload",
        "k8s_pod": "k8s_pod",
        "k8s_service": "k8s_service",
        "azure_subscription": "azure_subscription",
        "azure_resource_group": "azure_resource_group",
        "azure_vnet": "azure_vnet",
        "azure_subnet": "azure_subnet",
        "azure_nsg": "azure_nsg",
        "azure_vm": "azure_vm",
        "gcp_project": "gcp_project",
        "gcp_network": "gcp_network",
        "gcp_subnetwork": "gcp_subnetwork",
        "gcp_firewall": "gcp_firewall",
        "gcp_instance": "gcp_instance",
        "db_instance": "db_instance",
        "db_database": "db_database",
        "db_schema": "db_schema",
        "db_table": "db_table",
    }
    for name, value in expected.items():
        member = CIType[name]
        assert member.value == value, (
            f"Pre-existing CIType.{name}.value changed: expected {value!r}, got {member.value!r}"
        )


def test_edgetype_unchanged():
    """AC 2: EdgeType has exactly the 10 existing members; no new members added."""
    expected_members = {
        "CONTAINS", "RUNS_ON", "CONNECTS_TO", "DEPENDS_ON", "ROUTES_TO",
        "HAS_ACCESS_TO", "OWNS", "EXPOSES", "MEMBER_OF", "RESOLVES_TO",
    }
    actual = {m.value for m in EdgeType}
    assert actual == expected_members, (
        f"EdgeType members changed. Extra: {actual - expected_members}, "
        f"Missing: {expected_members - actual}"
    )


def test_edgesource_has_declared_and_inferred():
    """AC 2: EdgeSource has exactly 'declared' and 'inferred'."""
    values = {m.value for m in EdgeSource}
    assert values == {"declared", "inferred"}, f"EdgeSource changed: {values}"


def test_evidence_model_fields_for_saas_source():
    """AC 2: Evidence(source='saas', detail='x') has .source, .detail, .observed_at set."""
    ev = Evidence(source="saas", detail="x")
    assert ev.source == "saas"
    assert ev.detail == "x"
    assert ev.observed_at is not None


# ===========================================================================
# AC 3: SaasDiscoveryConnector.source == "saas"
# ===========================================================================


def test_connector_source():
    """AC 3: SaasDiscoveryConnector.source == 'saas'."""
    assert SaasDiscoveryConnector.source == "saas"


# ===========================================================================
# AC 4: SaasDiscoveryConnector.ci_types
# ===========================================================================


def test_connector_ci_types():
    """AC 4: SaasDiscoveryConnector.ci_types == frozenset of all 3 saas_* CI types."""
    expected = frozenset({CIType.saas_app, CIType.saas_account, CIType.saas_resource})
    assert SaasDiscoveryConnector.ci_types == expected


# ===========================================================================
# AC 5: SaasDiscoveryConnector.edge_types
# ===========================================================================


def test_connector_edge_types():
    """AC 5: SaasDiscoveryConnector.edge_types == frozenset({CONTAINS, HAS_ACCESS_TO, DEPENDS_ON})."""
    expected = frozenset({EdgeType.CONTAINS, EdgeType.HAS_ACCESS_TO, EdgeType.DEPENDS_ON})
    assert SaasDiscoveryConnector.edge_types == expected


# ===========================================================================
# AC 6: isinstance(connector, Connector) protocol check
# ===========================================================================


def test_connector_satisfies_protocol(fake_client):
    """AC 6: isinstance(SaasDiscoveryConnector(fake, ...), Connector) is True."""
    conn = SaasDiscoveryConnector(fake_client, account_id="acct")
    assert isinstance(conn, Connector)


# ===========================================================================
# AC 7: isinstance(FakeSaasClient(), SaasDiscoveryClient) protocol check
# ===========================================================================


def test_fake_client_satisfies_protocol():
    """AC 7: FakeSaasClient satisfies the SaasDiscoveryClient runtime_checkable Protocol."""
    assert isinstance(FakeSaasClient(), SaasDiscoveryClient)


# ===========================================================================
# AC 8: connector.py imports no forbidden SDK
# ===========================================================================


def test_connector_module_no_forbidden_imports():
    """AC 8: saas connector source must not import psycopg, boto3, kubernetes, azure SDK,
    google.cloud, or sibling connector packages at module level."""
    spec = importlib.util.find_spec("infra_twin.collectors.saas.connector")
    assert spec is not None, "saas connector module not found"
    source = open(spec.origin).read()

    assert "psycopg" not in source, "connector.py must not import psycopg"
    assert "boto3" not in source, "connector.py must not import boto3"
    assert "import kubernetes" not in source, "connector.py must not import kubernetes"
    assert "kubernetes." not in source, "connector.py must not reference kubernetes."
    assert "infra_twin.collectors.aws" not in source
    assert "infra_twin.collectors.azure" not in source
    assert "infra_twin.collectors.k8s" not in source
    assert "infra_twin.collectors.gcp" not in source
    assert "infra_twin.collectors.db" not in source

    import_lines = [
        ln.strip()
        for ln in source.splitlines()
        if ln.strip().startswith("import ") or ln.strip().startswith("from ")
    ]
    google_imports = [
        ln for ln in import_lines
        if "google.cloud" in ln or "google.oauth2" in ln or ln.startswith("from google")
    ]
    assert not google_imports, (
        f"connector.py must not import Google SDK at module level: {google_imports}"
    )
    azure_imports = [
        ln for ln in import_lines
        if "azure.identity" in ln or "azure.mgmt" in ln
    ]
    assert not azure_imports, (
        f"connector.py must not import Azure SDK: {azure_imports}"
    )


# ===========================================================================
# AC 9: package exports and __all__
# ===========================================================================


def test_saas_package_exports():
    """AC 9: SaasDiscoveryClient and SaasDiscoveryConnector importable from infra_twin.collectors.saas."""
    from infra_twin.collectors.saas import (
        SaasDiscoveryClient as _Client,
        SaasDiscoveryConnector as _Connector,
    )
    assert _Client is not None
    assert _Connector is not None


def test_all_six_connectors_importable_from_collectors():
    """AC 9: all 6 connectors importable from infra_twin.collectors."""
    assert AwsConnector is not None
    assert AzureConnector is not None
    assert GcpConnector is not None
    assert KubernetesConnector is not None
    assert DbIntrospectionConnector is not None
    assert SaasDiscoveryConnector is not None


def test_collectors_all_contains_all_six():
    """AC 9: infra_twin.collectors.__all__ contains all six connector names."""
    import infra_twin.collectors as pkg
    for name in (
        "AwsConnector",
        "AzureConnector",
        "GcpConnector",
        "KubernetesConnector",
        "DbIntrospectionConnector",
        "SaasDiscoveryConnector",
    ):
        assert name in pkg.__all__, f"{name} missing from infra_twin.collectors.__all__"


# ===========================================================================
# AC 10: three CI types discovered with correct type/external_id/attributes
# ===========================================================================


def test_all_expected_cis_emitted(cis):
    """AC 10: every seeded CI appears exactly once as a DiscoveredCI of the correct type."""
    by_id = {c.external_id: c for c in cis}

    checks: dict[str, CIType] = {
        APP1_EXT_ID: CIType.saas_app,
        APP2_EXT_ID: CIType.saas_app,
        ACC1_EXT_ID: CIType.saas_account,
        ACC2_EXT_ID: CIType.saas_account,
        f"{ACCOUNT_ID}/u-ghost": CIType.saas_account,  # §5.3: CI emitted even without CONTAINS
        RES1_EXT_ID: CIType.saas_resource,
        RES2_EXT_ID: CIType.saas_resource,
        RES3_EXT_ID: CIType.saas_resource,
        RES4_EXT_ID: CIType.saas_resource,
        RES5_EXT_ID: CIType.saas_resource,
        RES6_EXT_ID: CIType.saas_resource,
    }
    for ext_id, expected_type in checks.items():
        assert ext_id in by_id, (
            f"Expected DiscoveredCI with external_id={ext_id!r} not found in "
            f"{[c.external_id for c in cis]}"
        )
        assert by_id[ext_id].type == expected_type, (
            f"CI {ext_id} should have type {expected_type}, got {by_id[ext_id].type}"
        )


def test_saas_app_attributes(cis):
    """AC 10: saas_app CI has app_id, vendor, category attributes."""
    by_id = {c.external_id: c for c in cis}
    app_ci = by_id[APP1_EXT_ID]
    assert app_ci.attributes.get("app_id") == APP1_ID
    assert app_ci.attributes.get("vendor") == APP1_VENDOR
    assert app_ci.attributes.get("category") == APP1_CATEGORY


def test_saas_app_name(cis):
    """AC 10: saas_app CI name comes from app.get('name') or app_id."""
    by_id = {c.external_id: c for c in cis}
    app_ci = by_id[APP1_EXT_ID]
    assert app_ci.name == APP1_NAME


def test_saas_account_attributes(cis):
    """AC 10: saas_account CI has account_id, email, kind attributes."""
    by_id = {c.external_id: c for c in cis}
    acc_ci = by_id[ACC1_EXT_ID]
    assert acc_ci.attributes.get("account_id") == ACC1_ID
    assert acc_ci.attributes.get("email") == ACC1_EMAIL
    assert acc_ci.attributes.get("kind") == "user"


def test_saas_account_name(cis):
    """AC 10: saas_account CI name comes from account.get('name') or native_id."""
    by_id = {c.external_id: c for c in cis}
    acc_ci = by_id[ACC1_EXT_ID]
    assert acc_ci.name == "Alice"


def test_saas_resource_attributes(cis):
    """AC 10: saas_resource CI has app_id, resource_id, kind, external_handle attributes."""
    by_id = {c.external_id: c for c in cis}
    res_ci = by_id[RES1_EXT_ID]
    assert res_ci.attributes.get("app_id") == APP1_ID
    assert res_ci.attributes.get("resource_id") == RES1_ID
    assert res_ci.attributes.get("kind") == "dataset"
    assert res_ci.attributes.get("external_handle") == RES2_EXT_ID


def test_saas_resource_name(cis):
    """AC 10: saas_resource CI name comes from resource.get('name') or resource_id."""
    by_id = {c.external_id: c for c in cis}
    res_ci = by_id[RES1_EXT_ID]
    assert res_ci.name == "Deals"


# ===========================================================================
# AC 11: CONTAINS saas_app->saas_account edges with evidence detail "saas:app:account"
# ===========================================================================


def test_contains_app_to_account_emitted(edges):
    """AC 11: CONTAINS saas_app->saas_account edges emitted for discovered accounts."""
    app_to_acct = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.saas_app
        and e.to_ref.type == CIType.saas_account
    ]
    acct_ids = {e.to_ref.external_id for e in app_to_acct}
    assert ACC1_EXT_ID in acct_ids, f"CONTAINS app->alice missing; found {acct_ids}"
    assert ACC2_EXT_ID in acct_ids, f"CONTAINS app->bob missing; found {acct_ids}"


def test_contains_app_to_account_evidence_detail(edges):
    """AC 11: CONTAINS saas_app->saas_account evidence detail == 'saas:app:account'."""
    for e in edges:
        if (
            e.type == EdgeType.CONTAINS
            and e.from_ref.type == CIType.saas_app
            and e.to_ref.type == CIType.saas_account
        ):
            assert e.evidence[0].detail == "saas:app:account", (
                f"CONTAINS app->account evidence detail wrong: {e.evidence[0].detail!r}"
            )


# ===========================================================================
# AC 12: CONTAINS saas_app->saas_resource edges with evidence detail "saas:app:resource"
# ===========================================================================


def test_contains_app_to_resource_emitted(edges):
    """AC 12: CONTAINS saas_app->saas_resource edges emitted for resources with resolved parent."""
    app_to_res = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.saas_app
        and e.to_ref.type == CIType.saas_resource
    ]
    res_ids = {e.to_ref.external_id for e in app_to_res}
    assert RES1_EXT_ID in res_ids, f"CONTAINS app->r-deals missing; found {res_ids}"
    assert RES2_EXT_ID in res_ids, f"CONTAINS app->r-contacts missing; found {res_ids}"
    assert RES3_EXT_ID in res_ids, f"CONTAINS app->r-ledger missing; found {res_ids}"


def test_contains_app_to_resource_evidence_detail(edges):
    """AC 12: CONTAINS saas_app->saas_resource evidence detail == 'saas:app:resource'."""
    for e in edges:
        if (
            e.type == EdgeType.CONTAINS
            and e.from_ref.type == CIType.saas_app
            and e.to_ref.type == CIType.saas_resource
        ):
            assert e.evidence[0].detail == "saas:app:resource", (
                f"CONTAINS app->resource evidence detail wrong: {e.evidence[0].detail!r}"
            )


# ===========================================================================
# AC 13: HAS_ACCESS_TO edges with source=declared, confidence=1.0, non-empty edge_key
# ===========================================================================


def test_has_access_to_edges_emitted(edges):
    """AC 13: HAS_ACCESS_TO saas_account->saas_resource edges emitted for valid grants."""
    access_edges = [e for e in edges if e.type == EdgeType.HAS_ACCESS_TO]
    assert access_edges, "No HAS_ACCESS_TO edges emitted"


def test_has_access_to_source_confidence_evidence(edges):
    """AC 13: HAS_ACCESS_TO edges have source=declared, confidence=1.0, non-empty evidence."""
    for e in edges:
        if e.type == EdgeType.HAS_ACCESS_TO:
            assert e.source == EdgeSource.declared, f"source wrong: {e.source}"
            assert e.confidence == 1.0, f"confidence wrong: {e.confidence}"
            assert e.evidence, "evidence must be non-empty"


def test_has_access_to_edge_key_from_grant_id(edges):
    """AC 13: HAS_ACCESS_TO edge_key is derived from grant id/scope, non-empty."""
    access_edges = [e for e in edges if e.type == EdgeType.HAS_ACCESS_TO]
    for e in access_edges:
        assert e.edge_key, f"HAS_ACCESS_TO must have non-empty edge_key; got {e.edge_key!r}"


def test_has_access_to_alice_to_deals_two_grants(edges):
    """AC 13 / §5.8: two grants from alice -> r-deals produce two distinct HAS_ACCESS_TO edges."""
    alice_deals = [
        e for e in edges
        if e.type == EdgeType.HAS_ACCESS_TO
        and e.from_ref.external_id == ACC1_EXT_ID
        and e.to_ref.external_id == RES1_EXT_ID
    ]
    assert len(alice_deals) == 2, (
        f"Expected 2 HAS_ACCESS_TO alice->r-deals edges, got {len(alice_deals)}"
    )
    keys = {e.edge_key for e in alice_deals}
    assert len(keys) == 2, f"Two grants must produce two distinct edge_keys; got {keys}"
    assert GRANT1_ID in keys, f"grant-1 edge_key missing; got {keys}"
    assert GRANT2_ID in keys, f"grant-2 edge_key missing; got {keys}"


def test_has_access_to_evidence_detail_contains_grant_key(edges):
    """AC 13: HAS_ACCESS_TO evidence detail contains the grant key and scope."""
    alice_deals = [
        e for e in edges
        if e.type == EdgeType.HAS_ACCESS_TO
        and e.from_ref.external_id == ACC1_EXT_ID
        and e.to_ref.external_id == RES1_EXT_ID
    ]
    details = {e.evidence[0].detail for e in alice_deals}
    assert any(GRANT1_ID in d for d in details), f"grant-1 missing from details: {details}"
    assert any(GRANT2_ID in d for d in details), f"grant-2 missing from details: {details}"


# ===========================================================================
# AC 14: DEPENDS_ON edges from resources with external_handle
# ===========================================================================


def test_depends_on_edge_from_resource_with_handle(edges):
    """AC 14: DEPENDS_ON edge from r-deals (which has external_handle -> r-contacts)."""
    depends_on = [
        e for e in edges
        if e.type == EdgeType.DEPENDS_ON
        and e.from_ref.external_id == RES1_EXT_ID
    ]
    assert depends_on, f"DEPENDS_ON from r-deals missing"
    assert depends_on[0].to_ref.external_id == RES2_EXT_ID


def test_depends_on_to_ref_is_external_handle(edges):
    """AC 14: DEPENDS_ON to_ref.external_id == external_handle verbatim."""
    # r-external-dep has external_handle -> undiscovered endpoint (§5.11)
    dep_edges = [
        e for e in edges
        if e.type == EdgeType.DEPENDS_ON
        and e.from_ref.external_id == RES6_EXT_ID
    ]
    assert dep_edges, f"DEPENDS_ON from r-external-dep missing"
    assert dep_edges[0].to_ref.external_id == RES6_HANDLE, (
        f"DEPENDS_ON to_ref.external_id should be {RES6_HANDLE!r}; got {dep_edges[0].to_ref.external_id!r}"
    )


def test_depends_on_evidence_detail_contains_handle(edges):
    """AC 14: DEPENDS_ON evidence detail contains the external_handle value."""
    dep_edges = [
        e for e in edges
        if e.type == EdgeType.DEPENDS_ON
        and e.from_ref.external_id == RES6_EXT_ID
    ]
    assert dep_edges
    detail = dep_edges[0].evidence[0].detail
    assert RES6_HANDLE in detail, f"external_handle {RES6_HANDLE!r} missing from detail: {detail!r}"


# ===========================================================================
# AC 15: EVERY emitted DiscoveredEdge has source=declared, confidence=1.0,
#         evidence[*].source=="saas", non-empty detail
# ===========================================================================


def test_all_edges_have_saas_provenance(edges):
    """AC 15: every DiscoveredEdge has source=declared, confidence=1.0,
    non-empty evidence, all with source=='saas' and non-empty detail."""
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
            assert ev.source == "saas", (
                f"Edge {edge.type} evidence.source must be 'saas'; got {ev.source!r}"
            )
            assert ev.detail, (
                f"Edge {edge.type} evidence.detail must be non-empty; got {ev.detail!r}"
            )


# ===========================================================================
# AC 16 / §5.1: empty client returns ZERO CIs and ZERO edges (no implicit root CI)
# ===========================================================================


def test_edge_case_5_1_empty_client_zero_cis_zero_edges():
    """§5.1: all four client methods return [] -> ZERO CIs and ZERO edges (no implicit root CI)."""

    class EmptyClient:
        def list_apps(self): return []
        def list_accounts(self): return []
        def list_resources(self): return []
        def list_access_grants(self): return []

    conn = SaasDiscoveryConnector(EmptyClient(), account_id=ACCOUNT_ID)
    events = list(conn.discover())
    cis_out = [e for e in events if isinstance(e, DiscoveredCI)]
    edges_out = [e for e in events if isinstance(e, DiscoveredEdge)]

    assert len(cis_out) == 0, f"Expected 0 CIs for empty client, got {len(cis_out)}"
    assert len(edges_out) == 0, f"Expected 0 edges for empty client, got {len(edges_out)}"


# ===========================================================================
# AC 17 / §5.2: app/account/resource dict with missing/falsy id -> skipped
# ===========================================================================


def test_edge_case_5_2_missing_falsy_id_skipped():
    """§5.2: resource dict with missing/falsy id is skipped; other valid items still emitted."""

    class FalsyIdClient:
        def list_apps(self):
            return [
                {"id": None, "name": "nope"},    # None -> skip
                {"id": "", "name": "nope"},       # empty string -> skip
                {"id": APP1_ID, "name": "CRM"},   # valid -> emit
            ]

        def list_accounts(self):
            return [
                # valid account with no id key -> skip
                {"name": "nobody"},
                # valid account
                {"id": ACC1_ID, "name": "Alice", "app_id": APP1_ID},
            ]

        def list_resources(self):
            return [
                {"id": "", "name": "nope", "app_id": APP1_ID},   # falsy -> skip
                {"id": RES1_ID, "name": "Deals", "app_id": APP1_ID},  # valid
            ]

        def list_access_grants(self): return []

    conn = SaasDiscoveryConnector(FalsyIdClient(), account_id=ACCOUNT_ID)
    events = list(conn.discover())
    cis_out = [e for e in events if isinstance(e, DiscoveredCI)]

    app_cis = [c for c in cis_out if c.type == CIType.saas_app]
    assert len(app_cis) == 1, f"Expected 1 saas_app CI, got {len(app_cis)}"
    assert app_cis[0].external_id == APP1_EXT_ID

    acc_cis = [c for c in cis_out if c.type == CIType.saas_account]
    assert len(acc_cis) == 1, f"Expected 1 saas_account CI, got {len(acc_cis)}"
    assert acc_cis[0].external_id == ACC1_EXT_ID

    res_cis = [c for c in cis_out if c.type == CIType.saas_resource]
    assert len(res_cis) == 1, f"Expected 1 saas_resource CI, got {len(res_cis)}"
    assert res_cis[0].external_id == RES1_EXT_ID


# ===========================================================================
# §5.3: account whose app_id is absent or not in discovered_apps ->
#        saas_account CI emitted, NO CONTAINS saas_app->saas_account edge
# ===========================================================================


def test_edge_case_5_3_account_unresolved_app_id(edges, cis):
    """§5.3: account with non-discovered app_id -> CI emitted, no CONTAINS app->account edge."""
    # u-ghost has app_id == "app-nonexistent" which is not discovered
    ghost_ext_id = f"{ACCOUNT_ID}/u-ghost"
    ghost_cis = [c for c in cis if c.external_id == ghost_ext_id]
    assert len(ghost_cis) == 1, "u-ghost CI must still be emitted (§5.3)"

    # No CONTAINS edge should point to ghost
    ghost_contains = [
        e for e in edges
        if e.type == EdgeType.CONTAINS and e.to_ref.external_id == ghost_ext_id
    ]
    assert not ghost_contains, (
        f"No CONTAINS edge should be emitted for account with non-discovered app_id; got {ghost_contains}"
    )


# ===========================================================================
# §5.4: resource whose app_id is absent or not in discovered_apps ->
#        saas_resource CI emitted, NO CONTAINS saas_app->saas_resource edge
# ===========================================================================


def test_edge_case_5_4_resource_unresolved_app_id():
    """§5.4: resource with non-discovered app_id -> CI emitted, no CONTAINS app->resource edge."""

    class OrphanResourceClient:
        def list_apps(self):
            return [{"id": APP1_ID, "name": "CRM"}]

        def list_accounts(self): return []

        def list_resources(self):
            return [
                # Valid app_id -> CONTAINS emitted
                {"id": RES1_ID, "name": "Deals", "app_id": APP1_ID},
                # Non-discovered app_id -> no CONTAINS
                {"id": "r-orphan", "name": "Orphan", "app_id": "app-missing"},
            ]

        def list_access_grants(self): return []

    conn = SaasDiscoveryConnector(OrphanResourceClient(), account_id=ACCOUNT_ID)
    events = list(conn.discover())
    cis_out = [e for e in events if isinstance(e, DiscoveredCI)]
    edges_out = [e for e in events if isinstance(e, DiscoveredEdge)]

    res_cis = [c for c in cis_out if c.type == CIType.saas_resource]
    assert len(res_cis) == 2, f"Both resource CIs should be emitted; got {len(res_cis)}"

    orphan_ext_id = f"{ACCOUNT_ID}/app-missing/r-orphan"
    contains_to_orphan = [
        e for e in edges_out
        if e.type == EdgeType.CONTAINS and e.to_ref.external_id == orphan_ext_id
    ]
    assert not contains_to_orphan, "CONTAINS must not be emitted for resource with non-discovered app_id"


# ===========================================================================
# §5.5: grant whose account_id is not in discovered_accounts -> NO HAS_ACCESS_TO
# ===========================================================================


def test_edge_case_5_5_grant_unresolved_account(edges):
    """§5.5: grant with non-discovered account_id -> no HAS_ACCESS_TO edge."""
    # The fixture has grant-bad-acct with account_id="u-does-not-exist"
    bad_acct_edges = [
        e for e in edges
        if e.type == EdgeType.HAS_ACCESS_TO
        and e.from_ref.external_id == f"{ACCOUNT_ID}/u-does-not-exist"
    ]
    assert not bad_acct_edges, (
        f"HAS_ACCESS_TO must not be emitted for non-discovered account; got {bad_acct_edges}"
    )


# ===========================================================================
# §5.6: grant whose resource_id is not in discovered_resources -> NO HAS_ACCESS_TO
# ===========================================================================


def test_edge_case_5_6_grant_unresolved_resource(edges):
    """§5.6: grant with non-discovered resource_id -> no HAS_ACCESS_TO edge."""
    # The fixture has grant-bad-res with resource_id="r-does-not-exist"
    # No HAS_ACCESS_TO edge should point to any undiscovered resource
    unknown_res_edges = [
        e for e in edges
        if e.type == EdgeType.HAS_ACCESS_TO
        and "r-does-not-exist" in e.to_ref.external_id
    ]
    assert not unknown_res_edges, (
        f"HAS_ACCESS_TO must not be emitted for non-discovered resource; got {unknown_res_edges}"
    )


# ===========================================================================
# §5.7: grant with absent/falsy id AND scope -> edge_key == ""; evidence contains "<unnamed>"
# ===========================================================================


def test_edge_case_5_7_unnamed_grant():
    """§5.7: grant with no id and no scope -> edge_key == '', evidence contains '<unnamed>'."""

    class UnnamedGrantClient:
        def list_apps(self):
            return [{"id": APP1_ID, "name": "CRM"}]

        def list_accounts(self):
            return [{"id": ACC1_ID, "name": "Alice", "app_id": APP1_ID}]

        def list_resources(self):
            return [{"id": RES1_ID, "name": "Deals", "app_id": APP1_ID}]

        def list_access_grants(self):
            return [
                # No id, no scope -> grant_key="<unnamed>", edge_key=""
                {"account_id": ACC1_ID, "resource_id": RES1_ID},
            ]

    conn = SaasDiscoveryConnector(UnnamedGrantClient(), account_id=ACCOUNT_ID)
    events = list(conn.discover())
    access_edges = [e for e in events if isinstance(e, DiscoveredEdge) and e.type == EdgeType.HAS_ACCESS_TO]
    assert len(access_edges) == 1, f"Expected 1 HAS_ACCESS_TO for unnamed grant, got {len(access_edges)}"
    edge = access_edges[0]
    assert edge.edge_key == "", f"Unnamed grant edge_key must be ''; got {edge.edge_key!r}"
    assert "<unnamed>" in edge.evidence[0].detail, (
        f"Evidence detail must contain '<unnamed>'; got {edge.evidence[0].detail!r}"
    )


# ===========================================================================
# §5.8: two distinct grants between same (account, resource) pair ->
#        two HAS_ACCESS_TO edges with distinct edge_key and distinct evidence detail
# ===========================================================================


def test_edge_case_5_8_two_parallel_grants_two_edges(edges):
    """§5.8: two grants from alice -> r-deals produce 2 HAS_ACCESS_TO edges with distinct edge_key."""
    alice_deals = [
        e for e in edges
        if e.type == EdgeType.HAS_ACCESS_TO
        and e.from_ref.external_id == ACC1_EXT_ID
        and e.to_ref.external_id == RES1_EXT_ID
    ]
    assert len(alice_deals) == 2, (
        f"Two parallel grants should produce 2 HAS_ACCESS_TO edges, got {len(alice_deals)}"
    )
    keys = {e.edge_key for e in alice_deals}
    assert len(keys) == 2, f"Two grants must have two distinct edge_keys; got {keys}"
    details = {e.evidence[0].detail for e in alice_deals}
    assert len(details) == 2, f"Two grants must have two distinct evidence details; got {details}"


# ===========================================================================
# §5.9: resource with falsy/absent external_handle -> NO DEPENDS_ON edge
# ===========================================================================


def test_edge_case_5_9_no_external_handle_no_depends_on(edges):
    """§5.9: resource with no external_handle -> no DEPENDS_ON from that resource."""
    noop_dep = [
        e for e in edges
        if e.type == EdgeType.DEPENDS_ON
        and e.from_ref.external_id == RES5_EXT_ID
    ]
    assert not noop_dep, (
        f"DEPENDS_ON must not be emitted for resource with no external_handle; got {noop_dep}"
    )

    # r-contacts also has no external_handle
    contacts_dep = [
        e for e in edges
        if e.type == EdgeType.DEPENDS_ON
        and e.from_ref.external_id == RES2_EXT_ID
    ]
    assert not contacts_dep, (
        f"DEPENDS_ON must not be emitted for r-contacts (no external_handle); got {contacts_dep}"
    )


# ===========================================================================
# §5.10: resource external_handle -> discovered resource (intra-graph DEPENDS_ON)
# ===========================================================================


def test_edge_case_5_10_internal_depends_on(edges):
    """§5.10: r-deals.external_handle == r-contacts external_id -> DEPENDS_ON with both endpoints discovered."""
    dep = [
        e for e in edges
        if e.type == EdgeType.DEPENDS_ON
        and e.from_ref.external_id == RES1_EXT_ID
        and e.to_ref.external_id == RES2_EXT_ID
    ]
    assert dep, (
        f"DEPENDS_ON r-deals->r-contacts missing; from={RES1_EXT_ID!r} to={RES2_EXT_ID!r}"
    )


# ===========================================================================
# §5.11: resource external_handle -> undiscovered endpoint -> DEPENDS_ON still emitted
# ===========================================================================


def test_edge_case_5_11_undiscovered_handle_depends_on_emitted(edges):
    """§5.11: r-external-dep has external_handle pointing at an undiscovered handle -> DEPENDS_ON still emitted."""
    dep = [
        e for e in edges
        if e.type == EdgeType.DEPENDS_ON
        and e.from_ref.external_id == RES6_EXT_ID
    ]
    assert dep, "DEPENDS_ON must be emitted even when to-endpoint is undiscovered"
    assert dep[0].to_ref.external_id == RES6_HANDLE


# ===========================================================================
# §5.12: two resources in different apps with same resource_id -> distinct external_ids
# ===========================================================================


def test_edge_case_5_12_same_resource_id_different_apps(cis):
    """§5.12: resources with same id in different apps -> distinct external_ids, distinct CIs."""
    same_name_res = [
        c for c in cis
        if c.type == CIType.saas_resource and c.attributes.get("resource_id") == RES1_ID
    ]
    assert len(same_name_res) == 2, (
        f"Expected 2 saas_resource CIs with resource_id={RES1_ID!r}, got {len(same_name_res)}"
    )
    ids = {c.external_id for c in same_name_res}
    assert len(ids) == 2, f"Same resource_id in different apps must have distinct external_ids; got {ids}"
    assert RES1_EXT_ID in ids
    assert RES4_EXT_ID in ids


# ===========================================================================
# §5.13: optional attribute keys absent -> no raise; attributes hold None for missing
# ===========================================================================


def test_edge_case_5_13_missing_optional_keys_no_raise():
    """§5.13: optional keys absent -> no raise; attribute dict holds None for missing values."""

    class MinimalClient:
        def list_apps(self):
            # No vendor, no category
            return [{"id": APP1_ID}]

        def list_accounts(self):
            # No email, no kind
            return [{"id": ACC1_ID, "app_id": APP1_ID}]

        def list_resources(self):
            # No kind, no external_handle
            return [{"id": RES1_ID, "app_id": APP1_ID}]

        def list_access_grants(self):
            return []

    conn = SaasDiscoveryConnector(MinimalClient(), account_id=ACCOUNT_ID)
    events = list(conn.discover())  # must not raise
    cis_out = [e for e in events if isinstance(e, DiscoveredCI)]

    app_ci = next(c for c in cis_out if c.type == CIType.saas_app)
    assert app_ci.attributes.get("vendor") is None
    assert app_ci.attributes.get("category") is None

    acc_ci = next(c for c in cis_out if c.type == CIType.saas_account)
    assert acc_ci.attributes.get("email") is None
    assert acc_ci.attributes.get("kind") is None

    res_ci = next(c for c in cis_out if c.type == CIType.saas_resource)
    assert res_ci.attributes.get("kind") is None
    assert res_ci.attributes.get("external_handle") is None


# ===========================================================================
# §5.14: discover() called twice yields identical event stream
# ===========================================================================


def test_edge_case_5_14_discover_twice_identical_stream(connector):
    """§5.14: calling discover() twice on the same connector yields the same event stream."""
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
                and e1.edge_key == e2.edge_key
            ), f"Edge event {i} changed: {e1} vs {e2}"


# ===========================================================================
# §5.15: connector never mutates client; each list method called exactly once;
#         fake exposes no write methods
# ===========================================================================


def test_edge_case_5_15_client_called_exactly_once():
    """§5.15: each list method is called exactly once per discover() call."""

    class TrackingClient:
        def __init__(self):
            self._apps_calls = 0
            self._accounts_calls = 0
            self._resources_calls = 0
            self._grants_calls = 0

        def list_apps(self) -> list[dict]:
            self._apps_calls += 1
            return []

        def list_accounts(self) -> list[dict]:
            self._accounts_calls += 1
            return []

        def list_resources(self) -> list[dict]:
            self._resources_calls += 1
            return []

        def list_access_grants(self) -> list[dict]:
            self._grants_calls += 1
            return []

    client = TrackingClient()
    conn = SaasDiscoveryConnector(client, account_id=ACCOUNT_ID)
    list(conn.discover())

    assert client._apps_calls == 1, "list_apps should be called exactly once"
    assert client._accounts_calls == 1, "list_accounts should be called exactly once"
    assert client._resources_calls == 1, "list_resources should be called exactly once"
    assert client._grants_calls == 1, "list_access_grants should be called exactly once"


def test_edge_case_5_15_connector_does_not_mutate_client(fake_client):
    """§5.15: discover() must not invoke any write-named method on the client."""
    write_methods = ["create", "update", "delete", "put", "patch", "post", "insert"]
    for method_name in dir(fake_client):
        if any(wm in method_name.lower() for wm in write_methods):
            assert False, f"Fake client has unexpected write method: {method_name}"


# ===========================================================================
# AC 18 / §5.16: no duplicate (type, external_id) CIs
# ===========================================================================


def test_no_duplicate_ci_external_ids(cis):
    """AC 18 / §5.16: each (type, external_id) pair appears exactly once."""
    seen: dict = {}
    for ci in cis:
        key = (ci.type, ci.external_id)
        assert key not in seen, f"Duplicate CI emitted: {key}"
        seen[key] = True


# ===========================================================================
# §5.17: connector.py imports no forbidden SDKs (covered by AC 8 test)
# (re-confirmed here for explicitness as separate test)
# ===========================================================================


def test_edge_case_5_17_no_forbidden_sdk_imports():
    """§5.17: saas connector.py does not import any forbidden SDK at module level."""
    spec = importlib.util.find_spec("infra_twin.collectors.saas.connector")
    assert spec is not None
    source = open(spec.origin).read()
    for forbidden in ("boto3", "psycopg", "import kubernetes", "google.cloud",
                      "google.oauth2", "azure.identity", "azure.mgmt"):
        assert forbidden not in source, (
            f"connector.py must not contain forbidden import: {forbidden!r}"
        )


# ===========================================================================
# §5.19: cross-tenant isolation check (basic — full E2E in later section)
# ===========================================================================

# Full cross-tenant isolation is tested in the E2E section below.

# ===========================================================================
# §5.20: external_id has no surrounding whitespace; account_id used verbatim
# ===========================================================================


def test_edge_case_5_20_external_id_no_whitespace():
    """§5.20: external_id has no surrounding whitespace; account_id used verbatim as prefix."""

    class SimpleClient:
        def list_apps(self):
            return [{"id": APP1_ID, "name": "CRM"}]

        def list_accounts(self): return []
        def list_resources(self): return []
        def list_access_grants(self): return []

    conn = SaasDiscoveryConnector(SimpleClient(), account_id=ACCOUNT_ID)
    events = list(conn.discover())
    app_ci = next(c for c in events if isinstance(c, DiscoveredCI) and c.type == CIType.saas_app)
    assert app_ci.external_id == app_ci.external_id.strip(), "external_id must not have whitespace"
    assert app_ci.external_id.startswith(ACCOUNT_ID), (
        f"external_id must start with account_id {ACCOUNT_ID!r}; got {app_ci.external_id!r}"
    )


# ===========================================================================
# AC 19: migration 0020 content
# ===========================================================================


def test_migration_0020_saas_vertex_labels_exists():
    """AC 19: migration 0020 exists, calls create_vlabel for saas_app/saas_account/saas_resource,
    includes both GRANT statements, no create_elabel, no CREATE TABLE."""
    migration_path = os.path.normpath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "migrations",
            "0020_saas_vertex_labels.sql",
        )
    )
    assert os.path.isfile(migration_path), f"Migration 0020 not found: {migration_path}"

    content = open(migration_path).read()

    assert "ag_catalog" in content, "Migration must set ag_catalog in search_path"
    assert "create_elabel" not in content, "Migration must NOT call create_elabel"
    assert "CREATE TABLE" not in content, "Migration must NOT contain CREATE TABLE"

    for label in ("saas_app", "saas_account", "saas_resource"):
        assert label in content, f"Migration must create vertex label '{label}'"

    assert "create_vlabel" in content, "Migration must call create_vlabel"
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES" in content, (
        "Migration must re-apply table GRANT"
    )
    assert "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES" in content, (
        "Migration must re-apply sequence GRANT"
    )


# ===========================================================================
# AC 20: migration ordering — 0001..0020 exist; 0020 is highest; none > 0020
# ===========================================================================


def test_migrations_0001_to_0020_exist_and_0020_is_highest():
    """AC 20 (updated): files 0001 through 0024 all exist; 0024 is the highest-numbered migration;
    no file numbered > 0024 may exist."""
    migrations_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "migrations")
    )
    for n in range(1, 25):
        pattern = f"{n:04d}_"
        matches = [f for f in os.listdir(migrations_dir) if f.startswith(pattern)]
        assert matches, f"Migration {pattern}* not found in {migrations_dir}"

    # 0020 must exist
    all_files = os.listdir(migrations_dir)
    assert any(f.startswith("0020") for f in all_files), (
        "Migration 0020_* must exist (saas_vertex_labels)"
    )

    # 0021 must exist
    assert any(f.startswith("0021") for f in all_files), (
        "Migration 0021_* must exist (entity_alias_keys)"
    )

    # 0022 must exist
    assert any(f.startswith("0022") for f in all_files), (
        "Migration 0022_* must exist (ci_unmerges)"
    )

    # 0023 must exist
    assert any(f.startswith("0023") for f in all_files), (
        "Migration 0023_* must exist (ci_merge_candidates)"
    )

    # 0024 must exist
    assert any(f.startswith("0024") for f in all_files), (
        "Migration 0024_* must exist (freshness_slo)"
    )

    # 0025 must exist (history_retention)
    assert any(f.startswith("0025") for f in all_files), (
        "Migration 0025_* must exist (history_retention)"
    )

    # No file numbered > 0025
    higher = [
        f for f in all_files
        if len(f) >= 4 and f[:4].isdigit() and int(f[:4]) > 25
    ]
    assert not higher, f"Unexpected migration(s) higher than 0025 found: {higher}"


# ===========================================================================
# AC 21: CLI discover-saas subcommand wiring
# ===========================================================================


def test_cli_discover_saas_subparser_registered():
    """AC 21: 'discover-saas' subcommand registered; handler receives correct parsed values."""
    captured = {}

    def fake_handler(args):
        captured["args"] = args
        return 0

    from infra_twin.cli.main import main as cli_main

    with patch("infra_twin.cli.main._discover_saas", fake_handler):
        rc = cli_main([
            "discover-saas",
            "--tenant", "00000000-0000-0000-0000-000000000001",
            "--account-id", "my-saas-acct",
        ])

    assert rc == 0
    args = captured["args"]
    assert args.tenant == "00000000-0000-0000-0000-000000000001"
    assert args.account_id == "my-saas-acct"
    assert args.account_name is None  # optional, defaults to None


def test_cli_discover_saas_account_name_arg():
    """AC 21: --account-name is optional; when supplied it reaches the handler."""
    captured = {}

    def fake_handler(args):
        captured["args"] = args
        return 0

    from infra_twin.cli.main import main as cli_main

    with patch("infra_twin.cli.main._discover_saas", fake_handler):
        cli_main([
            "discover-saas",
            "--tenant", "00000000-0000-0000-0000-000000000001",
            "--account-id", "my-saas-acct",
            "--account-name", "My SaaS Account",
        ])

    assert captured["args"].account_name == "My SaaS Account"


# ===========================================================================
# E2E + ADVERSARIAL ISOLATION TESTS (use pool + make_tenant from conftest.py)
# These tests require the local Postgres+AGE stack with migration 0020 applied.
# ===========================================================================


class _E2eFakeSaasClient:
    """E2E SaaS client with TWO parallel grants from alice to r-deals (§5.8 / AC §5.8).

    The edge-key discriminator (migration 0019) allows two HAS_ACCESS_TO edges between
    the same ordered (from_id, to_id) pair when their edge_key values differ (grant id).
    Both grant-1 and grant-2 are included so the E2E reconcile produces two distinct edges.
    """

    def list_apps(self) -> list[dict]:
        return [
            {"id": APP1_ID, "name": APP1_NAME, "vendor": APP1_VENDOR, "category": APP1_CATEGORY},
            {"id": APP2_ID, "name": APP2_NAME, "vendor": APP2_VENDOR, "category": APP2_CATEGORY},
        ]

    def list_accounts(self) -> list[dict]:
        return [
            {"id": ACC1_ID, "name": "Alice", "email": ACC1_EMAIL, "kind": "user", "app_id": APP1_ID},
            {"id": ACC2_ID, "name": "Bob", "email": ACC2_EMAIL, "kind": "user", "app_id": APP1_ID},
        ]

    def list_resources(self) -> list[dict]:
        return [
            {"id": RES1_ID, "name": "Deals", "app_id": APP1_ID, "kind": "dataset", "external_handle": RES2_EXT_ID},
            {"id": RES2_ID, "name": "Contacts", "app_id": APP1_ID, "kind": "dataset"},
            {"id": RES3_ID, "name": "Ledger", "app_id": APP2_ID, "kind": "report"},
        ]

    def list_access_grants(self) -> list[dict]:
        # Two parallel grants from alice -> r-deals; distinct edge_keys (grant-1, grant-2)
        return [
            {"id": GRANT1_ID, "account_id": ACC1_ID, "resource_id": RES1_ID, "scope": GRANT1_SCOPE},
            {"id": GRANT2_ID, "account_id": ACC1_ID, "resource_id": RES1_ID, "scope": GRANT2_SCOPE},
        ]


def _make_connector_for_e2e() -> SaasDiscoveryConnector:
    return SaasDiscoveryConnector(
        _E2eFakeSaasClient(), account_id=ACCOUNT_ID, account_name="E2E SaaS"
    )


# ---------------------------------------------------------------------------
# AC 22: discover_and_reconcile returns positive counts
# ---------------------------------------------------------------------------


def test_discover_and_reconcile_returns_positive_counts(pool, make_tenant):
    """AC 22: discover_and_reconcile creates CIs and writes edges for SaaS connector."""
    from infra_twin.reconciliation import discover_and_reconcile

    tenant = make_tenant("saas-a")
    result = discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    assert result.cis_created > 0, f"Expected cis_created > 0, got {result.cis_created}"
    assert result.edges_written > 0, f"Expected edges_written > 0, got {result.edges_written}"


# ---------------------------------------------------------------------------
# AC 23: connector registry + runs + raw_facts
# ---------------------------------------------------------------------------


def test_connector_registry_has_saas_type(pool, make_tenant):
    """AC 23: after reconcile, connectors row with type='saas' and display_name='saas' exists."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connectors import ConnectorRegistry
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("saas-registry")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        registry = ConnectorRegistry(conn, tenant)
        connectors_list = registry.list()

    saas_connectors = [c for c in connectors_list if c.type == "saas"]
    assert saas_connectors, (
        f"No connector with type='saas' found; got: {[c.type for c in connectors_list]}"
    )
    assert saas_connectors[0].display_name == "saas"


def test_connector_run_ok_and_raw_facts(pool, make_tenant):
    """AC 23: connector_runs row with source='saas' and status='ok'; >= 1 raw_facts row."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connector_health import ConnectorRunRepository
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("saas-run")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        run_repo = ConnectorRunRepository(conn, tenant)
        summaries = run_repo.latest_per_source()

    saas_runs = [s for s in summaries if s.source == "saas"]
    assert saas_runs, "No connector_run with source='saas' found"
    assert saas_runs[0].status == "ok", (
        f"connector_run status expected 'ok', got {saas_runs[0].status!r}"
    )

    with tenant_session(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = %s", ("saas",)
        ).fetchone()[0]
    assert count >= 1, f"Expected at least 1 raw_facts row for source='saas', got {count}"


# ---------------------------------------------------------------------------
# AC 24: all three saas_* CI types persisted current with correct tenant_id
# ---------------------------------------------------------------------------


def test_saas_cis_persisted_current_with_correct_tenant(pool, make_tenant):
    """AC 24: all three saas_* CI types are persisted current (valid_to IS NULL) with tenant_id == tenant."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.repositories import CIRepository
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("saas-cis")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        for ci_type in (CIType.saas_app, CIType.saas_account, CIType.saas_resource):
            cis = repo.get_current(type=ci_type)
            assert cis, f"No current {ci_type.value} CIs found after saas reconcile"
            for ci in cis:
                assert ci.valid_to is None, (
                    f"{ci_type.value} CI {ci.external_id} has valid_to={ci.valid_to}, expected NULL"
                )
                assert ci.tenant_id == tenant, (
                    f"{ci_type.value} CI tenant_id {ci.tenant_id} != expected {tenant}"
                )


def test_saas_edges_persisted_with_provenance(pool, make_tenant):
    """AC 24: persisted saas edges have source, non-null confidence, and non-empty evidence."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("saas-edges")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT source, confidence, evidence FROM edges WHERE valid_to IS NULL",
        ).fetchall()

    assert rows, "No current edges found after saas reconcile"
    for source, confidence, evidence in rows:
        assert source in ("declared", "inferred"), (
            f"Edge source must be 'declared' or 'inferred'; got {source!r}"
        )
        assert confidence is not None, "Edge confidence must be set"
        assert evidence, "Edge evidence must be non-empty"
        for ev in evidence:
            assert "source" in ev, f"Evidence entry missing 'source' key: {ev!r}"


# ---------------------------------------------------------------------------
# AC 25: AGE projection for saas_* nodes and edges
# ---------------------------------------------------------------------------


def test_age_projection_saas_resource(pool, make_tenant):
    """AC 25: MATCH (n:saas_resource) WHERE n.tenant_id='<A>' RETURN n returns >= 1."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("saas-age-resource")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(conn, f"MATCH (n:saas_resource) WHERE n.tenant_id = '{tenant}' RETURN n")

    assert len(rows) >= 1, (
        f"Expected >= 1 saas_resource node in AGE for tenant {tenant}, got {len(rows)}"
    )


def test_age_projection_saas_app_contains_saas_account(pool, make_tenant):
    """AC 25: MATCH (:saas_app)-[r:CONTAINS]->(:saas_account) WHERE r.tenant_id=... >= 1."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("saas-age-contains-acct")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:saas_app)-[r:CONTAINS]->(:saas_account) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )

    assert len(rows) >= 1, (
        f"Expected >= 1 CONTAINS saas_app->saas_account in AGE, got {len(rows)}"
    )


def test_age_projection_saas_app_contains_saas_resource(pool, make_tenant):
    """AC 25: MATCH (:saas_app)-[r:CONTAINS]->(:saas_resource) WHERE r.tenant_id=... >= 1."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("saas-age-contains-res")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:saas_app)-[r:CONTAINS]->(:saas_resource) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )

    assert len(rows) >= 1, (
        f"Expected >= 1 CONTAINS saas_app->saas_resource in AGE, got {len(rows)}"
    )


def test_age_projection_saas_has_access_to_two_edges(pool, make_tenant):
    """AC 25 / §5.8: MATCH (:saas_account)-[r:HAS_ACCESS_TO]->(:saas_resource) WHERE r.tenant_id=...
    returns >= 2 (two distinct relationships from the two parallel grants)."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("saas-age-access")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:saas_account)-[r:HAS_ACCESS_TO]->(:saas_resource) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )

    assert len(rows) >= 2, (
        f"Expected >= 2 HAS_ACCESS_TO saas_account->saas_resource in AGE "
        f"(two parallel grants), got {len(rows)}"
    )


# ---------------------------------------------------------------------------
# AC 26: second identical reconcile is a no-op (§5.18)
# ---------------------------------------------------------------------------


def test_second_reconcile_is_noop(pool, make_tenant):
    """AC 26 / §5.18: cis_created==0, cis_closed==0, edges_closed==0 on second identical run."""
    from infra_twin.reconciliation import discover_and_reconcile

    tenant = make_tenant("saas-idempotent")

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
# AC 27: adversarial cross-tenant isolation (§5.19)
# ---------------------------------------------------------------------------


def test_cross_tenant_isolation_saas_cis(pool, make_tenant):
    """AC 27a / §5.19: tenant B sees zero saas_* CIs belonging to tenant A."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.repositories import CIRepository
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("saas-iso-a")
    tenant_b = make_tenant("saas-iso-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        repo = CIRepository(conn, tenant_b)
        b_cis = repo.get_current()

    saas_types = {CIType.saas_app, CIType.saas_account, CIType.saas_resource}
    b_saas = [c for c in b_cis if c.type in saas_types]
    assert not b_saas, (
        f"Tenant B should see 0 saas_* CIs belonging to A; got {len(b_saas)}: {b_saas[:3]}"
    )


def test_cross_tenant_isolation_saas_edges(pool, make_tenant):
    """AC 27b: tenant B sees zero edges written for tenant A."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("saas-iso-edge-a")
    tenant_b = make_tenant("saas-iso-edge-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM edges WHERE valid_to IS NULL"
        ).fetchone()[0]
    assert count == 0, f"Tenant B should see 0 edges; got {count}"


def test_cross_tenant_isolation_saas_connector_runs(pool, make_tenant):
    """AC 27c: tenant B sees no connector_runs with source='saas'."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connector_health import ConnectorRunRepository
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("saas-iso-run-a")
    tenant_b = make_tenant("saas-iso-run-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        run_repo = ConnectorRunRepository(conn, tenant_b)
        summaries = run_repo.latest_per_source()

    saas_runs = [s for s in summaries if s.source == "saas"]
    assert not saas_runs, f"Tenant B should see no saas connector_runs; got {saas_runs}"


def test_cross_tenant_isolation_connector_registry(pool, make_tenant):
    """AC 27d: ConnectorRegistry for tenant B shows no 'saas' connector."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connectors import ConnectorRegistry
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("saas-iso-reg-a")
    tenant_b = make_tenant("saas-iso-reg-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        registry = ConnectorRegistry(conn, tenant_b)
        b_connectors = registry.list()

    saas_reg = [c for c in b_connectors if c.type == "saas"]
    assert not saas_reg, (
        f"Tenant B should have no saas connector in registry; got {saas_reg}"
    )


def test_cross_tenant_isolation_raw_facts(pool, make_tenant):
    """AC 27e: tenant B sees zero raw_facts rows written for tenant A's saas run."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("saas-iso-rf-a")
    tenant_b = make_tenant("saas-iso-rf-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = %s", ("saas",)
        ).fetchone()[0]
    assert count == 0, f"Tenant B should see 0 saas raw_facts; got {count}"
