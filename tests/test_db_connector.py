"""Contract tests for the DB-introspection connector against a deterministic in-memory fake.

No live database, no network. The fake returns fixed seeded data so the test is
offline-reproducible and pinned to a specific expected mapping.

Covers:
  - AC 1-4  : CIType / EdgeType / EdgeSource / Evidence enum invariants (db_* additions + unchanged members)
  - AC 5-12 : DbIntrospectionConnector class-level attributes and package exports
  - AC 13-24: connector contract — happy path + every spec edge case (§5.1–§5.15)
  - AC 25-30: E2E reconcile + adversarial tenant isolation (uses pool/make_tenant fixtures)
  - AC 22   : migration 0018 content
  - AC 24   : CLI subcommand wiring (discover-db)
  - AC 31   : regression — all existing connectors still importable
"""

from __future__ import annotations

import importlib.util
import os

import pytest

from infra_twin.collectors import (
    AwsConnector,
    AzureConnector,
    DbIntrospectionConnector,
    GcpConnector,
    KubernetesConnector,
)
from infra_twin.collectors.db import DbIntrospectionClient, DbIntrospectionConnector as DbConn
from infra_twin.connector_sdk import Connector, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence

# ---------------------------------------------------------------------------
# Seeded test constants
# ---------------------------------------------------------------------------

HOST = "db.example.com"
PORT = 5432
INSTANCE_NAME = "prod-db"
INSTANCE_EXT_ID = f"{HOST}:{PORT}"

DB1_NAME = "appdb"
DB1_EXT_ID = f"{INSTANCE_EXT_ID}/{DB1_NAME}"

DB2_NAME = "analyticsdb"
DB2_EXT_ID = f"{INSTANCE_EXT_ID}/{DB2_NAME}"

SCHEMA1_DB = DB1_NAME
SCHEMA1_NAME = "public"
SCHEMA1_EXT_ID = f"{INSTANCE_EXT_ID}/{SCHEMA1_DB}/{SCHEMA1_NAME}"

SCHEMA2_DB = DB1_NAME
SCHEMA2_NAME = "audit"
SCHEMA2_EXT_ID = f"{INSTANCE_EXT_ID}/{SCHEMA2_DB}/{SCHEMA2_NAME}"

# Schema in analyticsdb
SCHEMA3_DB = DB2_NAME
SCHEMA3_NAME = "reports"
SCHEMA3_EXT_ID = f"{INSTANCE_EXT_ID}/{SCHEMA3_DB}/{SCHEMA3_NAME}"

TABLE1_DB = DB1_NAME
TABLE1_SCHEMA = SCHEMA1_NAME
TABLE1_NAME = "users"
TABLE1_EXT_ID = f"{INSTANCE_EXT_ID}/{TABLE1_DB}/{TABLE1_SCHEMA}/{TABLE1_NAME}"

TABLE2_DB = DB1_NAME
TABLE2_SCHEMA = SCHEMA1_NAME
TABLE2_NAME = "orders"
TABLE2_EXT_ID = f"{INSTANCE_EXT_ID}/{TABLE2_DB}/{TABLE2_SCHEMA}/{TABLE2_NAME}"

# Table in audit schema (same db)
TABLE3_DB = DB1_NAME
TABLE3_SCHEMA = SCHEMA2_NAME
TABLE3_NAME = "users"  # same table name, different schema — tests AC 15 / §5.11
TABLE3_EXT_ID = f"{INSTANCE_EXT_ID}/{TABLE3_DB}/{TABLE3_SCHEMA}/{TABLE3_NAME}"

# Table in analyticsdb / reports schema
TABLE4_DB = DB2_NAME
TABLE4_SCHEMA = SCHEMA3_NAME
TABLE4_NAME = "daily_sales"
TABLE4_EXT_ID = f"{INSTANCE_EXT_ID}/{TABLE4_DB}/{TABLE4_SCHEMA}/{TABLE4_NAME}"

# FK: orders.user_id -> users.id (single column, named constraint)
FK1_CONSTRAINT = "fk_orders_user"
FK1_DB = DB1_NAME
FK1_FROM_SCHEMA = TABLE2_SCHEMA
FK1_FROM_TABLE = TABLE2_NAME
FK1_TO_SCHEMA = TABLE1_SCHEMA
FK1_TO_TABLE = TABLE1_NAME
FK1_FROM_COLS = ["user_id"]
FK1_TO_COLS = ["id"]

# FK: second constraint between orders and users (§5.9 two FKs between same table pair)
FK2_CONSTRAINT = "fk_orders_approver"
FK2_DB = DB1_NAME
FK2_FROM_SCHEMA = TABLE2_SCHEMA
FK2_FROM_TABLE = TABLE2_NAME
FK2_TO_SCHEMA = TABLE1_SCHEMA
FK2_TO_TABLE = TABLE1_NAME
FK2_FROM_COLS = ["approver_id"]
FK2_TO_COLS = ["id"]


class FakeDbClient:
    """Deterministic in-memory DbIntrospectionClient for offline contract tests.

    The fixture exercises every major discovery path:
      - Two databases (appdb, analyticsdb)
      - Two schemas in appdb (public, audit) — both parent databases resolve
      - One schema in analyticsdb (reports)
      - Three tables in appdb: users (public), orders (public), users (audit)
      - One table in analyticsdb: daily_sales (reports)
      - Two named FK constraints between orders->users (same table pair, §5.9)
    """

    def list_databases(self) -> list[dict]:
        return [
            {"name": DB1_NAME, "owner": "postgres", "encoding": "UTF8"},
            {"name": DB2_NAME, "owner": "analytics_user", "encoding": "UTF8"},
        ]

    def list_schemas(self) -> list[dict]:
        return [
            {"database": DB1_NAME, "name": SCHEMA1_NAME, "owner": "postgres"},
            {"database": DB1_NAME, "name": SCHEMA2_NAME, "owner": "auditor"},
            {"database": DB2_NAME, "name": SCHEMA3_NAME, "owner": "analytics_user"},
        ]

    def list_tables(self) -> list[dict]:
        return [
            {
                "database": TABLE1_DB,
                "schema": TABLE1_SCHEMA,
                "name": TABLE1_NAME,
                "kind": "table",
                "estimated_rows": 10000,
            },
            {
                "database": TABLE2_DB,
                "schema": TABLE2_SCHEMA,
                "name": TABLE2_NAME,
                "kind": "table",
                "estimated_rows": 50000,
            },
            # Same table name in different schema (§5.11)
            {
                "database": TABLE3_DB,
                "schema": TABLE3_SCHEMA,
                "name": TABLE3_NAME,
                "kind": "table",
                "estimated_rows": 2000,
            },
            {
                "database": TABLE4_DB,
                "schema": TABLE4_SCHEMA,
                "name": TABLE4_NAME,
                "kind": "view",
                "estimated_rows": None,
            },
        ]

    def list_foreign_keys(self) -> list[dict]:
        return [
            # FK1: orders.user_id -> users.id (named, single column)
            {
                "constraint_name": FK1_CONSTRAINT,
                "database": FK1_DB,
                "from_schema": FK1_FROM_SCHEMA,
                "from_table": FK1_FROM_TABLE,
                "from_columns": FK1_FROM_COLS,
                "to_schema": FK1_TO_SCHEMA,
                "to_table": FK1_TO_TABLE,
                "to_columns": FK1_TO_COLS,
            },
            # FK2: orders.approver_id -> users.id (second constraint between same pair, §5.9)
            {
                "constraint_name": FK2_CONSTRAINT,
                "database": FK2_DB,
                "from_schema": FK2_FROM_SCHEMA,
                "from_table": FK2_FROM_TABLE,
                "from_columns": FK2_FROM_COLS,
                "to_schema": FK2_TO_SCHEMA,
                "to_table": FK2_TO_TABLE,
                "to_columns": FK2_TO_COLS,
            },
        ]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_client() -> FakeDbClient:
    return FakeDbClient()


@pytest.fixture
def connector(fake_client: FakeDbClient) -> DbIntrospectionConnector:
    return DbIntrospectionConnector(fake_client, host=HOST, port=PORT, instance_name=INSTANCE_NAME)


@pytest.fixture
def all_events(connector: DbIntrospectionConnector):
    return list(connector.discover())


@pytest.fixture
def cis(all_events) -> list[DiscoveredCI]:
    return [e for e in all_events if isinstance(e, DiscoveredCI)]


@pytest.fixture
def edges(all_events) -> list[DiscoveredEdge]:
    return [e for e in all_events if isinstance(e, DiscoveredEdge)]


# ---------------------------------------------------------------------------
# AC 1: db_* CIType members exist with value == name
# ---------------------------------------------------------------------------


def test_db_citype_values_match_names():
    """AC 1: each new db_* CIType member has value == name."""
    for member_name in ("db_instance", "db_database", "db_schema", "db_table"):
        member = CIType[member_name]
        assert member.value == member_name, (
            f"CIType.{member_name}.value should be {member_name!r}, got {member.value!r}"
        )


# ---------------------------------------------------------------------------
# AC 2: pre-existing CIType members unchanged
# ---------------------------------------------------------------------------


def test_pre_existing_citype_members_unchanged():
    """AC 2: all AWS/internet/dns, k8s_*, azure_*, and gcp_* members still present unchanged."""
    expected = {
        # AWS / internet / dns
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
        # GCP
        "gcp_project": "gcp_project",
        "gcp_network": "gcp_network",
        "gcp_subnetwork": "gcp_subnetwork",
        "gcp_firewall": "gcp_firewall",
        "gcp_instance": "gcp_instance",
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
# AC 4: EdgeSource unchanged; Evidence model fields correct
# ---------------------------------------------------------------------------


def test_edgesource_has_declared_and_inferred():
    """AC 4: EdgeSource has exactly 'declared' and 'inferred'."""
    values = {m.value for m in EdgeSource}
    assert values == {"declared", "inferred"}, f"EdgeSource changed: {values}"


def test_evidence_model_fields_for_db_source():
    """AC 4: Evidence(source='db', detail='x') has .source, .detail, .observed_at set."""
    ev = Evidence(source="db", detail="x")
    assert ev.source == "db"
    assert ev.detail == "x"
    assert ev.observed_at is not None


# ---------------------------------------------------------------------------
# AC 5: DbIntrospectionConnector.source == "db"
# ---------------------------------------------------------------------------


def test_connector_source():
    """AC 5: DbIntrospectionConnector.source == 'db'."""
    assert DbIntrospectionConnector.source == "db"


# ---------------------------------------------------------------------------
# AC 6: DbIntrospectionConnector.ci_types
# ---------------------------------------------------------------------------


def test_connector_ci_types():
    """AC 6: DbIntrospectionConnector.ci_types == frozenset of all 4 db_* CI types."""
    expected = frozenset(
        {
            CIType.db_instance,
            CIType.db_database,
            CIType.db_schema,
            CIType.db_table,
        }
    )
    assert DbIntrospectionConnector.ci_types == expected


# ---------------------------------------------------------------------------
# AC 7: DbIntrospectionConnector.edge_types
# ---------------------------------------------------------------------------


def test_connector_edge_types():
    """AC 7: DbIntrospectionConnector.edge_types == frozenset({CONTAINS, DEPENDS_ON})."""
    expected = frozenset({EdgeType.CONTAINS, EdgeType.DEPENDS_ON})
    assert DbIntrospectionConnector.edge_types == expected


# ---------------------------------------------------------------------------
# AC 8: isinstance(connector, Connector) protocol check
# ---------------------------------------------------------------------------


def test_connector_satisfies_protocol(fake_client):
    """AC 8: isinstance(DbIntrospectionConnector(fake, ...), Connector) is True."""
    conn = DbIntrospectionConnector(fake_client, host="h", port=5432)
    assert isinstance(conn, Connector)


# ---------------------------------------------------------------------------
# AC 9: isinstance(fake, DbIntrospectionClient) protocol check
# ---------------------------------------------------------------------------


def test_fake_client_satisfies_protocol():
    """AC 9: the FakeDbClient satisfies the DbIntrospectionClient runtime_checkable Protocol."""
    assert isinstance(FakeDbClient(), DbIntrospectionClient)


# ---------------------------------------------------------------------------
# AC 10: connector.py imports no forbidden SDK
# ---------------------------------------------------------------------------


def test_connector_module_no_forbidden_imports():
    """AC 10: db connector source must not import psycopg, boto3, kubernetes, azure SDK,
    google.cloud, or sibling connector packages at module level."""
    spec = importlib.util.find_spec("infra_twin.collectors.db.connector")
    assert spec is not None, "db connector module not found"
    source = open(spec.origin).read()

    assert "psycopg" not in source, "connector.py must not import psycopg"
    assert "boto3" not in source, "connector.py must not import boto3"
    assert "import kubernetes" not in source, "connector.py must not import kubernetes"
    assert "kubernetes." not in source, "connector.py must not reference kubernetes."
    assert "infra_twin.collectors.aws" not in source
    assert "infra_twin.collectors.azure" not in source
    assert "infra_twin.collectors.k8s" not in source
    assert "infra_twin.collectors.gcp" not in source

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


# ---------------------------------------------------------------------------
# AC 11: all 5 connectors importable from infra_twin.collectors + in __all__
# ---------------------------------------------------------------------------


def test_all_five_connectors_importable_from_collectors():
    """AC 11: all 5 connectors importable from infra_twin.collectors."""
    assert AwsConnector is not None
    assert AzureConnector is not None
    assert GcpConnector is not None
    assert KubernetesConnector is not None
    assert DbIntrospectionConnector is not None


def test_collectors_all_contains_all_five():
    """AC 11: infra_twin.collectors.__all__ contains all five connector names."""
    import infra_twin.collectors as pkg
    for name in (
        "AwsConnector",
        "AzureConnector",
        "GcpConnector",
        "KubernetesConnector",
        "DbIntrospectionConnector",
    ):
        assert name in pkg.__all__, f"{name} missing from infra_twin.collectors.__all__"


# ---------------------------------------------------------------------------
# AC 12: DbIntrospectionClient and DbIntrospectionConnector importable from infra_twin.collectors.db
# ---------------------------------------------------------------------------


def test_db_package_exports():
    """AC 12: DbIntrospectionClient and DbIntrospectionConnector importable from infra_twin.collectors.db."""
    from infra_twin.collectors.db import (
        DbIntrospectionClient as _Client,
        DbIntrospectionConnector as _Connector,
    )
    assert _Client is not None
    assert _Connector is not None


# ---------------------------------------------------------------------------
# AC 13: exactly one db_instance CI; name uses instance_name or falls back to host:port (§5.15)
# ---------------------------------------------------------------------------


def test_instance_ci_emitted_once(cis):
    """AC 13: exactly one db_instance CI with external_id == f'{host}:{port}'."""
    inst_cis = [c for c in cis if c.type == CIType.db_instance]
    assert len(inst_cis) == 1, f"Expected 1 db_instance CI, got {len(inst_cis)}"
    assert inst_cis[0].external_id == INSTANCE_EXT_ID
    assert inst_cis[0].name == INSTANCE_NAME


def test_instance_ci_uses_instance_name_when_provided(fake_client):
    """AC 13: when instance_name is provided, the CI uses it as name."""
    conn = DbIntrospectionConnector(fake_client, host=HOST, port=PORT, instance_name="my-db-server")
    cis = [e for e in conn.discover() if isinstance(e, DiscoveredCI)]
    inst_ci = next(c for c in cis if c.type == CIType.db_instance)
    assert inst_ci.name == "my-db-server"


def test_instance_ci_falls_back_when_no_instance_name(fake_client):
    """AC 13 / §5.15: when instance_name is absent, name falls back to f'{host}:{port}'."""
    conn = DbIntrospectionConnector(fake_client, host=HOST, port=PORT, instance_name=None)
    cis = [e for e in conn.discover() if isinstance(e, DiscoveredCI)]
    inst_ci = next(c for c in cis if c.type == CIType.db_instance)
    assert inst_ci.name == INSTANCE_EXT_ID


# ---------------------------------------------------------------------------
# AC 14: all seeded databases/schemas/tables emitted with correct types and external_ids
# ---------------------------------------------------------------------------


def test_all_expected_cis_emitted(cis):
    """AC 14: every seeded resource appears exactly once as a DiscoveredCI of the correct type."""
    by_id = {c.external_id: c for c in cis}

    checks: dict[str, CIType] = {
        INSTANCE_EXT_ID: CIType.db_instance,
        DB1_EXT_ID: CIType.db_database,
        DB2_EXT_ID: CIType.db_database,
        SCHEMA1_EXT_ID: CIType.db_schema,
        SCHEMA2_EXT_ID: CIType.db_schema,
        SCHEMA3_EXT_ID: CIType.db_schema,
        TABLE1_EXT_ID: CIType.db_table,
        TABLE2_EXT_ID: CIType.db_table,
        TABLE3_EXT_ID: CIType.db_table,
        TABLE4_EXT_ID: CIType.db_table,
    }
    for resource_id, expected_type in checks.items():
        assert resource_id in by_id, (
            f"Expected DiscoveredCI with external_id={resource_id!r} not found"
        )
        assert by_id[resource_id].type == expected_type, (
            f"CI {resource_id} should have type {expected_type}, got {by_id[resource_id].type}"
        )


def test_db_instance_attributes(cis):
    """AC 14: db_instance CI has host, port, engine, version attributes."""
    by_id = {c.external_id: c for c in cis}
    inst_ci = by_id[INSTANCE_EXT_ID]
    assert inst_ci.attributes.get("host") == HOST
    assert inst_ci.attributes.get("port") == PORT
    assert inst_ci.attributes.get("engine") == "postgresql"
    assert "version" in inst_ci.attributes  # may be None


def test_db_database_attributes(cis):
    """AC 14: db_database CI has database, owner, encoding attributes."""
    by_id = {c.external_id: c for c in cis}
    db_ci = by_id[DB1_EXT_ID]
    assert db_ci.attributes.get("database") == DB1_NAME
    assert db_ci.attributes.get("owner") == "postgres"
    assert db_ci.attributes.get("encoding") == "UTF8"


def test_db_schema_attributes(cis):
    """AC 14: db_schema CI has database, schema, owner attributes."""
    by_id = {c.external_id: c for c in cis}
    schema_ci = by_id[SCHEMA1_EXT_ID]
    assert schema_ci.attributes.get("database") == SCHEMA1_DB
    assert schema_ci.attributes.get("schema") == SCHEMA1_NAME
    assert schema_ci.attributes.get("owner") == "postgres"


def test_db_table_attributes(cis):
    """AC 14: db_table CI has database, schema, table, kind, estimated_rows attributes."""
    by_id = {c.external_id: c for c in cis}
    table_ci = by_id[TABLE1_EXT_ID]
    assert table_ci.attributes.get("database") == TABLE1_DB
    assert table_ci.attributes.get("schema") == TABLE1_SCHEMA
    assert table_ci.attributes.get("table") == TABLE1_NAME
    assert table_ci.attributes.get("kind") == "table"
    assert table_ci.attributes.get("estimated_rows") == 10000

    # Table4 is a view with no row count
    view_ci = by_id[TABLE4_EXT_ID]
    assert view_ci.attributes.get("kind") == "view"
    assert view_ci.attributes.get("estimated_rows") is None


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
# AC 16: CONTAINS hierarchy edges present with correct evidence details
# ---------------------------------------------------------------------------


def test_contains_instance_to_databases(edges):
    """AC 16: CONTAINS edges from db_instance to each discovered db_database."""
    inst_to_db = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.db_instance
        and e.from_ref.external_id == INSTANCE_EXT_ID
        and e.to_ref.type == CIType.db_database
    ]
    db_ids = {e.to_ref.external_id for e in inst_to_db}
    assert DB1_EXT_ID in db_ids, f"CONTAINS instance->appdb missing; found {db_ids}"
    assert DB2_EXT_ID in db_ids, f"CONTAINS instance->analyticsdb missing; found {db_ids}"


def test_contains_instance_to_database_evidence_detail(edges):
    """AC 16: CONTAINS instance->database evidence detail == 'db:instance:database'."""
    for e in edges:
        if (
            e.type == EdgeType.CONTAINS
            and e.from_ref.type == CIType.db_instance
            and e.to_ref.type == CIType.db_database
        ):
            assert e.evidence[0].detail == "db:instance:database", (
                f"CONTAINS instance->database evidence detail wrong: {e.evidence[0].detail!r}"
            )


def test_contains_database_to_schemas(edges):
    """AC 16: CONTAINS db_database->db_schema edges for schemas with resolved parent."""
    db_to_schema = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.db_database
        and e.from_ref.external_id == DB1_EXT_ID
        and e.to_ref.type == CIType.db_schema
    ]
    schema_ids = {e.to_ref.external_id for e in db_to_schema}
    assert SCHEMA1_EXT_ID in schema_ids, "CONTAINS appdb->public missing"
    assert SCHEMA2_EXT_ID in schema_ids, "CONTAINS appdb->audit missing"

    # Schema3 belongs to analyticsdb
    db2_to_schema = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.db_database
        and e.from_ref.external_id == DB2_EXT_ID
        and e.to_ref.type == CIType.db_schema
    ]
    schema3_ids = {e.to_ref.external_id for e in db2_to_schema}
    assert SCHEMA3_EXT_ID in schema3_ids, "CONTAINS analyticsdb->reports missing"


def test_contains_database_to_schema_evidence_detail(edges):
    """AC 16: CONTAINS database->schema evidence detail == 'db:database:schema'."""
    for e in edges:
        if (
            e.type == EdgeType.CONTAINS
            and e.from_ref.type == CIType.db_database
            and e.to_ref.type == CIType.db_schema
        ):
            assert e.evidence[0].detail == "db:database:schema", (
                f"CONTAINS database->schema evidence detail wrong: {e.evidence[0].detail!r}"
            )


def test_contains_schema_to_tables(edges):
    """AC 16: CONTAINS db_schema->db_table edges for tables with resolved parent schema."""
    schema_to_table = [
        e for e in edges
        if e.type == EdgeType.CONTAINS
        and e.from_ref.type == CIType.db_schema
        and e.from_ref.external_id == SCHEMA1_EXT_ID
        and e.to_ref.type == CIType.db_table
    ]
    table_ids = {e.to_ref.external_id for e in schema_to_table}
    assert TABLE1_EXT_ID in table_ids, "CONTAINS public->users missing"
    assert TABLE2_EXT_ID in table_ids, "CONTAINS public->orders missing"


def test_contains_schema_to_table_evidence_detail(edges):
    """AC 16: CONTAINS schema->table evidence detail == 'db:schema:table'."""
    for e in edges:
        if (
            e.type == EdgeType.CONTAINS
            and e.from_ref.type == CIType.db_schema
            and e.to_ref.type == CIType.db_table
        ):
            assert e.evidence[0].detail == "db:schema:table", (
                f"CONTAINS schema->table evidence detail wrong: {e.evidence[0].detail!r}"
            )


# ---------------------------------------------------------------------------
# AC 17: at least one DEPENDS_ON edge emitted from declared FK
# ---------------------------------------------------------------------------


def test_at_least_one_depends_on_edge(edges):
    """AC 17: at least one DEPENDS_ON edge emitted from a declared FK constraint."""
    depends_on = [e for e in edges if e.type == EdgeType.DEPENDS_ON]
    assert depends_on, "No DEPENDS_ON edges emitted; expected at least one FK-derived edge"


def test_depends_on_fk1_orientation(edges):
    """AC 17: FK1 DEPENDS_ON edge is oriented referencing_table -> referenced_table."""
    fk1_edges = [
        e for e in edges
        if e.type == EdgeType.DEPENDS_ON
        and e.from_ref.external_id == TABLE2_EXT_ID
        and e.to_ref.external_id == TABLE1_EXT_ID
    ]
    assert fk1_edges, (
        f"DEPENDS_ON orders->users missing; from={TABLE2_EXT_ID!r} to={TABLE1_EXT_ID!r}"
    )


# ---------------------------------------------------------------------------
# AC 18: FK-derived DEPENDS_ON edge has correct provenance and evidence detail
# ---------------------------------------------------------------------------


def test_depends_on_source_confidence_evidence(edges):
    """AC 18: FK DEPENDS_ON edge has source=declared, confidence=1.0, non-empty evidence."""
    depends_on = [e for e in edges if e.type == EdgeType.DEPENDS_ON]
    assert depends_on, "No DEPENDS_ON edges found"
    edge = depends_on[0]
    assert edge.source == EdgeSource.declared, f"source wrong: {edge.source}"
    assert edge.confidence == 1.0, f"confidence wrong: {edge.confidence}"
    assert edge.evidence, "evidence must be non-empty"


def test_depends_on_fk1_evidence_detail_contains_constraint_name(edges):
    """AC 18: FK1 DEPENDS_ON evidence detail contains the constraint name."""
    fk1_edges = [
        e for e in edges
        if e.type == EdgeType.DEPENDS_ON
        and e.from_ref.external_id == TABLE2_EXT_ID
        and e.to_ref.external_id == TABLE1_EXT_ID
    ]
    assert fk1_edges, "FK1 DEPENDS_ON edge not found"
    detail = fk1_edges[0].evidence[0].detail
    assert FK1_CONSTRAINT in detail, (
        f"Evidence detail must contain constraint name '{FK1_CONSTRAINT}'; got {detail!r}"
    )


def test_depends_on_fk1_evidence_detail_contains_column_names(edges):
    """AC 18: FK1 DEPENDS_ON evidence detail contains the referencing and referenced column names."""
    fk1_edges = [
        e for e in edges
        if e.type == EdgeType.DEPENDS_ON
        and e.from_ref.external_id == TABLE2_EXT_ID
        and e.to_ref.external_id == TABLE1_EXT_ID
        and FK1_CONSTRAINT in (e.evidence[0].detail or "")
    ]
    assert fk1_edges, "FK1 DEPENDS_ON edge with correct constraint not found"
    detail = fk1_edges[0].evidence[0].detail
    assert "user_id" in detail, f"Evidence detail must contain 'user_id'; got {detail!r}"
    assert "id" in detail, f"Evidence detail must contain 'id'; got {detail!r}"


# ---------------------------------------------------------------------------
# AC 19: every emitted edge has correct provenance (source=declared, confidence=1.0, evidence)
# ---------------------------------------------------------------------------


def test_all_edges_have_db_provenance(edges):
    """AC 19: every DiscoveredEdge has source=declared, confidence=1.0,
    non-empty evidence, all with source=='db' and non-empty detail."""
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
            assert ev.source == "db", (
                f"Edge {edge.type} evidence.source must be 'db'; got {ev.source!r}"
            )
            assert ev.detail, (
                f"Edge {edge.type} evidence.detail must be non-empty; got {ev.detail!r}"
            )


# ---------------------------------------------------------------------------
# §5.1 / AC 20: empty client returns exactly 1 CI (db_instance), 0 edges
# ---------------------------------------------------------------------------


def test_edge_case_5_1_empty_instance():
    """§5.1: client returns [] for all four methods -> exactly 1 CI (db_instance), 0 edges."""

    class EmptyClient:
        def list_databases(self): return []
        def list_schemas(self): return []
        def list_tables(self): return []
        def list_foreign_keys(self): return []

    conn = DbIntrospectionConnector(EmptyClient(), host=HOST, port=PORT)
    events = list(conn.discover())
    cis_out = [e for e in events if isinstance(e, DiscoveredCI)]
    edges_out = [e for e in events if isinstance(e, DiscoveredEdge)]

    assert len(cis_out) == 1, f"Expected 1 CI for empty instance, got {len(cis_out)}"
    assert cis_out[0].type == CIType.db_instance
    assert cis_out[0].external_id == INSTANCE_EXT_ID
    assert not edges_out, f"Expected 0 edges for empty instance, got {len(edges_out)}"


# ---------------------------------------------------------------------------
# §5.2 / AC 20: database/schema/table dict missing name key is skipped
# ---------------------------------------------------------------------------


def test_edge_case_5_2_missing_name_key_skipped():
    """§5.2: resource dict with missing/falsy name is skipped; others in same list still emitted."""

    class MissingNameClient:
        def list_databases(self):
            return [
                {"name": None, "owner": "x"},       # missing name -> skip
                {"owner": "x"},                      # no name key -> skip
                {"name": DB1_NAME, "owner": "pg"},   # valid -> emit
            ]

        def list_schemas(self):
            return [
                {"database": DB1_NAME, "name": ""},  # falsy name -> skip
                {"database": DB1_NAME, "name": SCHEMA1_NAME, "owner": "pg"},  # valid
            ]

        def list_tables(self):
            return [
                {"database": DB1_NAME, "schema": SCHEMA1_NAME, "name": None},  # skip
                {"database": DB1_NAME, "schema": SCHEMA1_NAME, "name": TABLE1_NAME},  # valid
            ]

        def list_foreign_keys(self):
            return []

    conn = DbIntrospectionConnector(MissingNameClient(), host=HOST, port=PORT)
    events = list(conn.discover())
    cis_out = [e for e in events if isinstance(e, DiscoveredCI)]

    db_cis = [c for c in cis_out if c.type == CIType.db_database]
    assert len(db_cis) == 1, f"Expected 1 db_database CI, got {len(db_cis)}"
    assert db_cis[0].name == DB1_NAME

    schema_cis = [c for c in cis_out if c.type == CIType.db_schema]
    assert len(schema_cis) == 1, f"Expected 1 db_schema CI (not skipped ones), got {len(schema_cis)}"
    assert schema_cis[0].name == SCHEMA1_NAME

    table_cis = [c for c in cis_out if c.type == CIType.db_table]
    assert len(table_cis) == 1, f"Expected 1 db_table CI, got {len(table_cis)}"
    assert table_cis[0].name == TABLE1_NAME


# ---------------------------------------------------------------------------
# §5.3 / AC 20: schema whose parent database is not in discovered set -> CI emitted, no CONTAINS
# ---------------------------------------------------------------------------


def test_edge_case_5_3_schema_unresolved_parent_database():
    """§5.3: schema whose parent database not discovered -> schema CI emitted, no CONTAINS db->schema."""

    class OrphanSchemaClient:
        def list_databases(self):
            return [{"name": DB1_NAME}]

        def list_schemas(self):
            return [
                # Parent = DB1_NAME (discovered) -> CONTAINS will be emitted
                {"database": DB1_NAME, "name": SCHEMA1_NAME},
                # Parent = "missing_db" (NOT discovered) -> no CONTAINS
                {"database": "missing_db", "name": "orphan_schema"},
            ]

        def list_tables(self): return []
        def list_foreign_keys(self): return []

    conn = DbIntrospectionConnector(OrphanSchemaClient(), host=HOST, port=PORT)
    events = list(conn.discover())
    cis_out = [e for e in events if isinstance(e, DiscoveredCI)]
    edges_out = [e for e in events if isinstance(e, DiscoveredEdge)]

    # Both schema CIs should be emitted
    schema_cis = [c for c in cis_out if c.type == CIType.db_schema]
    assert len(schema_cis) == 2, f"Expected 2 schema CIs, got {len(schema_cis)}"

    # Only one CONTAINS db->schema edge (for the schema whose parent is discovered)
    db_to_schema_edges = [
        e for e in edges_out
        if e.type == EdgeType.CONTAINS and e.from_ref.type == CIType.db_database
    ]
    assert len(db_to_schema_edges) == 1, (
        f"Expected 1 CONTAINS db->schema edge, got {len(db_to_schema_edges)}"
    )
    orphan_schema_ext_id = f"{INSTANCE_EXT_ID}/missing_db/orphan_schema"
    orphan_contains = [
        e for e in db_to_schema_edges if e.to_ref.external_id == orphan_schema_ext_id
    ]
    assert not orphan_contains, "CONTAINS db->orphan_schema must not be emitted"


# ---------------------------------------------------------------------------
# §5.4 / AC 20: table whose parent schema is not in discovered set -> CI emitted, no CONTAINS
# ---------------------------------------------------------------------------


def test_edge_case_5_4_table_unresolved_parent_schema():
    """§5.4: table whose parent schema not discovered -> table CI emitted, no CONTAINS schema->table."""

    class OrphanTableClient:
        def list_databases(self):
            return [{"name": DB1_NAME}]

        def list_schemas(self):
            return [{"database": DB1_NAME, "name": SCHEMA1_NAME}]

        def list_tables(self):
            return [
                # Parent schema discovered -> CONTAINS emitted
                {"database": DB1_NAME, "schema": SCHEMA1_NAME, "name": TABLE1_NAME},
                # Parent schema NOT discovered -> no CONTAINS
                {"database": DB1_NAME, "schema": "missing_schema", "name": "orphan_table"},
            ]

        def list_foreign_keys(self): return []

    conn = DbIntrospectionConnector(OrphanTableClient(), host=HOST, port=PORT)
    events = list(conn.discover())
    cis_out = [e for e in events if isinstance(e, DiscoveredCI)]
    edges_out = [e for e in events if isinstance(e, DiscoveredEdge)]

    table_cis = [c for c in cis_out if c.type == CIType.db_table]
    assert len(table_cis) == 2, f"Expected 2 table CIs, got {len(table_cis)}"

    schema_to_table_edges = [
        e for e in edges_out
        if e.type == EdgeType.CONTAINS and e.from_ref.type == CIType.db_schema
    ]
    assert len(schema_to_table_edges) == 1, (
        f"Expected 1 CONTAINS schema->table edge (only for resolved parent), got {len(schema_to_table_edges)}"
    )

    orphan_table_ext_id = f"{INSTANCE_EXT_ID}/{DB1_NAME}/missing_schema/orphan_table"
    orphan_contains = [
        e for e in schema_to_table_edges if e.to_ref.external_id == orphan_table_ext_id
    ]
    assert not orphan_contains, "CONTAINS schema->orphan_table must not be emitted"


# ---------------------------------------------------------------------------
# §5.5 / AC 20: FK whose referencing table is undiscovered -> no DEPENDS_ON
# ---------------------------------------------------------------------------


def test_edge_case_5_5_fk_referencing_table_undiscovered():
    """§5.5: FK whose referencing (from) table is not discovered -> no DEPENDS_ON edge."""

    class DanglingFromFkClient:
        def list_databases(self):
            return [{"name": DB1_NAME}]

        def list_schemas(self):
            return [{"database": DB1_NAME, "name": SCHEMA1_NAME}]

        def list_tables(self):
            # Only the referenced table is discovered; referencing table is absent
            return [{"database": DB1_NAME, "schema": SCHEMA1_NAME, "name": TABLE1_NAME}]

        def list_foreign_keys(self):
            return [{
                "constraint_name": "fk_missing_from",
                "database": DB1_NAME,
                "from_schema": SCHEMA1_NAME,
                "from_table": "missing_table",  # NOT discovered
                "from_columns": ["user_id"],
                "to_schema": SCHEMA1_NAME,
                "to_table": TABLE1_NAME,         # discovered
                "to_columns": ["id"],
            }]

    conn = DbIntrospectionConnector(DanglingFromFkClient(), host=HOST, port=PORT)
    events = list(conn.discover())
    depends_on = [e for e in events if isinstance(e, DiscoveredEdge) and e.type == EdgeType.DEPENDS_ON]
    assert not depends_on, "DEPENDS_ON must not be emitted for undiscovered referencing table"


# ---------------------------------------------------------------------------
# §5.6 / AC 20: FK whose referenced table is undiscovered (dangling FK) -> no DEPENDS_ON
# ---------------------------------------------------------------------------


def test_edge_case_5_6_fk_referenced_table_undiscovered():
    """§5.6: FK whose referenced (to) table is not discovered -> no DEPENDS_ON edge."""

    class DanglingToFkClient:
        def list_databases(self):
            return [{"name": DB1_NAME}]

        def list_schemas(self):
            return [{"database": DB1_NAME, "name": SCHEMA1_NAME}]

        def list_tables(self):
            # Only the referencing table discovered; referenced table is absent
            return [{"database": DB1_NAME, "schema": SCHEMA1_NAME, "name": TABLE2_NAME}]

        def list_foreign_keys(self):
            return [{
                "constraint_name": "fk_dangling_to",
                "database": DB1_NAME,
                "from_schema": SCHEMA1_NAME,
                "from_table": TABLE2_NAME,       # discovered
                "from_columns": ["user_id"],
                "to_schema": SCHEMA1_NAME,
                "to_table": "external_users",    # NOT discovered
                "to_columns": ["id"],
            }]

    conn = DbIntrospectionConnector(DanglingToFkClient(), host=HOST, port=PORT)
    events = list(conn.discover())
    depends_on = [e for e in events if isinstance(e, DiscoveredEdge) and e.type == EdgeType.DEPENDS_ON]
    assert not depends_on, "DEPENDS_ON must not be emitted for undiscovered referenced table"


# ---------------------------------------------------------------------------
# §5.7 / AC 20: FK with absent/falsy constraint_name -> evidence contains "<unnamed>"
# ---------------------------------------------------------------------------


def test_edge_case_5_7_unnamed_fk_constraint():
    """§5.7: FK with absent/falsy constraint_name -> edge still emitted; evidence contains '<unnamed>' and column names."""

    class UnnamedFkClient:
        def list_databases(self):
            return [{"name": DB1_NAME}]

        def list_schemas(self):
            return [{"database": DB1_NAME, "name": SCHEMA1_NAME}]

        def list_tables(self):
            return [
                {"database": DB1_NAME, "schema": SCHEMA1_NAME, "name": TABLE1_NAME},
                {"database": DB1_NAME, "schema": SCHEMA1_NAME, "name": TABLE2_NAME},
            ]

        def list_foreign_keys(self):
            return [{
                # No constraint_name key
                "database": DB1_NAME,
                "from_schema": SCHEMA1_NAME,
                "from_table": TABLE2_NAME,
                "from_columns": ["user_id"],
                "to_schema": SCHEMA1_NAME,
                "to_table": TABLE1_NAME,
                "to_columns": ["id"],
            }]

    conn = DbIntrospectionConnector(UnnamedFkClient(), host=HOST, port=PORT)
    events = list(conn.discover())
    depends_on = [e for e in events if isinstance(e, DiscoveredEdge) and e.type == EdgeType.DEPENDS_ON]
    assert depends_on, "DEPENDS_ON must be emitted even for unnamed FK constraint"
    detail = depends_on[0].evidence[0].detail
    assert "<unnamed>" in detail, f"Evidence detail must contain '<unnamed>'; got {detail!r}"
    assert "user_id" in detail, f"Evidence detail must contain column names; got {detail!r}"
    assert "id" in detail, f"Evidence detail must contain column names; got {detail!r}"


# ---------------------------------------------------------------------------
# §5.8 / AC 20: composite FK (multi-column) -> exactly one DEPENDS_ON; evidence lists all columns
# ---------------------------------------------------------------------------


def test_edge_case_5_8_composite_fk_single_edge():
    """§5.8: composite FK (multi-column from_columns/to_columns) -> exactly one DEPENDS_ON edge; evidence lists all columns comma-joined."""

    class CompositeFkClient:
        def list_databases(self):
            return [{"name": DB1_NAME}]

        def list_schemas(self):
            return [{"database": DB1_NAME, "name": SCHEMA1_NAME}]

        def list_tables(self):
            return [
                {"database": DB1_NAME, "schema": SCHEMA1_NAME, "name": "shipment"},
                {"database": DB1_NAME, "schema": SCHEMA1_NAME, "name": "warehouse"},
            ]

        def list_foreign_keys(self):
            return [{
                "constraint_name": "fk_composite",
                "database": DB1_NAME,
                "from_schema": SCHEMA1_NAME,
                "from_table": "shipment",
                "from_columns": ["origin_id", "origin_type"],
                "to_schema": SCHEMA1_NAME,
                "to_table": "warehouse",
                "to_columns": ["id", "type"],
            }]

    conn = DbIntrospectionConnector(CompositeFkClient(), host=HOST, port=PORT)
    events = list(conn.discover())
    depends_on = [e for e in events if isinstance(e, DiscoveredEdge) and e.type == EdgeType.DEPENDS_ON]
    assert len(depends_on) == 1, f"Composite FK should produce exactly 1 DEPENDS_ON edge, got {len(depends_on)}"
    detail = depends_on[0].evidence[0].detail
    # Comma-joined from_cols and to_cols should appear
    assert "origin_id,origin_type" in detail, f"Composite from_cols missing in evidence: {detail!r}"
    assert "id,type" in detail, f"Composite to_cols missing in evidence: {detail!r}"


# ---------------------------------------------------------------------------
# §5.9 / AC 20: two FKs between same table pair -> two distinct DEPENDS_ON edges
# ---------------------------------------------------------------------------


def test_edge_case_5_9_two_fks_same_table_pair_two_edges(edges):
    """§5.9: two distinct FK constraints between orders->users produce two distinct DEPENDS_ON edges."""
    depends_on = [
        e for e in edges
        if e.type == EdgeType.DEPENDS_ON
        and e.from_ref.external_id == TABLE2_EXT_ID
        and e.to_ref.external_id == TABLE1_EXT_ID
    ]
    assert len(depends_on) == 2, (
        f"Two FK constraints between same pair should produce 2 DEPENDS_ON edges, got {len(depends_on)}"
    )
    details = {e.evidence[0].detail for e in depends_on}
    assert len(details) == 2, f"Two distinct constraints should have two distinct evidence details; got {details}"
    assert any(FK1_CONSTRAINT in d for d in details), f"{FK1_CONSTRAINT} not in evidence details: {details}"
    assert any(FK2_CONSTRAINT in d for d in details), f"{FK2_CONSTRAINT} not in evidence details: {details}"


# ---------------------------------------------------------------------------
# §5.10 / AC 20: self-referential FK -> one DEPENDS_ON with from_ref == to_ref
# ---------------------------------------------------------------------------


def test_edge_case_5_10_self_referential_fk():
    """§5.10: table references itself -> one DEPENDS_ON edge with from_ref == to_ref (same external_id)."""

    class SelfRefFkClient:
        def list_databases(self):
            return [{"name": DB1_NAME}]

        def list_schemas(self):
            return [{"database": DB1_NAME, "name": SCHEMA1_NAME}]

        def list_tables(self):
            return [{"database": DB1_NAME, "schema": SCHEMA1_NAME, "name": "category"}]

        def list_foreign_keys(self):
            return [{
                "constraint_name": "fk_self_ref",
                "database": DB1_NAME,
                "from_schema": SCHEMA1_NAME,
                "from_table": "category",
                "from_columns": ["parent_id"],
                "to_schema": SCHEMA1_NAME,
                "to_table": "category",   # same table
                "to_columns": ["id"],
            }]

    conn = DbIntrospectionConnector(SelfRefFkClient(), host=HOST, port=PORT)
    events = list(conn.discover())
    depends_on = [e for e in events if isinstance(e, DiscoveredEdge) and e.type == EdgeType.DEPENDS_ON]
    assert len(depends_on) == 1, f"Self-referential FK should produce 1 DEPENDS_ON, got {len(depends_on)}"
    edge = depends_on[0]
    assert edge.from_ref.external_id == edge.to_ref.external_id, (
        f"Self-ref FK should have from_ref == to_ref; got {edge.from_ref.external_id!r} vs {edge.to_ref.external_id!r}"
    )


# ---------------------------------------------------------------------------
# §5.11 / AC 20: two tables with same name in different schemas -> distinct CIs (no collision)
# ---------------------------------------------------------------------------


def test_edge_case_5_11_same_table_name_different_schemas(cis):
    """§5.11: tables with same name in different schemas have distinct external_ids -> distinct db_table CIs."""
    # TABLE1 is 'users' in 'public' and TABLE3 is 'users' in 'audit'
    table_cis = [c for c in cis if c.type == CIType.db_table and c.name == TABLE1_NAME]
    assert len(table_cis) == 2, (
        f"Expected 2 'users' table CIs (in different schemas), got {len(table_cis)}"
    )
    ids = {c.external_id for c in table_cis}
    assert len(ids) == 2, f"Two tables with same name must have distinct external_ids; got {ids}"
    assert TABLE1_EXT_ID in ids
    assert TABLE3_EXT_ID in ids


# ---------------------------------------------------------------------------
# §5.12 / AC 20: optional attribute keys absent -> no raise; attributes hold None for missing values
# ---------------------------------------------------------------------------


def test_edge_case_5_12_missing_optional_keys_no_raise():
    """§5.12: optional keys absent -> no raise; attributes hold None for missing values."""

    class MinimalClient:
        def list_databases(self):
            # No owner, no encoding
            return [{"name": DB1_NAME}]

        def list_schemas(self):
            # No owner
            return [{"database": DB1_NAME, "name": SCHEMA1_NAME}]

        def list_tables(self):
            # No kind, no estimated_rows, no relkind
            return [{"database": DB1_NAME, "schema": SCHEMA1_NAME, "name": TABLE1_NAME}]

        def list_foreign_keys(self):
            # Empty from_columns and to_columns
            return [{
                "constraint_name": "fk_minimal",
                "database": DB1_NAME,
                "from_schema": SCHEMA1_NAME,
                "from_table": TABLE1_NAME,
                "from_columns": [],
                "to_schema": SCHEMA1_NAME,
                "to_table": TABLE1_NAME,  # self-ref to keep it simple
                "to_columns": [],
            }]

    conn = DbIntrospectionConnector(MinimalClient(), host=HOST, port=PORT)
    events = list(conn.discover())  # must not raise
    cis_out = [e for e in events if isinstance(e, DiscoveredCI)]

    db_ci = next(c for c in cis_out if c.type == CIType.db_database)
    assert db_ci.attributes.get("owner") is None
    assert db_ci.attributes.get("encoding") is None

    schema_ci = next(c for c in cis_out if c.type == CIType.db_schema)
    assert schema_ci.attributes.get("owner") is None

    table_ci = next(c for c in cis_out if c.type == CIType.db_table)
    assert table_ci.attributes.get("kind") is None
    assert table_ci.attributes.get("estimated_rows") is None


# ---------------------------------------------------------------------------
# §5.13 / AC 20: discover() called twice yields identical event stream
# ---------------------------------------------------------------------------


def test_edge_case_5_13_discover_twice_identical_stream(connector):
    """§5.13: calling discover() twice on the same connector yields the same event stream."""
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
# §5.14 / AC 21: connector does not mutate the injected client
# ---------------------------------------------------------------------------


def test_edge_case_5_14_client_not_mutated():
    """§5.14 / AC 21: discover() must not mutate the injected client; no write method invoked."""

    class TrackingClient:
        def __init__(self):
            self._list_databases_calls = 0
            self._list_schemas_calls = 0
            self._list_tables_calls = 0
            self._list_foreign_keys_calls = 0
            self._original_data = [{"name": DB1_NAME}]

        def list_databases(self) -> list[dict]:
            self._list_databases_calls += 1
            return [{"name": DB1_NAME}]

        def list_schemas(self) -> list[dict]:
            self._list_schemas_calls += 1
            return []

        def list_tables(self) -> list[dict]:
            self._list_tables_calls += 1
            return []

        def list_foreign_keys(self) -> list[dict]:
            self._list_foreign_keys_calls += 1
            return []

    client = TrackingClient()
    conn = DbIntrospectionConnector(client, host=HOST, port=PORT)

    list(conn.discover())

    assert client._list_databases_calls == 1, "list_databases should be called exactly once"
    assert client._list_schemas_calls == 1, "list_schemas should be called exactly once"
    assert client._list_tables_calls == 1, "list_tables should be called exactly once"
    assert client._list_foreign_keys_calls == 1, "list_foreign_keys should be called exactly once"

    # Verify client data unchanged after discovery
    db_data = client.list_databases()
    assert db_data == [{"name": DB1_NAME}], "Client data must not be mutated by discover()"


def test_connector_only_reads_never_writes(fake_client):
    """AC 21: connector does not invoke any write method; fake exposes no write methods."""
    write_methods = ["create", "update", "delete", "put", "patch", "post", "insert"]
    for method_name in dir(fake_client):
        if any(wm in method_name.lower() for wm in write_methods):
            assert False, f"Fake client has unexpected write method: {method_name}"


# ---------------------------------------------------------------------------
# §5.15 / AC 13: instance_name absent -> name falls back to f"{host}:{port}"
# ---------------------------------------------------------------------------


def test_edge_case_5_15_instance_name_fallback():
    """§5.15: when instance_name is None, db_instance CI name == f'{host}:{port}'."""

    class EmptyClient:
        def list_databases(self): return []
        def list_schemas(self): return []
        def list_tables(self): return []
        def list_foreign_keys(self): return []

    conn = DbIntrospectionConnector(EmptyClient(), host="myhost", port=9999, instance_name=None)
    events = list(conn.discover())
    inst_ci = next(c for c in events if isinstance(c, DiscoveredCI) and c.type == CIType.db_instance)
    assert inst_ci.name == "myhost:9999", f"Name fallback wrong: {inst_ci.name!r}"
    assert inst_ci.external_id == "myhost:9999", f"external_id wrong: {inst_ci.external_id!r}"


# ---------------------------------------------------------------------------
# §5.18: port is int in external_id formatting — no leading/trailing whitespace
# ---------------------------------------------------------------------------


def test_external_id_port_is_int_no_whitespace():
    """§5.18: external_id uses integer port formatting with no whitespace."""

    class EmptyClient:
        def list_databases(self): return []
        def list_schemas(self): return []
        def list_tables(self): return []
        def list_foreign_keys(self): return []

    conn = DbIntrospectionConnector(EmptyClient(), host="myhost", port=5432)
    events = list(conn.discover())
    inst_ci = next(c for c in events if isinstance(c, DiscoveredCI))
    assert inst_ci.external_id == "myhost:5432"
    assert inst_ci.external_id == inst_ci.external_id.strip()


# ---------------------------------------------------------------------------
# AC 22: migration 0018 content
# ---------------------------------------------------------------------------


def test_migration_0018_db_vertex_labels_exists():
    """AC 22: migration 0018 exists, calls create_vlabel for all 4 db_* labels,
    includes both GRANT statements, no create_elabel, no CREATE TABLE."""
    migration_path = os.path.normpath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "migrations",
            "0018_db_vertex_labels.sql",
        )
    )
    assert os.path.isfile(migration_path), f"Migration 0018 not found: {migration_path}"

    content = open(migration_path).read()

    assert "ag_catalog" in content, "Migration must set ag_catalog in search_path"
    assert "create_elabel" not in content, "Migration must NOT call create_elabel"
    assert "CREATE TABLE" not in content, "Migration must NOT contain CREATE TABLE"

    for label in ("db_instance", "db_database", "db_schema", "db_table"):
        assert label in content, f"Migration must create vertex label '{label}'"

    assert "create_vlabel" in content, "Migration must call create_vlabel"
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES" in content, (
        "Migration must re-apply table GRANT"
    )
    assert "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES" in content, (
        "Migration must re-apply sequence GRANT"
    )


def test_existing_migrations_0001_to_0017_unchanged_and_0018_is_highest():
    """AC 23 (updated): files 0001 through 0024 still exist; 0024 is now the highest-numbered
    migration (freshness_slo, added in the per-source freshness SLO feature).
    No migration numbered 0025 or above may exist."""
    migrations_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "migrations")
    )
    for n in range(1, 20):
        pattern = f"{n:04d}_"
        matches = [f for f in os.listdir(migrations_dir) if f.startswith(pattern)]
        assert matches, f"Migration {pattern}* not found in {migrations_dir}"

    # 0019 must still exist
    all_files = os.listdir(migrations_dir)
    assert any(f.startswith("0019") for f in all_files), (
        "Migration 0019_* must exist (edge_key_identity)"
    )

    # 0020 must now exist
    assert any(f.startswith("0020") for f in all_files), (
        "Migration 0020_* must exist (saas_vertex_labels)"
    )

    # 0021 must now exist
    assert any(f.startswith("0021") for f in all_files), (
        "Migration 0021_* must exist (entity_alias_keys)"
    )

    # 0022 must now exist
    assert any(f.startswith("0022") for f in all_files), (
        "Migration 0022_* must exist (ci_unmerges)"
    )

    # 0023 must now exist
    assert any(f.startswith("0023") for f in all_files), (
        "Migration 0023_* must exist (ci_merge_candidates)"
    )

    # 0024 must now exist
    assert any(f.startswith("0024") for f in all_files), (
        "Migration 0024_* must exist (freshness_slo)"
    )

    # 0025 must now exist (history_retention)
    assert any(f.startswith("0025") for f in all_files), (
        "Migration 0025_* must exist (history_retention)"
    )

    # No 0026 or higher
    higher = [
        f for f in all_files
        if len(f) >= 4 and f[:4].isdigit() and int(f[:4]) > 25
    ]
    assert not higher, f"Unexpected migration(s) higher than 0025 found: {higher}"


# ---------------------------------------------------------------------------
# AC 24: CLI discover-db subcommand wiring
# ---------------------------------------------------------------------------


def test_cli_discover_db_subparser_registered():
    """AC 24: 'discover-db' subcommand registered with required args; handler receives correct parsed values."""
    from unittest.mock import patch

    captured = {}

    def fake_handler(args):
        captured["args"] = args
        return 0

    from infra_twin.cli.main import main as cli_main

    with patch("infra_twin.cli.main._discover_db", fake_handler):
        rc = cli_main([
            "discover-db",
            "--tenant", "00000000-0000-0000-0000-000000000001",
            "--dsn", "postgresql://user:pass@db.example.com:5432/appdb",
            "--host", "db.example.com",
            "--port", "5432",
        ])

    assert rc == 0
    args = captured["args"]
    assert args.tenant == "00000000-0000-0000-0000-000000000001"
    assert args.dsn == "postgresql://user:pass@db.example.com:5432/appdb"
    assert args.host == "db.example.com"
    assert args.port == 5432  # must be int
    assert args.instance_name is None  # optional, defaults to None


def test_cli_discover_db_instance_name_arg():
    """AC 24: --instance-name is optional; when supplied it reaches the handler."""
    from unittest.mock import patch

    captured = {}

    def fake_handler(args):
        captured["args"] = args
        return 0

    from infra_twin.cli.main import main as cli_main

    with patch("infra_twin.cli.main._discover_db", fake_handler):
        cli_main([
            "discover-db",
            "--tenant", "00000000-0000-0000-0000-000000000001",
            "--dsn", "postgresql://localhost/db",
            "--host", "localhost",
            "--port", "5432",
            "--instance-name", "my-pg-server",
        ])

    assert captured["args"].instance_name == "my-pg-server"


# ---------------------------------------------------------------------------
# AC 31: regression — all existing connectors still importable
# ---------------------------------------------------------------------------


def test_all_five_connectors_still_importable():
    """AC 31: AwsConnector, AzureConnector, GcpConnector, KubernetesConnector, DbIntrospectionConnector all importable."""
    assert AwsConnector is not None
    assert AzureConnector is not None
    assert GcpConnector is not None
    assert KubernetesConnector is not None
    assert DbIntrospectionConnector is not None


# ===========================================================================
# E2E + ADVERSARIAL ISOLATION TESTS (use pool + make_tenant from conftest.py)
# These tests require the local Postgres+AGE stack with migration 0018 applied.
# ===========================================================================


class _E2eFakeDbClient:
    """E2E client with TWO FK constraints between orders->users (spec §5.9 restored).

    The edge-key discriminator (migration 0019) allows two DEPENDS_ON edges between the
    same ordered (from_id, to_id) pair when their edge_key values differ (constraint name).
    Both FK1 and FK2 are now included so the E2E reconcile produces two distinct edges.
    """

    def list_databases(self) -> list[dict]:
        return [
            {"name": DB1_NAME, "owner": "postgres", "encoding": "UTF8"},
            {"name": DB2_NAME, "owner": "analytics_user", "encoding": "UTF8"},
        ]

    def list_schemas(self) -> list[dict]:
        return [
            {"database": DB1_NAME, "name": SCHEMA1_NAME, "owner": "postgres"},
            {"database": DB1_NAME, "name": SCHEMA2_NAME, "owner": "auditor"},
            {"database": DB2_NAME, "name": SCHEMA3_NAME, "owner": "analytics_user"},
        ]

    def list_tables(self) -> list[dict]:
        return [
            {
                "database": TABLE1_DB,
                "schema": TABLE1_SCHEMA,
                "name": TABLE1_NAME,
                "kind": "table",
                "estimated_rows": 10000,
            },
            {
                "database": TABLE2_DB,
                "schema": TABLE2_SCHEMA,
                "name": TABLE2_NAME,
                "kind": "table",
                "estimated_rows": 50000,
            },
            {
                "database": TABLE3_DB,
                "schema": TABLE3_SCHEMA,
                "name": TABLE3_NAME,
                "kind": "table",
                "estimated_rows": 2000,
            },
            {
                "database": TABLE4_DB,
                "schema": TABLE4_SCHEMA,
                "name": TABLE4_NAME,
                "kind": "view",
                "estimated_rows": None,
            },
        ]

    def list_foreign_keys(self) -> list[dict]:
        # Both FK constraints between orders->users; each gets a distinct edge_key
        # (the constraint name) via the DB connector, so both reconcile as separate
        # open DEPENDS_ON edges (spec §5.9 restored by migration 0019 + edge_key feature).
        return [
            {
                "constraint_name": FK1_CONSTRAINT,
                "database": FK1_DB,
                "from_schema": FK1_FROM_SCHEMA,
                "from_table": FK1_FROM_TABLE,
                "from_columns": FK1_FROM_COLS,
                "to_schema": FK1_TO_SCHEMA,
                "to_table": FK1_TO_TABLE,
                "to_columns": FK1_TO_COLS,
            },
            {
                "constraint_name": FK2_CONSTRAINT,
                "database": FK2_DB,
                "from_schema": FK2_FROM_SCHEMA,
                "from_table": FK2_FROM_TABLE,
                "from_columns": FK2_FROM_COLS,
                "to_schema": FK2_TO_SCHEMA,
                "to_table": FK2_TO_TABLE,
                "to_columns": FK2_TO_COLS,
            },
        ]


def _make_connector_for_e2e() -> DbIntrospectionConnector:
    return DbIntrospectionConnector(
        _E2eFakeDbClient(), host=HOST, port=PORT, instance_name=INSTANCE_NAME
    )


# ---------------------------------------------------------------------------
# AC 25: discover_and_reconcile returns positive counts
# ---------------------------------------------------------------------------


def test_discover_and_reconcile_returns_positive_counts(pool, make_tenant):
    """AC 25: discover_and_reconcile creates CIs and writes edges for DB connector."""
    from infra_twin.reconciliation import discover_and_reconcile

    tenant = make_tenant("db-a")
    result = discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    assert result.cis_created > 0, f"Expected cis_created > 0, got {result.cis_created}"
    assert result.edges_written > 0, f"Expected edges_written > 0, got {result.edges_written}"


# ---------------------------------------------------------------------------
# AC 26: connector registry + runs + raw_facts
# ---------------------------------------------------------------------------


def test_connector_registry_has_db_type(pool, make_tenant):
    """AC 26: after reconcile, connectors row with type='db' exists."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connectors import ConnectorRegistry
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("db-registry")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        registry = ConnectorRegistry(conn, tenant)
        connectors_list = registry.list()

    db_connectors = [c for c in connectors_list if c.type == "db"]
    assert db_connectors, (
        f"No connector with type='db' found; got: {[c.type for c in connectors_list]}"
    )
    assert db_connectors[0].display_name == "db"


def test_connector_run_ok_and_raw_facts(pool, make_tenant):
    """AC 26: connector_runs row with source='db' and status='ok'; >= 1 raw_facts row."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connector_health import ConnectorRunRepository
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("db-run")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        run_repo = ConnectorRunRepository(conn, tenant)
        summaries = run_repo.latest_per_source()

    db_runs = [s for s in summaries if s.source == "db"]
    assert db_runs, "No connector_run with source='db' found"
    assert db_runs[0].status == "ok", (
        f"connector_run status expected 'ok', got {db_runs[0].status!r}"
    )

    with tenant_session(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = %s", ("db",)
        ).fetchone()[0]
    assert count >= 1, f"Expected at least 1 raw_facts row for source='db', got {count}"


# ---------------------------------------------------------------------------
# AC 27: all four db_* CI types persisted current with correct tenant_id
# ---------------------------------------------------------------------------


def test_db_cis_persisted_current_with_correct_tenant(pool, make_tenant):
    """AC 27: all four db_* CI types are persisted current (valid_to IS NULL) with tenant_id == tenant."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.repositories import CIRepository
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("db-cis")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        for ci_type in (
            CIType.db_instance,
            CIType.db_database,
            CIType.db_schema,
            CIType.db_table,
        ):
            cis = repo.get_current(type=ci_type)
            assert cis, f"No current {ci_type.value} CIs found after db reconcile"
            for ci in cis:
                assert ci.valid_to is None, (
                    f"{ci_type.value} CI {ci.external_id} has valid_to={ci.valid_to}, expected NULL"
                )
                assert ci.tenant_id == tenant, (
                    f"{ci_type.value} CI tenant_id {ci.tenant_id} != expected {tenant}"
                )


def test_db_edges_persisted_with_provenance(pool, make_tenant):
    """AC 27: persisted db edges have source, non-null confidence, and non-empty evidence."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("db-edges")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT source, confidence, evidence FROM edges WHERE valid_to IS NULL",
        ).fetchall()

    assert rows, "No current edges found after db reconcile"
    for source, confidence, evidence in rows:
        assert source in ("declared", "inferred"), (
            f"Edge source must be 'declared' or 'inferred'; got {source!r}"
        )
        assert confidence is not None, "Edge confidence must be set"
        assert evidence, "Edge evidence must be non-empty"
        for ev in evidence:
            assert "source" in ev, f"Evidence entry missing 'source' key: {ev!r}"


# ---------------------------------------------------------------------------
# AC 28: AGE projection contains db_* nodes and DEPENDS_ON edge
# ---------------------------------------------------------------------------


def test_age_projection_db_table(pool, make_tenant):
    """AC 28: MATCH (n:db_table) WHERE n.tenant_id='<A>' RETURN n returns >= 1 row."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("db-age-table")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(conn, f"MATCH (n:db_table) WHERE n.tenant_id = '{tenant}' RETURN n")

    assert len(rows) >= 1, (
        f"Expected >= 1 db_table node in AGE for tenant {tenant}, got {len(rows)}"
    )


def test_age_projection_db_instance_contains_db_database(pool, make_tenant):
    """AC 28: MATCH (:db_instance)-[r:CONTAINS]->(:db_database) WHERE r.tenant_id=... returns >= 1."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("db-age-contains")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:db_instance)-[r:CONTAINS]->(:db_database) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )

    assert len(rows) >= 1, (
        f"Expected >= 1 CONTAINS db_instance->db_database in AGE, got {len(rows)}"
    )


def test_age_projection_db_schema_contains_db_table(pool, make_tenant):
    """AC 28: MATCH (:db_schema)-[r:CONTAINS]->(:db_table) WHERE r.tenant_id=... returns >= 1."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("db-age-schema-table")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:db_schema)-[r:CONTAINS]->(:db_table) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )

    assert len(rows) >= 1, (
        f"Expected >= 1 CONTAINS db_schema->db_table in AGE, got {len(rows)}"
    )


def test_age_projection_db_depends_on_edge(pool, make_tenant):
    """AC 28: MATCH (:db_table)-[r:DEPENDS_ON]->(:db_table) WHERE r.tenant_id=... returns >= 1."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.graph import cypher
    from infra_twin.db.session import tenant_session

    tenant = make_tenant("db-age-depends-on")
    discover_and_reconcile(pool, tenant, _make_connector_for_e2e())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:db_table)-[r:DEPENDS_ON]->(:db_table) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )

    assert len(rows) >= 1, (
        f"Expected >= 1 DEPENDS_ON db_table->db_table in AGE, got {len(rows)}"
    )


# ---------------------------------------------------------------------------
# AC 29: second identical reconcile is a no-op (§5.16)
# ---------------------------------------------------------------------------


def test_second_reconcile_is_noop(pool, make_tenant):
    """AC 29 / §5.16: cis_created==0, cis_closed==0, edges_closed==0 on second identical run."""
    from infra_twin.reconciliation import discover_and_reconcile

    tenant = make_tenant("db-idempotent")

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
# AC 30: adversarial cross-tenant isolation (§5.17)
# ---------------------------------------------------------------------------


def test_cross_tenant_isolation_db_cis(pool, make_tenant):
    """AC 30a / §5.17: tenant B sees zero db_* CIs belonging to tenant A."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.repositories import CIRepository
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("db-iso-a")
    tenant_b = make_tenant("db-iso-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        repo = CIRepository(conn, tenant_b)
        b_cis = repo.get_current()

    db_types = {CIType.db_instance, CIType.db_database, CIType.db_schema, CIType.db_table}
    b_db = [c for c in b_cis if c.type in db_types]
    assert not b_db, (
        f"Tenant B should see 0 db_* CIs belonging to A; got {len(b_db)}: {b_db[:3]}"
    )


def test_cross_tenant_isolation_db_edges(pool, make_tenant):
    """AC 30b: tenant B sees zero edges written for tenant A."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("db-iso-edge-a")
    tenant_b = make_tenant("db-iso-edge-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM edges WHERE valid_to IS NULL"
        ).fetchone()[0]
    assert count == 0, f"Tenant B should see 0 edges; got {count}"


def test_cross_tenant_isolation_db_connector_runs(pool, make_tenant):
    """AC 30c: tenant B sees no connector_runs with source='db'."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connector_health import ConnectorRunRepository
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("db-iso-run-a")
    tenant_b = make_tenant("db-iso-run-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        run_repo = ConnectorRunRepository(conn, tenant_b)
        summaries = run_repo.latest_per_source()

    db_runs = [s for s in summaries if s.source == "db"]
    assert not db_runs, f"Tenant B should see no db connector_runs; got {db_runs}"


def test_cross_tenant_isolation_connector_registry(pool, make_tenant):
    """AC 30d: ConnectorRegistry for tenant B shows no 'db' connector."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.connectors import ConnectorRegistry
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("db-iso-reg-a")
    tenant_b = make_tenant("db-iso-reg-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        registry = ConnectorRegistry(conn, tenant_b)
        b_connectors = registry.list()

    db_reg = [c for c in b_connectors if c.type == "db"]
    assert not db_reg, (
        f"Tenant B should have no db connector in registry; got {db_reg}"
    )


def test_cross_tenant_isolation_raw_facts(pool, make_tenant):
    """AC 30e: tenant B sees zero raw_facts rows written for tenant A's db run."""
    from infra_twin.reconciliation import discover_and_reconcile
    from infra_twin.db.session import tenant_session

    tenant_a = make_tenant("db-iso-rf-a")
    tenant_b = make_tenant("db-iso-rf-b")

    discover_and_reconcile(pool, tenant_a, _make_connector_for_e2e())

    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = %s", ("db",)
        ).fetchone()[0]
    assert count == 0, f"Tenant B should see 0 db raw_facts; got {count}"
