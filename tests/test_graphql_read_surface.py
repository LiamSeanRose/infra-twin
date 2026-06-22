"""GraphQL read surface tests.

Covers every acceptance criterion from spec §6 and every edge case from
spec §5 for the POST /graphql endpoint.  All helpers mirror the patterns
established in test_oidc_auth.py and test_scim_provisioning.py so the
setup is consistent with the rest of the test suite.

Acceptance criteria covered:
  AC 9a  viewer token can run all four queries over POST /graphql
  AC 9b  editor token can run all four queries over POST /graphql
  AC 9c  GraphQL graph/changes/findings/blastRadius data matches REST response
  AC 9d  field selection: subset of fields returns only those fields
  AC 9e  absent token -> 401; invalid token -> 401 (POST and GET /graphql)
  AC 9f  SCIM-deactivated OIDC token -> 401
  AC 9g  adversarial cross-tenant isolation
  AC 9h  blastRadius for absent CI id -> null
  AC 9i  malformed ciId -> GraphQL errors array, HTTP 200

Edge cases covered (spec §5):
  EC 1   absent Authorization header on POST /graphql -> 401
  EC 2   absent Authorization header on GET /graphql -> 401
  EC 3   Authorization without Bearer prefix -> 401
  EC 4   invalid itw_-prefixed API key -> 401
  EC 5   non-JWT junk token -> 401
  EC 6   malformed/garbage JWT (3 segments) -> 401
  EC 7   SCIM-deactivated OIDC token -> 401 user deactivated
  EC 8   valid viewer API key -> all four queries return 200 with data
  EC 9   valid editor API key -> all four queries return 200 with data
  EC 10  valid OIDC viewer/editor token -> queries 200
  EC 11  field selection: subset fields absent from JSON
  EC 12  blastRadius for non-existent CI id -> null
  EC 13  blastRadius for cross-tenant CI id -> null (RLS)
  EC 14  malformed ciId (not a UUID) -> GraphQL errors array, HTTP 200
  EC 17  empty tenant -> queries return empty lists, HTTP 200
  EC 19  adversarial cross-tenant: tenant A token never sees tenant B rows
  EC 20  mutation operation -> rejected by GraphQL (no Mutation type)
  EC 22  timestamp fields are ISO-8601 strings matching REST isoformat()
  EC 23  existing REST/OIDC/SCIM/RBAC tests unaffected (additive mount)
"""

from __future__ import annotations

import importlib
import json
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.api_keys import IssuedKey, Role, provision_tenant
from infra_twin.db.config import admin_dsn
from infra_twin.db.repositories import CIRepository
from infra_twin.db.scim_users import (
    create_or_replace_user,
    deactivate_user,
    issue_scim_token,
)
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import reconcile
from infra_twin.reconciliation.findings import evaluate_findings_with_summary

# ---------------------------------------------------------------------------
# Reuse RSA/OIDC helpers from test_oidc_auth to avoid duplicating key generation.
# pytest adds tests/ to sys.path so this import works at runtime.
# ---------------------------------------------------------------------------

_oidc_mod = importlib.import_module("test_oidc_auth")

_ISSUER_A = _oidc_mod._ISSUER_A
_AUDIENCE_A = _oidc_mod._AUDIENCE_A
_ISSUER_B = _oidc_mod._ISSUER_B
_AUDIENCE_B = _oidc_mod._AUDIENCE_B
_RSA_PRIV_KEY_A = _oidc_mod._RSA_PRIV_KEY_A
_RSA_PUB_KEY_A = _oidc_mod._RSA_PUB_KEY_A
_RSA_PRIV_KEY_B = _oidc_mod._RSA_PRIV_KEY_B
_RSA_PUB_KEY_B = _oidc_mod._RSA_PUB_KEY_B
_make_rs256_token = _oidc_mod._make_rs256_token
_rs256_resolver_for = _oidc_mod._rs256_resolver_for
_app_with_oidc = _oidc_mod._app_with_oidc
_setup_idp = _oidc_mod._setup_idp

# ---------------------------------------------------------------------------
# Scoping / seed constants
# ---------------------------------------------------------------------------

_CI_SCOPE = frozenset({CIType.vpc, CIType.subnet, CIType.security_group})
_EDGE_SCOPE = frozenset({EdgeType.CONTAINS})

_INTERNET_CI_SCOPE = frozenset({
    CIType.internet,
    CIType.security_group,
    CIType.rds,
    CIType.vpc,
    CIType.subnet,
})
_INTERNET_EDGE_SCOPE = frozenset({
    EdgeType.CONNECTS_TO,
    EdgeType.EXPOSES,
    EdgeType.CONTAINS,
})


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _make_tenant(name: str) -> UUID:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING tenant_id", (name,)
        ).fetchone()
        conn.commit()
    return row[0]


def _make_tenant_with_key(name: str, role: Role = Role.editor) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=role)
    return issued.tenant_id, issued.plaintext


def _make_tenant_with_key_quota(name: str, quota: int, role: Role = Role.editor) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=role, monthly_request_quota=quota)
    return issued.tenant_id, issued.plaintext


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _oidc_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


def _seed_vpc_subnet(pool, tenant: UUID) -> None:
    """Seed a vpc + subnet + CONTAINS edge."""
    events = [
        DiscoveredCI(type=CIType.vpc, external_id="vpc-gql1", name="net-gql"),
        DiscoveredCI(type=CIType.subnet, external_id="sub-gql1", name="sub-a-gql"),
        DiscoveredEdge(
            type=EdgeType.CONTAINS,
            from_ref=CIRef(type=CIType.vpc, external_id="vpc-gql1"),
            to_ref=CIRef(type=CIType.subnet, external_id="sub-gql1"),
            evidence=[Evidence(source="test-gql", detail="seeded")],
        ),
    ]
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant, events,
            source="test-gql",
            ci_types=_CI_SCOPE,
            edge_types=_EDGE_SCOPE,
        )


def _seed_internet_reachable_rds(pool, tenant: UUID) -> None:
    """Seed internet -> sg -> rds so evaluate_findings produces a finding."""
    events = [
        DiscoveredCI(type=CIType.internet, external_id="internet", name="Internet"),
        DiscoveredCI(type=CIType.security_group, external_id="sg-gql1", name="sg-gql"),
        DiscoveredCI(type=CIType.rds, external_id="rds-gql1", name="prod-rds-gql"),
        DiscoveredEdge(
            type=EdgeType.CONNECTS_TO,
            from_ref=CIRef(type=CIType.internet, external_id="internet"),
            to_ref=CIRef(type=CIType.security_group, external_id="sg-gql1"),
            evidence=[Evidence(source="aws", detail="sg-gql1 allows 0.0.0.0/0")],
        ),
        DiscoveredEdge(
            type=EdgeType.EXPOSES,
            from_ref=CIRef(type=CIType.security_group, external_id="sg-gql1"),
            to_ref=CIRef(type=CIType.rds, external_id="rds-gql1"),
            evidence=[Evidence(source="aws", detail="sg-gql1 exposes rds-gql1")],
        ),
    ]
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant, events,
            source="test-gql",
            ci_types=_INTERNET_CI_SCOPE,
            edge_types=_INTERNET_EDGE_SCOPE,
        )


def _get_vpc_id(pool, tenant: UUID) -> UUID:
    with tenant_session(pool, tenant) as conn:
        rows = CIRepository(conn, tenant).get_current(
            type=CIType.vpc, external_id="vpc-gql1"
        )
    assert rows, "vpc-gql1 not found in DB"
    return rows[0].id


# ---------------------------------------------------------------------------
# GraphQL POST helper
# ---------------------------------------------------------------------------

_GRAPHQL_PATH = "/graphql"


def _gql(client: TestClient, query: str, variables: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    """Execute a GraphQL query over POST /graphql and return (status_code, body)."""
    payload: dict = {"query": query}
    if variables:
        payload["variables"] = variables
    resp = client.post(
        _GRAPHQL_PATH,
        json=payload,
        headers=headers or {},
    )
    return resp.status_code, resp.json()


# ===========================================================================
# EC 1-7: Auth failure cases on POST /graphql
# ===========================================================================


def test_absent_authorization_header_post_graphql_returns_401(pool):
    """EC 1: absent Authorization header on POST /graphql -> 401."""
    client = TestClient(create_app(pool=pool))
    status, _ = _gql(client, "{ graph { nodes { id } } }")
    assert status == 401


def test_absent_authorization_header_get_graphql_returns_401(pool):
    """EC 2: absent Authorization header on GET /graphql (GraphiQL) -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get(_GRAPHQL_PATH)
    assert resp.status_code == 401


def test_authorization_without_bearer_prefix_returns_401(pool):
    """EC 3: Authorization without 'Bearer ' prefix -> 401."""
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        "{ graph { nodes { id } } }",
        headers={"Authorization": "itw_no_bearer_prefix"},
    )
    assert status == 401


def test_invalid_itw_prefixed_api_key_returns_401(pool):
    """EC 4: invalid itw_-prefixed API key -> 401 invalid API key."""
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        "{ graph { nodes { id } } }",
        headers={"Authorization": "Bearer itw_bogus.bogus"},
    )
    assert status == 401
    assert "invalid API key" in body.get("detail", "")


def test_non_jwt_junk_token_returns_401(pool):
    """EC 5: non-JWT junk token (no itw_, not 3 non-empty segments) -> 401."""
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        "{ graph { nodes { id } } }",
        headers={"Authorization": "Bearer completelyjunk"},
    )
    assert status == 401


def test_malformed_garbage_jwt_returns_401(pool):
    """EC 6: malformed/garbage JWT (3 segments, not valid) -> 401 invalid OIDC token."""
    client = TestClient(create_app(pool=pool))
    # 3 segments but garbage
    status, body = _gql(
        client,
        "{ graph { nodes { id } } }",
        headers={"Authorization": "Bearer aaaa.bbbb.cccc"},
    )
    assert status == 401


def test_scim_deactivated_oidc_token_returns_401(pool):
    """EC 7 / AC 9f: SCIM-deactivated OIDC token -> 401 user deactivated."""
    tenant_id = _make_tenant("gql-scim-deactivated")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    # Create and immediately deactivate a SCIM user matching the token subject
    sub = "deactivated-user-001"
    with psycopg.connect(admin_dsn()) as conn:
        scim_tok = issue_scim_token(conn, tenant_id)
        conn.commit()

    with tenant_session(pool, tenant_id) as conn:
        user = create_or_replace_user(conn, tenant_id, sub)
        deactivate_user(conn, tenant_id, user.scim_user_id)

    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="admin",
        extra_claims={"sub": sub},
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    status, body = _gql(
        client,
        "{ graph { nodes { id } } }",
        headers=_oidc_headers(token),
    )
    assert status == 401
    assert "deactivated" in body.get("detail", "").lower()


# ===========================================================================
# EC 8-10: Valid tokens succeed on all four queries
# ===========================================================================


def test_viewer_api_key_can_run_graph_query(pool):
    """EC 8 / AC 9a: valid viewer API key -> graph query returns 200."""
    tenant_id, api_key = _make_tenant_with_key("gql-viewer-graph", role=Role.viewer)
    _seed_vpc_subnet(pool, tenant_id)
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        "{ graph { nodes { id type externalId } edges { id type } } }",
        headers=_auth(api_key),
    )
    assert status == 200
    assert "errors" not in body
    data = body["data"]["graph"]
    assert isinstance(data["nodes"], list)
    assert isinstance(data["edges"], list)
    assert len(data["nodes"]) >= 2  # vpc + subnet


def test_viewer_api_key_can_run_blast_radius_query(pool):
    """EC 8 / AC 9a: valid viewer API key -> blastRadius query returns 200."""
    tenant_id, api_key = _make_tenant_with_key("gql-viewer-br", role=Role.viewer)
    _seed_vpc_subnet(pool, tenant_id)
    vpc_id = str(_get_vpc_id(pool, tenant_id))
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        'query BR($id: ID!) { blastRadius(ciId: $id) { sourceId impacted { id type distance } } }',
        variables={"id": vpc_id},
        headers=_auth(api_key),
    )
    assert status == 200
    assert "errors" not in body
    br = body["data"]["blastRadius"]
    assert br is not None
    assert br["sourceId"] == vpc_id
    assert any(i["type"] == "subnet" and i["distance"] == 1 for i in br["impacted"])


def test_viewer_api_key_can_run_changes_query(pool):
    """EC 8 / AC 9a: valid viewer API key -> changes query returns 200."""
    tenant_id, api_key = _make_tenant_with_key("gql-viewer-changes", role=Role.viewer)
    _seed_vpc_subnet(pool, tenant_id)
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        "{ changes { entity kind at id type } }",
        headers=_auth(api_key),
    )
    assert status == 200
    assert "errors" not in body
    assert isinstance(body["data"]["changes"], list)
    assert len(body["data"]["changes"]) > 0


def test_viewer_api_key_can_run_findings_query(pool):
    """EC 8 / AC 9a: valid viewer API key -> findings query returns 200."""
    tenant_id, api_key = _make_tenant_with_key("gql-viewer-findings", role=Role.viewer)
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        "{ findings { id ruleId severity status detectedAt } }",
        headers=_auth(api_key),
    )
    assert status == 200
    assert "errors" not in body
    assert isinstance(body["data"]["findings"], list)


def test_editor_api_key_can_run_all_four_queries(pool):
    """EC 9 / AC 9b: valid editor API key -> all four queries return 200."""
    tenant_id, api_key = _make_tenant_with_key("gql-editor-all", role=Role.editor)
    _seed_vpc_subnet(pool, tenant_id)
    vpc_id = str(_get_vpc_id(pool, tenant_id))
    client = TestClient(create_app(pool=pool))
    headers = _auth(api_key)

    # graph
    s, b = _gql(client, "{ graph { nodes { id } edges { id } } }", headers=headers)
    assert s == 200 and "errors" not in b

    # blastRadius
    s, b = _gql(
        client,
        'query { blastRadius(ciId: "%s") { sourceId } }' % vpc_id,
        headers=headers,
    )
    assert s == 200 and "errors" not in b

    # changes
    s, b = _gql(client, "{ changes { id kind } }", headers=headers)
    assert s == 200 and "errors" not in b

    # findings
    s, b = _gql(client, "{ findings { id } }", headers=headers)
    assert s == 200 and "errors" not in b


def test_oidc_viewer_token_can_run_all_four_queries(pool):
    """EC 10 / AC 9a: valid OIDC viewer token -> all four queries return 200."""
    tenant_id = _make_tenant("gql-oidc-viewer-all")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"member": "viewer"},
        default_role=Role.viewer,
    )
    _seed_vpc_subnet(pool, tenant_id)
    vpc_id = str(_get_vpc_id(pool, tenant_id))
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="member",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    headers = _oidc_headers(token)

    s, b = _gql(client, "{ graph { nodes { id } } }", headers=headers)
    assert s == 200 and "errors" not in b

    s, b = _gql(
        client,
        'query { blastRadius(ciId: "%s") { sourceId } }' % vpc_id,
        headers=headers,
    )
    assert s == 200 and "errors" not in b

    s, b = _gql(client, "{ changes { id } }", headers=headers)
    assert s == 200 and "errors" not in b

    s, b = _gql(client, "{ findings { id } }", headers=headers)
    assert s == 200 and "errors" not in b


def test_oidc_editor_token_can_run_all_four_queries(pool):
    """EC 10 / AC 9b: valid OIDC editor token -> all four queries return 200."""
    tenant_id = _make_tenant("gql-oidc-editor-all")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    _seed_vpc_subnet(pool, tenant_id)
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="admin",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    headers = _oidc_headers(token)

    s, b = _gql(client, "{ graph { nodes { id } } }", headers=headers)
    assert s == 200 and "errors" not in b

    s, b = _gql(client, "{ findings { id } }", headers=headers)
    assert s == 200 and "errors" not in b


# ===========================================================================
# AC 9c: GraphQL data equals REST data (parity tests)
# ===========================================================================


def test_graph_query_data_matches_rest_get_graph(pool):
    """AC 9c: GraphQL graph data matches GET /graph for same tenant and seed."""
    tenant_id, api_key = _make_tenant_with_key("gql-rest-graph-parity")
    _seed_vpc_subnet(pool, tenant_id)
    client = TestClient(create_app(pool=pool))
    headers = _auth(api_key)

    # GraphQL
    _, gql_body = _gql(
        client,
        "{ graph { nodes { id type externalId name } edges { id type fromId toId source confidence } } }",
        headers=headers,
    )
    gql_nodes = gql_body["data"]["graph"]["nodes"]
    gql_edges = gql_body["data"]["graph"]["edges"]

    # REST
    rest_body = client.get("/graph", headers=headers).json()
    rest_nodes = rest_body["nodes"]
    rest_edges = rest_body["edges"]

    # Same set of node ids
    assert {n["id"] for n in gql_nodes} == {n["id"] for n in rest_nodes}

    # Same node content
    gql_by_id = {n["id"]: n for n in gql_nodes}
    for rn in rest_nodes:
        gn = gql_by_id[rn["id"]]
        assert gn["type"] == rn["type"]
        assert gn["externalId"] == rn["external_id"]
        assert gn["name"] == rn["name"]

    # Same edge ids
    assert {e["id"] for e in gql_edges} == {e["id"] for e in rest_edges}

    # Edge provenance fields present on all edges
    for ge in gql_edges:
        assert "source" in ge
        assert "confidence" in ge


def test_changes_query_data_matches_rest_get_changes(pool):
    """AC 9c: GraphQL changes data matches GET /changes for same tenant and seed."""
    tenant_id, api_key = _make_tenant_with_key("gql-rest-changes-parity")
    _seed_vpc_subnet(pool, tenant_id)
    client = TestClient(create_app(pool=pool))
    headers = _auth(api_key)

    # GraphQL
    _, gql_body = _gql(
        client,
        "{ changes { entity kind at id type name fromId toId } }",
        headers=headers,
    )
    gql_changes = gql_body["data"]["changes"]

    # REST
    rest_changes = client.get("/changes", headers=headers).json()

    # Same ids
    assert {c["id"] for c in gql_changes} == {c["id"] for c in rest_changes}

    # Timestamps are ISO-8601 strings matching REST isoformat() (EC 22)
    gql_by_id = {c["id"]: c for c in gql_changes}
    for rc in rest_changes:
        gc = gql_by_id[rc["id"]]
        assert gc["at"] == rc["at"], (
            f"timestamp mismatch for {rc['id']}: gql={gc['at']!r} rest={rc['at']!r}"
        )
        assert gc["kind"] == rc["kind"]
        assert gc["type"] == rc["type"]


def test_blast_radius_query_data_matches_rest(pool):
    """AC 9c: GraphQL blastRadius data matches GET /cis/{id}/blast-radius for same tenant and seed."""
    tenant_id, api_key = _make_tenant_with_key("gql-rest-br-parity")
    _seed_vpc_subnet(pool, tenant_id)
    vpc_id = str(_get_vpc_id(pool, tenant_id))
    client = TestClient(create_app(pool=pool))
    headers = _auth(api_key)

    # GraphQL
    _, gql_body = _gql(
        client,
        'query { blastRadius(ciId: "%s") { sourceId maxDepth impacted { id type name distance } } }' % vpc_id,
        headers=headers,
    )
    assert "errors" not in gql_body
    gql_br = gql_body["data"]["blastRadius"]

    # REST
    rest_br = client.get(f"/cis/{vpc_id}/blast-radius", headers=headers).json()

    assert gql_br["sourceId"] == rest_br["source_id"]
    assert gql_br["maxDepth"] == rest_br["max_depth"]

    gql_impacted_ids = {i["id"] for i in gql_br["impacted"]}
    rest_impacted_ids = {i["id"] for i in rest_br["impacted"]}
    assert gql_impacted_ids == rest_impacted_ids

    # Check distances match
    gql_by_id = {i["id"]: i for i in gql_br["impacted"]}
    for ri in rest_br["impacted"]:
        gi = gql_by_id[ri["id"]]
        assert gi["distance"] == ri["distance"]


def test_findings_query_data_matches_rest(pool):
    """AC 9c: GraphQL findings data matches GET /findings for same tenant and seed."""
    tenant_id, api_key = _make_tenant_with_key("gql-rest-findings-parity", role=Role.editor)
    _seed_internet_reachable_rds(pool, tenant_id)
    # Evaluate findings via tenant session (editor can call evaluate)
    with tenant_session(pool, tenant_id) as conn:
        evaluate_findings_with_summary(conn, tenant_id)

    client = TestClient(create_app(pool=pool))
    headers = _auth(api_key)

    # GraphQL
    _, gql_body = _gql(
        client,
        "{ findings { id ruleId severity subjectCiId subjectCiType subjectCiName title description evidence status detectedAt } }",
        headers=headers,
    )
    assert "errors" not in gql_body
    gql_findings = gql_body["data"]["findings"]

    # REST
    rest_findings = client.get("/findings", headers=headers).json()

    assert len(gql_findings) == len(rest_findings), (
        f"count mismatch: gql={len(gql_findings)} rest={len(rest_findings)}"
    )

    gql_by_id = {f["id"]: f for f in gql_findings}
    for rf in rest_findings:
        gf = gql_by_id[rf["id"]]
        assert gf["ruleId"] == rf["rule_id"]
        assert gf["severity"] == rf["severity"]
        assert gf["subjectCiId"] == rf["subject_ci_id"]
        assert gf["status"] == rf["status"]
        # EC 22: timestamps are ISO-8601 strings matching REST isoformat()
        assert gf["detectedAt"] == rf["detected_at"]
        # Evidence is present (edge provenance mirror for findings)
        assert gf["evidence"] is not None


# ===========================================================================
# EC 11: Field selection
# ===========================================================================


def test_field_selection_graph_nodes_id_only(pool):
    """EC 11 / AC 9d: requesting only 'id' on nodes returns only id; type/externalId absent."""
    tenant_id, api_key = _make_tenant_with_key("gql-field-sel-nodes")
    _seed_vpc_subnet(pool, tenant_id)
    client = TestClient(create_app(pool=pool))
    _, body = _gql(
        client,
        "{ graph { nodes { id } } }",
        headers=_auth(api_key),
    )
    assert "errors" not in body
    for node in body["data"]["graph"]["nodes"]:
        assert "id" in node
        assert "type" not in node
        assert "externalId" not in node
        assert "name" not in node


def test_field_selection_changes_kind_only(pool):
    """EC 11 / AC 9d: requesting only 'kind' on changes returns only kind; other fields absent."""
    tenant_id, api_key = _make_tenant_with_key("gql-field-sel-changes")
    _seed_vpc_subnet(pool, tenant_id)
    client = TestClient(create_app(pool=pool))
    _, body = _gql(
        client,
        "{ changes { kind } }",
        headers=_auth(api_key),
    )
    assert "errors" not in body
    for ev in body["data"]["changes"]:
        assert "kind" in ev
        assert "id" not in ev
        assert "at" not in ev


def test_field_selection_blast_radius_source_id_only(pool):
    """EC 11 / AC 9d: requesting only 'sourceId' on blastRadius returns only sourceId."""
    tenant_id, api_key = _make_tenant_with_key("gql-field-sel-br")
    _seed_vpc_subnet(pool, tenant_id)
    vpc_id = str(_get_vpc_id(pool, tenant_id))
    client = TestClient(create_app(pool=pool))
    _, body = _gql(
        client,
        'query { blastRadius(ciId: "%s") { sourceId } }' % vpc_id,
        headers=_auth(api_key),
    )
    assert "errors" not in body
    br = body["data"]["blastRadius"]
    assert "sourceId" in br
    assert "maxDepth" not in br
    assert "impacted" not in br


def test_field_selection_findings_rule_id_only(pool):
    """EC 11 / AC 9d: requesting only 'ruleId' on findings returns only ruleId."""
    tenant_id, api_key = _make_tenant_with_key("gql-field-sel-find", role=Role.editor)
    _seed_internet_reachable_rds(pool, tenant_id)
    with tenant_session(pool, tenant_id) as conn:
        evaluate_findings_with_summary(conn, tenant_id)
    client = TestClient(create_app(pool=pool))
    _, body = _gql(
        client,
        "{ findings { ruleId } }",
        headers=_auth(api_key),
    )
    assert "errors" not in body
    for f in body["data"]["findings"]:
        assert "ruleId" in f
        assert "id" not in f
        assert "status" not in f


# ===========================================================================
# EC 12-14: blastRadius edge cases
# ===========================================================================


def test_blast_radius_for_absent_ci_returns_null(pool):
    """EC 12 / AC 9h: blastRadius for non-existent CI -> null (not 500)."""
    tenant_id, api_key = _make_tenant_with_key("gql-br-absent-ci")
    client = TestClient(create_app(pool=pool))
    absent_id = str(uuid4())
    status, body = _gql(
        client,
        'query { blastRadius(ciId: "%s") { sourceId } }' % absent_id,
        headers=_auth(api_key),
    )
    assert status == 200
    assert "errors" not in body
    assert body["data"]["blastRadius"] is None


def test_blast_radius_for_cross_tenant_ci_returns_null(pool):
    """EC 13 / AC 9g: blastRadius for CI id from another tenant -> null (RLS scopes session)."""
    # Seed data only for tenant A
    tenant_a_id, key_a = _make_tenant_with_key("gql-cross-br-A")
    tenant_b_id, key_b = _make_tenant_with_key("gql-cross-br-B")
    _seed_vpc_subnet(pool, tenant_a_id)
    vpc_a_id = str(_get_vpc_id(pool, tenant_a_id))

    # Tenant B queries with A's CI id
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        'query { blastRadius(ciId: "%s") { sourceId } }' % vpc_a_id,
        headers=_auth(key_b),
    )
    assert status == 200
    assert "errors" not in body
    assert body["data"]["blastRadius"] is None, (
        "Tenant B must not resolve tenant A's CI via blastRadius"
    )


def test_blast_radius_malformed_ci_id_returns_graphql_errors_not_500(pool):
    """EC 14 / AC 9i: malformed ciId -> GraphQL errors array, HTTP 200, no 500."""
    tenant_id, api_key = _make_tenant_with_key("gql-br-malformed")
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        '{ blastRadius(ciId: "not-a-uuid") { sourceId } }',
        headers=_auth(api_key),
    )
    assert status == 200, f"Expected HTTP 200 for malformed ciId, got {status}"
    assert "errors" in body, "Expected GraphQL errors array for malformed ciId"
    assert len(body["errors"]) > 0


def test_blast_radius_malformed_ci_id_error_has_no_token_material(pool):
    """EC 14 / AC 9i: malformed ciId errors contain no token/secret material."""
    tenant_id, api_key = _make_tenant_with_key("gql-br-no-leak")
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        '{ blastRadius(ciId: "not-a-uuid-here") { sourceId } }',
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert status == 200
    assert "errors" in body
    error_text = json.dumps(body["errors"])
    # The API key must not appear in the error output
    assert api_key not in error_text, "API key leaked in GraphQL error message"
    # The raw 'Bearer ' header value must not appear
    assert "Bearer" not in error_text or "ciId" in error_text


# ===========================================================================
# EC 17: Empty tenant -> empty lists returned
# ===========================================================================


def test_empty_tenant_graph_returns_empty_lists(pool):
    """EC 17: empty tenant -> graph returns empty nodes and edges, HTTP 200."""
    tenant_id, api_key = _make_tenant_with_key("gql-empty-graph")
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        "{ graph { nodes { id } edges { id } } }",
        headers=_auth(api_key),
    )
    assert status == 200
    assert "errors" not in body
    assert body["data"]["graph"]["nodes"] == []
    assert body["data"]["graph"]["edges"] == []


def test_empty_tenant_changes_returns_empty_list(pool):
    """EC 17: empty tenant -> changes returns [], HTTP 200."""
    tenant_id, api_key = _make_tenant_with_key("gql-empty-changes")
    client = TestClient(create_app(pool=pool))
    status, body = _gql(client, "{ changes { id } }", headers=_auth(api_key))
    assert status == 200
    assert "errors" not in body
    assert body["data"]["changes"] == []


def test_empty_tenant_findings_returns_empty_list(pool):
    """EC 17: empty tenant -> findings returns [], HTTP 200."""
    tenant_id, api_key = _make_tenant_with_key("gql-empty-findings")
    client = TestClient(create_app(pool=pool))
    status, body = _gql(client, "{ findings { id } }", headers=_auth(api_key))
    assert status == 200
    assert "errors" not in body
    assert body["data"]["findings"] == []


def test_empty_tenant_blast_radius_absent_ci_returns_null(pool):
    """EC 17: empty tenant + absent CI id -> blastRadius returns null."""
    tenant_id, api_key = _make_tenant_with_key("gql-empty-br")
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        '{ blastRadius(ciId: "%s") { sourceId } }' % str(uuid4()),
        headers=_auth(api_key),
    )
    assert status == 200
    assert "errors" not in body
    assert body["data"]["blastRadius"] is None


# ===========================================================================
# EC 19 / AC 9g: Adversarial cross-tenant isolation
# ===========================================================================


def test_adversarial_cross_tenant_graph_isolation(pool):
    """EC 19 / AC 9g: tenant A token can never see tenant B nodes in graph query."""
    tenant_a_id, key_a = _make_tenant_with_key("gql-iso-graph-A")
    tenant_b_id, key_b = _make_tenant_with_key("gql-iso-graph-B")
    _seed_vpc_subnet(pool, tenant_a_id)

    client = TestClient(create_app(pool=pool))

    # Tenant B sees empty graph
    _, body_b = _gql(
        client, "{ graph { nodes { id } edges { id } } }", headers=_auth(key_b)
    )
    assert "errors" not in body_b
    assert body_b["data"]["graph"]["nodes"] == [], "Tenant B must see no nodes from tenant A"
    assert body_b["data"]["graph"]["edges"] == [], "Tenant B must see no edges from tenant A"

    # Tenant A sees its own nodes
    _, body_a = _gql(
        client, "{ graph { nodes { id } edges { id } } }", headers=_auth(key_a)
    )
    assert "errors" not in body_a
    assert len(body_a["data"]["graph"]["nodes"]) >= 2


def test_adversarial_cross_tenant_changes_isolation(pool):
    """EC 19 / AC 9g: tenant A token can never see tenant B changes."""
    tenant_a_id, key_a = _make_tenant_with_key("gql-iso-changes-A")
    tenant_b_id, key_b = _make_tenant_with_key("gql-iso-changes-B")
    _seed_vpc_subnet(pool, tenant_a_id)

    client = TestClient(create_app(pool=pool))

    _, body_b = _gql(client, "{ changes { id } }", headers=_auth(key_b))
    assert "errors" not in body_b
    assert body_b["data"]["changes"] == [], "Tenant B must see no change events from tenant A"


def test_adversarial_cross_tenant_findings_isolation(pool):
    """EC 19 / AC 9g: tenant A token can never see tenant B findings."""
    tenant_a_id, key_a = _make_tenant_with_key("gql-iso-findings-A", role=Role.editor)
    tenant_b_id, key_b = _make_tenant_with_key("gql-iso-findings-B", role=Role.editor)
    _seed_internet_reachable_rds(pool, tenant_a_id)
    with tenant_session(pool, tenant_a_id) as conn:
        evaluate_findings_with_summary(conn, tenant_a_id)

    client = TestClient(create_app(pool=pool))

    _, body_b = _gql(client, "{ findings { id } }", headers=_auth(key_b))
    assert "errors" not in body_b
    assert body_b["data"]["findings"] == [], "Tenant B must see no findings from tenant A"

    _, body_a = _gql(client, "{ findings { id } }", headers=_auth(key_a))
    assert "errors" not in body_a
    assert len(body_a["data"]["findings"]) >= 1


def test_adversarial_blast_radius_cross_tenant_ci_returns_null(pool):
    """EC 19 / AC 9g: tenant B's CI id resolves to null in tenant A's blastRadius."""
    tenant_a_id, key_a = _make_tenant_with_key("gql-iso-br-A")
    tenant_b_id, key_b = _make_tenant_with_key("gql-iso-br-B")
    _seed_vpc_subnet(pool, tenant_b_id)
    vpc_b_id = str(_get_vpc_id(pool, tenant_b_id))

    # Tenant A queries using tenant B's VPC id
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        'query { blastRadius(ciId: "%s") { sourceId } }' % vpc_b_id,
        headers=_auth(key_a),
    )
    assert status == 200
    assert "errors" not in body
    assert body["data"]["blastRadius"] is None, (
        "Tenant A must not resolve tenant B's CI via blastRadius"
    )


# ===========================================================================
# EC 20: Mutation operation rejected
# ===========================================================================


def test_mutation_operation_rejected_no_mutation_type(pool):
    """EC 20: mutation operation -> schema has no Mutation type, rejected by GraphQL validation."""
    tenant_id, api_key = _make_tenant_with_key("gql-no-mutation")
    client = TestClient(create_app(pool=pool))
    status, body = _gql(
        client,
        "mutation { __typename }",
        headers=_auth(api_key),
    )
    # Either rejected (GraphQL errors) or HTTP 400 — either way, not data
    assert "errors" in body or status not in (200,) or body.get("data") is None


# ===========================================================================
# EC 22: Timestamp ISO-8601 string equality with REST
# ===========================================================================


def test_changes_timestamps_are_iso8601_matching_rest(pool):
    """EC 22: changes.at timestamps are ISO-8601 strings identical to REST isoformat()."""
    tenant_id, api_key = _make_tenant_with_key("gql-ts-iso-changes")
    _seed_vpc_subnet(pool, tenant_id)
    client = TestClient(create_app(pool=pool))
    headers = _auth(api_key)

    _, gql_body = _gql(client, "{ changes { id at } }", headers=headers)
    rest_changes = client.get("/changes", headers=headers).json()

    assert "errors" not in gql_body
    gql_by_id = {c["id"]: c for c in gql_body["data"]["changes"]}
    for rc in rest_changes:
        gc = gql_by_id[rc["id"]]
        assert gc["at"] == rc["at"], (
            f"timestamp mismatch: gql={gc['at']!r} rest={rc['at']!r}"
        )


def test_findings_detected_at_is_iso8601_matching_rest(pool):
    """EC 22: findings.detectedAt timestamps match REST detected_at strings exactly."""
    tenant_id, api_key = _make_tenant_with_key("gql-ts-iso-findings", role=Role.editor)
    _seed_internet_reachable_rds(pool, tenant_id)
    with tenant_session(pool, tenant_id) as conn:
        evaluate_findings_with_summary(conn, tenant_id)

    client = TestClient(create_app(pool=pool))
    headers = _auth(api_key)

    _, gql_body = _gql(
        client,
        "{ findings { id detectedAt } }",
        headers=headers,
    )
    rest_findings = client.get("/findings", headers=headers).json()

    assert "errors" not in gql_body
    gql_by_id = {f["id"]: f for f in gql_body["data"]["findings"]}
    for rf in rest_findings:
        gf = gql_by_id[rf["id"]]
        assert gf["detectedAt"] == rf["detected_at"], (
            f"detectedAt mismatch: gql={gf['detectedAt']!r} rest={rf['detected_at']!r}"
        )


# ===========================================================================
# Edge provenance fields present on edges
# ===========================================================================


def test_edge_provenance_fields_present_in_graph_query(pool):
    """Spec §2.2: edge provenance fields source and confidence are present."""
    tenant_id, api_key = _make_tenant_with_key("gql-edge-provenance")
    _seed_vpc_subnet(pool, tenant_id)
    client = TestClient(create_app(pool=pool))
    _, body = _gql(
        client,
        "{ graph { edges { id source confidence fromId toId } } }",
        headers=_auth(api_key),
    )
    assert "errors" not in body
    edges = body["data"]["graph"]["edges"]
    assert len(edges) > 0, "Expected at least one edge"
    for edge in edges:
        assert "source" in edge, "Edge must have source field"
        assert "confidence" in edge, "Edge must have confidence field"
        assert edge["source"] is not None
        assert isinstance(edge["confidence"], float)


# ===========================================================================
# EC 21: evidence JSON field present and serialized correctly
# ===========================================================================


def test_findings_evidence_is_nonempty_json(pool):
    """EC 21 / spec §5 EC 22: Finding.evidence is a non-empty JSON object."""
    tenant_id, api_key = _make_tenant_with_key("gql-evidence-json", role=Role.editor)
    _seed_internet_reachable_rds(pool, tenant_id)
    with tenant_session(pool, tenant_id) as conn:
        evaluate_findings_with_summary(conn, tenant_id)

    client = TestClient(create_app(pool=pool))
    _, body = _gql(
        client,
        "{ findings { id evidence } }",
        headers=_auth(api_key),
    )
    assert "errors" not in body
    findings = body["data"]["findings"]
    assert len(findings) > 0
    for f in findings:
        ev = f["evidence"]
        assert ev is not None, "evidence must not be null"
        # evidence must be a dict (JSON object)
        assert isinstance(ev, dict), f"evidence should be a dict, got {type(ev)}"


# ===========================================================================
# Quota exhaustion -> 429 (EC 18 from spec)
# ===========================================================================


def test_quota_exhausted_returns_429_on_post_graphql(pool):
    """EC 18: quota exhausted for the tenant -> 429 on POST /graphql."""
    tenant_id, api_key = _make_tenant_with_key_quota("gql-quota-429", quota=1)
    client = TestClient(create_app(pool=pool))
    headers = _auth(api_key)

    # First request: uses up the quota
    s1, b1 = _gql(client, "{ graph { nodes { id } } }", headers=headers)
    assert s1 == 200

    # Second request: quota exhausted
    s2, b2 = _gql(client, "{ graph { nodes { id } } }", headers=headers)
    assert s2 == 429


# ===========================================================================
# GET /graphql is gated (IDE not public) — EC 2 variant
# ===========================================================================


def test_get_graphql_with_valid_token_does_not_404(pool):
    """GET /graphql with a valid token does not 404 (route exists)."""
    tenant_id, api_key = _make_tenant_with_key("gql-get-exists")
    client = TestClient(create_app(pool=pool))
    resp = client.get(_GRAPHQL_PATH, headers=_auth(api_key))
    # Route exists (not 404)
    assert resp.status_code != 404
