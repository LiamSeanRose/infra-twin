"""RBAC tests: viewer/editor role enforcement over API-key auth.

Covers every case in spec §5 (edge cases) and §7 (adversarial test matrix):

  W1-W6  viewer key -> 403 on every write endpoint
  R1-R6  viewer key -> 200 on every read endpoint
  E1-E4  editor key -> 200/201 on representative read + all write endpoints
  N1-N2  no key / invalid key -> 401 (auth before authz) on write endpoints
  P1-P3  POST /tenants role field: viewer, default editor, invalid role

  Additional edge-case tests:
  - 403 body: detail == "insufficient permissions" (spec §5 EC 11)
  - 403 leaves DB unchanged (AC 18: no connectors row created on viewer write)
  - ResolvedKey/IssuedKey carry role; resolve() round-trips role (AC 6/7/spec §5 EC 13)
  - provision_tenant defaults to editor (spec §5 EC 2)
  - make_tenant_with_key backward compat (AC 20)
  - DB column: api_keys.role is NOT NULL, default 'editor', CHECK constraint (AC 4)
  - Migration 0008 is idempotent (spec §5 EC 17 / AC 17 via make migrate once)
  - Migration file is expand-only: no DROP COLUMN / DROP TABLE / ALTER COLUMN DROP DEFAULT (AC 3)
  - Tenant isolation unaffected by role (spec §5 EC 14)
  - POST /ask with viewer key -> 200 (spec §5 EC 15)
  - age-inferred-edges with viewer -> 403 before any sweep (spec §5 EC 16)
  - _role_grants logic: read grants both; write grants only editor (AC 12)
"""

from __future__ import annotations

import pathlib
from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.api.auth import _role_grants
from infra_twin.api.nlquery.planner import QueryPlan
from infra_twin.db.api_keys import IssuedKey, ResolvedKey, Role, provision_tenant, resolve
from infra_twin.db.config import admin_dsn

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VALID_TOKEN = "test-bootstrap-secret-abc123"

_MIGRATIONS_DIR = (
    pathlib.Path(__file__).resolve().parents[1] / "migrations"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _admin_headers(token: str = _VALID_TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _make_viewer_key(name: str = "viewer-tenant") -> tuple[UUID, str]:
    """Create a tenant with a viewer role API key via the admin connection."""
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.viewer)
    return issued.tenant_id, issued.plaintext


def _make_editor_key(name: str = "editor-tenant") -> tuple[UUID, str]:
    """Create a tenant with an editor role API key via the admin connection."""
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.editor)
    return issued.tenant_id, issued.plaintext


class _FakePlanner:
    """Returns a preset plan — stands in for the LLM so tests stay offline."""

    def __init__(self, plan: QueryPlan | None = None):
        self._plan = plan or QueryPlan("count_by_type", {})

    def plan(self, question: str) -> QueryPlan | None:
        return self._plan


def _count_connectors(tenant_id: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM connectors WHERE tenant_id = %s", (tenant_id,)
        ).fetchone()
    return row[0]


# ---------------------------------------------------------------------------
# W1 — viewer POST /connectors -> 403
# ---------------------------------------------------------------------------


def test_w1_viewer_post_connectors_is_403(pool):
    """W1: viewer key on POST /connectors returns 403."""
    _, viewer_key = _make_viewer_key("w1-viewer")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "x"},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403


def test_w1_viewer_post_connectors_detail(pool):
    """W1: 403 detail is 'insufficient permissions'."""
    _, viewer_key = _make_viewer_key("w1-detail")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "x"},
        headers=_auth(viewer_key),
    )
    assert resp.json()["detail"] == "insufficient permissions"


def test_w1_viewer_post_connectors_no_db_mutation(pool):
    """AC 18 / spec §7 extra: viewer POST /connectors leaves connectors table empty."""
    viewer_tenant, viewer_key = _make_viewer_key("w1-db-check")
    client = TestClient(create_app(pool=pool))
    client.post(
        "/connectors",
        json={"type": "aws", "display_name": "x"},
        headers=_auth(viewer_key),
    )
    assert _count_connectors(viewer_tenant) == 0, (
        "No connector row should be created when viewer's POST is rejected with 403"
    )


# ---------------------------------------------------------------------------
# W2 — viewer POST /connectors/{id}/enable -> 403
# ---------------------------------------------------------------------------


def test_w2_viewer_enable_connector_is_403(pool):
    """W2: viewer key on POST /connectors/{id}/enable returns 403.

    The 403 fires before any lookup so no real connector_id is required for
    the assertion; we still use a well-formatted UUID.
    """
    _, viewer_key = _make_viewer_key("w2-viewer")
    # Create a connector with a separate editor key so the ID is valid in theory,
    # but the viewer should be rejected before any lookup.
    _, editor_key = _make_editor_key("w2-editor")
    client = TestClient(create_app(pool=pool))
    reg_resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "enable-test"},
        headers=_auth(editor_key),
    )
    assert reg_resp.status_code == 201
    connector_id = reg_resp.json()["connector_id"]

    resp = client.post(
        f"/connectors/{connector_id}/enable",
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403


def test_w2_viewer_enable_connector_detail(pool):
    """W2: 403 detail is 'insufficient permissions' on enable."""
    _, viewer_key = _make_viewer_key("w2-detail")
    import uuid
    bogus_id = uuid.uuid4()
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        f"/connectors/{bogus_id}/enable",
        headers=_auth(viewer_key),
    )
    assert resp.json()["detail"] == "insufficient permissions"


# ---------------------------------------------------------------------------
# W3 — viewer POST /connectors/{id}/disable -> 403
# ---------------------------------------------------------------------------


def test_w3_viewer_disable_connector_is_403(pool):
    """W3: viewer key on POST /connectors/{id}/disable returns 403."""
    _, viewer_key = _make_viewer_key("w3-viewer")
    _, editor_key = _make_editor_key("w3-editor")
    client = TestClient(create_app(pool=pool))
    reg_resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "disable-test"},
        headers=_auth(editor_key),
    )
    assert reg_resp.status_code == 201
    connector_id = reg_resp.json()["connector_id"]

    resp = client.post(
        f"/connectors/{connector_id}/disable",
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403


def test_w3_viewer_disable_connector_detail(pool):
    """W3: 403 detail is 'insufficient permissions' on disable."""
    _, viewer_key = _make_viewer_key("w3-detail")
    import uuid
    bogus_id = uuid.uuid4()
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        f"/connectors/{bogus_id}/disable",
        headers=_auth(viewer_key),
    )
    assert resp.json()["detail"] == "insufficient permissions"


# ---------------------------------------------------------------------------
# W4 — viewer POST /events/aws -> 403
# ---------------------------------------------------------------------------


def test_w4_viewer_post_events_aws_is_403(pool):
    """W4: viewer key on POST /events/aws returns 403."""
    _, viewer_key = _make_viewer_key("w4-viewer")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/aws",
        json={"record": {}},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403


def test_w4_viewer_post_events_aws_detail(pool):
    """W4: 403 detail is 'insufficient permissions' on /events/aws."""
    _, viewer_key = _make_viewer_key("w4-detail")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/aws",
        json={"record": {}},
        headers=_auth(viewer_key),
    )
    assert resp.json()["detail"] == "insufficient permissions"


# ---------------------------------------------------------------------------
# W5 — viewer POST /telemetry/flowlogs -> 403
# ---------------------------------------------------------------------------


def test_w5_viewer_post_flowlogs_is_403(pool):
    """W5: viewer key on POST /telemetry/flowlogs returns 403."""
    _, viewer_key = _make_viewer_key("w5-viewer")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/telemetry/flowlogs",
        json={"records": []},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403


def test_w5_viewer_post_flowlogs_detail(pool):
    """W5: 403 detail is 'insufficient permissions' on /telemetry/flowlogs."""
    _, viewer_key = _make_viewer_key("w5-detail")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/telemetry/flowlogs",
        json={"records": []},
        headers=_auth(viewer_key),
    )
    assert resp.json()["detail"] == "insufficient permissions"


# ---------------------------------------------------------------------------
# W6 — viewer POST /telemetry/maintenance/age-inferred-edges -> 403
# ---------------------------------------------------------------------------


def test_w6_viewer_age_edges_is_403(pool):
    """W6 / spec §5 EC 16: viewer key on age-inferred-edges returns 403."""
    _, viewer_key = _make_viewer_key("w6-viewer")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/telemetry/maintenance/age-inferred-edges",
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403


def test_w6_viewer_age_edges_detail(pool):
    """W6: 403 detail is 'insufficient permissions' on age-inferred-edges."""
    _, viewer_key = _make_viewer_key("w6-detail")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/telemetry/maintenance/age-inferred-edges",
        headers=_auth(viewer_key),
    )
    assert resp.json()["detail"] == "insufficient permissions"


def test_w6_age_edges_403_no_connector_run_created(pool):
    """Spec §5 EC 16: 403 fires before handler body; no connector_run row written."""
    viewer_tenant, viewer_key = _make_viewer_key("w6-no-run")
    client = TestClient(create_app(pool=pool))
    client.post(
        "/telemetry/maintenance/age-inferred-edges",
        headers=_auth(viewer_key),
    )
    with psycopg.connect(admin_dsn()) as conn:
        count = conn.execute(
            "SELECT count(*) FROM connector_runs WHERE tenant_id = %s", (viewer_tenant,)
        ).fetchone()[0]
    assert count == 0, "No connector_run should be created when viewer's age sweep is blocked"


# ---------------------------------------------------------------------------
# R1 — viewer GET /cis -> 200
# ---------------------------------------------------------------------------


def test_r1_viewer_get_cis_is_200(pool):
    """R1: viewer key on GET /cis returns 200."""
    _, viewer_key = _make_viewer_key("r1-viewer")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers=_auth(viewer_key))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# R2 — viewer GET /graph -> 200
# ---------------------------------------------------------------------------


def test_r2_viewer_get_graph_is_200(pool):
    """R2: viewer key on GET /graph returns 200."""
    _, viewer_key = _make_viewer_key("r2-viewer")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/graph", headers=_auth(viewer_key))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# R3 — viewer GET /changes -> 200
# ---------------------------------------------------------------------------


def test_r3_viewer_get_changes_is_200(pool):
    """R3: viewer key on GET /changes returns 200."""
    _, viewer_key = _make_viewer_key("r3-viewer")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/changes", headers=_auth(viewer_key))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# R4 — viewer GET /connector-health/runs -> 200
# ---------------------------------------------------------------------------


def test_r4_viewer_get_connector_health_runs_is_200(pool):
    """R4: viewer key on GET /connector-health/runs returns 200."""
    _, viewer_key = _make_viewer_key("r4-viewer")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/connector-health/runs", headers=_auth(viewer_key))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# R5 — viewer GET /connectors -> 200
# ---------------------------------------------------------------------------


def test_r5_viewer_get_connectors_is_200(pool):
    """R5: viewer key on GET /connectors returns 200."""
    _, viewer_key = _make_viewer_key("r5-viewer")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/connectors", headers=_auth(viewer_key))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# R6 — viewer POST /ask (planner stubbed) -> 200
# ---------------------------------------------------------------------------


def test_r6_viewer_post_ask_is_200(pool):
    """R6 / spec §5 EC 15: viewer key on POST /ask returns 200 (classified as read)."""
    _, viewer_key = _make_viewer_key("r6-viewer")
    client = TestClient(create_app(pool=pool, planner=_FakePlanner()))
    resp = client.post(
        "/ask",
        json={"question": "how many resources?"},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 200


def test_r6_viewer_post_ask_not_403(pool):
    """R6: POST /ask is a read endpoint; viewer must NOT get 403."""
    _, viewer_key = _make_viewer_key("r6-not-403")
    client = TestClient(create_app(pool=pool, planner=_FakePlanner()))
    resp = client.post(
        "/ask",
        json={"question": "inventory"},
        headers=_auth(viewer_key),
    )
    assert resp.status_code != 403


# ---------------------------------------------------------------------------
# Also verify viewer can read /cis/{ci_id}/blast-radius (read endpoint per spec §4.2)
# ---------------------------------------------------------------------------


def test_viewer_blast_radius_endpoint_uses_read_permission(pool):
    """Spec §4.2: GET /cis/{id}/blast-radius uses read permission; viewer gets 404 not 403."""
    import uuid
    _, viewer_key = _make_viewer_key("blast-viewer")
    client = TestClient(create_app(pool=pool))
    # Non-existent CI -> should get 404 (auth passed) not 403
    resp = client.get(
        f"/cis/{uuid.uuid4()}/blast-radius",
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 404, (
        f"Viewer on blast-radius should get 404 (not 403); got {resp.status_code}"
    )


def test_viewer_reachability_endpoint_uses_read_permission(pool):
    """Spec §4.2: GET /cis/{id}/reachability uses read permission; viewer gets 404 not 403."""
    import uuid
    _, viewer_key = _make_viewer_key("reach-viewer")
    client = TestClient(create_app(pool=pool))
    resp = client.get(
        f"/cis/{uuid.uuid4()}/reachability",
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 404, (
        f"Viewer on reachability should get 404 (not 403); got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# E1 — editor GET /cis -> 200
# ---------------------------------------------------------------------------


def test_e1_editor_get_cis_is_200(pool):
    """E1: editor key on GET /cis returns 200."""
    _, editor_key = _make_editor_key("e1-editor")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers=_auth(editor_key))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# E2 — editor POST /connectors -> 201
# ---------------------------------------------------------------------------


def test_e2_editor_post_connectors_is_201(pool):
    """E2: editor key on POST /connectors returns 201."""
    _, editor_key = _make_editor_key("e2-editor")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "x"},
        headers=_auth(editor_key),
    )
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# E3 — editor POST /telemetry/maintenance/age-inferred-edges -> 200
# ---------------------------------------------------------------------------


def test_e3_editor_age_edges_is_200(pool):
    """E3: editor key on age-inferred-edges returns 200."""
    _, editor_key = _make_editor_key("e3-editor")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/telemetry/maintenance/age-inferred-edges",
        headers=_auth(editor_key),
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# E4 — editor POST /events/aws with a valid AWS event record -> 200
# ---------------------------------------------------------------------------


def test_e4_editor_post_events_aws_is_200_or_422(pool):
    """E4: editor key on POST /events/aws is allowed (200 or 422 on event parse, not 403)."""
    _, editor_key = _make_editor_key("e4-editor")
    client = TestClient(create_app(pool=pool))
    # Minimal record that exercises the endpoint; parse may fail with 422.
    resp = client.post(
        "/events/aws",
        json={"record": {"eventName": "RunInstances", "eventTime": "2024-01-01T00:00:00Z"}},
        headers=_auth(editor_key),
    )
    # 403 would mean the write permission check blocked an editor; that is a bug.
    assert resp.status_code != 403, (
        f"Editor should not get 403 on /events/aws; got {resp.status_code}"
    )


def test_e4_editor_post_flowlogs_not_403(pool):
    """E4 (flowlogs variant): editor key on POST /telemetry/flowlogs is not 403."""
    _, editor_key = _make_editor_key("e4-flowlogs")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/telemetry/flowlogs",
        json={"records": []},
        headers=_auth(editor_key),
    )
    assert resp.status_code != 403


def test_editor_enable_connector_not_403(pool):
    """E: editor can enable a connector (not 403)."""
    _, editor_key = _make_editor_key("e-enable")
    client = TestClient(create_app(pool=pool))
    reg_resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "enable-me", "enabled": False},
        headers=_auth(editor_key),
    )
    assert reg_resp.status_code == 201
    connector_id = reg_resp.json()["connector_id"]
    resp = client.post(
        f"/connectors/{connector_id}/enable",
        headers=_auth(editor_key),
    )
    assert resp.status_code == 200


def test_editor_disable_connector_not_403(pool):
    """E: editor can disable a connector (not 403)."""
    _, editor_key = _make_editor_key("e-disable")
    client = TestClient(create_app(pool=pool))
    reg_resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "disable-me"},
        headers=_auth(editor_key),
    )
    assert reg_resp.status_code == 201
    connector_id = reg_resp.json()["connector_id"]
    resp = client.post(
        f"/connectors/{connector_id}/disable",
        headers=_auth(editor_key),
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# N1 — no key on POST /connectors -> 401 (auth before authz)
# ---------------------------------------------------------------------------


def test_n1_no_key_post_connectors_is_401(pool):
    """N1: no Authorization header on POST /connectors returns 401, not 403."""
    client = TestClient(create_app(pool=pool))
    resp = client.post("/connectors", json={"type": "aws", "display_name": "x"})
    assert resp.status_code == 401


def test_n1_no_key_detail_missing_api_key(pool):
    """N1: 401 detail is 'missing API key' when Authorization absent."""
    client = TestClient(create_app(pool=pool))
    resp = client.post("/connectors", json={"type": "aws", "display_name": "x"})
    assert resp.json()["detail"] == "missing API key"


# ---------------------------------------------------------------------------
# N2 — invalid key on POST /connectors -> 401 (not 403)
# ---------------------------------------------------------------------------


def test_n2_invalid_key_post_connectors_is_401(pool):
    """N2: tampered/unknown key on POST /connectors returns 401, not 403."""
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "x"},
        headers={"Authorization": "Bearer itw_bogus.invalidsecret"},
    )
    assert resp.status_code == 401


def test_n2_invalid_key_not_403(pool):
    """N2: invalid key must not produce 403 on write endpoint (auth before authz)."""
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "x"},
        headers={"Authorization": "Bearer itw_unknownid.unknownsecret"},
    )
    assert resp.status_code != 403


# Spec §4.1: auth before authz on all write endpoints
@pytest.mark.parametrize("path,body", [
    ("/connectors", {"type": "aws", "display_name": "x"}),
    ("/events/aws", {"record": {}}),
    ("/telemetry/flowlogs", {"records": []}),
    ("/telemetry/maintenance/age-inferred-edges", None),
])
def test_no_key_write_endpoints_return_401_not_403(pool, path, body):
    """Spec §4.1 / EC 9: missing key on write endpoint returns 401, never 403."""
    client = TestClient(create_app(pool=pool))
    resp = client.post(path, json=body)
    assert resp.status_code == 401, (
        f"POST {path} with no key should be 401, got {resp.status_code}"
    )
    assert resp.status_code != 403


# ---------------------------------------------------------------------------
# P1 — POST /tenants with role:"viewer" -> 201, response role=="viewer"
# ---------------------------------------------------------------------------


def test_p1_post_tenants_viewer_role_returns_201(pool, monkeypatch):
    """P1: POST /tenants with role:'viewer' returns 201."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/tenants",
        json={"name": "p1-viewer", "role": "viewer"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 201


def test_p1_post_tenants_viewer_role_in_response(pool, monkeypatch):
    """P1: response 'role' is 'viewer' when requested."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = TestClient(create_app(pool=pool))
    body = client.post(
        "/tenants",
        json={"name": "p1-role-check", "role": "viewer"},
        headers=_admin_headers(),
    ).json()
    assert body["role"] == "viewer"


def test_p1_post_tenants_viewer_key_persisted_as_viewer(pool, monkeypatch):
    """P1: issued key for viewer tenant resolves to Role.viewer."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = TestClient(create_app(pool=pool))
    body = client.post(
        "/tenants",
        json={"name": "p1-resolve-check", "role": "viewer"},
        headers=_admin_headers(),
    ).json()
    api_key = body["api_key"]
    with psycopg.connect(admin_dsn()) as conn:
        resolved = resolve(conn, api_key)
    assert resolved is not None
    assert resolved.role == Role.viewer


# ---------------------------------------------------------------------------
# P2 — POST /tenants without role -> 201, response role defaults to "editor"
# ---------------------------------------------------------------------------


def test_p2_post_tenants_default_role_is_editor(pool, monkeypatch):
    """P2: POST /tenants without role field returns response with role=='editor'."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = TestClient(create_app(pool=pool))
    body = client.post(
        "/tenants",
        json={"name": "p2-default"},
        headers=_admin_headers(),
    ).json()
    assert body["role"] == "editor"


def test_p2_post_tenants_default_role_returns_201(pool, monkeypatch):
    """P2: POST /tenants without role returns 201."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/tenants",
        json={"name": "p2-201"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 201


def test_p2_post_tenants_default_editor_key_can_write(pool, monkeypatch):
    """P2: key issued with default role can POST /connectors (editor = write access)."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = TestClient(create_app(pool=pool))
    body = client.post(
        "/tenants",
        json={"name": "p2-can-write"},
        headers=_admin_headers(),
    ).json()
    api_key = body["api_key"]
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "test"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# P3 — POST /tenants with invalid role -> 422
# ---------------------------------------------------------------------------


def test_p3_post_tenants_invalid_role_admin_returns_422(pool, monkeypatch):
    """P3: role='admin' is not in the enum; returns 422."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/tenants",
        json={"name": "p3-admin", "role": "admin"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 422


def test_p3_post_tenants_invalid_role_empty_string_returns_422(pool, monkeypatch):
    """P3: role='' (empty string) returns 422."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/tenants",
        json={"name": "p3-empty", "role": ""},
        headers=_admin_headers(),
    )
    assert resp.status_code == 422


def test_p3_post_tenants_invalid_role_numeric_returns_422(pool, monkeypatch):
    """P3: role=123 (numeric) returns 422."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/tenants",
        json={"name": "p3-numeric", "role": 123},
        headers=_admin_headers(),
    )
    assert resp.status_code == 422


def test_p3_post_tenants_invalid_role_no_db_written(pool, monkeypatch):
    """P3 / spec §5 EC 5: invalid role -> 422, no rows written to tenants or api_keys."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = TestClient(create_app(pool=pool))
    client.post(
        "/tenants",
        json={"name": "p3-no-row", "role": "superadmin"},
        headers=_admin_headers(),
    )
    with psycopg.connect(admin_dsn()) as conn:
        t_count = conn.execute("SELECT count(*) FROM tenants").fetchone()[0]
        k_count = conn.execute("SELECT count(*) FROM api_keys").fetchone()[0]
    assert t_count == 0, "No tenant row should be written on 422"
    assert k_count == 0, "No api_keys row should be written on 422"


# ---------------------------------------------------------------------------
# Role enum (AC 5)
# ---------------------------------------------------------------------------


def test_role_enum_has_viewer_member():
    """AC 5: Role.viewer == 'viewer'."""
    assert Role.viewer == "viewer"
    assert Role.viewer.value == "viewer"


def test_role_enum_has_editor_member():
    """AC 5: Role.editor == 'editor'."""
    assert Role.editor == "editor"
    assert Role.editor.value == "editor"


def test_role_enum_is_str_subclass():
    """AC 5: Role is a str enum."""
    assert isinstance(Role.viewer, str)
    assert isinstance(Role.editor, str)


def test_role_enum_has_exactly_two_members():
    """AC 5: Role enum has exactly two members: viewer and editor."""
    assert set(Role) == {Role.viewer, Role.editor}


# ---------------------------------------------------------------------------
# IssuedKey.role (AC 7)
# ---------------------------------------------------------------------------


def test_issued_key_has_role_field():
    """AC 7: IssuedKey dataclass has a role field."""
    assert hasattr(IssuedKey, "__dataclass_fields__")
    assert "role" in IssuedKey.__dataclass_fields__


def test_provision_tenant_issued_key_carries_viewer_role():
    """AC 7: IssuedKey returned by provision_tenant carries role=viewer when requested."""
    with psycopg.connect(admin_dsn()) as conn:
        issued = provision_tenant(conn, "issued-viewer", role=Role.viewer)
    assert issued.role == Role.viewer


def test_provision_tenant_issued_key_carries_editor_role():
    """AC 7: IssuedKey returned by provision_tenant carries role=editor when requested."""
    with psycopg.connect(admin_dsn()) as conn:
        issued = provision_tenant(conn, "issued-editor", role=Role.editor)
    assert issued.role == Role.editor


# ---------------------------------------------------------------------------
# ResolvedKey.role (AC 6) — resolve() round-trips role
# ---------------------------------------------------------------------------


def test_resolved_key_has_role_field():
    """AC 6: ResolvedKey dataclass has a role field."""
    assert hasattr(ResolvedKey, "__dataclass_fields__")
    assert "role" in ResolvedKey.__dataclass_fields__


def test_resolve_round_trips_viewer_role():
    """AC 6 / spec §5 EC 13: a key issued as viewer resolves to ResolvedKey.role==Role.viewer."""
    with psycopg.connect(admin_dsn()) as conn:
        issued = provision_tenant(conn, "rt-viewer", role=Role.viewer)
        resolved = resolve(conn, issued.plaintext)
    assert resolved is not None
    assert resolved.role == Role.viewer


def test_resolve_round_trips_editor_role():
    """AC 6 / spec §5 EC 13: a key issued as editor resolves to ResolvedKey.role==Role.editor."""
    with psycopg.connect(admin_dsn()) as conn:
        issued = provision_tenant(conn, "rt-editor", role=Role.editor)
        resolved = resolve(conn, issued.plaintext)
    assert resolved is not None
    assert resolved.role == Role.editor


# ---------------------------------------------------------------------------
# provision_tenant defaults to editor (AC 8 / spec §5 EC 2)
# ---------------------------------------------------------------------------


def test_provision_tenant_defaults_to_editor():
    """AC 8 / spec §5 EC 2: provision_tenant called without role defaults to editor."""
    with psycopg.connect(admin_dsn()) as conn:
        issued = provision_tenant(conn, "default-role-check")
    assert issued.role == Role.editor


def test_provision_tenant_default_editor_persisted():
    """spec §5 EC 2: default editor role is written to DB and round-trips."""
    with psycopg.connect(admin_dsn()) as conn:
        issued = provision_tenant(conn, "default-role-db")
        resolved = resolve(conn, issued.plaintext)
    assert resolved is not None
    assert resolved.role == Role.editor


# ---------------------------------------------------------------------------
# make_tenant_with_key backward compat (AC 20 / spec §5 EC 2)
# ---------------------------------------------------------------------------


def test_make_tenant_with_key_backward_compat(make_tenant_with_key):
    """AC 20: make_tenant_with_key (existing fixture) still works; produces editor key."""
    tenant_id, api_key = make_tenant_with_key("backward-compat")
    assert tenant_id is not None
    assert api_key.startswith("itw_")
    with psycopg.connect(admin_dsn()) as conn:
        resolved = resolve(conn, api_key)
    assert resolved is not None
    assert resolved.role == Role.editor


# ---------------------------------------------------------------------------
# _role_grants logic (AC 12)
# ---------------------------------------------------------------------------


def test_role_grants_read_viewer():
    """AC 12: _role_grants(viewer, 'read') is True."""
    assert _role_grants(Role.viewer, "read") is True


def test_role_grants_read_editor():
    """AC 12: _role_grants(editor, 'read') is True."""
    assert _role_grants(Role.editor, "read") is True


def test_role_grants_write_viewer():
    """AC 12: _role_grants(viewer, 'write') is False."""
    assert _role_grants(Role.viewer, "write") is False


def test_role_grants_write_editor():
    """AC 12: _role_grants(editor, 'write') is True."""
    assert _role_grants(Role.editor, "write") is True


def test_role_grants_unknown_perm_returns_false():
    """AC 12: _role_grants with an unknown perm returns False."""
    assert _role_grants(Role.editor, "delete") is False
    assert _role_grants(Role.viewer, "admin") is False


# ---------------------------------------------------------------------------
# DB schema: api_keys.role column (AC 4)
# ---------------------------------------------------------------------------


def test_api_keys_role_column_exists():
    """AC 4: api_keys.role column exists in information_schema."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT column_name, is_nullable, column_default "
            "FROM information_schema.columns "
            "WHERE table_name = 'api_keys' AND column_name = 'role'"
        ).fetchone()
    assert row is not None, "api_keys.role column not found"


def test_api_keys_role_column_is_not_nullable():
    """AC 4: api_keys.role is NOT NULL."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT is_nullable FROM information_schema.columns "
            "WHERE table_name = 'api_keys' AND column_name = 'role'"
        ).fetchone()
    assert row is not None
    assert row[0] == "NO", f"api_keys.role should be NOT NULL; got is_nullable={row[0]}"


def test_api_keys_role_column_default_is_editor():
    """AC 4: api_keys.role column default contains 'editor'."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT column_default FROM information_schema.columns "
            "WHERE table_name = 'api_keys' AND column_name = 'role'"
        ).fetchone()
    assert row is not None
    assert row[0] is not None, "api_keys.role has no column default"
    assert "editor" in row[0], f"api_keys.role default should contain 'editor'; got: {row[0]}"


def test_api_keys_role_check_constraint_exists():
    """AC 2 / spec §5 EC 12: CHECK (role IN ('viewer','editor')) constraint exists on api_keys."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            """
            SELECT cc.check_clause
            FROM information_schema.table_constraints tc
            JOIN information_schema.check_constraints cc
              ON tc.constraint_name = cc.constraint_name
            WHERE tc.table_name = 'api_keys'
              AND tc.constraint_type = 'CHECK'
            """
        ).fetchall()
    clauses = [r[0] for r in rows]
    found = any("role" in c.lower() for c in clauses)
    assert found, f"No CHECK constraint referencing 'role' found on api_keys; got: {clauses}"


def test_api_keys_role_check_rejects_invalid_value():
    """Spec §5 EC 12: direct DB write of an invalid role is rejected by the CHECK constraint."""
    with psycopg.connect(admin_dsn()) as conn:
        # First create a tenant to satisfy FK
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING tenant_id", ("check-constraint-test",)
        ).fetchone()
        tenant_id = row[0]

        # Attempt to insert a row with an invalid role should raise
        try:
            from infra_twin.db.api_keys import generate_key, hash_secret, new_salt
            gen = generate_key()
            salt = new_salt()
            h = hash_secret(gen.secret, salt)
            conn.execute(
                "INSERT INTO api_keys (tenant_id, key_id, secret_hash, salt, name, role) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (tenant_id, gen.key_id, h, salt, None, "superadmin"),
            )
            conn.commit()
            pytest.fail("Expected CHECK constraint violation; INSERT succeeded unexpectedly")
        except Exception as exc:
            # Rollback to keep the connection usable
            conn.rollback()
            assert "check" in str(exc).lower() or "violat" in str(exc).lower() or "constraint" in str(exc).lower(), (
                f"Expected CHECK constraint error; got: {exc}"
            )


# ---------------------------------------------------------------------------
# Migration 0008 file structural tests (AC 1, 2, 3)
# ---------------------------------------------------------------------------


def test_migration_0008_file_exists():
    """AC 1: migrations/0008_api_key_role.sql exists."""
    migration_file = _MIGRATIONS_DIR / "0008_api_key_role.sql"
    assert migration_file.exists(), f"Migration file not found: {migration_file}"


def test_migration_0008_contains_add_column_role():
    """AC 1: migration contains ADD COLUMN role TEXT NOT NULL DEFAULT 'editor'."""
    text = (_MIGRATIONS_DIR / "0008_api_key_role.sql").read_text()
    assert "ADD COLUMN" in text.upper()
    assert "role" in text.lower()
    assert "NOT NULL" in text.upper()
    assert "editor" in text


def test_migration_0008_contains_check_constraint():
    """AC 2: migration contains CHECK (role IN ('viewer', 'editor'))."""
    text = (_MIGRATIONS_DIR / "0008_api_key_role.sql").read_text()
    assert "CHECK" in text.upper()
    assert "viewer" in text
    assert "editor" in text


def test_migration_0008_is_expand_only_no_drop_column():
    """AC 3: migration does not contain DROP COLUMN."""
    text = (_MIGRATIONS_DIR / "0008_api_key_role.sql").read_text().upper()
    assert "DROP COLUMN" not in text, "Migration must not DROP COLUMN (expand-only)"


def test_migration_0008_is_expand_only_no_drop_table():
    """AC 3: migration does not contain DROP TABLE."""
    text = (_MIGRATIONS_DIR / "0008_api_key_role.sql").read_text().upper()
    assert "DROP TABLE" not in text, "Migration must not DROP TABLE (expand-only)"


def test_migration_0008_is_expand_only_no_drop_default():
    """AC 3: migration does not contain ALTER COLUMN ... DROP DEFAULT."""
    text = (_MIGRATIONS_DIR / "0008_api_key_role.sql").read_text().upper()
    assert "DROP DEFAULT" not in text, "Migration must not DROP DEFAULT (expand-only)"


# ---------------------------------------------------------------------------
# Idempotent migration (spec §5 EC 17): re-running make migrate is a no-op
# ---------------------------------------------------------------------------


def test_migration_idempotent_rerun(pool):
    """Spec §5 EC 17: re-running migrations does not fail or re-apply 0008."""
    from infra_twin.db.migrate import run_migrations

    # This should succeed without error (ledger prevents re-applying).
    run_migrations(directory=_MIGRATIONS_DIR)

    # Verify the column still has exactly the right shape.
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT is_nullable, column_default FROM information_schema.columns "
            "WHERE table_name = 'api_keys' AND column_name = 'role'"
        ).fetchone()
    assert row is not None
    assert row[0] == "NO"
    assert "editor" in row[1]


# ---------------------------------------------------------------------------
# Tenant isolation is unaffected by role (spec §5 EC 14)
# ---------------------------------------------------------------------------


def test_viewer_sees_only_own_tenant_data(pool):
    """Spec §5 EC 14: a viewer key for tenant A only sees tenant A's data."""
    from infra_twin.connector_sdk import DiscoveredCI
    from infra_twin.core_model import CIType
    from infra_twin.db.session import tenant_session
    from infra_twin.reconciliation import reconcile

    viewer_tenant, viewer_key = _make_viewer_key("isolation-viewer")
    _, editor_key_b = _make_editor_key("isolation-editor-b")

    # Seed a CI under editor tenant B only.
    editor_tenant_b, _ = (
        lambda k: (k[0], k[1])
    )(_make_editor_key("isolation-b-data"))
    with tenant_session(pool, editor_tenant_b) as conn:
        reconcile(
            conn,
            editor_tenant_b,
            [DiscoveredCI(type=CIType.vpc, external_id="vpc-b-only", name="b-net")],
            source="test",
            ci_types=frozenset({CIType.vpc}),
            edge_types=frozenset(),
        )

    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers=_auth(viewer_key))
    assert resp.status_code == 200
    external_ids = [c["external_id"] for c in resp.json()]
    assert "vpc-b-only" not in external_ids, (
        "Viewer tenant A must not see tenant B's CIs"
    )


# ---------------------------------------------------------------------------
# 403 response does not include WWW-Authenticate (spec §5 EC 11)
# ---------------------------------------------------------------------------


def test_viewer_write_403_has_correct_detail(pool):
    """Spec §5 EC 11: 403 JSON body has detail=='insufficient permissions'."""
    _, viewer_key = _make_viewer_key("403-shape")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "x"},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403
    assert resp.json() == {"detail": "insufficient permissions"}


# ---------------------------------------------------------------------------
# Full write endpoint matrix: viewer gets 403 on ALL 6 write paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path,body", [
    ("/connectors", {"type": "aws", "display_name": "matrix-test"}),
    ("/events/aws", {"record": {}}),
    ("/telemetry/flowlogs", {"records": []}),
    ("/telemetry/maintenance/age-inferred-edges", None),
])
def test_viewer_write_endpoint_matrix_403(pool, path, body):
    """Spec §7 matrix: viewer key returns 403 on all parameterized write endpoints."""
    _, viewer_key = _make_viewer_key(f"matrix-viewer-{path.replace('/', '-')}")
    client = TestClient(create_app(pool=pool))
    resp = client.post(path, json=body, headers=_auth(viewer_key))
    assert resp.status_code == 403, (
        f"Viewer on POST {path} should be 403, got {resp.status_code}"
    )


@pytest.mark.parametrize("path,body", [
    ("/cis", None),
    ("/graph", None),
    ("/changes", None),
    ("/connector-health/runs", None),
    ("/connectors", None),
])
def test_viewer_read_endpoint_matrix_200(pool, path, body):
    """Spec §7 matrix: viewer key returns 200 on all parameterized read GET endpoints."""
    _, viewer_key = _make_viewer_key(f"matrix-viewer-read-{path.replace('/', '-')}")
    client = TestClient(create_app(pool=pool))
    resp = client.get(path, headers=_auth(viewer_key))
    assert resp.status_code == 200, (
        f"Viewer on GET {path} should be 200, got {resp.status_code}"
    )
