"""E2E and unit tests for POST /events/webhook (generic webhook event-intake).

Covers all 19 edge cases (EC1-EC19) from the spec and all acceptance criteria (AC 1-15).

Structure:
1.  Structural / import checks (AC 1-3, 12).
2.  Source-validation edge cases EC1-EC8: blank, whitespace, reserved discovery names,
    reserved event/telemetry names, case-insensitive, whitespace-trimmed.
3.  E2E happy path: 200, 7-key response, CI created bitemporally (EC7, EC10, EC11, EC12).
4.  E2E CI close (not hard-delete) (EC14, AC 14c).
5.  connector_runs row and freshness SLO (EC7, AC 14d-e).
6.  Edge provenance: valid edge written (EC9, AC 14f); missing-evidence edge -> 422 (EC8, AC 14g).
7.  observed_at variants: omitted (EC10), trailing Z (EC11), naive (EC12), malformed (EC13).
8.  Stray tenant_id in body ignored (EC15, AC 12).
9.  Idempotent re-POST yields cis_unchanged (EC19).
10. RBAC: viewer 403, editor 200 (EC16, AC 14k).
11. Audit: editor POST produces allow/write audit row (AC 14l).
12. Cross-tenant isolation (EC17, EC18, AC 14j).
13. Two tenants same source label no collision (EC18).
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.db.api_keys import IssuedKey, Role, provision_tenant
from infra_twin.db.config import admin_dsn
from infra_twin.db.repositories import CIRepository
from infra_twin.db.session import tenant_session

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WEBHOOK_SOURCE = "my-cmdb"
_CI_EXTERNAL_ID = "cmdb-server-001"
_CI_TYPE = "ec2_instance"  # A valid CIType value

# An EdgeType value disjoint from CIType — used to force routing into DiscoveredEdge
# (per spec EC8 / AC 14g).  "RUNS_ON" is a valid EdgeType but NOT a valid CIType.
_EDGE_TYPE_NOT_CI_TYPE = "RUNS_ON"

# ---------------------------------------------------------------------------
# Auth helpers (mirrors test_k8s_events.py)
# ---------------------------------------------------------------------------


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _make_viewer_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.viewer)
    return issued.tenant_id, issued.plaintext


def _make_editor_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.editor)
    return issued.tenant_id, issued.plaintext


def _count_rows_admin(table: str, tenant: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        return conn.execute(
            f"SELECT count(*) FROM {table} WHERE tenant_id = %s", (tenant,)
        ).fetchone()[0]


def _count_rows_tenant(pool, tenant: UUID, table: str) -> int:
    with tenant_session(pool, tenant) as conn:
        return conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def _get_audit_rows(tenant_id: UUID) -> list[dict]:
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT method, path, permission, decision, status_code "
            "FROM audit_log WHERE tenant_id = %s ORDER BY occurred_at DESC",
            (tenant_id,),
        ).fetchall()
    return [
        {
            "method": r[0],
            "path": r[1],
            "permission": r[2],
            "decision": r[3],
            "status_code": r[4],
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Delta builders
# ---------------------------------------------------------------------------


def _empty_delta() -> dict:
    return {"upserts": [], "removed_cis": [], "removed_edges": []}


def _ci_upsert_delta(external_id: str = _CI_EXTERNAL_ID, ci_type: str = _CI_TYPE) -> dict:
    return {
        "upserts": [
            {
                "type": ci_type,
                "external_id": external_id,
                "name": external_id,
                "attributes": {},
            }
        ],
        "removed_cis": [],
        "removed_edges": [],
    }


def _ci_remove_delta(external_id: str = _CI_EXTERNAL_ID, ci_type: str = _CI_TYPE) -> dict:
    return {
        "upserts": [],
        "removed_cis": [{"type": ci_type, "external_id": external_id}],
        "removed_edges": [],
    }


def _edge_upsert_delta(
    from_type: str = "ec2_instance",
    from_id: str = "node-001",
    to_type: str = "ec2_instance",
    to_id: str = "node-002",
    edge_type: str = "CONTAINS",
    include_evidence: bool = True,
) -> dict:
    edge: dict = {
        "type": edge_type,
        "from_ref": {"type": from_type, "external_id": from_id},
        "to_ref": {"type": to_type, "external_id": to_id},
        "source": "declared",
        "confidence": 1.0,
    }
    if include_evidence:
        edge["evidence"] = [
            {
                "source": "my-cmdb",
                "detail": "webhook edge integration test",
                "observed_at": "2024-06-01T12:00:00Z",
            }
        ]
    return {
        "upserts": [edge],
        "removed_cis": [],
        "removed_edges": [],
    }


# ===========================================================================
# 1. STRUCTURAL / IMPORT CHECKS (AC 1-3, 12)
# ===========================================================================


def test_webhook_event_body_importable_from_app():
    """AC 1: WebhookEventBody is importable from infra_twin.api.app."""
    from infra_twin.api.app import WebhookEventBody  # noqa: F401


def test_webhook_event_body_has_source_field():
    """AC 1: WebhookEventBody.model_fields contains 'source'."""
    from infra_twin.api.app import WebhookEventBody
    assert "source" in WebhookEventBody.model_fields


def test_webhook_event_body_has_delta_field():
    """AC 1: WebhookEventBody.model_fields contains 'delta'."""
    from infra_twin.api.app import WebhookEventBody
    assert "delta" in WebhookEventBody.model_fields


def test_webhook_event_body_has_observed_at_field_defaulting_none():
    """AC 1: WebhookEventBody.observed_at defaults to None."""
    from infra_twin.api.app import WebhookEventBody
    field = WebhookEventBody.model_fields["observed_at"]
    assert field.default is None


def test_connector_delta_imported_not_redefined():
    """AC 2: ConnectorDelta is imported from infra_twin.connector_sdk in app.py — not redefined."""
    import infra_twin.api.app as app_mod
    from infra_twin.connector_sdk import ConnectorDelta
    # The app module uses ConnectorDelta; it must be the same class
    from infra_twin.api.app import WebhookEventBody
    # delta field annotation must resolve to ConnectorDelta
    delta_annotation = WebhookEventBody.model_fields["delta"].annotation
    assert delta_annotation is ConnectorDelta, (
        f"WebhookEventBody.delta must be ConnectorDelta, got {delta_annotation}"
    )


def test_reserved_webhook_sources_exists_and_is_frozenset():
    """AC 3: _RESERVED_WEBHOOK_SOURCES is a module-level frozenset in app.py."""
    import infra_twin.api.app as app_mod
    assert hasattr(app_mod, "_RESERVED_WEBHOOK_SOURCES"), (
        "_RESERVED_WEBHOOK_SOURCES must exist in app.py"
    )
    assert isinstance(app_mod._RESERVED_WEBHOOK_SOURCES, frozenset)


def test_reserved_webhook_sources_contains_exactly_nine_members():
    """AC 3: _RESERVED_WEBHOOK_SOURCES has exactly 9 members."""
    from infra_twin.api.app import _RESERVED_WEBHOOK_SOURCES
    assert len(_RESERVED_WEBHOOK_SOURCES) == 9, (
        f"expected 9 reserved sources, got {len(_RESERVED_WEBHOOK_SOURCES)}: {_RESERVED_WEBHOOK_SOURCES}"
    )


def test_reserved_webhook_sources_contains_discovery_names():
    """AC 3: _RESERVED_WEBHOOK_SOURCES contains all 6 discovery connector names."""
    from infra_twin.api.app import _RESERVED_WEBHOOK_SOURCES
    for name in ("aws", "azure", "gcp", "kubernetes", "saas", "db"):
        assert name in _RESERVED_WEBHOOK_SOURCES, f"'{name}' must be reserved"


def test_reserved_webhook_sources_contains_event_telemetry_names():
    """AC 3: _RESERVED_WEBHOOK_SOURCES contains all 3 event/telemetry source names."""
    from infra_twin.api.app import _RESERVED_WEBHOOK_SOURCES
    for name in ("aws-events", "k8s-events", "aws-flowlogs"):
        assert name in _RESERVED_WEBHOOK_SOURCES, f"'{name}' must be reserved"


def test_handler_does_not_read_tenant_from_body():
    """AC 12: tenant field is not in WebhookEventBody model fields."""
    from infra_twin.api.app import WebhookEventBody
    assert "tenant_id" not in WebhookEventBody.model_fields
    assert "tenant" not in WebhookEventBody.model_fields


# ===========================================================================
# 2. SOURCE VALIDATION EDGE CASES (EC1-EC6)
# ===========================================================================


def test_empty_source_returns_422(pool, make_tenant_with_key):
    """EC1: source='' returns 422."""
    _, api_key = make_tenant_with_key("wh-ec1-empty")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_whitespace_source_returns_422(pool, make_tenant_with_key):
    """EC2: source='   ' (whitespace only) returns 422."""
    _, api_key = make_tenant_with_key("wh-ec2-ws")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "   ", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_empty_source_422_detail(pool, make_tenant_with_key):
    """EC1: 422 detail for empty source mentions 'empty or whitespace'."""
    _, api_key = make_tenant_with_key("wh-ec1-detail")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422
    body = resp.json()
    # detail could be at top level or nested in Pydantic validation errors
    detail_str = str(body)
    assert "empty" in detail_str.lower() or "whitespace" in detail_str.lower(), (
        f"422 detail should mention empty/whitespace: {body}"
    )


def test_reserved_discovery_name_aws_returns_422(pool, make_tenant_with_key):
    """EC3: source='aws' (discovery connector name) returns 422."""
    _, api_key = make_tenant_with_key("wh-ec3-aws")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "aws", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_reserved_discovery_name_azure_returns_422(pool, make_tenant_with_key):
    """EC3: source='azure' returns 422."""
    _, api_key = make_tenant_with_key("wh-ec3-azure")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "azure", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_reserved_discovery_name_gcp_returns_422(pool, make_tenant_with_key):
    """EC3: source='gcp' returns 422."""
    _, api_key = make_tenant_with_key("wh-ec3-gcp")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "gcp", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_reserved_discovery_name_kubernetes_returns_422(pool, make_tenant_with_key):
    """EC3: source='kubernetes' returns 422."""
    _, api_key = make_tenant_with_key("wh-ec3-k8s")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "kubernetes", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_reserved_discovery_name_saas_returns_422(pool, make_tenant_with_key):
    """EC3: source='saas' returns 422."""
    _, api_key = make_tenant_with_key("wh-ec3-saas")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "saas", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_reserved_discovery_name_db_returns_422(pool, make_tenant_with_key):
    """EC3: source='db' returns 422."""
    _, api_key = make_tenant_with_key("wh-ec3-db")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "db", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_reserved_event_source_aws_events_returns_422(pool, make_tenant_with_key):
    """EC4: source='aws-events' (internal event source) returns 422."""
    _, api_key = make_tenant_with_key("wh-ec4-awsev")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "aws-events", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_reserved_event_source_k8s_events_returns_422(pool, make_tenant_with_key):
    """EC4: source='k8s-events' returns 422."""
    _, api_key = make_tenant_with_key("wh-ec4-k8sev")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "k8s-events", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_reserved_event_source_aws_flowlogs_returns_422(pool, make_tenant_with_key):
    """EC4: source='aws-flowlogs' returns 422."""
    _, api_key = make_tenant_with_key("wh-ec4-fl")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "aws-flowlogs", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_reserved_source_uppercase_aws_returns_422(pool, make_tenant_with_key):
    """EC5: source='AWS' (uppercase) returns 422 — case-insensitive check."""
    _, api_key = make_tenant_with_key("wh-ec5-AWS")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "AWS", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_reserved_source_mixed_case_k8s_events_returns_422(pool, make_tenant_with_key):
    """EC5: source='K8s-Events' (mixed case) returns 422."""
    _, api_key = make_tenant_with_key("wh-ec5-mixcase")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "K8s-Events", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_reserved_source_with_surrounding_whitespace_returns_422(pool, make_tenant_with_key):
    """EC6: source=' aws-events ' (whitespace-padded reserved name) returns 422."""
    _, api_key = make_tenant_with_key("wh-ec6-ws-reserved")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": " aws-events ", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_reserved_source_whitespace_padded_aws_returns_422(pool, make_tenant_with_key):
    """EC6: source=' aws ' returns 422."""
    _, api_key = make_tenant_with_key("wh-ec6-ws-aws")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": " aws ", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


# ===========================================================================
# 3. E2E HAPPY PATH (EC7, AC 14a-b)
# ===========================================================================


def test_valid_source_empty_delta_returns_200(pool, make_tenant_with_key):
    """EC7: valid non-reserved source with empty delta returns 200 (AC 14a)."""
    _, api_key = make_tenant_with_key("wh-ec7-empty")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": "github-actions", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200


def test_valid_source_empty_delta_response_has_seven_keys(pool, make_tenant_with_key):
    """AC 14a: response has exactly 7 keys matching the spec shape."""
    _, api_key = make_tenant_with_key("wh-7keys")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    expected_keys = {
        "connector_run_id",
        "cis_created",
        "cis_updated",
        "cis_unchanged",
        "cis_closed",
        "edges_written",
        "edges_closed",
    }
    assert set(resp.json().keys()) == expected_keys


def test_connector_run_id_is_valid_uuid(pool, make_tenant_with_key):
    """AC 14a: connector_run_id in response is a valid UUID string."""
    _, api_key = make_tenant_with_key("wh-run-uuid")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    run_id_str = resp.json()["connector_run_id"]
    parsed = UUID(run_id_str)
    assert str(parsed) == run_id_str


def test_upsert_ci_creates_ci_bitemporally(pool, make_tenant_with_key):
    """AC 14b / EC7: an upsert CI is created with valid_to IS NULL (open) in the DB."""
    tenant, api_key = make_tenant_with_key("wh-ci-create")
    client = TestClient(create_app(pool=pool))
    from infra_twin.core_model import CIType

    resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_upsert_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    assert resp.json()["cis_created"] == 1

    with tenant_session(pool, tenant) as conn:
        cis = CIRepository(conn, tenant).get_current(
            type=CIType.ec2_instance, external_id=_CI_EXTERNAL_ID
        )
    assert len(cis) == 1
    assert cis[0].valid_to is None
    assert cis[0].external_id == _CI_EXTERNAL_ID


def test_upsert_ci_queryable_via_ci_repository(pool, make_tenant_with_key):
    """AC 14b: CI created by webhook is queryable via CIRepository.get_current."""
    tenant, api_key = make_tenant_with_key("wh-ci-query")
    client = TestClient(create_app(pool=pool))
    from infra_twin.core_model import CIType

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_upsert_delta(external_id="srv-query")},
        headers=_auth(api_key),
    )

    with tenant_session(pool, tenant) as conn:
        cis = CIRepository(conn, tenant).get_current(
            type=CIType.ec2_instance, external_id="srv-query"
        )
    assert len(cis) == 1, f"expected 1 CI, got {len(cis)}"


# ===========================================================================
# 4. E2E CI CLOSE / BITEMPORAL NON-DELETE (EC14, AC 14c)
# ===========================================================================


def test_removed_ci_closes_bitemporal_row(pool, make_tenant_with_key):
    """EC14 / AC 14c: a follow-up removed_cis POST closes the CI (cis_closed >= 1)."""
    tenant, api_key = make_tenant_with_key("wh-ci-close")
    client = TestClient(create_app(pool=pool))

    # Step 1: create the CI
    create_resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_upsert_delta()},
        headers=_auth(api_key),
    )
    assert create_resp.status_code == 200
    assert create_resp.json()["cis_created"] == 1

    # Step 2: close it
    close_resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_remove_delta()},
        headers=_auth(api_key),
    )
    assert close_resp.status_code == 200
    assert close_resp.json()["cis_closed"] >= 1


def test_removed_ci_row_not_hard_deleted(pool, make_tenant_with_key):
    """EC14 / AC 14c: after removed_cis, the CI row still exists in DB with valid_to set (never hard-deleted)."""
    tenant, api_key = make_tenant_with_key("wh-ci-nodelete")
    client = TestClient(create_app(pool=pool))

    # Create then close the CI
    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_upsert_delta(external_id="srv-nodelete")},
        headers=_auth(api_key),
    )
    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_remove_delta(external_id="srv-nodelete")},
        headers=_auth(api_key),
    )

    # Admin view: row must still exist, valid_to must be set
    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT valid_to FROM cis WHERE type = %s AND external_id = %s AND tenant_id = %s",
            (_CI_TYPE, "srv-nodelete", tenant),
        ).fetchone()
    assert row is not None, "CI row must physically exist (no hard-delete)"
    assert row[0] is not None, "valid_to must be set after removal (bitemporal close)"


def test_removed_ci_row_count_positive_after_close(pool, make_tenant_with_key):
    """EC14: row count for that external_id is > 0 (row still exists after close)."""
    tenant, api_key = make_tenant_with_key("wh-ci-rowcount")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_upsert_delta(external_id="srv-rowcount")},
        headers=_auth(api_key),
    )
    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_remove_delta(external_id="srv-rowcount")},
        headers=_auth(api_key),
    )

    with psycopg.connect(admin_dsn()) as admin_conn:
        count = admin_conn.execute(
            "SELECT count(*) FROM cis WHERE type = %s AND external_id = %s AND tenant_id = %s",
            (_CI_TYPE, "srv-rowcount", tenant),
        ).fetchone()[0]
    assert count >= 1, "row count must be > 0 after close (never hard-deleted)"


def test_removed_ci_valid_to_prior_row_still_exists(pool, make_tenant_with_key):
    """EC14: the prior open row still physically exists with valid_to set (closed, not deleted)."""
    tenant, api_key = make_tenant_with_key("wh-prior-row")
    client = TestClient(create_app(pool=pool))
    ext_id = "srv-prior-row"

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_upsert_delta(external_id=ext_id)},
        headers=_auth(api_key),
    )
    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_remove_delta(external_id=ext_id)},
        headers=_auth(api_key),
    )

    # Confirm via admin conn that at least one row has valid_to IS NOT NULL
    with psycopg.connect(admin_dsn()) as admin_conn:
        closed_count = admin_conn.execute(
            "SELECT count(*) FROM cis WHERE type = %s AND external_id = %s "
            "AND tenant_id = %s AND valid_to IS NOT NULL",
            (_CI_TYPE, ext_id, tenant),
        ).fetchone()[0]
    assert closed_count >= 1, "at least one closed (valid_to set) row must exist"


# ===========================================================================
# 5. CONNECTOR_RUNS ROW AND FRESHNESS SLO (EC7, AC 14d-e)
# ===========================================================================


def test_connector_runs_row_written_after_webhook_post(pool, make_tenant_with_key):
    """AC 14d / EC7: a connector_runs row with source=my-cmdb and status=ok is stamped."""
    tenant, api_key = make_tenant_with_key("wh-run-row")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(api_key),
    )

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT status, source FROM connector_runs WHERE source = %s",
            (_WEBHOOK_SOURCE,),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "ok"
    assert rows[0][1] == _WEBHOOK_SOURCE


def test_connector_run_id_matches_db(pool, make_tenant_with_key):
    """AC 14d: response connector_run_id == connector_runs.run_id written to DB."""
    tenant, api_key = make_tenant_with_key("wh-run-dbmatch")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    run_id_str = resp.json()["connector_run_id"]

    with tenant_session(pool, tenant) as conn:
        db_run_id = conn.execute(
            "SELECT run_id FROM connector_runs WHERE source = %s",
            (_WEBHOOK_SOURCE,),
        ).fetchone()[0]
    assert str(db_run_id) == run_id_str


def test_raw_facts_written_after_webhook_post(pool, make_tenant_with_key):
    """AC 14d: at least one raw_facts row with source=my-cmdb exists after POST."""
    tenant, api_key = make_tenant_with_key("wh-raw-facts")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_upsert_delta()},
        headers=_auth(api_key),
    )

    with tenant_session(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = %s",
            (_WEBHOOK_SOURCE,),
        ).fetchone()[0]
    assert count >= 1


def test_freshness_slo_evaluate_fresh_after_webhook_post(pool, make_tenant_with_key):
    """AC 14e: after PUT /freshness-slos/<source> and a POST, GET /freshness-slos/evaluate shows my-cmdb as fresh."""
    tenant, api_key = make_tenant_with_key("wh-slo-fresh")
    client = TestClient(create_app(pool=pool))

    # Configure a generous SLO (1 hour) for the webhook source
    put_resp = client.put(
        f"/freshness-slos/{_WEBHOOK_SOURCE}",
        json={"expected_interval_seconds": 3600},
        headers=_auth(api_key),
    )
    assert put_resp.status_code == 200

    # POST a webhook event to stamp the source fresh
    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(api_key),
    )

    # Evaluate freshness
    eval_resp = client.get("/freshness-slos/evaluate", headers=_auth(api_key))
    assert eval_resp.status_code == 200
    sources = eval_resp.json()["sources"]
    cmdb_row = next((s for s in sources if s["source"] == _WEBHOOK_SOURCE), None)
    assert cmdb_row is not None, f"{_WEBHOOK_SOURCE} must appear in evaluate output"
    assert cmdb_row["status"] == "fresh", (
        f"{_WEBHOOK_SOURCE} should be fresh after a POST, got: {cmdb_row}"
    )


def test_empty_delta_still_stamps_connector_run_row(pool, make_tenant_with_key):
    """EC7: even an empty delta stamps a connector_runs row (freshness stays fresh)."""
    tenant, api_key = make_tenant_with_key("wh-ec7-run")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/webhook",
        json={"source": "github-actions", "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200

    with tenant_session(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM connector_runs WHERE source = 'github-actions'"
        ).fetchone()[0]
    assert count == 1


# ===========================================================================
# 6. EDGE PROVENANCE (EC8, EC9, AC 14f-g)
# ===========================================================================


def test_valid_edge_with_evidence_written_200(pool, make_tenant_with_key):
    """EC9 / AC 14f: a DiscoveredEdge with valid provenance is persisted (edges_written >= 1)."""
    tenant, api_key = make_tenant_with_key("wh-edge-valid")
    client = TestClient(create_app(pool=pool))

    # Include both endpoint CIs plus the edge itself
    delta = {
        "upserts": [
            {
                "type": "ec2_instance",
                "external_id": "node-a",
                "name": "node-a",
                "attributes": {},
            },
            {
                "type": "ec2_instance",
                "external_id": "node-b",
                "name": "node-b",
                "attributes": {},
            },
            {
                "type": "CONTAINS",
                "from_ref": {"type": "ec2_instance", "external_id": "node-a"},
                "to_ref": {"type": "ec2_instance", "external_id": "node-b"},
                "source": "declared",
                "confidence": 1.0,
                "evidence": [
                    {
                        "source": "my-cmdb",
                        "detail": "edge provenance test",
                        "observed_at": "2024-06-01T12:00:00Z",
                    }
                ],
            },
        ],
        "removed_cis": [],
        "removed_edges": [],
    }
    resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": delta},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    assert resp.json()["edges_written"] >= 1


def test_missing_evidence_on_edge_returns_422(pool, make_tenant_with_key):
    """EC8 / AC 14g: DiscoveredEdge with missing evidence returns 422 (Pydantic min_length=1).

    Uses EdgeType 'RUNS_ON' as the type — this is a valid EdgeType but NOT a valid CIType,
    so Pydantic cannot mis-coerce this into a DiscoveredCI (the two enums are disjoint).
    """
    _, api_key = make_tenant_with_key("wh-ec8-missing-ev")
    client = TestClient(create_app(pool=pool))

    edge_without_evidence = {
        "type": _EDGE_TYPE_NOT_CI_TYPE,  # RUNS_ON — not a CIType, forces DiscoveredEdge routing
        "from_ref": {"type": "ec2_instance", "external_id": "node-a"},
        "to_ref": {"type": "k8s_node", "external_id": "node-b"},
        "source": "declared",
        "confidence": 1.0,
        # evidence intentionally omitted
    }
    delta = {
        "upserts": [edge_without_evidence],
        "removed_cis": [],
        "removed_edges": [],
    }
    resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": delta},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_empty_evidence_list_on_edge_returns_422(pool, make_tenant_with_key):
    """EC8: DiscoveredEdge with evidence=[] (empty list) returns 422 (min_length=1 violated)."""
    _, api_key = make_tenant_with_key("wh-ec8-empty-ev")
    client = TestClient(create_app(pool=pool))

    edge_with_empty_evidence = {
        "type": _EDGE_TYPE_NOT_CI_TYPE,
        "from_ref": {"type": "ec2_instance", "external_id": "node-a"},
        "to_ref": {"type": "k8s_node", "external_id": "node-b"},
        "source": "declared",
        "confidence": 1.0,
        "evidence": [],  # empty list — violates min_length=1
    }
    delta = {
        "upserts": [edge_with_empty_evidence],
        "removed_cis": [],
        "removed_edges": [],
    }
    resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": delta},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_missing_evidence_creates_no_edge_no_ci(pool, make_tenant_with_key):
    """EC8: 422 for missing evidence means no CI/edge/connector_run rows written."""
    tenant, api_key = make_tenant_with_key("wh-ec8-noci")
    client = TestClient(create_app(pool=pool))

    edge_without_evidence = {
        "type": _EDGE_TYPE_NOT_CI_TYPE,
        "from_ref": {"type": "ec2_instance", "external_id": "node-a"},
        "to_ref": {"type": "k8s_node", "external_id": "node-b"},
        "source": "declared",
        "confidence": 1.0,
    }
    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": {"upserts": [edge_without_evidence], "removed_cis": [], "removed_edges": []}},
        headers=_auth(api_key),
    )

    assert _count_rows_admin("cis", tenant) == 0
    assert _count_rows_admin("edges", tenant) == 0
    assert _count_rows_admin("connector_runs", tenant) == 0


# ===========================================================================
# 7. OBSERVED_AT VARIANTS (EC10-EC13)
# ===========================================================================


def test_observed_at_omitted_request_succeeds(pool, make_tenant_with_key):
    """EC10: observed_at omitted -> falls back to datetime.now(timezone.utc); request succeeds."""
    _, api_key = make_tenant_with_key("wh-ec10-no-obs")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200


def test_observed_at_trailing_z_accepted(pool, make_tenant_with_key):
    """EC11: observed_at with trailing Z is parsed correctly; request succeeds."""
    _, api_key = make_tenant_with_key("wh-ec11-trailz")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={
            "source": _WEBHOOK_SOURCE,
            "delta": _empty_delta(),
            "observed_at": "2024-06-01T12:00:00Z",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 200


def test_observed_at_naive_datetime_accepted(pool, make_tenant_with_key):
    """EC12: observed_at provided naive (no offset) is normalised to UTC; request succeeds."""
    _, api_key = make_tenant_with_key("wh-ec12-naive")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={
            "source": _WEBHOOK_SOURCE,
            "delta": _empty_delta(),
            "observed_at": "2024-06-01T12:00:00",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 200


def test_observed_at_malformed_returns_422(pool, make_tenant_with_key):
    """EC13: malformed observed_at returns 422 (Pydantic), never 500."""
    _, api_key = make_tenant_with_key("wh-ec13-bad-obs")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={
            "source": _WEBHOOK_SOURCE,
            "delta": _empty_delta(),
            "observed_at": "not-a-datetime",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 422
    assert resp.status_code != 500


def test_observed_at_malformed_not_500(pool, make_tenant_with_key):
    """EC13: malformed observed_at must not be 500 — only 422."""
    _, api_key = make_tenant_with_key("wh-ec13-no500")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={
            "source": _WEBHOOK_SOURCE,
            "delta": _empty_delta(),
            "observed_at": "garbage",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code != 500


# ===========================================================================
# 8. STRAY TENANT_ID IN BODY IGNORED (EC15, AC 12)
# ===========================================================================


def test_stray_tenant_id_in_body_is_ignored(pool, make_tenant_with_key):
    """EC15: extra 'tenant_id' field in the body is silently ignored; tenant from auth only."""
    tenant_a, key_a = make_tenant_with_key("wh-ec15-body-tenant-a")
    tenant_b, key_b = make_tenant_with_key("wh-ec15-body-tenant-b")
    client = TestClient(create_app(pool=pool))

    # Post with tenant_b's id in the body but using tenant_a's API key
    resp = client.post(
        "/events/webhook",
        json={
            "source": _WEBHOOK_SOURCE,
            "delta": _ci_upsert_delta(external_id="srv-stray-tenant"),
            "tenant_id": str(tenant_b),  # stray field — must be ignored
        },
        headers=_auth(key_a),
    )
    assert resp.status_code == 200

    # CI must be under tenant_a, not tenant_b
    assert _count_rows_admin("cis", tenant_a) == 1
    assert _count_rows_admin("cis", tenant_b) == 0


# ===========================================================================
# 9. IDEMPOTENT RE-POST (EC19)
# ===========================================================================


def test_idempotent_repeated_upsert_yields_cis_unchanged(pool, make_tenant_with_key):
    """EC19: second POST of identical upsert yields cis_unchanged >= 1 (idempotent reconcile)."""
    _, api_key = make_tenant_with_key("wh-ec19-idem")
    client = TestClient(create_app(pool=pool))

    delta = _ci_upsert_delta(external_id="srv-idempotent")

    # First POST: creates the CI
    resp1 = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": delta},
        headers=_auth(api_key),
    )
    assert resp1.status_code == 200
    assert resp1.json()["cis_created"] == 1

    # Second POST: same CI should be unchanged
    resp2 = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": delta},
        headers=_auth(api_key),
    )
    assert resp2.status_code == 200
    assert resp2.json()["cis_unchanged"] >= 1


def test_idempotent_repeated_upsert_stamps_fresh_connector_run(pool, make_tenant_with_key):
    """EC19: second POST still stamps a fresh connector_runs row."""
    tenant, api_key = make_tenant_with_key("wh-ec19-run")
    client = TestClient(create_app(pool=pool))

    delta = _ci_upsert_delta(external_id="srv-idem-run")

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": delta},
        headers=_auth(api_key),
    )
    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": delta},
        headers=_auth(api_key),
    )

    with tenant_session(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM connector_runs WHERE source = %s",
            (_WEBHOOK_SOURCE,),
        ).fetchone()[0]
    # Two POSTs = two connector_runs rows (one per call)
    assert count == 2


# ===========================================================================
# 10. RBAC: VIEWER 403, EDITOR 200 (EC16, AC 14k)
# ===========================================================================


def test_viewer_key_post_webhook_returns_403():
    """EC16 / AC 14k: viewer API key gets 403 on POST /events/webhook."""
    _, viewer_key = _make_viewer_key("wh-rbac-viewer")
    client = TestClient(create_app(pool=None))
    resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403


def test_viewer_key_403_detail_insufficient_permissions():
    """EC16: 403 detail is 'insufficient permissions' for viewer."""
    _, viewer_key = _make_viewer_key("wh-rbac-viewer-detail")
    client = TestClient(create_app(pool=None))
    resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(viewer_key),
    )
    assert resp.json()["detail"] == "insufficient permissions"


def test_viewer_key_creates_no_ci_or_connector_run(pool):
    """EC16: viewer 403 creates no CI and no connector_runs row."""
    viewer_tenant, viewer_key = _make_viewer_key("wh-rbac-viewer-noci")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_upsert_delta()},
        headers=_auth(viewer_key),
    )

    assert _count_rows_admin("cis", viewer_tenant) == 0
    assert _count_rows_admin("connector_runs", viewer_tenant) == 0


def test_editor_key_post_webhook_returns_200(pool, make_tenant_with_key):
    """EC16 / AC 14k: editor API key returns 200 on POST /events/webhook."""
    _, editor_key = make_tenant_with_key("wh-rbac-editor")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(editor_key),
    )
    assert resp.status_code == 200


# ===========================================================================
# 11. AUDIT LOGGING (AC 14l)
# ===========================================================================


def test_editor_post_webhook_produces_audit_row(pool):
    """AC 14l: editor POST /events/webhook produces an audit_log row."""
    editor_tenant, editor_key = _make_editor_key("wh-audit-editor")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(editor_key),
    )

    rows = _get_audit_rows(editor_tenant)
    assert len(rows) >= 1
    assert any(r["path"] == "/events/webhook" for r in rows), (
        f"expected audit_log row for /events/webhook, got: {rows}"
    )


def test_editor_post_webhook_audit_row_is_allow_write(pool):
    """AC 14l: audit row for editor POST /events/webhook has decision='allow', permission='write'."""
    editor_tenant, editor_key = _make_editor_key("wh-audit-allow")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(editor_key),
    )

    rows = _get_audit_rows(editor_tenant)
    webhook_rows = [r for r in rows if r["path"] == "/events/webhook"]
    assert len(webhook_rows) >= 1
    row = webhook_rows[0]
    assert row["decision"] == "allow"
    assert row["permission"] == "write"


def test_viewer_post_webhook_audit_row_is_deny(pool):
    """EC16 / AC 14l: viewer 403 on POST /events/webhook produces a deny audit_log row."""
    viewer_tenant, viewer_key = _make_viewer_key("wh-audit-deny")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(viewer_key),
    )

    rows = _get_audit_rows(viewer_tenant)
    webhook_rows = [r for r in rows if r["path"] == "/events/webhook"]
    assert len(webhook_rows) >= 1
    assert any(r["decision"] == "deny" for r in webhook_rows), (
        f"expected deny audit row for viewer POST /events/webhook: {webhook_rows}"
    )


# ===========================================================================
# 12. CROSS-TENANT ISOLATION (EC17, AC 14j)
# ===========================================================================


def test_cross_tenant_webhook_ci_isolation(pool, make_tenant_with_key):
    """EC17 / AC 14j: event posted under tenant A creates no CI visible to tenant B."""
    tenant_a, key_a = make_tenant_with_key("wh-iso-ci-A")
    tenant_b, key_b = make_tenant_with_key("wh-iso-ci-B")
    client = TestClient(create_app(pool=pool))
    from infra_twin.core_model import CIType

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_upsert_delta(external_id="srv-tenant-a")},
        headers=_auth(key_a),
    )

    with tenant_session(pool, tenant_b) as conn:
        b_cis = CIRepository(conn, tenant_b).get_current()
    assert b_cis == [], "tenant B must see zero CIs from tenant A's webhook POST"


def test_cross_tenant_webhook_connector_runs_isolation(pool, make_tenant_with_key):
    """EC17: connector_runs of tenant A not visible to tenant B."""
    tenant_a, key_a = make_tenant_with_key("wh-iso-run-A")
    tenant_b, key_b = make_tenant_with_key("wh-iso-run-B")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _empty_delta()},
        headers=_auth(key_a),
    )

    assert _count_rows_tenant(pool, tenant_a, "connector_runs") == 1
    assert _count_rows_tenant(pool, tenant_b, "connector_runs") == 0


def test_cross_tenant_webhook_all_tables_isolated(pool, make_tenant_with_key):
    """EC17 / AC 14j: posting under tenant A produces zero rows visible to tenant B across all tables."""
    tenant_a, key_a = make_tenant_with_key("wh-iso-all-A")
    tenant_b, key_b = make_tenant_with_key("wh-iso-all-B")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/webhook",
        json={"source": _WEBHOOK_SOURCE, "delta": _ci_upsert_delta()},
        headers=_auth(key_a),
    )

    for table in ("cis", "edges", "connector_runs", "raw_facts", "connectors"):
        count = _count_rows_tenant(pool, tenant_b, table)
        assert count == 0, (
            f"tenant B should see 0 rows in {table} after tenant A's webhook POST, got {count}"
        )


# ===========================================================================
# 13. TWO TENANTS SAME SOURCE LABEL — NO COLLISION (EC18)
# ===========================================================================


def test_two_tenants_same_source_label_no_collision(pool, make_tenant_with_key):
    """EC18: two different tenants using the same source label work independently without collision."""
    tenant_a, key_a = make_tenant_with_key("wh-ec18-same-A")
    tenant_b, key_b = make_tenant_with_key("wh-ec18-same-B")
    client = TestClient(create_app(pool=pool))

    # Both use the same source label
    shared_source = "shared-cmdb"
    resp_a = client.post(
        "/events/webhook",
        json={"source": shared_source, "delta": _ci_upsert_delta(external_id="srv-a")},
        headers=_auth(key_a),
    )
    resp_b = client.post(
        "/events/webhook",
        json={"source": shared_source, "delta": _ci_upsert_delta(external_id="srv-b")},
        headers=_auth(key_b),
    )
    assert resp_a.status_code == 200
    assert resp_b.status_code == 200

    # Each tenant sees only their own CI
    assert _count_rows_admin("cis", tenant_a) == 1
    assert _count_rows_admin("cis", tenant_b) == 1

    with tenant_session(pool, tenant_a) as conn:
        a_cis = CIRepository(conn, tenant_a).get_current()
    with tenant_session(pool, tenant_b) as conn:
        b_cis = CIRepository(conn, tenant_b).get_current()

    a_ids = {c.external_id for c in a_cis}
    b_ids = {c.external_id for c in b_cis}
    assert "srv-a" in a_ids
    assert "srv-b" not in a_ids
    assert "srv-b" in b_ids
    assert "srv-a" not in b_ids


def test_two_tenants_same_source_independent_freshness(pool, make_tenant_with_key):
    """EC18: two tenants with same source label have independent freshness SLOs."""
    tenant_a, key_a = make_tenant_with_key("wh-ec18-slo-A")
    tenant_b, key_b = make_tenant_with_key("wh-ec18-slo-B")
    client = TestClient(create_app(pool=pool))

    shared_source = "shared-source"

    # Only tenant_a configures and posts
    client.put(
        f"/freshness-slos/{shared_source}",
        json={"expected_interval_seconds": 3600},
        headers=_auth(key_a),
    )
    client.post(
        "/events/webhook",
        json={"source": shared_source, "delta": _empty_delta()},
        headers=_auth(key_a),
    )

    # Tenant A sees the source as fresh
    eval_a = client.get("/freshness-slos/evaluate", headers=_auth(key_a))
    sources_a = eval_a.json()["sources"]
    a_row = next((s for s in sources_a if s["source"] == shared_source), None)
    assert a_row is not None and a_row["status"] == "fresh"

    # Tenant B has no SLO for this source configured — their evaluate should not
    # include a stale row from tenant A's data
    eval_b = client.get("/freshness-slos/evaluate", headers=_auth(key_b))
    sources_b = eval_b.json()["sources"]
    b_row = next((s for s in sources_b if s["source"] == shared_source), None)
    # tenant B either sees nothing for this source or whatever they've configured independently
    # The key invariant: it must not be infected by tenant A's data
    if b_row is not None:
        # If tenant B sees a row, it must be from their own data (none posted)
        # Since tenant B never posted, any row would be a leak — fail
        assert False, (
            f"tenant B should see no {shared_source} SLO row (only tenant A posted), got: {b_row}"
        )
