"""E2E tests for the read-only MERGE-REVIEW API surface.

Exercises GET /merges and GET /merges/{ci_id} against the real reconcile path,
real Postgres + AGE stack, and real RLS — no mocking.

Five independent, deterministic tests:

  (a) test_get_merges_lists_the_merge
      After a cross-source merge (scenario 1 of test_entity_resolution.py exactly),
      GET /merges returns exactly one row with all expected fields.

  (b) test_get_merges_for_ci_returns_provenance_and_alias_keys
      GET /merges/{canonical_ci_id} returns the merge row AND the alias key binding.

  (c) test_no_merges_empty_and_unknown_ci_404
      A tenant with no merges gets [] from GET /merges; a random UUID gets 404 from
      GET /merges/{unknown}.

  (d) test_cross_tenant_isolation
      Merge under tenant A is invisible to tenant B; GET /merges/{A_ci_id} is 404
      for tenant B (RLS-enforced).

  (e) test_auth_and_rbac
      Unauthenticated request returns 401; a viewer-role key is sufficient for 200.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import psycopg
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.connector_sdk import DiscoveredCI
from infra_twin.core_model import CIType, EdgeType
from infra_twin.db.api_keys import Role, provision_tenant
from infra_twin.db.config import admin_dsn
from infra_twin.db.repositories import CIRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import reconcile

# ---------------------------------------------------------------------------
# Shared constants — exactly as scenario 1 of test_entity_resolution.py
# ---------------------------------------------------------------------------

ALIAS = "alias:shared-1"
EXT_A = "a-ext-1"
EXT_B = "b-ext-1"
CI_TYPE = CIType.s3_bucket
SOURCE_A = "srcA"
SOURCE_B = "srcB"
CI_SCOPE = frozenset({CIType.s3_bucket})
EDGE_SCOPE = frozenset({EdgeType.DEPENDS_ON})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _merge_two_sources(pool, tenant: UUID) -> None:
    """Run two reconcile calls that produce exactly one merge row.

    Source A emits EXT_A with ALIAS; source B emits EXT_B with the same ALIAS.
    The entity-resolution engine merges EXT_B into the canonical CI EXT_A and
    writes one ci_merges row.  Exactly replicates scenario 1 of
    test_entity_resolution.py.
    """
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            [DiscoveredCI(type=CI_TYPE, external_id=EXT_A, alias_keys=[ALIAS])],
            source=SOURCE_A,
            ci_types=CI_SCOPE,
            edge_types=EDGE_SCOPE,
        )
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            [DiscoveredCI(type=CI_TYPE, external_id=EXT_B, alias_keys=[ALIAS])],
            source=SOURCE_B,
            ci_types=CI_SCOPE,
            edge_types=EDGE_SCOPE,
        )


def _get_canonical_ci_id(pool, tenant: UUID) -> UUID:
    """Return the id of the single current s3_bucket CI (EXT_A after the merge)."""
    with tenant_session(pool, tenant) as conn:
        cis = CIRepository(conn, tenant).get_current(type=CI_TYPE)
    assert len(cis) == 1, f"Expected 1 current CI, got {len(cis)}"
    assert cis[0].external_id == EXT_A
    return cis[0].id


# ===========================================================================
# (a) GET /merges returns exactly one merge row with correct fields
# ===========================================================================


def test_get_merges_lists_the_merge(pool, make_tenant_with_key):
    """AC 17: after a cross-source merge, GET /merges returns exactly one row
    with canonical_ci_id, merged_source, merged_external_id, matched_alias_key,
    and a non-empty evidence string."""
    tenant, api_key = make_tenant_with_key("mr-list-merge")
    _merge_two_sources(pool, tenant)
    canonical_ci_id = _get_canonical_ci_id(pool, tenant)

    client = TestClient(create_app(pool=pool))
    resp = client.get("/merges", headers=_auth(api_key))

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert isinstance(body, list), f"Expected list, got {type(body)}"
    assert len(body) == 1, f"Expected exactly 1 merge row, got {len(body)}: {body}"

    row = body[0]
    assert str(row["canonical_ci_id"]) == str(canonical_ci_id), (
        f"canonical_ci_id {row['canonical_ci_id']} != expected {canonical_ci_id}"
    )
    assert row["merged_source"] == SOURCE_B, (
        f"merged_source should be {SOURCE_B!r}, got {row['merged_source']!r}"
    )
    assert row["merged_external_id"] == EXT_B, (
        f"merged_external_id should be {EXT_B!r}, got {row['merged_external_id']!r}"
    )
    assert row["matched_alias_key"] == ALIAS, (
        f"matched_alias_key should be {ALIAS!r}, got {row['matched_alias_key']!r}"
    )
    assert row["evidence"], (
        f"evidence must be non-empty (truthy), got {row['evidence']!r}"
    )
    # Verify required response fields are present
    assert "merge_id" in row, "merge_id must be present in response"
    assert "merged_at" in row, "merged_at must be present in response"


# ===========================================================================
# (b) GET /merges/{canonical_ci_id} returns provenance and alias key bindings
# ===========================================================================


def test_get_merges_for_ci_returns_provenance_and_alias_keys(pool, make_tenant_with_key):
    """AC 18: GET /merges/{canonical_ci_id} returns 200 with one merge row (matching
    AC 17 fields) and alias_keys containing alias:shared-1 with ci_type s3_bucket."""
    tenant, api_key = make_tenant_with_key("mr-provenance")
    _merge_two_sources(pool, tenant)
    canonical_ci_id = _get_canonical_ci_id(pool, tenant)

    client = TestClient(create_app(pool=pool))
    resp = client.get(f"/merges/{canonical_ci_id}", headers=_auth(api_key))

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()

    assert str(body["canonical_ci_id"]) == str(canonical_ci_id), (
        f"canonical_ci_id {body['canonical_ci_id']} != {canonical_ci_id}"
    )

    # Merge rows
    merges = body["merges"]
    assert isinstance(merges, list), f"merges must be a list, got {type(merges)}"
    assert len(merges) == 1, f"Expected exactly 1 merge row, got {len(merges)}"
    m = merges[0]
    assert str(m["canonical_ci_id"]) == str(canonical_ci_id), (
        "merge row canonical_ci_id must equal the canonical CI id"
    )
    assert m["merged_source"] == SOURCE_B, (
        f"merged_source should be {SOURCE_B!r}, got {m['merged_source']!r}"
    )
    assert m["merged_external_id"] == EXT_B, (
        f"merged_external_id should be {EXT_B!r}, got {m['merged_external_id']!r}"
    )
    assert m["matched_alias_key"] == ALIAS, (
        f"matched_alias_key should be {ALIAS!r}, got {m['matched_alias_key']!r}"
    )
    assert m["evidence"], f"evidence must be non-empty, got {m['evidence']!r}"

    # Alias key bindings
    alias_keys = body["alias_keys"]
    assert isinstance(alias_keys, list), f"alias_keys must be a list, got {type(alias_keys)}"
    alias_values = [a["alias_key"] for a in alias_keys]
    assert ALIAS in alias_values, (
        f"alias_keys must contain {ALIAS!r}; got {alias_values}"
    )
    alias_binding = next(a for a in alias_keys if a["alias_key"] == ALIAS)
    assert alias_binding["ci_type"] == CI_TYPE.value, (
        f"alias_key ci_type should be {CI_TYPE.value!r}, got {alias_binding['ci_type']!r}"
    )


# ===========================================================================
# (c) No-merge tenant gets [] from GET /merges; unknown CI id gets 404
# ===========================================================================


def test_no_merges_empty_and_unknown_ci_404(pool, make_tenant_with_key):
    """Edge case 1 (empty list) and edge case 3 (unknown CI 404).

    A tenant that ran no merge gets [] from GET /merges (200, not 404).
    GET /merges/{random_uuid} returns 404 with detail 'CI not found'.
    """
    tenant, api_key = make_tenant_with_key("mr-empty")
    client = TestClient(create_app(pool=pool))

    # Edge case 1: no merges -> empty list, 200
    resp = client.get("/merges", headers=_auth(api_key))
    assert resp.status_code == 200, f"Expected 200 for empty merges, got {resp.status_code}"
    assert resp.json() == [], f"Expected [], got {resp.json()}"

    # Edge case 3: unknown UUID -> 404 with correct detail
    unknown_id = uuid4()
    resp404 = client.get(f"/merges/{unknown_id}", headers=_auth(api_key))
    assert resp404.status_code == 404, (
        f"Expected 404 for unknown CI id, got {resp404.status_code}: {resp404.text}"
    )
    assert resp404.json()["detail"] == "CI not found", (
        f"404 detail must be 'CI not found', got {resp404.json()['detail']!r}"
    )


# ===========================================================================
# (d) Adversarial cross-tenant isolation (RLS)
# ===========================================================================


def test_cross_tenant_isolation(pool, make_tenant_with_key):
    """Edge cases 4 and 5: merge under tenant A is invisible to tenant B.

    Tenant B's GET /merges returns [] (empty, no leak).
    Tenant B's GET /merges/{A_canonical_ci_id} returns 404 (RLS hides A's CI,
    get_current_by_id returns None -> 404, not 403 and not a data leak).
    """
    tenant_a, key_a = make_tenant_with_key("mr-iso-a")
    _, key_b = make_tenant_with_key("mr-iso-b")

    # Seed a merge under tenant A only
    _merge_two_sources(pool, tenant_a)
    a_canonical_ci_id = _get_canonical_ci_id(pool, tenant_a)

    client = TestClient(create_app(pool=pool))

    # Tenant B sees no merges (RLS hides A's rows)
    resp_list = client.get("/merges", headers=_auth(key_b))
    assert resp_list.status_code == 200, (
        f"Expected 200 from tenant B GET /merges, got {resp_list.status_code}"
    )
    assert resp_list.json() == [], (
        f"Tenant B must see 0 merge rows (RLS), got {resp_list.json()}"
    )

    # Tenant B gets 404 (not 403, not data) for tenant A's CI id
    resp_ci = client.get(f"/merges/{a_canonical_ci_id}", headers=_auth(key_b))
    assert resp_ci.status_code == 404, (
        f"Tenant B must get 404 for tenant A's CI id, got {resp_ci.status_code}: {resp_ci.text}"
    )
    assert resp_ci.json()["detail"] == "CI not found", (
        f"404 detail must be 'CI not found', got {resp_ci.json()['detail']!r}"
    )


# ===========================================================================
# (e) Auth and RBAC: 401 without key; viewer is sufficient for 200
# ===========================================================================


def test_auth_and_rbac(pool):
    """Edge cases 9 and spec §5 EC 15 analogue.

    Unauthenticated GET /merges returns 401 (no Bearer header).
    A viewer-role key for a tenant with a merge returns 200 with that merge row.
    """
    # Create a viewer-role tenant + key
    with psycopg.connect(admin_dsn()) as conn:
        from infra_twin.db.api_keys import IssuedKey
        issued: IssuedKey = provision_tenant(conn, "mr-viewer-auth", role=Role.viewer)
    viewer_tenant_id = issued.tenant_id
    viewer_key = issued.plaintext

    # Seed a merge under that viewer tenant
    _merge_two_sources(pool, viewer_tenant_id)

    client = TestClient(create_app(pool=pool))

    # 401: no Authorization header
    resp_noauth = client.get("/merges")
    assert resp_noauth.status_code == 401, (
        f"Unauthenticated GET /merges must return 401, got {resp_noauth.status_code}"
    )

    # 200: viewer key is sufficient (read permission)
    resp_viewer = client.get("/merges", headers=_auth(viewer_key))
    assert resp_viewer.status_code == 200, (
        f"Viewer key must be sufficient for GET /merges (read), got {resp_viewer.status_code}"
    )
    body = resp_viewer.json()
    assert isinstance(body, list), f"Response must be a list, got {type(body)}"
    assert len(body) == 1, (
        f"Viewer tenant with one merge should see 1 merge row, got {len(body)}"
    )
    # Confirm the merge row has the expected fields
    assert body[0]["merged_source"] == SOURCE_B
    assert body[0]["merged_external_id"] == EXT_B
    assert body[0]["matched_alias_key"] == ALIAS
    assert body[0]["evidence"]
