"""Hard rule #2: tenant isolation is enforced at the storage layer.

These tests are adversarial — they actively try to read, write, and update across tenants and
assert the database refuses, rather than only checking the happy path.
"""

from __future__ import annotations

import psycopg
import pytest

from infra_twin.core_model import CI, CIType
from infra_twin.db.repositories import CIRepository
from infra_twin.db.session import tenant_session


def _seed(pool, tenant, external_id, name):
    with tenant_session(pool, tenant) as conn:
        return CIRepository(conn, tenant).upsert(
            CI(tenant_id=tenant, type=CIType.vpc, external_id=external_id, name=name)
        )


def test_reads_are_scoped_to_the_session_tenant(pool, make_tenant):
    a, b = make_tenant("A"), make_tenant("B")
    _seed(pool, a, "vpc-a", "alpha")
    _seed(pool, b, "vpc-b", "beta")

    with tenant_session(pool, a) as conn:
        seen = CIRepository(conn, a).get_current()
    assert [ci.external_id for ci in seen] == ["vpc-a"]


def test_raw_select_cannot_see_other_tenant(pool, make_tenant):
    a, b = make_tenant("A"), make_tenant("B")
    _seed(pool, a, "vpc-a", "alpha")
    _seed(pool, b, "vpc-b", "beta")

    # Even a raw count under tenant A's session sees only A's row.
    with tenant_session(pool, a) as conn:
        count = conn.execute("SELECT count(*) FROM cis").fetchone()[0]
    assert count == 1


def test_no_tenant_guc_means_no_rows(pool, make_tenant):
    a = make_tenant("A")
    _seed(pool, a, "vpc-a", "alpha")

    # A bare connection (no app.tenant_id set) sees nothing.
    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM cis").fetchone()[0]
    assert count == 0


def test_repo_rejects_mismatched_tenant(pool, make_tenant):
    a, b = make_tenant("A"), make_tenant("B")
    with tenant_session(pool, a) as conn:
        repo = CIRepository(conn, a)
        with pytest.raises(ValueError):
            repo.upsert(CI(tenant_id=b, type=CIType.vpc, external_id="vpc-x", name="x"))


def test_rls_blocks_cross_tenant_insert(pool, make_tenant):
    a, b = make_tenant("A"), make_tenant("B")
    # Raw insert under A's session, but stamping B's tenant_id, violates the WITH CHECK policy.
    with pytest.raises(psycopg.Error):
        with tenant_session(pool, a) as conn:
            conn.execute(
                "INSERT INTO cis "
                "(tenant_id, type, external_id, name, attributes, confidence, "
                " first_seen, last_seen, valid_from) "
                "VALUES (%s, 'vpc', 'vpc-x', 'x', '{}', 1.0, now(), now(), now())",
                (str(b),),
            )


def test_cross_tenant_update_affects_nothing(pool, make_tenant):
    a, b = make_tenant("A"), make_tenant("B")
    _seed(pool, b, "vpc-b", "beta")

    # Tenant A tries to mutate B's row; B's row is invisible, so zero rows change.
    with tenant_session(pool, a) as conn:
        cur = conn.execute("UPDATE cis SET name = 'hacked' WHERE external_id = 'vpc-b'")
        assert cur.rowcount == 0

    with tenant_session(pool, b) as conn:
        rows = CIRepository(conn, b).get_current()
    assert rows[0].name == "beta"  # untouched
