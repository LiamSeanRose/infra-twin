"""Hard rule #1: changes close-and-open; nothing is ever physically deleted."""

from __future__ import annotations

from infra_twin.core_model import CI, CIType
from infra_twin.db.repositories import CIRepository
from infra_twin.db.session import tenant_session


def _ci(tenant, name, attrs=None):
    return CI(
        tenant_id=tenant,
        type=CIType.ec2_instance,
        external_id="i-0abc",
        name=name,
        attributes=attrs or {},
    )


def test_unchanged_upsert_touches_last_seen_without_versioning(pool, make_tenant):
    tenant = make_tenant()
    with tenant_session(pool, tenant) as conn:
        v1 = CIRepository(conn, tenant).upsert(_ci(tenant, "web-1"))
    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        v2 = repo.upsert(_ci(tenant, "web-1"))
        history = repo.history(v1.id)
    assert len(history) == 1  # no new version
    assert v2.last_seen >= v1.last_seen


def test_change_closes_old_and_opens_new(pool, make_tenant):
    tenant = make_tenant()
    with tenant_session(pool, tenant) as conn:
        v1 = CIRepository(conn, tenant).upsert(_ci(tenant, "web-1", {"state": "running"}))
    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        v2 = repo.upsert(_ci(tenant, "web-1", {"state": "stopped"}))

    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        current = repo.get_current(type=CIType.ec2_instance)
        history = repo.history(v1.id)
        at_v1 = repo.as_of(v1.valid_from, type=CIType.ec2_instance)
        at_v2 = repo.as_of(v2.valid_from, type=CIType.ec2_instance)

    assert v2.id == v1.id  # same stable identity across versions
    assert len(current) == 1 and current[0].attributes == {"state": "stopped"}
    assert len(history) == 2  # old version retained, not deleted
    closed, opened = history[0], history[1]
    assert closed.valid_to == opened.valid_from  # contiguous validity
    assert opened.valid_to is None
    assert at_v1[0].attributes == {"state": "running"}
    assert at_v2[0].attributes == {"state": "stopped"}


def test_close_sets_valid_to_without_deleting(pool, make_tenant):
    tenant = make_tenant()
    with tenant_session(pool, tenant) as conn:
        v1 = CIRepository(conn, tenant).upsert(_ci(tenant, "web-1"))
    with tenant_session(pool, tenant) as conn:
        assert CIRepository(conn, tenant).close(CIType.ec2_instance, "i-0abc") is True
    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        assert repo.get_current(type=CIType.ec2_instance) == []
        history = repo.history(v1.id)
    assert len(history) == 1 and history[0].valid_to is not None  # retained, just closed
