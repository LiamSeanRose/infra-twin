"""Hard rule #3: an edge can never exist without source, confidence and evidence."""

from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest
from pydantic import ValidationError

from infra_twin.core_model import Edge, EdgeSource, EdgeType, Evidence
from infra_twin.db.session import tenant_session


def test_edge_requires_evidence():
    with pytest.raises(ValidationError):
        Edge(
            tenant_id=uuid4(),
            type=EdgeType.DEPENDS_ON,
            from_id=uuid4(),
            to_id=uuid4(),
            source=EdgeSource.declared,
            confidence=0.9,
            evidence=[],  # empty -> rejected
        )


def test_edge_requires_source_and_confidence():
    with pytest.raises(ValidationError):
        Edge(
            tenant_id=uuid4(),
            type=EdgeType.DEPENDS_ON,
            from_id=uuid4(),
            to_id=uuid4(),
            evidence=[Evidence(source="aws")],
        )  # missing source + confidence


def test_db_rejects_edge_without_evidence(pool, make_tenant):
    """Defense in depth: the CHECK constraint blocks an empty-evidence edge even via raw SQL."""
    tenant = make_tenant()
    with pytest.raises(psycopg.Error):
        with tenant_session(pool, tenant) as conn:
            conn.execute(
                "INSERT INTO edges "
                "(id, tenant_id, type, from_id, to_id, source, confidence, evidence, valid_from) "
                "VALUES (gen_random_uuid(), %s, 'DEPENDS_ON', gen_random_uuid(), "
                "gen_random_uuid(), 'declared', 1.0, '[]', now())",
                (str(tenant),),
            )
