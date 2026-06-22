"""Shared fixtures. Tests run against the dockerized Postgres + AGE instance."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import psycopg
import pytest

from infra_twin.db.api_keys import IssuedKey, provision_tenant
from infra_twin.db.config import admin_dsn
from infra_twin.db.migrate import run_migrations
from infra_twin.db.pool import make_pool

MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"

_DATA_TABLES = "history_aggregates, history_retention_policies, ci_merge_candidates, ci_unmerges, ci_merges, ci_alias_keys, scim_user, scim_provisioning_token, notification_delivery, notification_subscription, usage_event, audit_log, finding, edges, cis, source_keys, raw_facts, connector_runs, freshness_slos, connectors, api_keys, tenant_idp_config, tenants"


@pytest.fixture(scope="session", autouse=True)
def _migrated() -> None:
    """Apply migrations once for the whole test session."""
    run_migrations(directory=MIGRATIONS_DIR)


@pytest.fixture(scope="session")
def pool():
    p = make_pool()
    yield p
    p.close()


@pytest.fixture(autouse=True)
def _clean() -> None:
    """Truncate all tenant data before each test (as superuser, bypassing RLS)."""
    with psycopg.connect(admin_dsn()) as conn:
        conn.execute(f"TRUNCATE {_DATA_TABLES} RESTART IDENTITY CASCADE")
        conn.commit()


@pytest.fixture
def make_tenant():
    """Factory creating a tenant row (as superuser) and returning its id."""

    def _make(name: str = "tenant") -> UUID:
        with psycopg.connect(admin_dsn()) as conn:
            row = conn.execute(
                "INSERT INTO tenants (name) VALUES (%s) RETURNING tenant_id", (name,)
            ).fetchone()
            conn.commit()
        return row[0]

    return _make


@pytest.fixture
def make_tenant_with_key():
    """Factory creating a tenant + API key via provision_tenant, returning (tenant_id, plaintext).

    Uses the admin connection so both the tenants row and the api_keys row are
    written in one transaction, exactly as the production POST /tenants path does.
    """

    def _make(name: str = "tenant") -> tuple[UUID, str]:
        with psycopg.connect(admin_dsn()) as conn:
            issued: IssuedKey = provision_tenant(conn, name)
        return issued.tenant_id, issued.plaintext

    return _make
