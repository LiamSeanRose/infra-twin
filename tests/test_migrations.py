"""The migration runner is idempotent and records what it applied."""

from __future__ import annotations

from pathlib import Path

import psycopg

from infra_twin.db.config import admin_dsn
from infra_twin.db.migrate import run_migrations

MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"


def test_rerun_is_noop():
    # The session fixture already applied migrations; a second run applies nothing.
    assert run_migrations(directory=MIGRATIONS_DIR) == []


def test_ledger_records_init():
    with psycopg.connect(admin_dsn()) as conn:
        names = {r[0] for r in conn.execute("SELECT filename FROM schema_migrations").fetchall()}
    assert "0001_init.sql" in names
