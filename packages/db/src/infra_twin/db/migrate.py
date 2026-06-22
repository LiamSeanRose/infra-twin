"""Minimal forward-only migration runner.

Applies numbered ``*.sql`` files in order, each in its own transaction, recording applied
files in ``schema_migrations`` so re-running is a no-op. Runs as the superuser DSN because
migrations create extensions and roles.
"""

from __future__ import annotations

from pathlib import Path

import psycopg

from infra_twin.db.config import admin_dsn, migrations_dir


def _split_statements(sql: str) -> list[str]:
    """Split a SQL script into statements, respecting quotes, dollar-quotes and comments."""
    statements: list[str] = []
    buf: list[str] = []
    i, n = 0, len(sql)
    in_squote = in_dquote = False
    dollar: str | None = None

    while i < n:
        c = sql[i]
        if dollar is not None:
            if sql.startswith(dollar, i):
                buf.append(dollar)
                i += len(dollar)
                dollar = None
            else:
                buf.append(c)
                i += 1
            continue
        if in_squote:
            buf.append(c)
            if c == "'":
                if i + 1 < n and sql[i + 1] == "'":
                    buf.append("'")
                    i += 2
                    continue
                in_squote = False
            i += 1
            continue
        if in_dquote:
            buf.append(c)
            if c == '"':
                in_dquote = False
            i += 1
            continue
        # Outside any quoted region.
        if c == "-" and i + 1 < n and sql[i + 1] == "-":
            while i < n and sql[i] != "\n":
                i += 1
            continue
        if c == "'":
            in_squote = True
            buf.append(c)
            i += 1
            continue
        if c == '"':
            in_dquote = True
            buf.append(c)
            i += 1
            continue
        if c == "$":
            j = sql.find("$", i + 1)
            if j != -1 and (sql[i + 1 : j].isidentifier() or sql[i + 1 : j] == ""):
                dollar = sql[i : j + 1]
                buf.append(dollar)
                i = j + 1
                continue
            buf.append(c)
            i += 1
            continue
        if c == ";":
            stmt = "".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


def _ensure_ledger(conn: psycopg.Connection) -> None:
    with conn.transaction():
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " filename TEXT PRIMARY KEY,"
            " applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )


def _applied(conn: psycopg.Connection) -> set[str]:
    rows = conn.execute("SELECT filename FROM schema_migrations").fetchall()
    return {r[0] for r in rows}


def run_migrations(dsn: str | None = None, directory: Path | None = None) -> list[str]:
    """Apply pending migrations. Returns the filenames applied this run (empty if up to date)."""
    dsn = dsn or admin_dsn()
    directory = directory or migrations_dir()
    newly_applied: list[str] = []

    with psycopg.connect(dsn, autocommit=False) as conn:
        _ensure_ledger(conn)
        done = _applied(conn)
        for path in sorted(directory.glob("*.sql")):
            if path.name in done:
                continue
            statements = _split_statements(path.read_text())
            with conn.transaction():
                for statement in statements:
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations (filename) VALUES (%s)", (path.name,)
                )
            newly_applied.append(path.name)

    return newly_applied


def main() -> None:
    applied = run_migrations()
    if applied:
        print("Applied migrations:")
        for name in applied:
            print(f"  - {name}")
    else:
        print("Database is up to date; no migrations applied.")


if __name__ == "__main__":
    main()
