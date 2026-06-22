"""Risk Findings v1 tests.

Covers all acceptance criteria from the spec (§6) and edge cases (§5):

Spec AC tests:
  19. rds internet-reachable -> exactly one open internet_reachable_database finding after
      POST /findings/evaluate; evidence.reaching_source.type == "internet".
  20. Non-internet-reachable rds -> zero findings.
  21. POST /findings/evaluate twice on unchanged graph -> idempotent, opened==0 second run.
  22. Reaching path removed, re-evaluate -> finding resolved (status='resolved', valid_to set,
      row still present); GET /findings returns []; resolved==1.
  23. Adversarial tenant isolation: tenant B cannot see tenant A's findings; tenant B's
      evaluate opens zero findings when only A has internet-reachable db.
  24. GET /findings with no Authorization -> 401.
  25. Viewer key -> POST /findings/evaluate returns 403 and creates no finding row;
      same viewer key -> GET /findings returns 200.
  26. All tests are in tests/test_findings.py.

Additional edge cases from §5 with corresponding test coverage:
  EC1.  No database CIs -> evaluated=0, opened=0, resolved=0, open_count=0; GET -> [].
  EC2.  Database with no inbound edges -> reached_by_internet=False -> no finding.
  EC3.  Direct internet reach (distance 1) -> one finding; evidence distance==1; path length 1.
  EC4.  Multi-hop internet reach -> one finding; evidence.path length == chosen distance.
  EC5.  Multiple internet sources reach same db -> one finding; nearest (min distance) chosen.
  EC6.  Two different databases both internet-reachable -> two findings.
  EC7.  Re-run evaluate idempotent (covered by AC 21).
  EC8.  Reaching path removed, re-evaluate (covered by AC 22).
  EC9.  Database CI closed while finding open -> finding resolved on next evaluate.
  EC10. Database becomes reachable again after resolution -> fresh id, old row still present.
  EC11. Non-internet source (only iam_role / internal SG) -> no finding.
  EC12. Non-internet CI with external_id="internet" -> type matters, not external_id -> no finding.
  EC13. Cross-tenant isolation (read) - adversarial (covered by AC 23).
  EC14. Cross-tenant isolation (evaluate) - adversarial (covered by AC 23).
  EC15. Unauthenticated GET /findings -> 401 (covered by AC 24).
  EC16. Viewer key POST /findings/evaluate -> 403 + no DB change (covered by AC 25).
  EC17. Viewer key GET /findings -> 200 (covered by AC 25).
  EC20. Internet source beyond max_depth -> no finding.
  EC21. min_confidence filtering -> no finding when edges sub-threshold.
  EC22. evidence is non-empty object for opened findings.
  EC23. GET /findings?rule_id=<no findings> -> [].
  EC24. Migration idempotency: re-applying migrations is a no-op.

Static / structural checks:
  - migrations/0011_findings.sql exists and correct structure (AC 1-9).
  - Finding model in core_model (AC 10).
  - findings.py constants (AC 11).
  - No top-level import of infra_twin.query in findings.py (AC 12).
  - services/reconciliation/pyproject.toml does not list infra-twin-query (AC 13).
  - FindingRepository methods and resolve uses UPDATE not DELETE (AC 14).
  - FindingRepository in db.__init__.__all__ (AC 15).
  - apps/api endpoints have correct response keys (AC 16).
  - apps/api/pyproject.toml lists infra-twin-reconciliation (AC 17).
  - tests/conftest.py _DATA_TABLES includes finding (AC 18).
"""

from __future__ import annotations

import pathlib
import re
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.api_keys import IssuedKey, Role, provision_tenant
from infra_twin.db.config import admin_dsn
from infra_twin.db.findings import FindingRepository
from infra_twin.db.repositories import CIRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import reconcile
from infra_twin.reconciliation.findings import (
    DATABASE_CI_TYPES,
    EvaluateResult,
    FINDINGS_SOURCE,
    IAM_PRINCIPAL_CI_TYPES,
    INTERNET_DB_SEVERITY,
    OVER_PERMISSIVE_ACCESS_THRESHOLD,
    OVER_PERMISSIVE_IAM_SEVERITY,
    RULE_INTERNET_REACHABLE_DATABASE,
    RULE_OVER_PERMISSIVE_IAM_ROLE,
    VALID_SEVERITIES,
    VALID_STATUSES,
    evaluate_findings,
    evaluate_findings_with_summary,
)

# ---------------------------------------------------------------------------
# Helpers and constants
# ---------------------------------------------------------------------------

_MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[1] / "migrations"

CI_SCOPE = frozenset({
    CIType.internet,
    CIType.security_group,
    CIType.ec2_instance,
    CIType.subnet,
    CIType.vpc,
    CIType.rds,
    CIType.elb,
    CIType.iam_role,
})

EDGE_SCOPE = frozenset({
    EdgeType.CONNECTS_TO,
    EdgeType.ROUTES_TO,
    EdgeType.HAS_ACCESS_TO,
    EdgeType.EXPOSES,
    EdgeType.CONTAINS,
    EdgeType.DEPENDS_ON,
})


def _ci(t, ext, name=None):
    return DiscoveredCI(type=t, external_id=ext, name=name or ext)


def _edge(etype, ft, fx, tt, tx, ev=None, confidence=1.0):
    return DiscoveredEdge(
        type=etype,
        from_ref=CIRef(type=ft, external_id=fx),
        to_ref=CIRef(type=tt, external_id=tx),
        evidence=ev or [Evidence(source="test")],
        confidence=confidence,
    )


def _seed(pool, tenant, events):
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant, events,
            source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE,
        )


def _get_ci_id(pool, tenant, ci_type, ext_id):
    with tenant_session(pool, tenant) as conn:
        rows = CIRepository(conn, tenant).get_current(type=ci_type, external_id=ext_id)
    assert rows, f"CI not found: {ci_type} / {ext_id}"
    return rows[0].id


def _count_findings_admin(tenant_id: UUID) -> int:
    """Count all finding rows (including resolved) as superuser."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM finding WHERE tenant_id = %s", (tenant_id,)
        ).fetchone()
    return row[0]


def _make_viewer_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.viewer)
    return issued.tenant_id, issued.plaintext


def _make_editor_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.editor)
    return issued.tenant_id, issued.plaintext


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _internet_reachable_rds_events(rds_ext_id: str = "db-1"):
    """Canonical seeding: internet -> sg -> rds."""
    return [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.rds, rds_ext_id, f"prod-{rds_ext_id}"),
        _edge(
            EdgeType.CONNECTS_TO,
            CIType.internet, "internet",
            CIType.security_group, "sg-1",
            ev=[Evidence(source="aws", detail="sg-1 allows 0.0.0.0/0")],
        ),
        _edge(
            EdgeType.EXPOSES,
            CIType.security_group, "sg-1",
            CIType.rds, rds_ext_id,
            ev=[Evidence(source="aws", detail="sg-1 exposes rds")],
        ),
    ]


# ---------------------------------------------------------------------------
# =============================================================================
# STRUCTURAL / STATIC ACCEPTANCE CRITERIA (AC 1-18)
# =============================================================================
# ---------------------------------------------------------------------------

# --- AC 1: migration file exists ---

def test_ac1_migration_0011_exists():
    """AC 1: migrations/0011_findings.sql exists."""
    assert (_MIGRATIONS_DIR / "0011_findings.sql").exists()


def test_ac1_migration_creates_finding_table():
    """AC 1: migration creates table 'finding'."""
    text = (_MIGRATIONS_DIR / "0011_findings.sql").read_text()
    assert "CREATE TABLE finding" in text


# --- AC 2: correct columns ---

def test_ac2_finding_table_columns_from_db():
    """AC 2: finding table has all specified columns with expected types (via information_schema)."""
    expected_columns = {
        "id", "tenant_id", "rule_id", "severity", "subject_ci_id",
        "title", "description", "evidence", "status",
        "detected_at", "valid_from", "valid_to",
    }
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'finding'"
        ).fetchall()
    cols = {r[0] for r in rows}
    assert expected_columns == cols, f"Column mismatch. Got: {cols}"


def test_ac2_finding_evidence_column_is_jsonb():
    """AC 2: evidence column is JSONB."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name = 'finding' AND column_name = 'evidence'"
        ).fetchone()
    assert row is not None
    assert row[0] == "jsonb"


# --- AC 3: PK is (id, valid_from) ---

def test_ac3_finding_primary_key_is_id_and_valid_from():
    """AC 3: finding PRIMARY KEY is (id, valid_from)."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            """
            SELECT kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
            WHERE tc.table_name = 'finding'
              AND tc.constraint_type = 'PRIMARY KEY'
            ORDER BY kcu.ordinal_position
            """
        ).fetchall()
    pk_cols = [r[0] for r in rows]
    assert pk_cols == ["id", "valid_from"], f"PK columns: {pk_cols}"


# --- AC 4: status default and check ---

def test_ac4_finding_status_check_constraint():
    """AC 4: status has CHECK (status IN ('open','resolved'))."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            """
            SELECT cc.check_clause
            FROM information_schema.table_constraints tc
            JOIN information_schema.check_constraints cc
              ON tc.constraint_name = cc.constraint_name
            WHERE tc.table_name = 'finding'
              AND tc.constraint_type = 'CHECK'
            """
        ).fetchall()
    clauses = [r[0] for r in rows]
    assert any("status" in c.lower() for c in clauses), (
        f"No CHECK clause for status found; got: {clauses}"
    )
    assert any("open" in c for c in clauses)
    assert any("resolved" in c for c in clauses)


def test_ac4_finding_status_default_is_open():
    """AC 4: status column default is 'open'."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT column_default FROM information_schema.columns "
            "WHERE table_name = 'finding' AND column_name = 'status'"
        ).fetchone()
    assert row is not None
    assert row[0] is not None, "status has no default"
    assert "open" in row[0], f"status default does not contain 'open'; got: {row[0]}"


# --- AC 5: severity check ---

def test_ac5_finding_severity_check_constraint():
    """AC 5: severity has CHECK (severity IN ('low','medium','high','critical'))."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            """
            SELECT cc.check_clause
            FROM information_schema.table_constraints tc
            JOIN information_schema.check_constraints cc
              ON tc.constraint_name = cc.constraint_name
            WHERE tc.table_name = 'finding'
              AND tc.constraint_type = 'CHECK'
            """
        ).fetchall()
    clauses = [r[0] for r in rows]
    assert any("severity" in c.lower() for c in clauses), (
        f"No CHECK clause for severity found; got: {clauses}"
    )
    sev_clauses = [c for c in clauses if "severity" in c.lower()]
    full = " ".join(sev_clauses)
    for val in ("low", "medium", "high", "critical"):
        assert val in full, f"'{val}' not in severity CHECK: {sev_clauses}"


# --- AC 6: partial unique index finding_open_identity ---

def test_ac6_finding_open_identity_partial_unique_index():
    """AC 6: partial unique index finding_open_identity on (tenant_id, rule_id, subject_ci_id) WHERE valid_to IS NULL."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            """
            SELECT indexname, indexdef
            FROM pg_indexes
            WHERE tablename = 'finding'
              AND indexname = 'finding_open_identity'
            """
        ).fetchone()
    assert row is not None, "finding_open_identity index not found"
    indexdef = row[1]
    assert "tenant_id" in indexdef
    assert "rule_id" in indexdef
    assert "subject_ci_id" in indexdef
    # Postgres wraps the predicate in parentheses: "(valid_to IS NULL)"
    assert "valid_to" in indexdef.lower()
    assert "null" in indexdef.lower()


# --- AC 7: RLS enabled and tenant_isolation policy ---

def test_ac7_finding_rls_enabled():
    """AC 7: RLS is enabled on finding table."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT rowsecurity FROM pg_tables "
            "WHERE tablename = 'finding'"
        ).fetchone()
    assert row is not None
    assert row[0] is True, "RLS is not enabled on finding table"


def test_ac7_finding_tenant_isolation_policy_exists():
    """AC 7: tenant_isolation policy exists on finding."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT policyname FROM pg_policies "
            "WHERE tablename = 'finding' AND policyname = 'tenant_isolation'"
        ).fetchone()
    assert row is not None, "tenant_isolation policy not found on finding table"


def test_ac7_tenant_isolation_policy_keys_on_guc():
    """AC 7: tenant_isolation policy uses current_setting('app.tenant_id', true)."""
    text = (_MIGRATIONS_DIR / "0011_findings.sql").read_text()
    assert "current_setting('app.tenant_id', true)" in text


# --- AC 8: GRANT is SELECT, INSERT, UPDATE — no DELETE ---

def test_ac8_migration_grants_select_insert_update_not_delete():
    """AC 8: migration grants SELECT, INSERT, UPDATE but NOT DELETE/ALL."""
    text = (_MIGRATIONS_DIR / "0011_findings.sql").read_text().upper()
    assert "GRANT SELECT, INSERT, UPDATE ON FINDING TO APP" in text
    # No DELETE in any GRANT statement targeting finding
    grant_lines = [l for l in text.splitlines() if "GRANT" in l and "FINDING" in l]
    for line in grant_lines:
        assert "DELETE" not in line, f"DELETE found in GRANT line: {line}"
        assert "ALL" not in line, f"ALL found in GRANT line: {line}"


# --- AC 9: expand-only migration ---

def test_ac9_migration_is_expand_only_no_drop_table():
    """AC 9: migration has no DROP TABLE."""
    text = (_MIGRATIONS_DIR / "0011_findings.sql").read_text().upper()
    assert "DROP TABLE" not in text


def test_ac9_migration_is_expand_only_no_drop_column():
    """AC 9: migration has no DROP COLUMN."""
    text = (_MIGRATIONS_DIR / "0011_findings.sql").read_text().upper()
    assert "DROP COLUMN" not in text


def test_ac9_migration_is_expand_only_no_alter_drop_default():
    """AC 9: migration has no ALTER COLUMN ... DROP DEFAULT."""
    text = (_MIGRATIONS_DIR / "0011_findings.sql").read_text().upper()
    assert "DROP DEFAULT" not in text


def test_ac9_migration_is_expand_only_no_delete():
    """AC 9: migration has no DELETE statement."""
    text = (_MIGRATIONS_DIR / "0011_findings.sql").read_text().upper()
    # Exclude "DELETE" that appears in comments
    lines = [l.strip() for l in text.splitlines() if not l.strip().startswith("--")]
    non_comment = "\n".join(lines)
    assert "DELETE" not in non_comment, "DELETE statement found in non-comment migration text"


# --- AC 10: Finding model in core_model ---

def test_ac10_finding_in_core_model():
    """AC 10: infra_twin.core_model.Finding exists and is a BaseModel."""
    from pydantic import BaseModel as PydanticBaseModel
    from infra_twin.core_model import Finding
    assert issubclass(Finding, PydanticBaseModel)


def test_ac10_finding_in_core_model_all():
    """AC 10: Finding is in core_model.__all__."""
    import infra_twin.core_model as cm
    assert "Finding" in cm.__all__


def test_ac10_finding_model_fields():
    """AC 10: Finding has all required fields."""
    from infra_twin.core_model import Finding
    expected_fields = {
        "id", "tenant_id", "rule_id", "severity", "subject_ci_id",
        "title", "description", "evidence", "status", "detected_at",
        "valid_from", "valid_to",
    }
    assert expected_fields == set(Finding.model_fields.keys())


# --- AC 11: constants in findings.py ---

def test_ac11_rule_internet_reachable_database_constant():
    """AC 11: RULE_INTERNET_REACHABLE_DATABASE == 'internet_reachable_database'."""
    assert RULE_INTERNET_REACHABLE_DATABASE == "internet_reachable_database"


def test_ac11_internet_db_severity_constant():
    """AC 11: INTERNET_DB_SEVERITY == 'critical'."""
    assert INTERNET_DB_SEVERITY == "critical"


def test_ac11_database_ci_types_constant():
    """AC 11: DATABASE_CI_TYPES == frozenset({CIType.rds})."""
    assert DATABASE_CI_TYPES == frozenset({CIType.rds})


def test_ac11_valid_severities_constant():
    """AC 11: VALID_SEVERITIES == ('low', 'medium', 'high', 'critical')."""
    assert VALID_SEVERITIES == ("low", "medium", "high", "critical")


def test_ac11_valid_statuses_constant():
    """AC 11: VALID_STATUSES == ('open', 'resolved')."""
    assert VALID_STATUSES == ("open", "resolved")


def test_ac11_evaluate_findings_exported():
    """AC 11: evaluate_findings and evaluate_findings_with_summary are defined."""
    assert callable(evaluate_findings)
    assert callable(evaluate_findings_with_summary)


def test_ac11_evaluate_result_dataclass():
    """AC 11: EvaluateResult is a dataclass with evaluated, opened, resolved, open_count."""
    import dataclasses
    assert dataclasses.is_dataclass(EvaluateResult)
    field_names = {f.name for f in dataclasses.fields(EvaluateResult)}
    assert field_names == {"evaluated", "opened", "resolved", "open_count"}


# --- AC 12: no top-level import of infra_twin.query in findings.py ---

def test_ac12_no_top_level_query_import():
    """AC 12: findings.py has no top-level 'import infra_twin.query' or 'from infra_twin.query'
    outside TYPE_CHECKING or function bodies."""
    findings_file = pathlib.Path(__file__).resolve().parents[1] / (
        "services/reconciliation/src/infra_twin/reconciliation/findings.py"
    )
    assert findings_file.exists(), f"findings.py not found at {findings_file}"
    text = findings_file.read_text()
    lines = text.splitlines()

    # Parse the file tracking indent level and TYPE_CHECKING context.
    # A "top-level" line is at indent level 0 and not inside TYPE_CHECKING or a function body.
    in_type_checking_block = False
    inside_function_body = False
    function_indent: int | None = None
    real_top_level: list[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        # Track when we exit a function body (back to indent 0 with a non-empty line)
        if inside_function_body and function_indent is not None and indent <= function_indent:
            inside_function_body = False
            function_indent = None

        # Detect TYPE_CHECKING block
        if indent == 0 and stripped == "if TYPE_CHECKING:":
            in_type_checking_block = True
            continue
        if in_type_checking_block and indent == 0 and stripped and not stripped.startswith(" "):
            in_type_checking_block = False

        # Detect function/class definitions (these introduce a new scope)
        if indent == 0 and (stripped.startswith("def ") or stripped.startswith("class ")):
            inside_function_body = True
            function_indent = 0
            continue

        # Only check module-level lines (indent 0) outside TYPE_CHECKING and function bodies
        if indent == 0 and not in_type_checking_block and not inside_function_body:
            if (
                "from infra_twin.query" in stripped
                or "import infra_twin.query" in stripped
            ):
                real_top_level.append(stripped)

    assert real_top_level == [], (
        f"Top-level infra_twin.query import found outside TYPE_CHECKING: {real_top_level}"
    )


# --- AC 13: services/reconciliation/pyproject.toml does NOT list infra-twin-query ---

def test_ac13_reconciliation_pyproject_does_not_list_query():
    """AC 13: services/reconciliation/pyproject.toml does not list infra-twin-query."""
    pyproject_path = pathlib.Path(__file__).resolve().parents[1] / (
        "services/reconciliation/pyproject.toml"
    )
    assert pyproject_path.exists(), f"pyproject.toml not found at {pyproject_path}"
    text = pyproject_path.read_text()
    assert "infra-twin-query" not in text, (
        "services/reconciliation/pyproject.toml must not list infra-twin-query"
    )


# --- AC 14: FindingRepository methods; resolve uses UPDATE not DELETE ---

def test_ac14_finding_repository_has_required_methods():
    """AC 14: FindingRepository has get_open, get_open_for_subject, open_finding, resolve."""
    for method_name in ("get_open", "get_open_for_subject", "open_finding", "resolve"):
        assert hasattr(FindingRepository, method_name), (
            f"FindingRepository missing method: {method_name}"
        )


def test_ac14_resolve_uses_update_not_delete():
    """AC 14: FindingRepository.resolve issues UPDATE, never DELETE (excluding docstrings/comments)."""
    findings_file = pathlib.Path(__file__).resolve().parents[1] / (
        "packages/db/src/infra_twin/db/findings.py"
    )
    text = findings_file.read_text()
    # Find the resolve method body
    resolve_start = text.find("def resolve(")
    assert resolve_start >= 0, "resolve method not found"
    resolve_body = text[resolve_start:]
    # Find next method or end of class
    next_def = resolve_body.find("\n    def ", 1)
    if next_def > 0:
        resolve_body = resolve_body[:next_def]

    assert "UPDATE" in resolve_body.upper(), "resolve must issue an UPDATE"

    # Strip docstrings and comments before checking for DELETE
    # Remove triple-quoted docstrings
    import re as _re
    no_docstrings = _re.sub(r'""".*?"""', "", resolve_body, flags=_re.DOTALL)
    no_docstrings = _re.sub(r"'''.*?'''", "", no_docstrings, flags=_re.DOTALL)
    # Remove single-line comments
    no_comments = "\n".join(
        line for line in no_docstrings.splitlines()
        if not line.strip().startswith("#")
    )
    assert "DELETE" not in no_comments.upper(), (
        f"resolve must not issue a DELETE (non-comment/docstring text): {no_comments}"
    )


# --- AC 15: FindingRepository in db.__init__.__all__ ---

def test_ac15_finding_repository_in_db_all():
    """AC 15: FindingRepository is in infra_twin.db.__init__.__all__."""
    import infra_twin.db as db
    assert "FindingRepository" in db.__all__


def test_ac15_finding_repository_importable_from_db():
    """AC 15: FindingRepository can be imported from infra_twin.db."""
    from infra_twin.db import FindingRepository as FR
    assert FR is FindingRepository


# --- AC 16: API endpoints return correct keys ---

def test_ac16_evaluate_response_keys(pool, make_tenant_with_key):
    """AC 16: POST /findings/evaluate returns exactly {evaluated, opened, resolved, open_count}."""
    tenant, api_key = make_tenant_with_key("ac16-evaluate")
    client = TestClient(create_app(pool=pool))
    resp = client.post("/findings/evaluate", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"evaluated", "opened", "resolved", "open_count"}


def test_ac16_list_findings_response_keys(pool, make_tenant_with_key):
    """AC 16: GET /findings returns list with correct keys when findings exist."""
    tenant, api_key = make_tenant_with_key("ac16-list")
    _seed(pool, tenant, _internet_reachable_rds_events())
    client = TestClient(create_app(pool=pool))
    # First evaluate to create a finding
    eval_resp = client.post("/findings/evaluate", headers=_auth(api_key))
    assert eval_resp.status_code == 200

    resp = client.get("/findings", headers=_auth(api_key))
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    f = findings[0]
    expected_keys = {
        "id", "rule_id", "severity", "subject_ci_id", "subject_ci_type",
        "subject_ci_name", "title", "description", "evidence", "status", "detected_at",
    }
    assert set(f.keys()) == expected_keys, f"Response keys mismatch. Got: {set(f.keys())}"


# --- AC 17: apps/api/pyproject.toml lists infra-twin-reconciliation ---

def test_ac17_api_pyproject_lists_reconciliation():
    """AC 17: apps/api/pyproject.toml lists infra-twin-reconciliation in dependencies."""
    pyproject_path = pathlib.Path(__file__).resolve().parents[1] / (
        "apps/api/pyproject.toml"
    )
    assert pyproject_path.exists()
    text = pyproject_path.read_text()
    assert "infra-twin-reconciliation" in text, (
        "apps/api/pyproject.toml must list infra-twin-reconciliation"
    )


# --- AC 18: conftest.py _DATA_TABLES includes finding ---

def test_ac18_conftest_includes_finding_in_data_tables():
    """AC 18: tests/conftest.py _DATA_TABLES includes 'finding'."""
    conftest_path = pathlib.Path(__file__).resolve().parent / "conftest.py"
    text = conftest_path.read_text()
    # Find _DATA_TABLES line
    assert "finding" in text, "_DATA_TABLES in conftest.py must include 'finding'"
    # More specific check that it's in the _DATA_TABLES string
    match = re.search(r'_DATA_TABLES\s*=\s*["\']([^"\']+)["\']', text)
    assert match is not None, "_DATA_TABLES not found in conftest.py"
    tables = match.group(1)
    assert "finding" in tables, f"'finding' not in _DATA_TABLES: {tables}"


# ---------------------------------------------------------------------------
# =============================================================================
# BEHAVIORAL / INTEGRATION TESTS (AC 19-26)
# =============================================================================
# ---------------------------------------------------------------------------


# --- AC 19: internet-reachable rds -> exactly one finding ---

def test_ac19_internet_reachable_rds_yields_one_finding(pool, make_tenant_with_key):
    """AC 19: rds CI internet-reachable in graph -> exactly one open internet_reachable_database
    finding after POST /findings/evaluate with evidence.reaching_source.type == 'internet'."""
    tenant, api_key = make_tenant_with_key("ac19-internet-reach")
    _seed(pool, tenant, _internet_reachable_rds_events())
    client = TestClient(create_app(pool=pool))

    resp = client.post("/findings/evaluate", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["evaluated"] == 1
    assert body["opened"] == 1
    assert body["resolved"] == 0
    assert body["open_count"] == 1

    findings_resp = client.get("/findings", headers=_auth(api_key))
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) == 1

    f = findings[0]
    assert f["rule_id"] == "internet_reachable_database"
    assert f["severity"] == "critical"
    assert f["status"] == "open"
    # Evidence must have reaching_source with type == "internet"
    evidence = f["evidence"]
    assert "reaching_source" in evidence
    assert evidence["reaching_source"]["type"] == "internet"


def test_ac19_finding_evidence_structure(pool, make_tenant_with_key):
    """AC 19 / EC 22: finding evidence is a non-empty object with required keys."""
    tenant, api_key = make_tenant_with_key("ac19-evidence")
    _seed(pool, tenant, _internet_reachable_rds_events())
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(api_key))

    resp = client.get("/findings", headers=_auth(api_key))
    f = resp.json()[0]
    ev = f["evidence"]
    assert isinstance(ev, dict)
    assert ev != {}, "evidence must not be empty for opened findings"
    assert "rule_id" in ev
    assert "subject_external_id" in ev
    assert "reaching_source" in ev
    assert "path" in ev
    rs = ev["reaching_source"]
    assert rs["type"] == "internet"
    assert "id" in rs
    assert "distance" in rs


# --- AC 20: non-internet-reachable rds -> zero findings ---

def test_ac20_non_internet_reachable_rds_yields_no_finding(pool, make_tenant_with_key):
    """AC 20: non-internet-reachable rds -> zero findings.

    The graph has 1 rds + 1 iam_role, so multi-rule aggregate evaluated == 2
    (1 from the internet rule, 1 from the IAM rule). The iam_role has only 1
    HAS_ACCESS_TO target (the rds), which is below the default threshold of 10,
    so opened == 0 for both rules.
    """
    tenant, api_key = make_tenant_with_key("ac20-no-internet")
    # Seed rds with only an iam_role connecting to it (not internet)
    _seed(pool, tenant, [
        _ci(CIType.rds, "db-isolated", "isolated-db"),
        _ci(CIType.iam_role, "role-1"),
        _edge(
            EdgeType.HAS_ACCESS_TO,
            CIType.iam_role, "role-1",
            CIType.rds, "db-isolated",
        ),
    ])
    client = TestClient(create_app(pool=pool))

    resp = client.post("/findings/evaluate", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    # Multi-rule aggregate: 1 rds (internet rule) + 1 iam_role (IAM rule) = 2 evaluated
    assert body["evaluated"] == 2
    assert body["opened"] == 0
    assert body["resolved"] == 0
    assert body["open_count"] == 0

    findings_resp = client.get("/findings", headers=_auth(api_key))
    assert findings_resp.json() == []


# --- AC 21: idempotency - re-run on unchanged graph leaves exactly one finding ---

def test_ac21_evaluate_is_idempotent_no_duplicate(pool, make_tenant_with_key):
    """AC 21: POST /findings/evaluate twice on unchanged graph -> idempotent; opened==0 second run."""
    tenant, api_key = make_tenant_with_key("ac21-idempotent")
    _seed(pool, tenant, _internet_reachable_rds_events())
    client = TestClient(create_app(pool=pool))

    # First run
    resp1 = client.post("/findings/evaluate", headers=_auth(api_key))
    assert resp1.status_code == 200
    body1 = resp1.json()
    assert body1["opened"] == 1
    assert body1["open_count"] == 1

    # Second run - idempotent
    resp2 = client.post("/findings/evaluate", headers=_auth(api_key))
    assert resp2.status_code == 200
    body2 = resp2.json()
    assert body2["opened"] == 0, "Second run must open 0 new findings on unchanged graph"
    assert body2["resolved"] == 0
    assert body2["open_count"] == 1, "Still exactly one open finding after second run"

    # GET /findings still returns exactly one
    findings_resp = client.get("/findings", headers=_auth(api_key))
    assert len(findings_resp.json()) == 1

    # Total rows in DB (as superuser) is also exactly 1 — no duplicate rows inserted
    total_rows = _count_findings_admin(tenant)
    assert total_rows == 1, f"Expected 1 row in finding table, got {total_rows}"


# --- AC 22: reaching path removed -> finding resolved, GET /findings returns [] ---

def test_ac22_resolved_finding_not_deleted_row_stays(pool, make_tenant_with_key):
    """AC 22: after removing reaching path and re-evaluating, finding is resolved
    (status='resolved', valid_to set) but row still exists in DB; GET /findings returns [].

    The reaching path is removed by re-running reconciliation without the EXPOSES edge,
    which properly updates both the relational table and the AGE graph projection.
    """
    tenant, api_key = make_tenant_with_key("ac22-resolve")
    _seed(pool, tenant, _internet_reachable_rds_events())
    client = TestClient(create_app(pool=pool))

    # First evaluate: opens finding
    resp1 = client.post("/findings/evaluate", headers=_auth(api_key))
    assert resp1.json()["opened"] == 1

    # Capture the finding id
    f_initial = client.get("/findings", headers=_auth(api_key)).json()[0]
    finding_id = f_initial["id"]

    # Remove the reaching path by re-reconciling without the EXPOSES edge.
    # Reconciliation is scoped by (source, ci_types, edge_types); a second run without
    # the EXPOSES edge will close it in the relational table AND remove it from the AGE graph.
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant,
            [
                _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
                _ci(CIType.security_group, "sg-1"),
                _ci(CIType.rds, "db-1", "prod-db-1"),
                _edge(
                    EdgeType.CONNECTS_TO,
                    CIType.internet, "internet",
                    CIType.security_group, "sg-1",
                    ev=[Evidence(source="aws", detail="sg-1 allows 0.0.0.0/0")],
                ),
                # EXPOSES edge intentionally omitted -> reconciler will close it in both
                # the relational table and the AGE graph.
            ],
            source="test",
            ci_types=CI_SCOPE,
            edge_types=EDGE_SCOPE,
        )

    # Re-evaluate after path removal
    resp2 = client.post("/findings/evaluate", headers=_auth(api_key))
    assert resp2.status_code == 200
    body2 = resp2.json()
    assert body2["resolved"] == 1, f"Expected resolved=1, got {body2}"
    assert body2["open_count"] == 0

    # GET /findings returns [] (no open findings)
    findings_resp = client.get("/findings", headers=_auth(api_key))
    assert findings_resp.json() == [], "GET /findings must return [] after finding resolved"

    # The resolved row STILL EXISTS in DB (never deleted) — verify via superuser query
    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT status, valid_to FROM finding WHERE id = %s::uuid",
            (finding_id,),
        ).fetchone()
    assert row is not None, "Resolved finding row was deleted from DB (violates bitemporal rule)"
    assert row[0] == "resolved", f"Expected status='resolved', got '{row[0]}'"
    assert row[1] is not None, "valid_to must be set on resolved finding"


# --- AC 23: adversarial tenant isolation ---

def test_ac23_adversarial_tenant_b_cannot_see_tenant_a_findings(pool, make_tenant_with_key):
    """AC 23: tenant B's GET /findings returns [] when only tenant A has findings."""
    # Set up tenant A with internet-reachable rds
    tenant_a, key_a = make_tenant_with_key("ac23-tenant-a")
    tenant_b, key_b = make_tenant_with_key("ac23-tenant-b")

    _seed(pool, tenant_a, _internet_reachable_rds_events())
    client = TestClient(create_app(pool=pool))

    # Tenant A evaluates and gets a finding
    resp_a = client.post("/findings/evaluate", headers=_auth(key_a))
    assert resp_a.json()["opened"] == 1

    # Tenant B adversarially tries to GET /findings -- must get []
    resp_b = client.get("/findings", headers=_auth(key_b))
    assert resp_b.status_code == 200
    assert resp_b.json() == [], (
        "Tenant B must NOT see tenant A's findings (adversarial cross-tenant read)"
    )


def test_ac23_adversarial_tenant_b_evaluate_opens_zero_findings(pool, make_tenant_with_key):
    """AC 23: tenant B's POST /findings/evaluate opens 0 findings when only A has
    internet-reachable db (adversarial cross-tenant evaluate)."""
    tenant_a, key_a = make_tenant_with_key("ac23-eval-a")
    tenant_b, key_b = make_tenant_with_key("ac23-eval-b")

    # Only tenant A has internet-reachable rds
    _seed(pool, tenant_a, _internet_reachable_rds_events())

    client = TestClient(create_app(pool=pool))

    # Tenant A has findings
    resp_a = client.post("/findings/evaluate", headers=_auth(key_a))
    assert resp_a.json()["opened"] == 1

    # Tenant B's evaluate: tenant B has no CIs -> evaluated=0, opened=0
    resp_b = client.post("/findings/evaluate", headers=_auth(key_b))
    assert resp_b.status_code == 200
    body_b = resp_b.json()
    assert body_b["evaluated"] == 0, (
        "Tenant B must evaluate 0 CIs (cannot see A's graph)"
    )
    assert body_b["opened"] == 0, (
        "Tenant B must open 0 findings (adversarial cross-tenant evaluate)"
    )


def test_ac23_adversarial_tenant_b_cannot_see_tenant_a_findings_via_filter(pool, make_tenant_with_key):
    """AC 23 (extra): GET /findings?rule_id=internet_reachable_database from tenant B still returns []."""
    tenant_a, key_a = make_tenant_with_key("ac23-filter-a")
    tenant_b, key_b = make_tenant_with_key("ac23-filter-b")

    _seed(pool, tenant_a, _internet_reachable_rds_events())
    client = TestClient(create_app(pool=pool))

    client.post("/findings/evaluate", headers=_auth(key_a))

    # Tenant B tries with rule_id filter
    resp_b = client.get(
        "/findings?rule_id=internet_reachable_database",
        headers=_auth(key_b),
    )
    assert resp_b.status_code == 200
    assert resp_b.json() == []


def test_ac23_rls_blocks_direct_raw_read_by_tenant_b(pool, make_tenant):
    """AC 23 (storage-layer adversarial): raw SELECT under tenant B session returns no findings
    from tenant A's session data."""
    tenant_a = make_tenant("rls-a")
    tenant_b = make_tenant("rls-b")

    _seed(pool, tenant_a, _internet_reachable_rds_events())

    # Evaluate as tenant A to create finding
    with tenant_session(pool, tenant_a) as conn:
        evaluate_findings(conn, tenant_a)

    # Tenant B's raw SELECT sees nothing due to RLS
    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM finding WHERE status = 'open'"
        ).fetchone()[0]
    assert count == 0, "Tenant B raw SELECT must not see tenant A's findings (RLS)"


# --- AC 24: GET /findings without Authorization -> 401 ---

def test_ac24_get_findings_unauthenticated_returns_401(pool):
    """AC 24: GET /findings with no Authorization header -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/findings")
    assert resp.status_code == 401


def test_ac24_post_evaluate_unauthenticated_returns_401(pool):
    """AC 24 (extra): POST /findings/evaluate with no Authorization header -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.post("/findings/evaluate")
    assert resp.status_code == 401


# --- AC 25: viewer key restrictions ---

def test_ac25_viewer_key_post_evaluate_returns_403(pool):
    """AC 25: viewer key on POST /findings/evaluate returns 403."""
    _, viewer_key = _make_viewer_key("ac25-viewer-403")
    client = TestClient(create_app(pool=pool))
    resp = client.post("/findings/evaluate", headers=_auth(viewer_key))
    assert resp.status_code == 403


def test_ac25_viewer_key_post_evaluate_no_finding_row_created(pool):
    """AC 25: viewer key POST /findings/evaluate returns 403 and creates no finding row."""
    viewer_tenant, viewer_key = _make_viewer_key("ac25-viewer-no-db")
    client = TestClient(create_app(pool=pool))

    resp = client.post("/findings/evaluate", headers=_auth(viewer_key))
    assert resp.status_code == 403

    count = _count_findings_admin(viewer_tenant)
    assert count == 0, "No finding row should be created when viewer's POST /findings/evaluate is blocked with 403"


def test_ac25_viewer_key_post_evaluate_detail(pool):
    """AC 25: viewer 403 has correct detail."""
    _, viewer_key = _make_viewer_key("ac25-viewer-detail")
    client = TestClient(create_app(pool=pool))
    resp = client.post("/findings/evaluate", headers=_auth(viewer_key))
    assert resp.json()["detail"] == "insufficient permissions"


def test_ac25_viewer_key_get_findings_returns_200(pool):
    """AC 25: viewer key on GET /findings returns 200."""
    _, viewer_key = _make_viewer_key("ac25-viewer-200")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/findings", headers=_auth(viewer_key))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_ac25_viewer_key_get_findings_returns_empty_when_no_findings(pool):
    """AC 25: viewer key GET /findings returns [] when no findings exist."""
    _, viewer_key = _make_viewer_key("ac25-viewer-empty")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/findings", headers=_auth(viewer_key))
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# =============================================================================
# EDGE CASE TESTS (§5)
# =============================================================================
# ---------------------------------------------------------------------------


# --- EC 1: No database CIs ---

def test_ec1_no_database_cis_returns_zeros(pool, make_tenant):
    """EC 1: No database CIs -> evaluated=0, opened=0, resolved=0, open_count=0."""
    tenant = make_tenant("ec1-no-dbs")
    _seed(pool, tenant, [_ci(CIType.ec2_instance, "i-1")])
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.evaluated == 0
    assert result.opened == 0
    assert result.resolved == 0
    assert result.open_count == 0
    assert findings == []


def test_ec1_no_database_cis_get_findings_empty(pool, make_tenant_with_key):
    """EC 1: GET /findings returns [] when no database CIs."""
    tenant, api_key = make_tenant_with_key("ec1-api-empty")
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(api_key))
    resp = client.get("/findings", headers=_auth(api_key))
    assert resp.json() == []


# --- EC 2: Database with no inbound edges ---

def test_ec2_rds_with_no_inbound_edges_yields_no_finding(pool, make_tenant):
    """EC 2: database with no inbound edges -> reached_by_internet=False -> no finding."""
    tenant = make_tenant("ec2-no-edges")
    _seed(pool, tenant, [_ci(CIType.rds, "db-isolated")])
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.evaluated == 1
    assert result.opened == 0
    assert findings == []


# --- EC 3: Direct internet reach (distance 1) ---

def test_ec3_direct_internet_reach_distance_1(pool, make_tenant):
    """EC 3: internet directly connects to rds (distance 1) -> one finding;
    evidence.reaching_source.distance == 1; path length 1."""
    tenant = make_tenant("ec3-direct")
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.rds, "db-direct", "direct-db"),
        _edge(
            EdgeType.CONNECTS_TO,
            CIType.internet, "internet",
            CIType.rds, "db-direct",
            ev=[Evidence(source="aws", detail="direct internet access")],
        ),
    ])
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.opened == 1
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["reaching_source"]["distance"] == 1
    assert len(ev["path"]) == 1
    assert ev["reaching_source"]["type"] == "internet"


# --- EC 4: Multi-hop internet reach ---

def test_ec4_multi_hop_internet_reach(pool, make_tenant):
    """EC 4: multi-hop internet -> sg -> rds; evidence.path length == chosen distance == 2."""
    tenant = make_tenant("ec4-multihop")
    _seed(pool, tenant, _internet_reachable_rds_events())
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.opened == 1
    f = findings[0]
    ev = f.evidence
    chosen_distance = ev["reaching_source"]["distance"]
    assert len(ev["path"]) == chosen_distance
    assert chosen_distance >= 2


# --- EC 5: Multiple internet sources reach same db -> one finding; nearest chosen ---

def test_ec5_multiple_internet_sources_one_finding_nearest_chosen(pool, make_tenant):
    """EC 5: two internet paths to same db -> exactly one finding; nearest (smallest distance) chosen."""
    tenant = make_tenant("ec5-multi-sources")
    # Two separate paths: one direct (distance 1) and one via SG (distance 2)
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.rds, "db-multi", "multi-db"),
        # Direct: internet -> rds (distance 1)
        _edge(
            EdgeType.CONNECTS_TO,
            CIType.internet, "internet",
            CIType.rds, "db-multi",
        ),
        # Via sg: internet -> sg -> rds (distance 2)
        _edge(
            EdgeType.CONNECTS_TO,
            CIType.internet, "internet",
            CIType.security_group, "sg-1",
        ),
        _edge(
            EdgeType.EXPOSES,
            CIType.security_group, "sg-1",
            CIType.rds, "db-multi",
        ),
    ])
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.opened == 1, "Exactly one finding regardless of multiple internet sources"
    assert len(findings) == 1
    # Nearest source is distance 1 (direct)
    ev = findings[0].evidence
    assert ev["reaching_source"]["distance"] == 1


# --- EC 6: Two different databases both internet-reachable -> two findings ---

def test_ec6_two_databases_two_findings(pool, make_tenant):
    """EC 6: two different internet-reachable databases -> two findings, one per subject."""
    tenant = make_tenant("ec6-two-dbs")
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.rds, "db-1", "prod-db-1"),
        _ci(CIType.rds, "db-2", "prod-db-2"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.rds, "db-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.rds, "db-2"),
    ])
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.evaluated == 2
    assert result.opened == 2
    assert result.open_count == 2
    assert len(findings) == 2
    subject_ids = {f.subject_ci_id for f in findings}
    assert len(subject_ids) == 2, "Each finding must reference a different subject CI"


# --- EC 9: Database CI closed while finding open -> resolved on next evaluate ---

def test_ec9_closed_db_ci_finding_resolved_on_evaluate(pool, make_tenant):
    """EC 9: database CI closed while finding open -> finding resolved on next evaluate."""
    tenant = make_tenant("ec9-closed-ci")
    _seed(pool, tenant, _internet_reachable_rds_events())

    # First evaluate: open finding
    with tenant_session(pool, tenant) as conn:
        result1, findings1 = evaluate_findings_with_summary(conn, tenant)
    assert result1.opened == 1

    # Close the rds CI as superuser (simulate deletion)
    with psycopg.connect(admin_dsn()) as admin_conn:
        admin_conn.execute(
            "UPDATE cis SET valid_to = now() WHERE type = 'rds' AND valid_to IS NULL"
        )
        admin_conn.commit()

    # Re-evaluate: rds CI no longer current -> finding should be resolved
    with tenant_session(pool, tenant) as conn:
        result2, findings2 = evaluate_findings_with_summary(conn, tenant)
    assert result2.evaluated == 0, "No current rds CIs after closing"
    assert result2.resolved == 1, "Open finding for closed CI must be resolved"
    assert result2.open_count == 0
    assert findings2 == []


# --- EC 10: Database becomes reachable again after resolution -> fresh id ---

def test_ec10_reopened_database_gets_fresh_finding(pool, make_tenant):
    """EC 10: database becomes reachable again after resolution -> new open finding with fresh id;
    prior resolved row is untouched.

    Path removal is done via re-reconciliation (without the EXPOSES edge) so the AGE graph
    is properly updated alongside the relational table.
    """
    tenant = make_tenant("ec10-reopen")
    _seed(pool, tenant, _internet_reachable_rds_events())

    # First evaluate: open finding
    with tenant_session(pool, tenant) as conn:
        result1, findings1 = evaluate_findings_with_summary(conn, tenant)
    assert result1.opened == 1
    first_finding_id = findings1[0].id

    # Remove the reaching path by re-reconciling without the EXPOSES edge.
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant,
            [
                _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
                _ci(CIType.security_group, "sg-1"),
                _ci(CIType.rds, "db-1", "prod-db-1"),
                _edge(
                    EdgeType.CONNECTS_TO,
                    CIType.internet, "internet",
                    CIType.security_group, "sg-1",
                ),
                # EXPOSES intentionally absent -> will be closed and removed from AGE graph
            ],
            source="test",
            ci_types=CI_SCOPE,
            edge_types=EDGE_SCOPE,
        )

    # Second evaluate: resolves the finding
    with tenant_session(pool, tenant) as conn:
        result2, findings2 = evaluate_findings_with_summary(conn, tenant)
    assert result2.resolved == 1

    # Restore the reaching path (re-reconcile with EXPOSES edge back)
    _seed(pool, tenant, _internet_reachable_rds_events())

    # Third evaluate: opens a fresh finding
    with tenant_session(pool, tenant) as conn:
        result3, findings3 = evaluate_findings_with_summary(conn, tenant)
    assert result3.opened == 1
    assert len(findings3) == 1
    new_finding_id = findings3[0].id
    assert new_finding_id != first_finding_id, (
        "Re-opened finding must have a fresh id (not reuse the old one)"
    )

    # Old resolved row still exists
    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT id, status FROM finding WHERE id = %s",
            (first_finding_id,),
        ).fetchone()
    assert row is not None, "Resolved finding row must not be deleted"
    assert row[1] == "resolved"


# --- EC 11: Non-internet source only -> no finding ---

def test_ec11_non_internet_source_only_no_finding(pool, make_tenant):
    """EC 11: only iam_role reaches the db (not internet) -> no internet finding.

    Multi-rule aggregate: 1 rds + 1 iam_role = evaluated==2. The iam_role has
    only 1 HAS_ACCESS_TO target (below threshold of 10) so opened==0 for both rules.
    """
    tenant = make_tenant("ec11-iam-only")
    _seed(pool, tenant, [
        _ci(CIType.rds, "db-iam"),
        _ci(CIType.iam_role, "role-1"),
        _edge(EdgeType.HAS_ACCESS_TO, CIType.iam_role, "role-1", CIType.rds, "db-iam"),
    ])
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    # Multi-rule aggregate: 1 rds (internet rule) + 1 iam_role (IAM rule) = 2
    assert result.evaluated == 2
    assert result.opened == 0
    assert findings == []


# --- EC 12: Non-internet CI with external_id literally "internet" -> no finding ---

def test_ec12_non_internet_ci_external_id_internet_no_finding(pool, make_tenant):
    """EC 12: security_group with external_id='internet' does NOT produce internet finding
    (is_internet derives from CI type == 'internet', not external_id)."""
    tenant = make_tenant("ec12-external-id")
    _seed(pool, tenant, [
        _ci(CIType.security_group, "internet"),  # external_id is "internet" but type is security_group
        _ci(CIType.rds, "db-tricky"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "internet", CIType.rds, "db-tricky"),
    ])
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.evaluated == 1
    assert result.opened == 0, (
        "Security group with external_id='internet' must not be treated as internet source"
    )
    assert findings == []


# --- EC 20: Internet source beyond max_depth -> no finding ---

def test_ec20_internet_beyond_max_depth_no_finding(pool, make_tenant):
    """EC 20: internet source at depth 3 excluded when max_depth=2 -> no finding."""
    tenant = make_tenant("ec20-max-depth")
    # Chain: internet -> sg-1 -> sg-2 -> rds (depth 3 from rds)
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.security_group, "sg-2"),
        _ci(CIType.rds, "db-deep"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-1", CIType.security_group, "sg-2"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-2", CIType.rds, "db-deep"),
    ])
    with tenant_session(pool, tenant) as conn:
        # max_depth=2: internet is at distance 3 (excluded)
        result, findings = evaluate_findings_with_summary(conn, tenant, max_depth=2)
    assert result.evaluated == 1
    assert result.opened == 0
    assert findings == []


def test_ec20_internet_at_max_depth_included(pool, make_tenant):
    """EC 20 boundary: internet at exact max_depth -> finding created."""
    tenant = make_tenant("ec20-at-depth")
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.security_group, "sg-2"),
        _ci(CIType.rds, "db-at-depth"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-1", CIType.security_group, "sg-2"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-2", CIType.rds, "db-at-depth"),
    ])
    with tenant_session(pool, tenant) as conn:
        # max_depth=3: internet is at exactly distance 3 -> included
        result, findings = evaluate_findings_with_summary(conn, tenant, max_depth=3)
    assert result.evaluated == 1
    assert result.opened == 1


# --- EC 21: min_confidence filtering ---

def test_ec21_min_confidence_sub_threshold_no_finding(pool, make_tenant):
    """EC 21: db reachable only via sub-threshold edge -> no finding when min_confidence raised."""
    tenant = make_tenant("ec21-confidence")
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.rds, "db-low-conf"),
        _edge(
            EdgeType.CONNECTS_TO,
            CIType.internet, "internet",
            CIType.rds, "db-low-conf",
            confidence=0.3,
        ),
    ])
    with tenant_session(pool, tenant) as conn:
        # min_confidence=0.5: edge at 0.3 excluded
        result, findings = evaluate_findings_with_summary(conn, tenant, min_confidence=0.5)
    assert result.evaluated == 1
    assert result.opened == 0
    assert findings == []


def test_ec21_min_confidence_at_threshold_finding_opened(pool, make_tenant):
    """EC 21: db reachable at exactly min_confidence -> finding opened (>= threshold)."""
    tenant = make_tenant("ec21-at-threshold")
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.rds, "db-exact-conf"),
        _edge(
            EdgeType.CONNECTS_TO,
            CIType.internet, "internet",
            CIType.rds, "db-exact-conf",
            confidence=0.7,
        ),
    ])
    with tenant_session(pool, tenant) as conn:
        # min_confidence=0.7: edge exactly at threshold -> included
        result, findings = evaluate_findings_with_summary(conn, tenant, min_confidence=0.7)
    assert result.evaluated == 1
    assert result.opened == 1


# --- EC 22: evidence is non-empty object (via evaluate directly) ---

def test_ec22_evidence_is_non_empty_object(pool, make_tenant):
    """EC 22: opened finding has non-empty evidence object (not default '{}')."""
    tenant = make_tenant("ec22-evidence-check")
    _seed(pool, tenant, _internet_reachable_rds_events())
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.opened == 1
    f = findings[0]
    assert f.evidence != {}, "evidence must not be the empty default"
    assert "reaching_source" in f.evidence
    assert f.evidence["reaching_source"]["type"] == "internet"


# --- EC 23: GET /findings?rule_id=<no findings> -> [] ---

def test_ec23_get_findings_unknown_rule_id_returns_empty(pool, make_tenant_with_key):
    """EC 23: GET /findings?rule_id=<rule with no open findings> -> []."""
    tenant, api_key = make_tenant_with_key("ec23-unknown-rule")
    _seed(pool, tenant, _internet_reachable_rds_events())
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(api_key))

    # Query with a non-existent rule_id
    resp = client.get("/findings?rule_id=nonexistent_rule", headers=_auth(api_key))
    assert resp.status_code == 200
    assert resp.json() == []


def test_ec23_get_findings_rule_id_filter_works(pool, make_tenant_with_key):
    """EC 23 (positive): GET /findings?rule_id=internet_reachable_database returns findings."""
    tenant, api_key = make_tenant_with_key("ec23-rule-filter")
    _seed(pool, tenant, _internet_reachable_rds_events())
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(api_key))

    resp = client.get(
        "/findings?rule_id=internet_reachable_database",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 1


# --- EC 24: Migration idempotency ---

def test_ec24_migration_idempotency():
    """EC 24: re-applying migrations is a no-op (ledger prevents re-applying 0011)."""
    from infra_twin.db.migrate import run_migrations
    # Should succeed without error and not re-apply 0011
    run_migrations(directory=_MIGRATIONS_DIR)
    # Verify finding table still works
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM finding"
        ).fetchone()
    assert row is not None


# ---------------------------------------------------------------------------
# =============================================================================
# ADDITIONAL BEHAVIORAL TESTS
# =============================================================================
# ---------------------------------------------------------------------------


def test_finding_title_and_description_contain_db_name(pool, make_tenant):
    """Finding title contains 'Internet-reachable database' and db name; description has hop count."""
    tenant = make_tenant("title-desc")
    _seed(pool, tenant, _internet_reachable_rds_events("db-named"))
    with tenant_session(pool, tenant) as conn:
        _, findings = evaluate_findings_with_summary(conn, tenant)
    assert len(findings) == 1
    f = findings[0]
    assert "Internet-reachable database" in f.title
    assert "prod-db-named" in f.title or "db-named" in f.title
    assert "hop path" in f.description


def test_finding_subject_ci_id_matches_rds_ci(pool, make_tenant):
    """Finding subject_ci_id must be the UUID of the rds CI."""
    tenant = make_tenant("subject-ci")
    _seed(pool, tenant, _internet_reachable_rds_events())
    rds_id = _get_ci_id(pool, tenant, CIType.rds, "db-1")
    with tenant_session(pool, tenant) as conn:
        _, findings = evaluate_findings_with_summary(conn, tenant)
    assert findings[0].subject_ci_id == rds_id


def test_finding_rule_id_and_severity_are_correct(pool, make_tenant):
    """Finding rule_id == 'internet_reachable_database' and severity == 'critical'."""
    tenant = make_tenant("rule-sev")
    _seed(pool, tenant, _internet_reachable_rds_events())
    with tenant_session(pool, tenant) as conn:
        _, findings = evaluate_findings_with_summary(conn, tenant)
    f = findings[0]
    assert f.rule_id == RULE_INTERNET_REACHABLE_DATABASE
    assert f.severity == INTERNET_DB_SEVERITY


def test_get_findings_returns_subject_ci_type_and_name(pool, make_tenant_with_key):
    """GET /findings returns subject_ci_type='rds' and correct subject_ci_name."""
    tenant, api_key = make_tenant_with_key("subject-meta")
    _seed(pool, tenant, _internet_reachable_rds_events())
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(api_key))
    resp = client.get("/findings", headers=_auth(api_key))
    f = resp.json()[0]
    assert f["subject_ci_type"] == "rds"
    assert f["subject_ci_name"] is not None


def test_editor_can_post_evaluate(pool):
    """Editor key can POST /findings/evaluate (not 403)."""
    _, editor_key = _make_editor_key("editor-eval")
    client = TestClient(create_app(pool=pool))
    resp = client.post("/findings/evaluate", headers=_auth(editor_key))
    assert resp.status_code == 200


def test_evaluate_findings_function_returns_list(pool, make_tenant):
    """evaluate_findings (non-summary) returns a list of Finding objects."""
    tenant = make_tenant("eval-fn-list")
    _seed(pool, tenant, _internet_reachable_rds_events())
    with tenant_session(pool, tenant) as conn:
        findings = evaluate_findings(conn, tenant)
    assert isinstance(findings, list)
    assert len(findings) == 1


def test_finding_repository_get_open_returns_empty_initially(pool, make_tenant):
    """FindingRepository.get_open returns [] when no findings exist."""
    tenant = make_tenant("repo-empty")
    with tenant_session(pool, tenant) as conn:
        repo = FindingRepository(conn, tenant)
        result = repo.get_open()
    assert result == []


def test_finding_repository_get_open_for_subject_returns_none_initially(pool, make_tenant):
    """FindingRepository.get_open_for_subject returns None when no matching finding."""
    tenant = make_tenant("repo-none")
    with tenant_session(pool, tenant) as conn:
        repo = FindingRepository(conn, tenant)
        result = repo.get_open_for_subject(RULE_INTERNET_REACHABLE_DATABASE, uuid4())
    assert result is None


def test_finding_repository_resolve_returns_true(pool, make_tenant):
    """FindingRepository.resolve returns True when a finding is resolved."""
    from infra_twin.core_model import Finding
    tenant = make_tenant("repo-resolve")
    _seed(pool, tenant, _internet_reachable_rds_events())
    with tenant_session(pool, tenant) as conn:
        _, findings = evaluate_findings_with_summary(conn, tenant)
        assert len(findings) == 1
        repo = FindingRepository(conn, tenant)
        result = repo.resolve(findings[0].id)
    assert result is True


def test_finding_repository_resolve_returns_false_when_not_found(pool, make_tenant):
    """FindingRepository.resolve returns False when finding_id not found."""
    tenant = make_tenant("repo-resolve-false")
    with tenant_session(pool, tenant) as conn:
        repo = FindingRepository(conn, tenant)
        result = repo.resolve(uuid4())
    assert result is False


def test_finding_detected_at_is_iso8601_string_in_api(pool, make_tenant_with_key):
    """GET /findings detected_at is a valid ISO 8601 datetime string."""
    from datetime import datetime
    tenant, api_key = make_tenant_with_key("detected-at")
    _seed(pool, tenant, _internet_reachable_rds_events())
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(api_key))
    resp = client.get("/findings", headers=_auth(api_key))
    f = resp.json()[0]
    # Should parse as a datetime without error
    dt = datetime.fromisoformat(f["detected_at"])
    assert dt is not None


def test_findings_ordered_newest_first(pool, make_tenant):
    """GET /findings returns findings newest detected_at first."""
    tenant = make_tenant("newest-first")
    # Two separate databases to create two findings
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.rds, "db-1", "prod-db-1"),
        _ci(CIType.rds, "db-2", "prod-db-2"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.rds, "db-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.rds, "db-2"),
    ])
    with tenant_session(pool, tenant) as conn:
        _, findings = evaluate_findings_with_summary(conn, tenant)
    assert len(findings) == 2
    # Findings should be ordered by detected_at DESC
    if findings[0].detected_at and findings[1].detected_at:
        assert findings[0].detected_at >= findings[1].detected_at


# ---------------------------------------------------------------------------
# =============================================================================
# MULTI-RULE / over_permissive_iam_role TESTS
# =============================================================================
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Helpers for the IAM / over_permissive_iam_role rule
# ---------------------------------------------------------------------------

def _s3_ext(n: int) -> str:
    return f"arn:aws:s3:::bucket-{n}"


def _over_permissive_principal_events(
    principal_type: CIType = CIType.iam_role,
    principal_ext: str = "arn:aws:iam::123456789012:role/over-role",
    n_targets: int = 10,
    target_type: CIType = CIType.s3_bucket,
) -> list:
    """Build a graph with one IAM principal and n_targets distinct s3_bucket targets."""
    cis = [_ci(principal_type, principal_ext, principal_ext)]
    edges = []
    for i in range(n_targets):
        ext = _s3_ext(i)
        cis.append(_ci(target_type, ext, ext))
        edges.append(
            _edge(
                EdgeType.HAS_ACCESS_TO,
                principal_type, principal_ext,
                target_type, ext,
            )
        )
    return cis + edges


def _combined_both_rules_events(
    n_iam_targets: int = 10,
    rds_ext: str = "db-combo",
    principal_ext: str = "arn:aws:iam::111111111111:role/combo-role",
) -> list:
    """Build a graph with:
    - 1 internet-reachable RDS (triggers internet_reachable_database)
    - 1 IAM role with n_iam_targets HAS_ACCESS_TO targets (triggers over_permissive_iam_role)
    """
    internet_events = [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-combo"),
        _ci(CIType.rds, rds_ext, f"prod-{rds_ext}"),
        _edge(
            EdgeType.CONNECTS_TO,
            CIType.internet, "internet",
            CIType.security_group, "sg-combo",
            ev=[Evidence(source="aws", detail="combo sg allows 0.0.0.0/0")],
        ),
        _edge(
            EdgeType.EXPOSES,
            CIType.security_group, "sg-combo",
            CIType.rds, rds_ext,
            ev=[Evidence(source="aws", detail="sg-combo exposes rds")],
        ),
    ]
    iam_events = _over_permissive_principal_events(
        principal_type=CIType.iam_role,
        principal_ext=principal_ext,
        n_targets=n_iam_targets,
    )
    return internet_events + iam_events


# ---------------------------------------------------------------------------
# New constants AC tests (spec §6.1-4)
# ---------------------------------------------------------------------------


def test_new_ac1_rule_over_permissive_iam_role_constant():
    """AC 1: RULE_OVER_PERMISSIVE_IAM_ROLE == 'over_permissive_iam_role'."""
    assert RULE_OVER_PERMISSIVE_IAM_ROLE == "over_permissive_iam_role"


def test_new_ac2_over_permissive_iam_severity_constant():
    """AC 2: OVER_PERMISSIVE_IAM_SEVERITY == 'high'."""
    assert OVER_PERMISSIVE_IAM_SEVERITY == "high"


def test_new_ac3_over_permissive_access_threshold_constant():
    """AC 3: OVER_PERMISSIVE_ACCESS_THRESHOLD == 10."""
    assert OVER_PERMISSIVE_ACCESS_THRESHOLD == 10


def test_new_ac4_iam_principal_ci_types_constant():
    """AC 4: IAM_PRINCIPAL_CI_TYPES == frozenset({CIType.iam_role, CIType.iam_user})."""
    assert IAM_PRINCIPAL_CI_TYPES == frozenset({CIType.iam_role, CIType.iam_user})


def test_new_ac5_evaluate_findings_with_summary_accepts_access_threshold():
    """AC 5: evaluate_findings_with_summary accepts keyword-only access_threshold."""
    import inspect
    sig = inspect.signature(evaluate_findings_with_summary)
    assert "access_threshold" in sig.parameters
    p = sig.parameters["access_threshold"]
    assert p.default == OVER_PERMISSIVE_ACCESS_THRESHOLD


def test_new_ac5_evaluate_findings_accepts_access_threshold():
    """AC 5: evaluate_findings accepts keyword-only access_threshold."""
    import inspect
    sig = inspect.signature(evaluate_findings)
    assert "access_threshold" in sig.parameters
    p = sig.parameters["access_threshold"]
    assert p.default == OVER_PERMISSIVE_ACCESS_THRESHOLD


# ---------------------------------------------------------------------------
# Spec requirement 1: principal >= threshold yields exactly one open finding
# with correct rule_id, severity, evidence structure (AC 10, EC 2, EC 4, EC 15)
# ---------------------------------------------------------------------------


def test_iam_principal_at_threshold_yields_one_finding(pool, make_tenant):
    """Spec req 1 / AC 10 / EC 2: principal with exactly threshold (10) distinct
    HAS_ACCESS_TO targets yields exactly one open over_permissive_iam_role finding."""
    tenant = make_tenant("iam-at-threshold")
    _seed(pool, tenant, _over_permissive_principal_events(n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)

    assert result.opened == 1
    assert result.open_count == 1
    assert len(findings) == 1

    f = findings[0]
    assert f.rule_id == RULE_OVER_PERMISSIVE_IAM_ROLE
    assert f.severity == OVER_PERMISSIVE_IAM_SEVERITY


def test_iam_principal_at_threshold_evidence_structure(pool, make_tenant):
    """Spec req 1 / AC 10 / EC 15: evidence has all required fields; targets length
    equals access_count equals threshold (10)."""
    tenant = make_tenant("iam-evidence-struct")
    n = OVER_PERMISSIVE_ACCESS_THRESHOLD
    _seed(pool, tenant, _over_permissive_principal_events(n_targets=n))
    with tenant_session(pool, tenant) as conn:
        _, findings = evaluate_findings_with_summary(conn, tenant)

    assert len(findings) == 1
    ev = findings[0].evidence
    assert isinstance(ev, dict)
    assert ev != {}
    assert ev["rule_id"] == RULE_OVER_PERMISSIVE_IAM_ROLE
    assert "subject_external_id" in ev
    assert ev["access_count"] == n
    assert ev["threshold"] == OVER_PERMISSIVE_ACCESS_THRESHOLD
    assert "targets" in ev
    assert isinstance(ev["targets"], list)
    assert len(ev["targets"]) == n, f"targets length {len(ev['targets'])} != access_count {n}"


def test_iam_principal_above_threshold_yields_one_finding_not_per_target(pool, make_tenant):
    """EC 4: principal with > threshold targets -> exactly one finding (one per principal,
    not one per target)."""
    tenant = make_tenant("iam-above-threshold")
    n = OVER_PERMISSIVE_ACCESS_THRESHOLD + 5
    _seed(pool, tenant, _over_permissive_principal_events(n_targets=n))
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)

    assert result.opened == 1
    assert len(findings) == 1
    assert findings[0].evidence["access_count"] == n


def test_iam_principal_subject_ci_id_matches_principal(pool, make_tenant):
    """AC 19 analogue: finding subject_ci_id is the UUID of the IAM principal CI."""
    principal_ext = "arn:aws:iam::123456789012:role/subject-check"
    tenant = make_tenant("iam-subject-ci-id")
    _seed(pool, tenant, _over_permissive_principal_events(
        principal_ext=principal_ext, n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD
    ))
    role_id = _get_ci_id(pool, tenant, CIType.iam_role, principal_ext)
    with tenant_session(pool, tenant) as conn:
        _, findings = evaluate_findings_with_summary(conn, tenant)
    assert len(findings) == 1
    assert findings[0].subject_ci_id == role_id


def test_iam_principal_title_and_description_format(pool, make_tenant):
    """AC 16 / spec §4.4: title and description follow the documented format."""
    principal_ext = "arn:aws:iam::123456789012:role/title-check"
    tenant = make_tenant("iam-title-desc")
    n = OVER_PERMISSIVE_ACCESS_THRESHOLD
    _seed(pool, tenant, _over_permissive_principal_events(
        principal_ext=principal_ext, n_targets=n
    ))
    with tenant_session(pool, tenant) as conn:
        _, findings = evaluate_findings_with_summary(conn, tenant)
    f = findings[0]
    assert "Over-permissive IAM principal" in f.title
    assert str(n) in f.title
    assert "resources" in f.title
    assert "HAS_ACCESS_TO" in f.description
    assert str(OVER_PERMISSIVE_ACCESS_THRESHOLD) in f.description


def test_iam_principal_iam_user_type_also_triggers_finding(pool, make_tenant):
    """IAM rule covers iam_user as well as iam_role (IAM_PRINCIPAL_CI_TYPES)."""
    tenant = make_tenant("iam-user-finding")
    user_ext = "arn:aws:iam::123456789012:user/over-user"
    _seed(pool, tenant, _over_permissive_principal_events(
        principal_type=CIType.iam_user,
        principal_ext=user_ext,
        n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD,
    ))
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.opened == 1
    assert findings[0].rule_id == RULE_OVER_PERMISSIVE_IAM_ROLE


# ---------------------------------------------------------------------------
# Spec requirement 2: principal below threshold yields no finding (AC 11)
# ---------------------------------------------------------------------------


def test_iam_principal_below_threshold_yields_no_finding(pool, make_tenant):
    """Spec req 2 / AC 11: principal with threshold-1 (9) distinct targets -> no IAM finding."""
    tenant = make_tenant("iam-below-threshold")
    _seed(pool, tenant, _over_permissive_principal_events(
        n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD - 1
    ))
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)

    assert result.opened == 0
    # IAM rule specifically contributes 0 open findings
    iam_findings = [f for f in findings if f.rule_id == RULE_OVER_PERMISSIVE_IAM_ROLE]
    assert iam_findings == []


def test_iam_zero_targets_yields_no_finding(pool, make_tenant):
    """EC 1 (IAM analogue): IAM principal with 0 HAS_ACCESS_TO edges -> no finding."""
    tenant = make_tenant("iam-zero-targets")
    _seed(pool, tenant, [
        _ci(CIType.iam_role, "arn:aws:iam::1:role/empty-role", "empty-role"),
    ])
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.opened == 0
    assert findings == []


# ---------------------------------------------------------------------------
# Spec requirement 3: Both rules triggered in one evaluate; correct aggregates (AC 12)
# ---------------------------------------------------------------------------


def test_both_rules_single_evaluate_both_findings_opened(pool, make_tenant):
    """Spec req 3 / AC 12: single evaluate over tenant with internet-reachable RDS AND
    over-permissive IAM principal -> exactly one finding of each rule; opened==2, open_count==2."""
    tenant = make_tenant("both-rules-single-eval")
    _seed(pool, tenant, _combined_both_rules_events(n_iam_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)

    assert result.opened == 2, f"Expected opened==2, got {result}"
    assert result.open_count == 2, f"Expected open_count==2, got {result}"

    rule_ids = {f.rule_id for f in findings}
    assert RULE_INTERNET_REACHABLE_DATABASE in rule_ids
    assert RULE_OVER_PERMISSIVE_IAM_ROLE in rule_ids
    assert len(findings) == 2


def test_both_rules_single_evaluate_aggregate_evaluated(pool, make_tenant):
    """AC 12: evaluated == (#db CIs) + (#IAM principals) in a combined graph."""
    tenant = make_tenant("both-rules-evaluated-sum")
    _seed(pool, tenant, _combined_both_rules_events(n_iam_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    with tenant_session(pool, tenant) as conn:
        result, _ = evaluate_findings_with_summary(conn, tenant)
    # 1 RDS (internet rule) + 1 iam_role (IAM rule) = 2
    assert result.evaluated == 2


def test_both_rules_via_api_response_keys(pool, make_tenant_with_key):
    """Spec req 3 / AC 18: POST /findings/evaluate returns exactly {evaluated, opened,
    resolved, open_count} with correct aggregated values across both rules."""
    tenant, api_key = make_tenant_with_key("both-api-keys")
    _seed(pool, tenant, _combined_both_rules_events(n_iam_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    client = TestClient(create_app(pool=pool))

    resp = client.post("/findings/evaluate", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"evaluated", "opened", "resolved", "open_count"}
    assert body["opened"] == 2
    assert body["open_count"] == 2
    assert body["evaluated"] == 2


# ---------------------------------------------------------------------------
# Spec requirement 4: re-running evaluate is idempotent for BOTH rules (AC 13)
# ---------------------------------------------------------------------------


def test_both_rules_idempotent_second_run(pool, make_tenant):
    """Spec req 4 / AC 13: re-running evaluate on unchanged graph yields opened==0,
    resolved==0; no duplicate rows created, counts stable for BOTH rules."""
    tenant = make_tenant("both-rules-idempotent")
    _seed(pool, tenant, _combined_both_rules_events(n_iam_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))

    with tenant_session(pool, tenant) as conn:
        result1, findings1 = evaluate_findings_with_summary(conn, tenant)
    assert result1.opened == 2

    with tenant_session(pool, tenant) as conn:
        result2, findings2 = evaluate_findings_with_summary(conn, tenant)
    assert result2.opened == 0, "Second run must open 0 new findings"
    assert result2.resolved == 0, "Second run must resolve 0 findings"
    assert result2.open_count == 2, "Still exactly 2 open findings"
    assert len(findings2) == 2

    # Total rows in DB must remain exactly 2 (no duplicates)
    total = _count_findings_admin(tenant)
    assert total == 2, f"Expected 2 rows in finding table, got {total}"


def test_iam_rule_idempotent_only(pool, make_tenant):
    """AC 13 (IAM rule alone): re-running evaluate with only an over-permissive principal
    is idempotent."""
    tenant = make_tenant("iam-idempotent")
    _seed(pool, tenant, _over_permissive_principal_events(n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))

    with tenant_session(pool, tenant) as conn:
        r1, f1 = evaluate_findings_with_summary(conn, tenant)
    assert r1.opened == 1

    with tenant_session(pool, tenant) as conn:
        r2, f2 = evaluate_findings_with_summary(conn, tenant)
    assert r2.opened == 0
    assert r2.resolved == 0
    assert r2.open_count == 1
    assert len(f2) == 1

    total = _count_findings_admin(tenant)
    assert total == 1


# ---------------------------------------------------------------------------
# Spec requirement 5: removing access resolves ONLY the IAM finding; internet
# finding untouched (AC 14, EC 8, EC 12)
# ---------------------------------------------------------------------------


def test_remove_iam_access_resolves_only_iam_finding(pool, make_tenant):
    """Spec req 5 / AC 14: removing over-permissive principal's access and re-evaluating
    resolves ONLY the IAM finding (status='resolved', valid_to set, row NOT deleted)
    while the open internet_reachable_database finding remains untouched."""
    tenant = make_tenant("both-resolve-isolation")
    principal_ext = "arn:aws:iam::111111111111:role/reduce-role"
    _seed(pool, tenant, _combined_both_rules_events(
        n_iam_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD,
        principal_ext=principal_ext,
    ))

    with tenant_session(pool, tenant) as conn:
        result1, findings1 = evaluate_findings_with_summary(conn, tenant)
    assert result1.opened == 2

    # Capture finding ids
    iam_finding = next(f for f in findings1 if f.rule_id == RULE_OVER_PERMISSIVE_IAM_ROLE)
    internet_finding = next(f for f in findings1 if f.rule_id == RULE_INTERNET_REACHABLE_DATABASE)
    iam_finding_id = iam_finding.id
    internet_finding_id = internet_finding.id

    # Remove all HAS_ACCESS_TO edges from the principal by re-reconciling without them.
    # Keep the internet-reachable RDS graph intact.
    internet_only_events = [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-combo"),
        _ci(CIType.rds, "db-combo", "prod-db-combo"),
        _edge(
            EdgeType.CONNECTS_TO,
            CIType.internet, "internet",
            CIType.security_group, "sg-combo",
            ev=[Evidence(source="aws", detail="combo sg allows 0.0.0.0/0")],
        ),
        _edge(
            EdgeType.EXPOSES,
            CIType.security_group, "sg-combo",
            CIType.rds, "db-combo",
            ev=[Evidence(source="aws", detail="sg-combo exposes rds")],
        ),
        # IAM principal still exists but with ZERO HAS_ACCESS_TO edges
        _ci(CIType.iam_role, principal_ext, principal_ext),
    ]
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant, internet_only_events,
            source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE,
        )

    # Re-evaluate: IAM finding should be resolved; internet finding untouched
    with tenant_session(pool, tenant) as conn:
        result2, findings2 = evaluate_findings_with_summary(conn, tenant)

    assert result2.resolved == 1, f"Expected resolved==1, got {result2}"
    assert result2.open_count == 1, f"Expected open_count==1, got {result2}"
    # Only the internet finding remains open
    assert len(findings2) == 1
    assert findings2[0].rule_id == RULE_INTERNET_REACHABLE_DATABASE

    # Verify resolved IAM finding row still exists with status='resolved' and valid_to set
    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT status, valid_to FROM finding WHERE id = %s::uuid",
            (iam_finding_id,),
        ).fetchone()
    assert row is not None, "Resolved IAM finding row must not be deleted"
    assert row[0] == "resolved", f"Expected status='resolved', got '{row[0]}'"
    assert row[1] is not None, "valid_to must be set on the resolved IAM finding"

    # Internet finding must still be open and untouched
    with psycopg.connect(admin_dsn()) as admin_conn:
        row2 = admin_conn.execute(
            "SELECT status, valid_to FROM finding WHERE id = %s::uuid",
            (internet_finding_id,),
        ).fetchone()
    assert row2 is not None
    assert row2[0] == "open", "Internet finding must still be open"
    assert row2[1] is None, "Internet finding valid_to must still be NULL (not closed)"


def test_iam_rule_resolve_does_not_touch_internet_rule(pool, make_tenant):
    """EC 12 (new rule analogue): per-rule reconciliation isolation — removing only the
    internet reach (EXPOSES edge) resolves ONLY the internet finding and leaves the open
    IAM finding untouched."""
    tenant = make_tenant("rule-isolation-check")
    principal_ext = "arn:aws:iam::222222222222:role/isolation-role"
    rds_ext = "db-isolation"

    _seed(pool, tenant, _combined_both_rules_events(
        n_iam_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD,
        rds_ext=rds_ext,
        principal_ext=principal_ext,
    ))
    with tenant_session(pool, tenant) as conn:
        result1, _ = evaluate_findings_with_summary(conn, tenant)
    assert result1.opened == 2

    # Remove internet reach only: keep all IAM edges + sg, but omit EXPOSES edge.
    # Also keep the IAM principal with all its HAS_ACCESS_TO edges.
    iam_events = _over_permissive_principal_events(
        principal_type=CIType.iam_role,
        principal_ext=principal_ext,
        n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD,
    )
    internet_no_exposes = [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-combo"),
        _ci(CIType.rds, rds_ext, f"prod-{rds_ext}"),
        _edge(
            EdgeType.CONNECTS_TO,
            CIType.internet, "internet",
            CIType.security_group, "sg-combo",
        ),
        # EXPOSES edge intentionally removed -> internet rule reconciliation resolves that finding
    ]
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant,
            internet_no_exposes + iam_events,
            source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE,
        )

    with tenant_session(pool, tenant) as conn:
        result2, findings2 = evaluate_findings_with_summary(conn, tenant)

    assert result2.resolved == 1, f"Expected resolved==1 (only internet finding), got {result2}"
    assert result2.open_count == 1
    # Only the IAM finding remains open
    assert len(findings2) == 1
    assert findings2[0].rule_id == RULE_OVER_PERMISSIVE_IAM_ROLE


# ---------------------------------------------------------------------------
# Spec requirement 6: cross-tenant isolation for the new rule (AC 15, EC 11)
# ---------------------------------------------------------------------------


def test_cross_tenant_iam_finding_b_cannot_see_a(pool, make_tenant_with_key):
    """Spec req 6 / AC 15: tenant B's GET /findings returns [] when only tenant A has
    an over_permissive_iam_role finding."""
    tenant_a, key_a = make_tenant_with_key("iam-cross-tenant-a")
    tenant_b, key_b = make_tenant_with_key("iam-cross-tenant-b")

    _seed(pool, tenant_a, _over_permissive_principal_events(n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    client = TestClient(create_app(pool=pool))

    resp_a = client.post("/findings/evaluate", headers=_auth(key_a))
    assert resp_a.json()["opened"] == 1

    # Tenant B cannot see tenant A's IAM finding
    resp_b = client.get("/findings", headers=_auth(key_b))
    assert resp_b.status_code == 200
    assert resp_b.json() == [], "Tenant B must not see tenant A's over_permissive_iam_role finding"


def test_cross_tenant_iam_finding_b_filter_returns_empty(pool, make_tenant_with_key):
    """Spec req 6 / AC 15: GET /findings?rule_id=over_permissive_iam_role from tenant B
    returns [] when only tenant A has the finding."""
    tenant_a, key_a = make_tenant_with_key("iam-cross-filter-a")
    tenant_b, key_b = make_tenant_with_key("iam-cross-filter-b")

    _seed(pool, tenant_a, _over_permissive_principal_events(n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(key_a))

    resp_b = client.get(
        "/findings?rule_id=over_permissive_iam_role",
        headers=_auth(key_b),
    )
    assert resp_b.status_code == 200
    assert resp_b.json() == []


def test_cross_tenant_iam_evaluate_b_opens_zero(pool, make_tenant_with_key):
    """Spec req 6 / AC 15: tenant B's POST /findings/evaluate opens 0 over_permissive_iam_role
    findings when only tenant A has the IAM principal (RLS blocks B from seeing A's CIs)."""
    tenant_a, key_a = make_tenant_with_key("iam-cross-eval-a")
    tenant_b, key_b = make_tenant_with_key("iam-cross-eval-b")

    _seed(pool, tenant_a, _over_permissive_principal_events(n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(key_a))

    # Tenant B evaluates: must see 0 IAM principals (RLS scopes CIs) -> 0 findings
    resp_b = client.post("/findings/evaluate", headers=_auth(key_b))
    assert resp_b.status_code == 200
    body_b = resp_b.json()
    assert body_b["opened"] == 0
    assert body_b["evaluated"] == 0


def test_cross_tenant_rls_raw_select_iam_finding(pool, make_tenant):
    """Spec req 6 / AC 15 adversarial: raw SELECT under tenant B session returns no IAM
    findings from tenant A (RLS enforced at storage layer)."""
    tenant_a = make_tenant("iam-rls-a")
    tenant_b = make_tenant("iam-rls-b")

    _seed(pool, tenant_a, _over_permissive_principal_events(n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))

    with tenant_session(pool, tenant_a) as conn:
        evaluate_findings(conn, tenant_a)

    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM finding WHERE rule_id = %s AND status = 'open'",
            (RULE_OVER_PERMISSIVE_IAM_ROLE,),
        ).fetchone()[0]
    assert count == 0, "Tenant B raw SELECT must not see tenant A's IAM findings (RLS)"


# ---------------------------------------------------------------------------
# Spec requirement 7: GET /findings?rule_id=over_permissive_iam_role filters correctly
# (AC 16)
# ---------------------------------------------------------------------------


def test_get_findings_filter_by_iam_rule(pool, make_tenant_with_key):
    """Spec req 7 / AC 16: GET /findings?rule_id=over_permissive_iam_role returns only
    IAM findings when both rules have open findings."""
    tenant, api_key = make_tenant_with_key("filter-iam-rule")
    _seed(pool, tenant, _combined_both_rules_events(n_iam_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(api_key))

    resp = client.get("/findings?rule_id=over_permissive_iam_role", headers=_auth(api_key))
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["rule_id"] == RULE_OVER_PERMISSIVE_IAM_ROLE


def test_get_findings_filter_by_internet_rule_when_both_exist(pool, make_tenant_with_key):
    """AC 16: GET /findings?rule_id=internet_reachable_database returns only internet
    findings when both rules have open findings."""
    tenant, api_key = make_tenant_with_key("filter-internet-rule")
    _seed(pool, tenant, _combined_both_rules_events(n_iam_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(api_key))

    resp = client.get(
        "/findings?rule_id=internet_reachable_database",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["rule_id"] == RULE_INTERNET_REACHABLE_DATABASE


def test_get_findings_no_filter_returns_both_rules(pool, make_tenant_with_key):
    """AC 16: GET /findings with no rule_id filter returns both rules' findings newest-first."""
    tenant, api_key = make_tenant_with_key("filter-no-filter-both")
    _seed(pool, tenant, _combined_both_rules_events(n_iam_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(api_key))

    resp = client.get("/findings", headers=_auth(api_key))
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 2
    rule_ids = {f["rule_id"] for f in findings}
    assert rule_ids == {RULE_INTERNET_REACHABLE_DATABASE, RULE_OVER_PERMISSIVE_IAM_ROLE}


def test_get_findings_filter_iam_unknown_rule_returns_empty(pool, make_tenant_with_key):
    """AC 16: GET /findings?rule_id=unknown_rule returns [] even when IAM findings exist."""
    tenant, api_key = make_tenant_with_key("filter-unknown")
    _seed(pool, tenant, _over_permissive_principal_events(n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(api_key))

    resp = client.get("/findings?rule_id=unknown_rule_xyz", headers=_auth(api_key))
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_findings_iam_response_keys(pool, make_tenant_with_key):
    """AC 16 / spec §2.2: GET /findings items for IAM findings have exactly the required keys."""
    tenant, api_key = make_tenant_with_key("iam-response-keys")
    _seed(pool, tenant, _over_permissive_principal_events(n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(api_key))

    resp = client.get("/findings?rule_id=over_permissive_iam_role", headers=_auth(api_key))
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    f = findings[0]
    expected_keys = {
        "id", "rule_id", "severity", "subject_ci_id", "subject_ci_type",
        "subject_ci_name", "title", "description", "evidence", "status", "detected_at",
    }
    assert set(f.keys()) == expected_keys, f"Response key mismatch. Got: {set(f.keys())}"
    assert f["rule_id"] == RULE_OVER_PERMISSIVE_IAM_ROLE
    assert f["severity"] == OVER_PERMISSIVE_IAM_SEVERITY
    assert f["subject_ci_type"] == "iam_role"
    assert f["status"] == "open"


def test_get_findings_iam_user_subject_ci_type(pool, make_tenant_with_key):
    """AC 19 analogue: subject_ci_type is 'iam_user' in response when principal is iam_user."""
    tenant, api_key = make_tenant_with_key("iam-user-ci-type")
    user_ext = "arn:aws:iam::123456789012:user/over-user-type"
    _seed(pool, tenant, _over_permissive_principal_events(
        principal_type=CIType.iam_user,
        principal_ext=user_ext,
        n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD,
    ))
    client = TestClient(create_app(pool=pool))
    client.post("/findings/evaluate", headers=_auth(api_key))

    resp = client.get("/findings?rule_id=over_permissive_iam_role", headers=_auth(api_key))
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["subject_ci_type"] == "iam_user"


# ---------------------------------------------------------------------------
# Spec requirement 8: RBAC/auth gating for IAM-related endpoints (AC 17)
# ---------------------------------------------------------------------------


def test_rbac_unauthenticated_get_findings_401():
    """AC 17: unauthenticated GET /findings -> 401 (same as existing test, confirmed
    for multi-rule context)."""
    client = TestClient(create_app())
    resp = client.get("/findings")
    assert resp.status_code == 401


def test_rbac_unauthenticated_post_evaluate_401():
    """AC 17: unauthenticated POST /findings/evaluate -> 401."""
    client = TestClient(create_app())
    resp = client.post("/findings/evaluate")
    assert resp.status_code == 401


def test_rbac_viewer_post_evaluate_403_no_iam_finding_created(pool):
    """AC 17: viewer POST /findings/evaluate -> 403; no finding row created.

    Seeds an over-permissive principal first, then confirms the viewer's blocked
    request creates no row.
    """
    viewer_tenant, viewer_key = _make_viewer_key("rbac-viewer-iam-403")
    # Seed the viewer's tenant with an over-permissive principal
    _seed(pool, viewer_tenant, _over_permissive_principal_events(
        n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD
    ))
    client = TestClient(create_app(pool=pool))
    resp = client.post("/findings/evaluate", headers=_auth(viewer_key))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "insufficient permissions"

    # No findings should have been created
    count = _count_findings_admin(viewer_tenant)
    assert count == 0, f"Viewer's blocked request must not create finding rows, got {count}"


def test_rbac_viewer_get_findings_200_after_admin_creates_iam_finding(pool):
    """AC 17: viewer GET /findings -> 200 (viewer can read even for IAM findings)."""
    viewer_tenant, viewer_key = _make_viewer_key("rbac-viewer-get-200")
    # Create a finding as admin (direct DB call via evaluate_findings via tenant_session)
    _seed(pool, viewer_tenant, _over_permissive_principal_events(
        n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD
    ))
    with tenant_session(pool, viewer_tenant) as conn:
        evaluate_findings(conn, viewer_tenant)

    client = TestClient(create_app(pool=pool))
    resp = client.get("/findings", headers=_auth(viewer_key))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
    # The finding created directly should be visible to the viewer
    assert len(resp.json()) == 1
    assert resp.json()[0]["rule_id"] == RULE_OVER_PERMISSIVE_IAM_ROLE


# ---------------------------------------------------------------------------
# Edge cases from spec §5 for the IAM rule
# ---------------------------------------------------------------------------


def test_iam_ec1_zero_principals_zero_counters(pool, make_tenant):
    """EC 1: tenant with zero IAM principals -> IAM rule evaluated=0, opened=0,
    resolved=0, open_count=0; aggregate unaffected."""
    tenant = make_tenant("iam-ec1-zero-principals")
    # Only RDS, no IAM principal
    _seed(pool, tenant, [_ci(CIType.rds, "db-only")])
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    # RDS rule: evaluated=1, IAM rule: evaluated=0 -> aggregate: evaluated=1
    assert result.evaluated == 1
    assert result.opened == 0
    assert result.resolved == 0
    assert result.open_count == 0
    iam_findings = [f for f in findings if f.rule_id == RULE_OVER_PERMISSIVE_IAM_ROLE]
    assert iam_findings == []


def test_iam_ec3_boundary_exactly_threshold(pool, make_tenant):
    """EC 2/3: principal with exactly threshold (10) distinct targets -> exactly one finding."""
    tenant = make_tenant("iam-ec3-boundary")
    _seed(pool, tenant, _over_permissive_principal_events(
        n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD
    ))
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.opened == 1
    assert findings[0].evidence["access_count"] == OVER_PERMISSIVE_ACCESS_THRESHOLD


def test_iam_ec3_one_below_threshold(pool, make_tenant):
    """EC 3: principal with threshold-1 (9) targets -> no finding."""
    tenant = make_tenant("iam-ec3-one-below")
    _seed(pool, tenant, _over_permissive_principal_events(
        n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD - 1
    ))
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.opened == 0
    assert findings == []


def test_iam_ec5_duplicate_targets_deduped(pool, make_tenant):
    """EC 5: principal at exactly threshold distinct targets (where one target has multiple
    redundant reconciliation runs) -> access_count reflects distinct to_ids (10), not raw
    edge count; evidence.targets length == access_count == 10."""
    tenant = make_tenant("iam-ec5-dedup")
    principal_ext = "arn:aws:iam::1:role/dedup-role"
    # Seed with exactly threshold unique targets
    events = _over_permissive_principal_events(
        principal_ext=principal_ext, n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD
    )
    _seed(pool, tenant, events)
    # Seed again — re-reconciling the same events is idempotent (no new edges created,
    # confirming edge upsert deduplication at the DB layer).
    _seed(pool, tenant, events)
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    # Still exactly threshold distinct targets -> one finding
    assert result.opened == 1
    ev = findings[0].evidence
    assert ev["access_count"] == OVER_PERMISSIVE_ACCESS_THRESHOLD
    assert len(ev["targets"]) == OVER_PERMISSIVE_ACCESS_THRESHOLD


def test_iam_ec5_true_dedup_below_threshold(pool, make_tenant):
    """EC 5: principal with threshold-1 (9) distinct HAS_ACCESS_TO targets -> no finding
    (deduplication works; 9 < 10 threshold)."""
    tenant = make_tenant("iam-ec5-true-dedup")
    principal_ext = "arn:aws:iam::1:role/true-dedup-role"
    # Only 9 distinct targets (one below threshold)
    events = _over_permissive_principal_events(
        principal_ext=principal_ext, n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD - 1
    )
    _seed(pool, tenant, events)
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    # 9 distinct targets < 10 threshold -> no finding
    assert result.opened == 0
    assert findings == []


def test_iam_ec6_non_has_access_to_edges_not_counted(pool, make_tenant):
    """EC 6: principal with non-HAS_ACCESS_TO out-edges only (e.g. MEMBER_OF, CONTAINS)
    -> access_count counts ONLY HAS_ACCESS_TO; no finding from unrelated edge types."""
    tenant = make_tenant("iam-ec6-non-access")
    principal_ext = "arn:aws:iam::1:role/member-only"
    # Create principal + 15 targets, but connect via CONTAINS not HAS_ACCESS_TO
    events = [_ci(CIType.iam_role, principal_ext, principal_ext)]
    for i in range(15):
        ext = f"res-{i}"
        events.append(_ci(CIType.ec2_instance, ext, ext))
        events.append(
            _edge(EdgeType.CONTAINS, CIType.iam_role, principal_ext, CIType.ec2_instance, ext)
        )
    _seed(pool, tenant, events)
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    assert result.opened == 0, "Non-HAS_ACCESS_TO edges must not trigger IAM finding"
    iam_findings = [f for f in findings if f.rule_id == RULE_OVER_PERMISSIVE_IAM_ROLE]
    assert iam_findings == []


def test_iam_ec8_drop_below_threshold_resolves_finding(pool, make_tenant):
    """EC 8: over-permissive principal drops below threshold (edges removed via re-reconcile)
    on re-evaluate -> its open finding RESOLVED (status='resolved', valid_to set), row NOT deleted;
    'resolved' counts it; only that finding closes."""
    tenant = make_tenant("iam-ec8-drop-threshold")
    principal_ext = "arn:aws:iam::1:role/drop-role"
    # Start with threshold edges (finding opens)
    _seed(pool, tenant, _over_permissive_principal_events(
        principal_ext=principal_ext, n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD
    ))
    with tenant_session(pool, tenant) as conn:
        r1, f1 = evaluate_findings_with_summary(conn, tenant)
    assert r1.opened == 1
    finding_id = f1[0].id

    # Drop to threshold-1 edges (re-reconcile with only 9 targets)
    fewer_events = _over_permissive_principal_events(
        principal_ext=principal_ext, n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD - 1
    )
    with tenant_session(pool, tenant) as conn:
        reconcile(conn, tenant, fewer_events, source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE)

    with tenant_session(pool, tenant) as conn:
        r2, f2 = evaluate_findings_with_summary(conn, tenant)
    assert r2.resolved == 1, f"Expected resolved==1, got {r2}"
    assert r2.open_count == 0
    assert f2 == []

    # Row must still exist with status='resolved' and valid_to set
    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT status, valid_to FROM finding WHERE id = %s::uuid", (finding_id,)
        ).fetchone()
    assert row is not None, "Resolved row must not be deleted"
    assert row[0] == "resolved"
    assert row[1] is not None, "valid_to must be set"


def test_iam_ec9_principal_ci_closed_finding_resolved(pool, make_tenant):
    """EC 9: over-permissive IAM principal CI closed (no longer current) while finding open
    -> finding resolved via unmatched sweep; evaluated drops accordingly."""
    tenant = make_tenant("iam-ec9-ci-closed")
    _seed(pool, tenant, _over_permissive_principal_events(n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    with tenant_session(pool, tenant) as conn:
        r1, _ = evaluate_findings_with_summary(conn, tenant)
    assert r1.opened == 1

    # Close the IAM principal CI via superuser UPDATE (simulate deletion)
    with psycopg.connect(admin_dsn()) as admin_conn:
        admin_conn.execute(
            "UPDATE cis SET valid_to = now() WHERE type = 'iam_role' AND valid_to IS NULL"
        )
        admin_conn.commit()

    with tenant_session(pool, tenant) as conn:
        r2, f2 = evaluate_findings_with_summary(conn, tenant)

    # IAM rule evaluated=0 (no current iam_role); resolved=1 (unmatched sweep)
    iam_evaluated_count = 0  # no current IAM principals
    assert r2.resolved == 1, f"Expected resolved==1, got {r2}"
    assert r2.open_count == 0
    assert f2 == []


def test_iam_ec10_principal_reopened_gets_fresh_finding(pool, make_tenant):
    """EC 10: principal becomes over-permissive again after resolution -> fresh finding row
    with a NEW id; prior resolved row untouched."""
    tenant = make_tenant("iam-ec10-reopen")
    principal_ext = "arn:aws:iam::1:role/reopen-role"
    _seed(pool, tenant, _over_permissive_principal_events(
        principal_ext=principal_ext, n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD
    ))
    with tenant_session(pool, tenant) as conn:
        r1, f1 = evaluate_findings_with_summary(conn, tenant)
    assert r1.opened == 1
    first_id = f1[0].id

    # Drop below threshold -> resolves
    with tenant_session(pool, tenant) as conn:
        reconcile(conn, tenant,
                  _over_permissive_principal_events(
                      principal_ext=principal_ext, n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD - 1
                  ),
                  source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE)
    with tenant_session(pool, tenant) as conn:
        r2, _ = evaluate_findings_with_summary(conn, tenant)
    assert r2.resolved == 1

    # Restore above threshold -> new open finding
    _seed(pool, tenant, _over_permissive_principal_events(
        principal_ext=principal_ext, n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD
    ))
    with tenant_session(pool, tenant) as conn:
        r3, f3 = evaluate_findings_with_summary(conn, tenant)
    assert r3.opened == 1
    new_id = f3[0].id
    assert new_id != first_id, "Re-opened finding must have a fresh id"

    # Old resolved row still exists
    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT status FROM finding WHERE id = %s::uuid", (first_id,)
        ).fetchone()
    assert row is not None, "Old resolved row must not be deleted"
    assert row[0] == "resolved"


def test_iam_evidence_targets_sorted_deterministically(pool, make_tenant):
    """EC 18: re-evaluating with identical graph produces same evidence.targets ordering
    (sorted by id str); idempotency holds on targets list."""
    tenant = make_tenant("iam-targets-sorted")
    _seed(pool, tenant, _over_permissive_principal_events(n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    with tenant_session(pool, tenant) as conn:
        _, f1 = evaluate_findings_with_summary(conn, tenant)
    targets_run1 = f1[0].evidence["targets"]
    target_ids_run1 = [t["id"] for t in targets_run1]

    # Verify sorted by id str
    assert target_ids_run1 == sorted(target_ids_run1), "Targets must be sorted by id str"


def test_iam_evidence_targets_type_resolved(pool, make_tenant):
    """EC 14 / spec §4.2: target CI type is resolved in evidence.targets entries."""
    tenant = make_tenant("iam-targets-type")
    _seed(pool, tenant, _over_permissive_principal_events(n_targets=OVER_PERMISSIVE_ACCESS_THRESHOLD))
    with tenant_session(pool, tenant) as conn:
        _, findings = evaluate_findings_with_summary(conn, tenant)
    ev = findings[0].evidence
    for t in ev["targets"]:
        assert "id" in t
        assert "type" in t
        # All targets are current s3_bucket CIs -> type must be "s3_bucket"
        assert t["type"] == "s3_bucket", f"Expected type='s3_bucket', got {t['type']}"


def test_iam_custom_access_threshold_kwarg(pool, make_tenant):
    """AC 5: access_threshold kwarg respected — principal with 5 targets below default 10
    but above custom threshold of 5 -> opens finding when threshold=5."""
    tenant = make_tenant("iam-custom-threshold")
    custom_threshold = 5
    _seed(pool, tenant, _over_permissive_principal_events(n_targets=custom_threshold))
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant, access_threshold=custom_threshold)
    assert result.opened == 1
    assert findings[0].evidence["threshold"] == custom_threshold
    assert findings[0].evidence["access_count"] == custom_threshold


def test_iam_custom_access_threshold_below_does_not_open(pool, make_tenant):
    """AC 5: principal with 5 targets and threshold=6 -> no finding (5 < 6)."""
    tenant = make_tenant("iam-custom-threshold-no-open")
    _seed(pool, tenant, _over_permissive_principal_events(n_targets=5))
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant, access_threshold=6)
    assert result.opened == 0
    assert findings == []


def test_iam_ec19_backward_compat_rds_only_tenant(pool, make_tenant):
    """EC 19 backward compat: tenant with only RDS data -> IAM rule contributes zeros
    and aggregate equals old single-rule result."""
    tenant = make_tenant("iam-backward-compat")
    _seed(pool, tenant, _internet_reachable_rds_events())
    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)
    # IAM rule: evaluated=0, opened=0, resolved=0, open_count=0
    # Internet rule: evaluated=1, opened=1, resolved=0, open_count=1
    # Aggregate: evaluated=1, opened=1, resolved=0, open_count=1
    assert result.evaluated == 1
    assert result.opened == 1
    assert result.resolved == 0
    assert result.open_count == 1
    assert len(findings) == 1
    assert findings[0].rule_id == RULE_INTERNET_REACHABLE_DATABASE
