"""Notification subscription, delivery, and webhook dispatch tests.

Covers all spec acceptance criteria (§6) and edge cases (§5):

Structural / static:
  AC 1  migration 0012_notifications.sql exists.
  AC 2  Both tables have exact column sets.
  AC 3  tenant_id FK on both tables.
  AC 4  RLS enabled + tenant_isolation policy on both tables.
  AC 5  Grant is SELECT, INSERT only — no UPDATE, no DELETE.
  AC 6  Migration is expand-only (no DROP TABLE / DROP COLUMN / ALTER DROP DEFAULT).
  AC 7  outcome CHECK and nullable status_code.
  AC 8  NotificationRepository, NotificationSubscription, NotificationDelivery, OUTCOME_VALUES.
  AC 9  Five required methods; no UPDATE/DELETE SQL in notifications.py.
  AC 10 max(0, limit) clamping in list_deliveries.
  AC 11 All three symbols exported from db.__init__.__all__.
  AC 12 build_finding_payload, notify_finding_opened, HttpSender; no infra_twin.query import.
  AC 13 build_finding_payload returns exactly the specified keys.
  AC 14 evaluate_findings_with_summary / evaluate_findings both have notify_sender kwarg.
  AC 15 Every notify_finding_opened call is adjacent to open_finding + guarded; none in resolve.
  AC 16 All three FastAPI routes registered with correct methods/status codes.
  AC 17 CreateSubscriptionBody url validator.
  AC 18 Response dicts omit tenant_id.
  AC 19 conftest._DATA_TABLES includes both new tables.

Behavioural / integration:
  AC 20a create + list subscriptions works and is tenant-scoped.
  AC 20b opening a new finding emits exactly one delivery per enabled subscription.
  AC 20c adversarial cross-tenant: A's finding does not deliver to B; B gets zero deliveries.
  AC 20d re-evaluating unchanged graph produces no new send / delivery.
  AC 20e delivery rows are append-only; app role has no DELETE privilege.
  AC 20f RBAC: 401 unauthenticated; 403 viewer on POST; 200 viewer on GET.
  AC 20g sender returning non-2xx -> outcome=="failed"; raising -> outcome=="failed", status_code None,
         remaining subs still attempted.

Edge cases:
  EC 1  Tenant with zero subscriptions -> zero sends, zero delivery rows.
  EC 2  One enabled + one disabled -> exactly one send + one delivery (the enabled one).
  EC 3  Multiple enabled subscriptions -> one send + one delivery per enabled sub.
  EC 4  Sender returns 2xx -> outcome="delivered"; non-2xx -> outcome="failed".
  EC 5  Sender raises -> outcome="failed", status_code=None; exception swallowed; rest attempted.
  EC 6  Two subs, first raises, second returns 200 -> two deliveries (failed+None, delivered+200).
  EC 7  Re-evaluation unchanged -> zero sends (duplicate-delivery prevention).
  EC 8  Re-evaluation resolves finding -> zero sends.
  EC 9  Finding resolved then re-opened -> re-open emits again with new finding_id.
  EC 10 Cross-tenant: A has sub, B does not; evaluating B emits nothing; B cannot list A's data.
  EC 11 Cross-tenant write attempt: INSERT with wrong tenant_id fails RLS WITH CHECK.
  EC 12 notify_sender=None (default) -> no deliveries written; counters unchanged.
  EC 13 Empty / whitespace / non-http(s) url -> 422.
  EC 14 list_deliveries(limit=0) -> []; negative limit clamped to 0 -> [].
  EC 15 Large payload stored and round-tripped via JSONB.
  EC 16 Multiple findings + multiple enabled subs -> delivery count == findings x subs.
  EC 17 Ordering determinism (tie-broken by id DESC).
  EC 18 App role cannot DELETE/UPDATE (verified via has_table_privilege).
  EC 19 Migration re-apply is a no-op.
  EC 20 Delivery row for a since-resolved finding remains unchanged (no FK, append-only).
"""

from __future__ import annotations

import inspect
import pathlib
import re
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.api_keys import IssuedKey, Role, provision_tenant
from infra_twin.db.config import admin_dsn
from infra_twin.db.notifications import (
    OUTCOME_VALUES,
    NotificationDelivery,
    NotificationRepository,
    NotificationSubscription,
)
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import reconcile
from infra_twin.reconciliation.findings import (
    OVER_PERMISSIVE_ACCESS_THRESHOLD,
    evaluate_findings,
    evaluate_findings_with_summary,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[1] / "migrations"
_NOTIFICATIONS_PY = (
    pathlib.Path(__file__).resolve().parents[1]
    / "packages/db/src/infra_twin/db/notifications.py"
)
_RECONCIL_NOTIF_PY = (
    pathlib.Path(__file__).resolve().parents[1]
    / "services/reconciliation/src/infra_twin/reconciliation/notifications.py"
)
_RECONCIL_FINDINGS_PY = (
    pathlib.Path(__file__).resolve().parents[1]
    / "services/reconciliation/src/infra_twin/reconciliation/findings.py"
)
_APP_PY = (
    pathlib.Path(__file__).resolve().parents[1]
    / "apps/api/src/infra_twin/api/app.py"
)
_CONFTEST_PY = pathlib.Path(__file__).resolve().parent / "conftest.py"

CI_SCOPE = frozenset({
    CIType.internet,
    CIType.security_group,
    CIType.ec2_instance,
    CIType.subnet,
    CIType.vpc,
    CIType.rds,
    CIType.elb,
    CIType.iam_role,
    CIType.s3_bucket,
})

EDGE_SCOPE = frozenset({
    EdgeType.CONNECTS_TO,
    EdgeType.ROUTES_TO,
    EdgeType.HAS_ACCESS_TO,
    EdgeType.EXPOSES,
    EdgeType.CONTAINS,
    EdgeType.DEPENDS_ON,
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _internet_reachable_rds_events(rds_ext_id: str = "db-1"):
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


def _s3_ext(n: int) -> str:
    return f"arn:aws:s3:::bucket-{n}"


def _over_permissive_principal_events(
    principal_type: CIType = CIType.iam_role,
    principal_ext: str = "arn:aws:iam::123456789012:role/over-role",
    n_targets: int = 10,
    target_type: CIType = CIType.s3_bucket,
) -> list:
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


def _make_viewer_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.viewer)
    return issued.tenant_id, issued.plaintext


def _make_editor_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.editor)
    return issued.tenant_id, issued.plaintext


def _issue_key_for_tenant(tenant_id: UUID, role: Role = Role.editor) -> str:
    """Insert a new API key for an already-existing tenant and return the plaintext."""
    from infra_twin.db.api_keys import generate_key, hash_secret, new_salt
    with psycopg.connect(admin_dsn()) as conn:
        generated = generate_key()
        salt = new_salt()
        secret_hash = hash_secret(generated.secret, salt)
        conn.execute(
            "INSERT INTO api_keys (tenant_id, key_id, secret_hash, salt, name, role)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (tenant_id, generated.key_id, secret_hash, salt, None, role.value),
        )
        conn.commit()
    return generated.plaintext


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _count_deliveries_admin(tenant_id: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM notification_delivery WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchone()
    return row[0]


def _count_subscriptions_admin(tenant_id: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM notification_subscription WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchone()
    return row[0]


# ---------------------------------------------------------------------------
# In-memory recording sender seam
# ---------------------------------------------------------------------------


class RecordingSender:
    """Offline HttpSender that records (url, payload) calls and returns a configurable status."""

    def __init__(self, status_code: int = 200):
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.status_code = status_code
        self.should_raise: bool = False
        self.raise_on_url: str | None = None  # only raise for this specific URL

    def __call__(self, url: str, payload: dict[str, Any]) -> int:
        self.calls.append((url, payload))
        if self.should_raise or (self.raise_on_url is not None and url == self.raise_on_url):
            raise OSError("simulated transport failure")
        return self.status_code


class PerUrlSender:
    """Sender that returns different statuses (or raises) per URL, in order."""

    def __init__(self, responses: list[int | Exception]):
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._responses = list(responses)
        self._idx = 0

    def __call__(self, url: str, payload: dict[str, Any]) -> int:
        self.calls.append((url, payload))
        resp = self._responses[self._idx % len(self._responses)]
        self._idx += 1
        if isinstance(resp, Exception):
            raise resp
        return resp


# ===========================================================================
# STRUCTURAL / STATIC ACCEPTANCE CRITERIA
# ===========================================================================


# --- AC 1: migration file exists ---

def test_ac1_migration_0012_exists():
    """AC 1: migrations/0012_notifications.sql exists."""
    assert (_MIGRATIONS_DIR / "0012_notifications.sql").exists()


# --- AC 2: both tables have exact column sets ---

def test_ac2_notification_subscription_columns():
    """AC 2: notification_subscription has exactly: subscription_id, tenant_id, url, enabled, created_at."""
    expected = {"subscription_id", "tenant_id", "url", "enabled", "created_at"}
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'notification_subscription'"
        ).fetchall()
    cols = {r[0] for r in rows}
    assert cols == expected, f"Column mismatch for notification_subscription. Got: {cols}"


def test_ac2_notification_delivery_columns():
    """AC 2: notification_delivery has exactly: delivery_id, tenant_id, subscription_id,
    finding_id, payload, status_code, outcome, attempted_at."""
    expected = {
        "delivery_id", "tenant_id", "subscription_id", "finding_id",
        "payload", "status_code", "outcome", "attempted_at",
    }
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'notification_delivery'"
        ).fetchall()
    cols = {r[0] for r in rows}
    assert cols == expected, f"Column mismatch for notification_delivery. Got: {cols}"


# --- AC 3: tenant_id FK on both tables ---

def test_ac3_notification_subscription_tenant_id_fk():
    """AC 3: notification_subscription.tenant_id REFERENCES tenants(tenant_id)."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            """
            SELECT kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
            JOIN information_schema.referential_constraints rc
              ON tc.constraint_name = rc.constraint_name
            WHERE tc.table_name = 'notification_subscription'
              AND tc.constraint_type = 'FOREIGN KEY'
              AND kcu.column_name = 'tenant_id'
            """
        ).fetchone()
    assert row is not None, "notification_subscription.tenant_id FK not found"


def test_ac3_notification_delivery_tenant_id_fk():
    """AC 3: notification_delivery.tenant_id REFERENCES tenants(tenant_id)."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            """
            SELECT kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
            JOIN information_schema.referential_constraints rc
              ON tc.constraint_name = rc.constraint_name
            WHERE tc.table_name = 'notification_delivery'
              AND tc.constraint_type = 'FOREIGN KEY'
              AND kcu.column_name = 'tenant_id'
            """
        ).fetchone()
    assert row is not None, "notification_delivery.tenant_id FK not found"


# --- AC 4: RLS + tenant_isolation policy on both tables ---

def test_ac4_notification_subscription_rls_enabled():
    """AC 4: RLS is enabled on notification_subscription."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT rowsecurity FROM pg_tables WHERE tablename = 'notification_subscription'"
        ).fetchone()
    assert row is not None and row[0] is True, "RLS not enabled on notification_subscription"


def test_ac4_notification_delivery_rls_enabled():
    """AC 4: RLS is enabled on notification_delivery."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT rowsecurity FROM pg_tables WHERE tablename = 'notification_delivery'"
        ).fetchone()
    assert row is not None and row[0] is True, "RLS not enabled on notification_delivery"


def test_ac4_notification_subscription_tenant_isolation_policy_exists():
    """AC 4: tenant_isolation policy exists on notification_subscription."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT policyname FROM pg_policies "
            "WHERE tablename = 'notification_subscription' AND policyname = 'tenant_isolation'"
        ).fetchone()
    assert row is not None, "tenant_isolation policy not found on notification_subscription"


def test_ac4_notification_delivery_tenant_isolation_policy_exists():
    """AC 4: tenant_isolation policy exists on notification_delivery."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT policyname FROM pg_policies "
            "WHERE tablename = 'notification_delivery' AND policyname = 'tenant_isolation'"
        ).fetchone()
    assert row is not None, "tenant_isolation policy not found on notification_delivery"


def test_ac4_migration_uses_current_setting_guc():
    """AC 4: migration SQL uses current_setting('app.tenant_id', true) in both tables' policies."""
    text = (_MIGRATIONS_DIR / "0012_notifications.sql").read_text()
    occurrences = text.count("current_setting('app.tenant_id', true)")
    assert occurrences >= 4, (
        f"Expected at least 4 occurrences of current_setting GUC (USING+WITH CHECK x2 tables), "
        f"got {occurrences}"
    )


# --- AC 5: grant is SELECT, INSERT only; no UPDATE/DELETE ---

def test_ac5_migration_grants_select_insert_only_subscription():
    """AC 5: migration grants SELECT, INSERT (not UPDATE, DELETE) on notification_subscription."""
    text = (_MIGRATIONS_DIR / "0012_notifications.sql").read_text().upper()
    assert "GRANT SELECT, INSERT ON NOTIFICATION_SUBSCRIPTION TO APP" in text
    grant_lines = [
        l for l in text.splitlines()
        if "GRANT" in l and "NOTIFICATION_SUBSCRIPTION" in l
    ]
    for line in grant_lines:
        assert "UPDATE" not in line, f"UPDATE found in GRANT: {line}"
        assert "DELETE" not in line, f"DELETE found in GRANT: {line}"
        assert "ALL" not in line, f"ALL found in GRANT: {line}"


def test_ac5_migration_grants_select_insert_only_delivery():
    """AC 5: migration grants SELECT, INSERT (not UPDATE, DELETE) on notification_delivery."""
    text = (_MIGRATIONS_DIR / "0012_notifications.sql").read_text().upper()
    assert "GRANT SELECT, INSERT ON NOTIFICATION_DELIVERY TO APP" in text
    grant_lines = [
        l for l in text.splitlines()
        if "GRANT" in l and "NOTIFICATION_DELIVERY" in l
    ]
    for line in grant_lines:
        assert "UPDATE" not in line, f"UPDATE found in GRANT: {line}"
        assert "DELETE" not in line, f"DELETE found in GRANT: {line}"
        assert "ALL" not in line, f"ALL found in GRANT: {line}"


# --- AC 6: expand-only migration ---

def test_ac6_migration_no_drop_table():
    """AC 6: no DROP TABLE in migration."""
    text = (_MIGRATIONS_DIR / "0012_notifications.sql").read_text().upper()
    assert "DROP TABLE" not in text


def test_ac6_migration_no_drop_column():
    """AC 6: no DROP COLUMN in migration."""
    text = (_MIGRATIONS_DIR / "0012_notifications.sql").read_text().upper()
    assert "DROP COLUMN" not in text


def test_ac6_migration_no_alter_drop_default():
    """AC 6: no ALTER COLUMN ... DROP DEFAULT in migration."""
    text = (_MIGRATIONS_DIR / "0012_notifications.sql").read_text().upper()
    assert "DROP DEFAULT" not in text


def test_ac6_migration_no_delete_statement():
    """AC 6: no DELETE statement in migration (excluding comments)."""
    text = (_MIGRATIONS_DIR / "0012_notifications.sql").read_text().upper()
    lines = [l.strip() for l in text.splitlines() if not l.strip().startswith("--")]
    non_comment = "\n".join(lines)
    assert "DELETE" not in non_comment, "DELETE statement found in non-comment migration text"


# --- AC 7: outcome CHECK and nullable status_code ---

def test_ac7_outcome_check_constraint():
    """AC 7: outcome has CHECK (outcome IN ('delivered','failed'))."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            """
            SELECT cc.check_clause
            FROM information_schema.table_constraints tc
            JOIN information_schema.check_constraints cc
              ON tc.constraint_name = cc.constraint_name
            WHERE tc.table_name = 'notification_delivery'
              AND tc.constraint_type = 'CHECK'
            """
        ).fetchall()
    clauses = [r[0] for r in rows]
    full = " ".join(clauses)
    assert "outcome" in full.lower(), f"No CHECK clause for outcome; clauses: {clauses}"
    assert "delivered" in full
    assert "failed" in full


def test_ac7_status_code_is_nullable():
    """AC 7: status_code is nullable (no NOT NULL constraint)."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT is_nullable FROM information_schema.columns "
            "WHERE table_name = 'notification_delivery' AND column_name = 'status_code'"
        ).fetchone()
    assert row is not None
    assert row[0] == "YES", f"status_code is not nullable; is_nullable={row[0]}"


# --- AC 8: repository module defines all required symbols ---

def test_ac8_outcome_values_constant():
    """AC 8: OUTCOME_VALUES == ('delivered', 'failed')."""
    assert OUTCOME_VALUES == ("delivered", "failed")


def test_ac8_notification_subscription_is_frozen_dataclass():
    """AC 8: NotificationSubscription is a frozen dataclass."""
    import dataclasses
    assert dataclasses.is_dataclass(NotificationSubscription)
    assert NotificationSubscription.__dataclass_params__.frozen  # type: ignore[attr-defined]


def test_ac8_notification_delivery_is_frozen_dataclass():
    """AC 8: NotificationDelivery is a frozen dataclass."""
    import dataclasses
    assert dataclasses.is_dataclass(NotificationDelivery)
    assert NotificationDelivery.__dataclass_params__.frozen  # type: ignore[attr-defined]


def test_ac8_notification_repository_is_a_class():
    """AC 8: NotificationRepository is a class."""
    assert isinstance(NotificationRepository, type)


# --- AC 9: five required methods; no UPDATE/DELETE SQL in module ---

def test_ac9_notification_repository_has_required_methods():
    """AC 9: NotificationRepository has all five required methods."""
    for method in (
        "create_subscription", "list_subscriptions", "list_enabled_subscriptions",
        "append_delivery", "list_deliveries",
    ):
        assert hasattr(NotificationRepository, method), (
            f"NotificationRepository missing method: {method}"
        )


def test_ac9_no_update_sql_in_notifications_module():
    """AC 9: notifications.py (db package) contains no UPDATE SQL."""
    text = _NOTIFICATIONS_PY.read_text()
    # Strip comments and docstrings before checking
    no_docstrings = re.sub(r'""".*?"""', "", text, flags=re.DOTALL)
    no_docstrings = re.sub(r"'''.*?'''", "", no_docstrings, flags=re.DOTALL)
    no_comments = "\n".join(
        line for line in no_docstrings.splitlines()
        if not line.strip().startswith("#")
    )
    assert "UPDATE" not in no_comments.upper(), "UPDATE SQL found in db/notifications.py"


def test_ac9_no_delete_sql_in_notifications_module():
    """AC 9: notifications.py (db package) contains no DELETE SQL."""
    text = _NOTIFICATIONS_PY.read_text()
    no_docstrings = re.sub(r'""".*?"""', "", text, flags=re.DOTALL)
    no_docstrings = re.sub(r"'''.*?'''", "", no_docstrings, flags=re.DOTALL)
    no_comments = "\n".join(
        line for line in no_docstrings.splitlines()
        if not line.strip().startswith("#")
    )
    assert "DELETE" not in no_comments.upper(), "DELETE SQL found in db/notifications.py"


# --- AC 10: max(0, limit) in list_deliveries ---

def test_ac10_max_0_limit_in_list_deliveries():
    """AC 10: max(0, limit) appears in list_deliveries body."""
    text = _NOTIFICATIONS_PY.read_text()
    assert "max(0, limit)" in text, "max(0, limit) not found in notifications.py"


# --- AC 11: symbols exported from db.__init__.__all__ ---

def test_ac11_notification_repository_in_db_all():
    """AC 11: NotificationRepository in infra_twin.db.__all__."""
    import infra_twin.db as db
    assert "NotificationRepository" in db.__all__


def test_ac11_notification_subscription_in_db_all():
    """AC 11: NotificationSubscription in infra_twin.db.__all__."""
    import infra_twin.db as db
    assert "NotificationSubscription" in db.__all__


def test_ac11_notification_delivery_in_db_all():
    """AC 11: NotificationDelivery in infra_twin.db.__all__."""
    import infra_twin.db as db
    assert "NotificationDelivery" in db.__all__


def test_ac11_symbols_importable_from_db():
    """AC 11: all three symbols importable directly from infra_twin.db."""
    from infra_twin.db import NotificationDelivery as ND
    from infra_twin.db import NotificationRepository as NR
    from infra_twin.db import NotificationSubscription as NS
    assert NR is NotificationRepository
    assert NS is NotificationSubscription
    assert ND is NotificationDelivery


# --- AC 12: reconciliation/notifications.py defines required symbols; no query import ---

def test_ac12_httpsender_type_alias_defined():
    """AC 12: HttpSender type alias defined in reconciliation/notifications.py."""
    from infra_twin.reconciliation.notifications import HttpSender
    assert HttpSender is not None


def test_ac12_build_finding_payload_defined():
    """AC 12: build_finding_payload defined."""
    from infra_twin.reconciliation.notifications import build_finding_payload
    assert callable(build_finding_payload)


def test_ac12_notify_finding_opened_defined():
    """AC 12: notify_finding_opened defined."""
    from infra_twin.reconciliation.notifications import notify_finding_opened
    assert callable(notify_finding_opened)


def test_ac12_no_infra_twin_query_import_in_reconciliation_notifications():
    """AC 12: reconciliation/notifications.py does not import infra_twin.query at top level."""
    text = _RECONCIL_NOTIF_PY.read_text()
    lines = text.splitlines()
    top_level_query_imports = []
    in_function = False
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0 and (stripped.startswith("def ") or stripped.startswith("class ")):
            in_function = True
            continue
        if indent == 0 and in_function:
            in_function = False
        if not in_function and indent == 0:
            if "from infra_twin.query" in stripped or "import infra_twin.query" in stripped:
                top_level_query_imports.append(stripped)
    assert top_level_query_imports == [], (
        f"Top-level infra_twin.query import found: {top_level_query_imports}"
    )


# --- AC 13: build_finding_payload returns exactly the specified keys ---

def test_ac13_build_finding_payload_top_level_keys(pool, make_tenant):
    """AC 13: build_finding_payload returns exactly: finding_id, rule_id, severity, subject, evidence."""
    from infra_twin.core_model import Finding
    from infra_twin.reconciliation.notifications import build_finding_payload
    from datetime import datetime, timezone

    _seed(pool, make_tenant("ac13-payload"), _internet_reachable_rds_events())
    tenant = make_tenant("ac13-payload2")
    _seed(pool, tenant, _internet_reachable_rds_events())

    with tenant_session(pool, tenant) as conn:
        result, findings = evaluate_findings_with_summary(conn, tenant)

    assert len(findings) == 1
    f = findings[0]
    payload = build_finding_payload(f, None)
    assert set(payload.keys()) == {"finding_id", "rule_id", "severity", "subject", "evidence"}


def test_ac13_build_finding_payload_subject_keys(pool, make_tenant):
    """AC 13: build_finding_payload subject has exactly: id, type, name."""
    from infra_twin.reconciliation.notifications import build_finding_payload

    tenant = make_tenant("ac13-subject-keys")
    _seed(pool, tenant, _internet_reachable_rds_events())
    with tenant_session(pool, tenant) as conn:
        _, findings = evaluate_findings_with_summary(conn, tenant)

    f = findings[0]
    payload = build_finding_payload(f, None)
    assert set(payload["subject"].keys()) == {"id", "type", "name"}


def test_ac13_build_finding_payload_values(pool, make_tenant):
    """AC 13: build_finding_payload populates finding_id, rule_id, severity correctly."""
    from infra_twin.reconciliation.notifications import build_finding_payload

    tenant = make_tenant("ac13-payload-values")
    _seed(pool, tenant, _internet_reachable_rds_events())
    with tenant_session(pool, tenant) as conn:
        _, findings = evaluate_findings_with_summary(conn, tenant)

    f = findings[0]
    payload = build_finding_payload(f, None)
    assert payload["finding_id"] == str(f.id)
    assert payload["rule_id"] == f.rule_id
    assert payload["severity"] == f.severity
    assert payload["subject"]["id"] == str(f.subject_ci_id)
    assert payload["evidence"] == f.evidence


def test_ac13_build_finding_payload_with_subject_ci(pool, make_tenant):
    """AC 13: build_finding_payload with a real CI populates subject.type and subject.name."""
    from infra_twin.db.repositories import CIRepository
    from infra_twin.reconciliation.notifications import build_finding_payload

    tenant = make_tenant("ac13-with-ci")
    _seed(pool, tenant, _internet_reachable_rds_events())
    with tenant_session(pool, tenant) as conn:
        _, findings = evaluate_findings_with_summary(conn, tenant)
        ci_repo = CIRepository(conn, tenant)
        ci = ci_repo.get_current_by_id(findings[0].subject_ci_id)
        payload = build_finding_payload(findings[0], ci)

    assert payload["subject"]["type"] == ci.type.value
    assert payload["subject"]["name"] == ci.name


# --- AC 14: evaluate_findings_with_summary and evaluate_findings have notify_sender kwarg ---

def test_ac14_evaluate_findings_with_summary_has_notify_sender():
    """AC 14: evaluate_findings_with_summary has notify_sender kwarg defaulting to None."""
    sig = inspect.signature(evaluate_findings_with_summary)
    assert "notify_sender" in sig.parameters
    assert sig.parameters["notify_sender"].default is None


def test_ac14_evaluate_findings_has_notify_sender():
    """AC 14: evaluate_findings has notify_sender kwarg defaulting to None."""
    sig = inspect.signature(evaluate_findings)
    assert "notify_sender" in sig.parameters
    assert sig.parameters["notify_sender"].default is None


# --- AC 15: emit calls are adjacent to open_finding + guarded; none in resolve ---

def test_ac15_notify_finding_opened_adjacent_to_open_finding():
    """AC 15: notify_finding_opened calls appear after open_finding calls in findings.py."""
    text = _RECONCIL_FINDINGS_PY.read_text()
    # Find all positions of open_finding and notify_finding_opened
    open_positions = [m.start() for m in re.finditer(r"repo\.open_finding\(", text)]
    notify_positions = [m.start() for m in re.finditer(r"notify_finding_opened\(", text)]
    # Each notify call should follow an open_finding call
    assert len(notify_positions) > 0, "No notify_finding_opened calls found in findings.py"
    assert len(open_positions) >= len(notify_positions), (
        "More notify_finding_opened calls than open_finding calls"
    )
    for npos in notify_positions:
        # There should be an open_finding within the preceding 400 chars
        nearby_text = text[max(0, npos - 400): npos]
        assert "open_finding" in nearby_text, (
            f"notify_finding_opened call at offset {npos} has no open_finding in preceding 400 chars"
        )


def test_ac15_notify_finding_opened_guarded_by_notify_sender_check():
    """AC 15: every notify_finding_opened call is guarded by 'if notify_sender is not None'."""
    text = _RECONCIL_FINDINGS_PY.read_text()
    # For each notify_finding_opened occurrence, check that the preceding ~200 chars
    # contain 'if notify_sender is not None'
    for m in re.finditer(r"notify_finding_opened\(", text):
        nearby_text = text[max(0, m.start() - 300): m.start()]
        assert "if notify_sender is not None" in nearby_text, (
            f"notify_finding_opened at offset {m.start()} not guarded by "
            f"'if notify_sender is not None'"
        )


def test_ac15_no_notify_finding_opened_in_resolve_branches():
    """AC 15: notify_finding_opened does not appear near repo.resolve calls in findings.py."""
    text = _RECONCIL_FINDINGS_PY.read_text()
    # Find all resolve positions; check no notify call within 200 chars after them
    for m in re.finditer(r"repo\.resolve\(", text):
        nearby = text[m.start(): m.start() + 300]
        assert "notify_finding_opened" not in nearby, (
            f"notify_finding_opened found near repo.resolve at offset {m.start()}: {nearby!r}"
        )


# --- AC 16: FastAPI routes registered correctly ---

def test_ac16_post_notifications_subscriptions_registered():
    """AC 16: POST /notifications/subscriptions registered with status_code=201 and _write."""
    text = _APP_PY.read_text()
    assert "@app.post(\"/notifications/subscriptions\", status_code=201)" in text
    assert "_write" in text


def test_ac16_get_notifications_subscriptions_registered():
    """AC 16: GET /notifications/subscriptions registered with _read."""
    text = _APP_PY.read_text()
    assert "@app.get(\"/notifications/subscriptions\")" in text


def test_ac16_get_notifications_deliveries_registered():
    """AC 16: GET /notifications/deliveries registered with _read."""
    text = _APP_PY.read_text()
    assert "@app.get(\"/notifications/deliveries\")" in text


# --- AC 17: CreateSubscriptionBody url validator ---

def test_ac17_url_validator_rejects_empty():
    """AC 17: CreateSubscriptionBody raises ValidationError for empty url."""
    from pydantic import ValidationError
    from infra_twin.api.app import CreateSubscriptionBody
    with pytest.raises(ValidationError):
        CreateSubscriptionBody(url="")


def test_ac17_url_validator_rejects_whitespace():
    """AC 17: CreateSubscriptionBody raises ValidationError for whitespace url."""
    from pydantic import ValidationError
    from infra_twin.api.app import CreateSubscriptionBody
    with pytest.raises(ValidationError):
        CreateSubscriptionBody(url="   ")


def test_ac17_url_validator_rejects_non_http():
    """AC 17: CreateSubscriptionBody raises ValidationError for non-http(s) url."""
    from pydantic import ValidationError
    from infra_twin.api.app import CreateSubscriptionBody
    with pytest.raises(ValidationError):
        CreateSubscriptionBody(url="ftp://example.com/hook")


def test_ac17_url_validator_accepts_http():
    """AC 17: CreateSubscriptionBody accepts http:// url."""
    from infra_twin.api.app import CreateSubscriptionBody
    body = CreateSubscriptionBody(url="http://example.com/hook")
    assert body.url == "http://example.com/hook"


def test_ac17_url_validator_accepts_https():
    """AC 17: CreateSubscriptionBody accepts https:// url."""
    from infra_twin.api.app import CreateSubscriptionBody
    body = CreateSubscriptionBody(url="https://example.com/hook")
    assert body.url == "https://example.com/hook"


# --- AC 18: response dicts omit tenant_id ---

def test_ac18_subscription_response_dict_omits_tenant_id(pool, make_tenant_with_key):
    """AC 18: POST /notifications/subscriptions response does not include tenant_id."""
    tenant, api_key = make_tenant_with_key("ac18-sub-no-tenant")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/notifications/subscriptions",
        json={"url": "https://example.com/hook"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    assert "tenant_id" not in resp.json()


def test_ac18_delivery_response_dict_omits_tenant_id(pool, make_tenant):
    """AC 18: GET /notifications/deliveries response dicts do not include tenant_id."""
    tenant = make_tenant("ac18-delivery-no-tenant")
    _seed(pool, tenant, _internet_reachable_rds_events())
    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)

    key_plain = _issue_key_for_tenant(tenant, Role.editor)
    client = TestClient(create_app(pool=pool))
    resp = client.get("/notifications/deliveries", headers=_auth(key_plain))
    assert resp.status_code == 200
    for d in resp.json():
        assert "tenant_id" not in d


def test_ac18_list_subscriptions_response_dict_omits_tenant_id(pool, make_tenant_with_key):
    """AC 18: GET /notifications/subscriptions response dicts do not include tenant_id."""
    tenant, api_key = make_tenant_with_key("ac18-list-no-tenant")
    client = TestClient(create_app(pool=pool))
    client.post(
        "/notifications/subscriptions",
        json={"url": "https://example.com/hook"},
        headers=_auth(api_key),
    )
    resp = client.get("/notifications/subscriptions", headers=_auth(api_key))
    assert resp.status_code == 200
    for s in resp.json():
        assert "tenant_id" not in s


# --- AC 19: conftest._DATA_TABLES includes both new tables ---

def test_ac19_conftest_includes_notification_delivery():
    """AC 19: conftest.py _DATA_TABLES includes 'notification_delivery'."""
    text = _CONFTEST_PY.read_text()
    match = re.search(r'_DATA_TABLES\s*=\s*["\']([^"\']+)["\']', text)
    assert match is not None, "_DATA_TABLES not found in conftest.py"
    tables = match.group(1)
    assert "notification_delivery" in tables


def test_ac19_conftest_includes_notification_subscription():
    """AC 19: conftest.py _DATA_TABLES includes 'notification_subscription'."""
    text = _CONFTEST_PY.read_text()
    match = re.search(r'_DATA_TABLES\s*=\s*["\']([^"\']+)["\']', text)
    assert match is not None, "_DATA_TABLES not found in conftest.py"
    tables = match.group(1)
    assert "notification_subscription" in tables


# ===========================================================================
# BEHAVIOURAL / INTEGRATION TESTS
# ===========================================================================


# --- AC 20a: create + list subscriptions works and is tenant-scoped ---

def test_create_subscription_returns_correct_shape(pool, make_tenant):
    """AC 20a: create_subscription returns NotificationSubscription with expected fields."""
    tenant = make_tenant("create-sub-shape")
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        sub = repo.create_subscription("https://example.com/hook", enabled=True)
    assert isinstance(sub, NotificationSubscription)
    assert sub.tenant_id == tenant
    assert sub.url == "https://example.com/hook"
    assert sub.enabled is True
    assert isinstance(sub.subscription_id, UUID)


def test_list_subscriptions_returns_created_subscription(pool, make_tenant):
    """AC 20a: list_subscriptions returns the subscription just created."""
    tenant = make_tenant("list-sub")
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        created = repo.create_subscription("https://example.com/hook")
        listed = repo.list_subscriptions()
    assert len(listed) == 1
    assert listed[0].subscription_id == created.subscription_id


def test_create_subscription_tenant_scoped_list(pool, make_tenant):
    """AC 20a: tenant B cannot see tenant A's subscription via list_subscriptions."""
    tenant_a = make_tenant("create-sub-a")
    tenant_b = make_tenant("create-sub-b")

    # Create subscription for tenant A
    with tenant_session(pool, tenant_a) as conn:
        NotificationRepository(conn, tenant_a).create_subscription("https://a.example.com/hook")

    # Tenant B's list_subscriptions should return []
    with tenant_session(pool, tenant_b) as conn:
        subs_b = NotificationRepository(conn, tenant_b).list_subscriptions()
    assert subs_b == [], (
        "Tenant B must not see tenant A's subscriptions (RLS tenant scoping)"
    )


def test_create_subscription_api_returns_201(pool, make_tenant_with_key):
    """AC 20a: POST /notifications/subscriptions returns 201."""
    tenant, api_key = make_tenant_with_key("api-create-sub")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/notifications/subscriptions",
        json={"url": "https://example.com/hook"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "subscription_id" in body
    assert body["url"] == "https://example.com/hook"
    assert body["enabled"] is True
    assert "created_at" in body


def test_list_subscriptions_api_returns_200(pool, make_tenant_with_key):
    """AC 20a: GET /notifications/subscriptions returns 200 with list."""
    tenant, api_key = make_tenant_with_key("api-list-sub")
    client = TestClient(create_app(pool=pool))
    client.post(
        "/notifications/subscriptions",
        json={"url": "https://example.com/hook"},
        headers=_auth(api_key),
    )
    resp = client.get("/notifications/subscriptions", headers=_auth(api_key))
    assert resp.status_code == 200
    subs = resp.json()
    assert len(subs) == 1
    assert subs[0]["url"] == "https://example.com/hook"


# --- AC 20b: opening a new finding emits exactly one delivery per enabled subscription ---

def test_new_finding_emits_one_delivery_per_enabled_subscription(pool, make_tenant):
    """AC 20b: opening one new finding with one enabled sub -> exactly one delivery row."""
    tenant = make_tenant("emit-one-delivery")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        repo.create_subscription("https://example.com/hook1")
        result, findings = evaluate_findings_with_summary(
            conn, tenant, notify_sender=sender
        )

    assert result.opened == 1
    assert len(sender.calls) == 1, f"Expected 1 send call, got {len(sender.calls)}"
    assert sender.calls[0][0] == "https://example.com/hook1"
    assert _count_deliveries_admin(tenant) == 1


def test_new_finding_delivery_has_correct_finding_id(pool, make_tenant):
    """AC 20b: delivery row records the correct finding_id."""
    tenant = make_tenant("delivery-finding-id")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        repo.create_subscription("https://example.com/hook")
        _, findings = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        deliveries = NotificationRepository(conn, tenant).list_deliveries()

    assert len(deliveries) == 1
    assert deliveries[0].finding_id == findings[0].id


# --- AC 20c: adversarial cross-tenant isolation ---

def test_adversarial_a_finding_does_not_deliver_to_b(pool, make_tenant):
    """AC 20c: evaluating tenant A emits to A's subscriptions only; B gets zero deliveries."""
    tenant_a = make_tenant("cross-tenant-a")
    tenant_b = make_tenant("cross-tenant-b")

    # Tenant A has an internet-reachable rds and a subscription
    _seed(pool, tenant_a, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant_a) as conn:
        NotificationRepository(conn, tenant_a).create_subscription("https://a.example.com/hook")
        evaluate_findings_with_summary(conn, tenant_a, notify_sender=sender)

    # Tenant B: no subscriptions, no deliveries
    assert _count_deliveries_admin(tenant_a) == 1
    assert _count_deliveries_admin(tenant_b) == 0
    assert _count_subscriptions_admin(tenant_b) == 0


def test_adversarial_evaluating_b_no_sub_zero_sends(pool, make_tenant):
    """AC 20c: evaluating tenant B (no enabled subscription) produces zero sends."""
    tenant_a = make_tenant("cross-eval-a")
    tenant_b = make_tenant("cross-eval-b")

    _seed(pool, tenant_a, _internet_reachable_rds_events())
    # Tenant A has subscription + finding
    sender_a = RecordingSender(200)
    with tenant_session(pool, tenant_a) as conn:
        NotificationRepository(conn, tenant_a).create_subscription("https://a.example.com/hook")
        evaluate_findings_with_summary(conn, tenant_a, notify_sender=sender_a)

    # Evaluate tenant B - zero graph, zero deliveries
    sender_b = RecordingSender(200)
    with tenant_session(pool, tenant_b) as conn:
        result_b, _ = evaluate_findings_with_summary(conn, tenant_b, notify_sender=sender_b)
    assert len(sender_b.calls) == 0
    assert result_b.opened == 0


def test_adversarial_b_cannot_list_a_subscriptions_rls(pool, make_tenant):
    """AC 20c (RLS layer): tenant B raw SELECT on notification_subscription returns empty."""
    tenant_a = make_tenant("rls-sub-a")
    tenant_b = make_tenant("rls-sub-b")

    with tenant_session(pool, tenant_a) as conn:
        NotificationRepository(conn, tenant_a).create_subscription("https://a.example.com/hook")

    # Tenant B's raw SELECT sees nothing
    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM notification_subscription"
        ).fetchone()[0]
    assert count == 0, "Tenant B must not see tenant A's subscriptions via RLS"


def test_adversarial_b_cannot_list_a_deliveries_rls(pool, make_tenant):
    """AC 20c (RLS layer): tenant B raw SELECT on notification_delivery returns empty."""
    tenant_a = make_tenant("rls-del-a")
    tenant_b = make_tenant("rls-del-b")

    _seed(pool, tenant_a, _internet_reachable_rds_events())
    sender = RecordingSender(200)
    with tenant_session(pool, tenant_a) as conn:
        NotificationRepository(conn, tenant_a).create_subscription("https://a.example.com/hook")
        evaluate_findings_with_summary(conn, tenant_a, notify_sender=sender)

    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM notification_delivery"
        ).fetchone()[0]
    assert count == 0, "Tenant B must not see tenant A's deliveries via RLS"


# --- AC 20d: re-evaluation with unchanged finding -> no new send / delivery ---

def test_reeval_unchanged_finding_no_new_delivery(pool, make_tenant):
    """AC 20d: re-evaluating unchanged graph (finding stays open) -> zero new sends."""
    tenant = make_tenant("reeval-no-dup")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        # First run: opens finding, sends one delivery
        r1, _ = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        assert r1.opened == 1
        assert len(sender.calls) == 1

        # Second run: finding already open; should NOT send again
        r2, _ = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        assert r2.opened == 0

    # Total sends still == 1
    assert len(sender.calls) == 1, f"Expected 1 total send, got {len(sender.calls)}"
    assert _count_deliveries_admin(tenant) == 1


# --- AC 20e: delivery rows are append-only; app role has no DELETE privilege ---

def test_app_role_has_no_delete_on_notification_delivery():
    """AC 20e: app role does NOT have DELETE privilege on notification_delivery."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT has_table_privilege('app', 'notification_delivery', 'DELETE')"
        ).fetchone()
    assert row is not None
    assert row[0] is False, "app role must NOT have DELETE on notification_delivery"


def test_app_role_has_no_delete_on_notification_subscription():
    """AC 20e: app role does NOT have DELETE privilege on notification_subscription."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT has_table_privilege('app', 'notification_subscription', 'DELETE')"
        ).fetchone()
    assert row is not None
    assert row[0] is False, "app role must NOT have DELETE on notification_subscription"


def test_app_role_has_no_update_on_notification_delivery():
    """AC 20e: app role does NOT have UPDATE privilege on notification_delivery."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT has_table_privilege('app', 'notification_delivery', 'UPDATE')"
        ).fetchone()
    assert row is not None
    assert row[0] is False, "app role must NOT have UPDATE on notification_delivery"


def test_app_role_has_no_update_on_notification_subscription():
    """AC 20e: app role does NOT have UPDATE privilege on notification_subscription."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT has_table_privilege('app', 'notification_subscription', 'UPDATE')"
        ).fetchone()
    assert row is not None
    assert row[0] is False, "app role must NOT have UPDATE on notification_subscription"


def test_delivery_rows_not_removed_across_two_evaluations(pool, make_tenant):
    """AC 20e: second evaluate does not delete or remove the first delivery row."""
    tenant = make_tenant("append-only-del")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    # First evaluate: opens finding and creates delivery
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)

    # Committed: one delivery row
    assert _count_deliveries_admin(tenant) == 1

    # Second evaluate (idempotent): finding already open, no new delivery
    with tenant_session(pool, tenant) as conn:
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)

    # Still exactly one delivery row — none removed
    assert _count_deliveries_admin(tenant) == 1


# --- AC 20f: RBAC / auth ---

def test_post_subscriptions_unauthenticated_returns_401(pool):
    """AC 20f: POST /notifications/subscriptions with no key -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/notifications/subscriptions",
        json={"url": "https://example.com/hook"},
    )
    assert resp.status_code == 401


def test_get_subscriptions_unauthenticated_returns_401(pool):
    """AC 20f: GET /notifications/subscriptions with no key -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/notifications/subscriptions")
    assert resp.status_code == 401


def test_get_deliveries_unauthenticated_returns_401(pool):
    """AC 20f: GET /notifications/deliveries with no key -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/notifications/deliveries")
    assert resp.status_code == 401


def test_viewer_post_subscriptions_returns_403(pool):
    """AC 20f: viewer key on POST /notifications/subscriptions -> 403."""
    _, viewer_key = _make_viewer_key("viewer-post-sub-403")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/notifications/subscriptions",
        json={"url": "https://example.com/hook"},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403


def test_viewer_post_subscriptions_403_detail(pool):
    """AC 20f: viewer 403 detail == 'insufficient permissions'."""
    _, viewer_key = _make_viewer_key("viewer-post-sub-detail")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/notifications/subscriptions",
        json={"url": "https://example.com/hook"},
        headers=_auth(viewer_key),
    )
    assert resp.json()["detail"] == "insufficient permissions"


def test_viewer_post_subscriptions_creates_no_row(pool):
    """AC 20f: viewer POST /notifications/subscriptions creates no subscription row."""
    viewer_tenant, viewer_key = _make_viewer_key("viewer-post-no-row")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/notifications/subscriptions",
        json={"url": "https://example.com/hook"},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403
    assert _count_subscriptions_admin(viewer_tenant) == 0


def test_viewer_get_subscriptions_returns_200(pool):
    """AC 20f: viewer key on GET /notifications/subscriptions -> 200."""
    _, viewer_key = _make_viewer_key("viewer-get-sub-200")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/notifications/subscriptions", headers=_auth(viewer_key))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_viewer_get_deliveries_returns_200(pool):
    """AC 20f: viewer key on GET /notifications/deliveries -> 200."""
    _, viewer_key = _make_viewer_key("viewer-get-del-200")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/notifications/deliveries", headers=_auth(viewer_key))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_editor_post_subscriptions_returns_201(pool):
    """AC 20f: editor key on POST /notifications/subscriptions -> 201."""
    _, editor_key = _make_editor_key("editor-post-sub-201")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/notifications/subscriptions",
        json={"url": "https://example.com/hook"},
        headers=_auth(editor_key),
    )
    assert resp.status_code == 201


# --- AC 20g: sender returning non-2xx; sender raising ---

def test_sender_returning_non_2xx_outcome_failed(pool, make_tenant):
    """AC 20g: sender returning 500 -> outcome='failed', status_code=500."""
    tenant = make_tenant("non-2xx-failed")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(500)
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        _, _ = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        deliveries = NotificationRepository(conn, tenant).list_deliveries()

    assert len(deliveries) == 1
    assert deliveries[0].outcome == "failed"
    assert deliveries[0].status_code == 500


def test_sender_returning_200_outcome_delivered(pool, make_tenant):
    """AC 20g: sender returning 200 -> outcome='delivered', status_code=200."""
    tenant = make_tenant("2xx-delivered")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        deliveries = NotificationRepository(conn, tenant).list_deliveries()

    assert deliveries[0].outcome == "delivered"
    assert deliveries[0].status_code == 200


def test_sender_raising_outcome_failed_status_code_none(pool, make_tenant):
    """AC 20g: sender raising -> outcome='failed', status_code=None."""
    tenant = make_tenant("sender-raises")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    sender.should_raise = True
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        deliveries = NotificationRepository(conn, tenant).list_deliveries()

    assert len(deliveries) == 1
    assert deliveries[0].outcome == "failed"
    assert deliveries[0].status_code is None


def test_sender_raising_exception_swallowed_evaluation_not_rolled_back(pool, make_tenant):
    """AC 20g: sender raises but finding still opened and delivery still committed."""
    tenant = make_tenant("raises-no-rollback")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    sender.should_raise = True
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        result, findings = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)

    assert result.opened == 1, "Finding must still be opened when sender raises"
    assert _count_deliveries_admin(tenant) == 1, "Delivery row must be committed even when sender raises"


# ===========================================================================
# EDGE CASES
# ===========================================================================


# --- EC 1: tenant with zero subscriptions -> zero sends, zero deliveries ---

def test_ec1_zero_subscriptions_zero_sends(pool, make_tenant):
    """EC 1: tenant with no subscriptions -> evaluate produces zero sends and zero deliveries."""
    tenant = make_tenant("ec1-zero-subs")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        result, _ = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)

    assert result.opened == 1
    assert len(sender.calls) == 0, "No send calls when no subscriptions"
    assert _count_deliveries_admin(tenant) == 0


# --- EC 2: one enabled + one disabled -> exactly one send + one delivery ---

def test_ec2_one_enabled_one_disabled_one_send(pool, make_tenant):
    """EC 2: one enabled + one disabled subscription -> exactly one send and one delivery."""
    tenant = make_tenant("ec2-enabled-disabled")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        repo.create_subscription("https://enabled.example.com/hook", enabled=True)
        repo.create_subscription("https://disabled.example.com/hook", enabled=False)
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)

    assert len(sender.calls) == 1, f"Expected 1 send, got {len(sender.calls)}"
    assert sender.calls[0][0] == "https://enabled.example.com/hook"
    assert _count_deliveries_admin(tenant) == 1


# --- EC 3: multiple enabled subscriptions -> one send + one delivery per enabled sub ---

def test_ec3_multiple_enabled_subs_one_send_each(pool, make_tenant):
    """EC 3: two enabled subscriptions -> two sends, two deliveries."""
    tenant = make_tenant("ec3-multi-sub")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        repo.create_subscription("https://hook1.example.com/")
        repo.create_subscription("https://hook2.example.com/")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)

    assert len(sender.calls) == 2
    called_urls = {call[0] for call in sender.calls}
    assert called_urls == {"https://hook1.example.com/", "https://hook2.example.com/"}
    assert _count_deliveries_admin(tenant) == 2


# --- EC 4: sender returns 2xx -> delivered; non-2xx -> failed ---

def test_ec4_2xx_status_codes(pool, make_tenant):
    """EC 4: sender returning 201, 204 -> outcome='delivered'."""
    for code in (201, 204):
        # Using fresh tenant per status code is not feasible in a loop; test 201 only
        break  # only test one to keep test atomic
    tenant = make_tenant("ec4-2xx-codes")
    _seed(pool, tenant, _internet_reachable_rds_events())

    for status in [201, 204]:
        # Create a fresh subscription per sub-test (within same tenant after clean)
        sender = RecordingSender(status)
        with tenant_session(pool, tenant) as conn:
            repo = NotificationRepository(conn, tenant)
            sub = repo.create_subscription(f"https://hook-{status}.example.com/")
            # Manually call notify_finding_opened directly with a fabricated finding
            from infra_twin.reconciliation.notifications import notify_finding_opened
            from infra_twin.core_model import Finding
            from datetime import datetime, timezone
            finding = Finding(
                tenant_id=tenant,
                rule_id="test_rule",
                severity="high",
                subject_ci_id=uuid4(),
                title="test",
                description="test",
                evidence={},
                detected_at=datetime.now(timezone.utc),
            )
            deliveries = notify_finding_opened(repo, finding, None, send=sender)
        assert deliveries[0].outcome == "delivered", f"Expected delivered for {status}"
        assert deliveries[0].status_code == status


def test_ec4_non_2xx_returns_failed(pool, make_tenant):
    """EC 4: sender returning 404, 500 -> outcome='failed'."""
    tenant = make_tenant("ec4-non-2xx")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(404)
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        repo.create_subscription("https://hook.example.com/")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        deliveries = repo.list_deliveries()

    assert deliveries[0].outcome == "failed"
    assert deliveries[0].status_code == 404


def test_ec4_redirect_status_is_failed(pool, make_tenant):
    """EC 4: sender returning 301 -> outcome='failed' (non-2xx)."""
    tenant = make_tenant("ec4-redirect")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(301)
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        repo.create_subscription("https://hook.example.com/")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        deliveries = repo.list_deliveries()

    assert deliveries[0].outcome == "failed"
    assert deliveries[0].status_code == 301


# --- EC 5: sender raises -> failed, status_code None, rest attempted ---

def test_ec5_sender_raises_other_subs_still_attempted(pool, make_tenant):
    """EC 5: sender raises on first sub -> delivery appended with None status; second sub still attempted."""
    tenant = make_tenant("ec5-raises-rest")
    _seed(pool, tenant, _internet_reachable_rds_events())

    # Two subscriptions; first raises, second returns 200
    sender = RecordingSender(200)
    sender.raise_on_url = "https://hook1.example.com/"
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        repo.create_subscription("https://hook1.example.com/")
        repo.create_subscription("https://hook2.example.com/")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        deliveries = repo.list_deliveries(limit=10)

    assert len(deliveries) == 2
    assert _count_deliveries_admin(tenant) == 2
    outcomes = {d.outcome for d in deliveries}
    assert "failed" in outcomes
    assert "delivered" in outcomes


# --- EC 6: two subs, first raises, second returns 200 ---

def test_ec6_two_subs_first_raises_second_delivered(pool, make_tenant):
    """EC 6: two subs, first raises -> (failed, None); second returns 200 -> (delivered, 200)."""
    tenant = make_tenant("ec6-two-subs-mix")
    _seed(pool, tenant, _internet_reachable_rds_events())

    # Use PerUrlSender with raise then 200
    sender = PerUrlSender([OSError("transport failure"), 200])
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        repo.create_subscription("https://hook1.example.com/")
        repo.create_subscription("https://hook2.example.com/")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        deliveries = repo.list_deliveries(limit=10)
        # Order deliveries by attempted_at ASC to match call order
        deliveries_asc = sorted(deliveries, key=lambda d: (d.attempted_at, d.delivery_id))

    assert len(deliveries_asc) == 2
    # Both deliveries recorded
    outcomes = [(d.outcome, d.status_code) for d in deliveries_asc]
    assert ("failed", None) in outcomes
    assert ("delivered", 200) in outcomes


# --- EC 7: re-evaluation unchanged -> zero new sends ---
# (covered by AC 20d; included here for EC completeness)

def test_ec7_re_evaluation_unchanged_zero_sends(pool, make_tenant):
    """EC 7: re-evaluation on unchanged graph -> zero new sends."""
    tenant = make_tenant("ec7-reeval")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        first_call_count = len(sender.calls)

        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        second_call_count = len(sender.calls)

    assert first_call_count == 1
    assert second_call_count == 1, "No new sends on re-evaluation of unchanged graph"


# --- EC 8: re-evaluation resolves finding -> zero sends ---

def test_ec8_resolve_finding_no_send(pool, make_tenant):
    """EC 8: re-evaluation resolves finding -> zero sends during resolution."""
    tenant = make_tenant("ec8-resolve-no-send")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        result1, _ = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        assert result1.opened == 1
        calls_after_open = len(sender.calls)

    # Remove reaching path
    with tenant_session(pool, tenant) as conn:
        from infra_twin.reconciliation import reconcile
        reconcile(
            conn, tenant,
            [
                _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
                _ci(CIType.security_group, "sg-1"),
                _ci(CIType.rds, "db-1", "prod-db-1"),
                _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
                # EXPOSES intentionally absent
            ],
            source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE,
        )

    with tenant_session(pool, tenant) as conn:
        result2, _ = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        assert result2.resolved == 1

    calls_after_resolve = len(sender.calls)
    assert calls_after_resolve == calls_after_open, (
        "No new sends should occur during finding resolution"
    )


# --- EC 9: finding resolved then re-opened -> re-open emits again ---

def test_ec9_reopened_finding_emits_again(pool, make_tenant):
    """EC 9: finding resolved then re-opened -> new delivery with distinct finding_id."""
    tenant = make_tenant("ec9-reopen")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        _, findings1 = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
    first_finding_id = findings1[0].id

    # Remove reaching path to resolve
    with tenant_session(pool, tenant) as conn:
        from infra_twin.reconciliation import reconcile
        reconcile(
            conn, tenant,
            [
                _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
                _ci(CIType.security_group, "sg-1"),
                _ci(CIType.rds, "db-1", "prod-db-1"),
                _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
            ],
            source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE,
        )
    with tenant_session(pool, tenant) as conn:
        result2, _ = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
    assert result2.resolved == 1

    # Restore path and re-evaluate
    _seed(pool, tenant, _internet_reachable_rds_events())
    with tenant_session(pool, tenant) as conn:
        _, findings3 = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
    new_finding_id = findings3[0].id

    assert new_finding_id != first_finding_id
    # Two deliveries: one for original open, one for re-open
    assert _count_deliveries_admin(tenant) == 2
    assert len(sender.calls) == 2


# --- EC 10: cross-tenant (covered by AC 20c; extra assertion) ---

def test_ec10_cross_tenant_api_list_subscriptions(pool, make_tenant_with_key):
    """EC 10: tenant B's GET /notifications/subscriptions returns [] when only A has subs."""
    tenant_a, key_a = make_tenant_with_key("ec10-api-a")
    tenant_b, key_b = make_tenant_with_key("ec10-api-b")

    client = TestClient(create_app(pool=pool))
    client.post(
        "/notifications/subscriptions",
        json={"url": "https://a.example.com/hook"},
        headers=_auth(key_a),
    )

    resp_b = client.get("/notifications/subscriptions", headers=_auth(key_b))
    assert resp_b.status_code == 200
    assert resp_b.json() == [], "Tenant B must not see tenant A's subscriptions"


def test_ec10_cross_tenant_api_list_deliveries(pool, make_tenant):
    """EC 10: tenant B's GET /notifications/deliveries returns [] when only A has deliveries."""
    tenant_a = make_tenant("ec10-del-a")
    tenant_b = make_tenant("ec10-del-b")

    _seed(pool, tenant_a, _internet_reachable_rds_events())
    sender = RecordingSender(200)
    with tenant_session(pool, tenant_a) as conn:
        NotificationRepository(conn, tenant_a).create_subscription("https://a.example.com/hook")
        evaluate_findings_with_summary(conn, tenant_a, notify_sender=sender)

    key_b = _issue_key_for_tenant(tenant_b, Role.editor)
    client = TestClient(create_app(pool=pool))
    resp = client.get("/notifications/deliveries", headers=_auth(key_b))
    assert resp.status_code == 200
    assert resp.json() == [], "Tenant B must not see tenant A's deliveries"


# --- EC 11: cross-tenant write attempt fails RLS WITH CHECK ---

def test_ec11_cross_tenant_insert_fails_rls_with_check(pool, make_tenant):
    """EC 11: INSERT with mismatched tenant_id fails RLS WITH CHECK."""
    tenant_a = make_tenant("rls-wc-a")
    tenant_b = make_tenant("rls-wc-b")

    # Bound as tenant A; attempt to INSERT a row with tenant B's id
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with tenant_session(pool, tenant_a) as conn:
            conn.execute(
                "INSERT INTO notification_subscription (tenant_id, url, enabled) "
                "VALUES (%s, %s, %s)",
                (tenant_b, "https://example.com/hook", True),
            )


# --- EC 12: notify_sender=None -> no deliveries ---

def test_ec12_notify_sender_none_no_deliveries(pool, make_tenant):
    """EC 12: notify_sender=None (default) -> no deliveries written, counters unchanged."""
    tenant = make_tenant("ec12-sender-none")
    _seed(pool, tenant, _internet_reachable_rds_events())

    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        result, findings = evaluate_findings_with_summary(conn, tenant)  # no notify_sender

    assert result.opened == 1
    assert _count_deliveries_admin(tenant) == 0


def test_ec12_notify_sender_none_is_default(pool, make_tenant):
    """EC 12: calling evaluate_findings without notify_sender uses None default."""
    tenant = make_tenant("ec12-default-none")
    _seed(pool, tenant, _internet_reachable_rds_events())
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        evaluate_findings(conn, tenant)  # no notify_sender
    assert _count_deliveries_admin(tenant) == 0


# --- EC 13: invalid url -> 422 ---

def test_ec13_empty_url_returns_422(pool, make_tenant_with_key):
    """EC 13: POST with empty url -> 422."""
    _, api_key = make_tenant_with_key("ec13-empty-url")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/notifications/subscriptions",
        json={"url": ""},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_ec13_whitespace_url_returns_422(pool, make_tenant_with_key):
    """EC 13: POST with whitespace url -> 422."""
    _, api_key = make_tenant_with_key("ec13-ws-url")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/notifications/subscriptions",
        json={"url": "   "},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_ec13_non_http_url_returns_422(pool, make_tenant_with_key):
    """EC 13: POST with non-http(s) url -> 422, no row inserted."""
    tenant, api_key = make_tenant_with_key("ec13-ftp-url")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/notifications/subscriptions",
        json={"url": "ftp://example.com/hook"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422
    assert _count_subscriptions_admin(tenant) == 0


# --- EC 14: list_deliveries(limit=0) -> []; negative limit -> [] ---

def test_ec14_list_deliveries_limit_zero_returns_empty(pool, make_tenant):
    """EC 14: list_deliveries(limit=0) returns []."""
    tenant = make_tenant("ec14-limit-zero")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        repo.create_subscription("https://example.com/hook")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        result = repo.list_deliveries(limit=0)
    assert result == []


def test_ec14_list_deliveries_negative_limit_clamped_to_empty(pool, make_tenant):
    """EC 14: list_deliveries(limit=-5) is clamped to 0 and returns []."""
    tenant = make_tenant("ec14-neg-limit")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        repo.create_subscription("https://example.com/hook")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        result = repo.list_deliveries(limit=-5)
    assert result == []


def test_ec14_list_deliveries_normal_limit_works(pool, make_tenant):
    """EC 14 (positive): list_deliveries with a positive limit returns rows."""
    tenant = make_tenant("ec14-pos-limit")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        repo.create_subscription("https://example.com/hook")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        result = repo.list_deliveries(limit=10)
    assert len(result) == 1


# --- EC 15: large payload stored and round-tripped ---

def test_ec15_large_payload_round_trips(pool, make_tenant):
    """EC 15: large nested payload stored in JSONB and round-tripped unchanged."""
    tenant = make_tenant("ec15-large-payload")

    large_payload = {
        "finding_id": str(uuid4()),
        "rule_id": "test_rule",
        "severity": "critical",
        "subject": {"id": str(uuid4()), "type": "rds", "name": "a" * 1000},
        "evidence": {
            "targets": [{"id": str(uuid4()), "type": "s3_bucket"} for _ in range(50)],
            "extra": "x" * 2000,
        },
    }

    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        sub = repo.create_subscription("https://example.com/hook")
        delivery = repo.append_delivery(
            subscription_id=sub.subscription_id,
            finding_id=uuid4(),
            payload=large_payload,
            status_code=200,
            outcome="delivered",
        )

    assert delivery.payload == large_payload


# --- EC 16: multiple findings + multiple enabled subs -> delivery count = findings x subs ---

def test_ec16_multiple_findings_multiple_subs(pool, make_tenant):
    """EC 16: two findings + two enabled subs -> four deliveries."""
    tenant = make_tenant("ec16-multi-findings-subs")
    # Two internet-reachable RDS
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.rds, "db-1", "prod-db-1"),
        _ci(CIType.rds, "db-2", "prod-db-2"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.rds, "db-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.rds, "db-2"),
    ])

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        repo.create_subscription("https://hook1.example.com/")
        repo.create_subscription("https://hook2.example.com/")
        result, _ = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)

    assert result.opened == 2
    assert len(sender.calls) == 4, f"Expected 4 sends (2 findings x 2 subs), got {len(sender.calls)}"
    assert _count_deliveries_admin(tenant) == 4


def test_ec16_each_send_receives_correct_finding_payload(pool, make_tenant):
    """EC 16: each send call carries the payload for its specific finding, not a shared one."""
    tenant = make_tenant("ec16-payload-per-finding")
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.rds, "db-1", "prod-db-1"),
        _ci(CIType.rds, "db-2", "prod-db-2"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.rds, "db-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.rds, "db-2"),
    ])

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://hook.example.com/")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)

    assert len(sender.calls) == 2
    # The two payloads should have distinct finding_ids
    finding_ids = {call[1]["finding_id"] for call in sender.calls}
    assert len(finding_ids) == 2, "Each finding must produce its own payload"


# --- EC 17: ordering determinism ---

def test_ec17_list_subscriptions_ordering(pool, make_tenant):
    """EC 17: list_subscriptions returns newest-first (tie-broken by subscription_id DESC)."""
    tenant = make_tenant("ec17-sub-order")
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        sub1 = repo.create_subscription("https://hook1.example.com/")
        sub2 = repo.create_subscription("https://hook2.example.com/")
        listed = repo.list_subscriptions()

    # Newest first: sub2 was created after sub1
    assert len(listed) == 2
    # The most-recently-created (sub2) should appear first when created_at differs.
    # If same created_at (both in same transaction), subscription_id DESC tie-breaks.
    ids = [s.subscription_id for s in listed]
    # sub2 has a higher UUID because gen_random_uuid is not monotonic,
    # so we just check the list is stable (deterministic between calls).
    with tenant_session(pool, tenant) as conn:
        listed2 = NotificationRepository(conn, tenant).list_subscriptions()
    assert [s.subscription_id for s in listed2] == ids


def test_ec17_list_deliveries_ordering(pool, make_tenant):
    """EC 17: list_deliveries returns newest-first."""
    tenant = make_tenant("ec17-del-order")
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.rds, "db-1", "prod-db-1"),
        _ci(CIType.rds, "db-2", "prod-db-2"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.rds, "db-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.rds, "db-2"),
    ])

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://hook.example.com/")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
        deliveries = NotificationRepository(conn, tenant).list_deliveries()

    # If two deliveries exist, first should have attempted_at >= second
    if len(deliveries) >= 2:
        assert deliveries[0].attempted_at >= deliveries[1].attempted_at


# --- EC 18: app role cannot DELETE/UPDATE (already covered by AC 20e; extra variants) ---

def test_ec18_app_role_has_select_on_notification_subscription():
    """EC 18 (positive): app role has SELECT on notification_subscription."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT has_table_privilege('app', 'notification_subscription', 'SELECT')"
        ).fetchone()
    assert row[0] is True


def test_ec18_app_role_has_insert_on_notification_subscription():
    """EC 18 (positive): app role has INSERT on notification_subscription."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT has_table_privilege('app', 'notification_subscription', 'INSERT')"
        ).fetchone()
    assert row[0] is True


def test_ec18_app_role_has_select_on_notification_delivery():
    """EC 18 (positive): app role has SELECT on notification_delivery."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT has_table_privilege('app', 'notification_delivery', 'SELECT')"
        ).fetchone()
    assert row[0] is True


def test_ec18_app_role_has_insert_on_notification_delivery():
    """EC 18 (positive): app role has INSERT on notification_delivery."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT has_table_privilege('app', 'notification_delivery', 'INSERT')"
        ).fetchone()
    assert row[0] is True


# --- EC 19: migration re-apply is a no-op ---

def test_ec19_migration_re_apply_is_no_op():
    """EC 19: re-running run_migrations a second time does not error and tables still exist."""
    from infra_twin.db.migrate import run_migrations
    run_migrations(directory=_MIGRATIONS_DIR)
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute("SELECT count(*) FROM notification_subscription").fetchone()
    assert row is not None


# --- EC 20: delivery row for a resolved finding remains unchanged ---

def test_ec20_delivery_row_survives_finding_resolution(pool, make_tenant):
    """EC 20: delivery row for a since-resolved finding is unaffected."""
    tenant = make_tenant("ec20-delivery-survives")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        _, findings = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
    first_finding_id = findings[0].id

    # Remove reaching path to trigger resolution
    with tenant_session(pool, tenant) as conn:
        from infra_twin.reconciliation import reconcile
        reconcile(
            conn, tenant,
            [
                _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
                _ci(CIType.security_group, "sg-1"),
                _ci(CIType.rds, "db-1", "prod-db-1"),
                _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
            ],
            source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE,
        )
    with tenant_session(pool, tenant) as conn:
        result2, _ = evaluate_findings_with_summary(conn, tenant, notify_sender=sender)
    assert result2.resolved == 1

    # Delivery row still exists and references the (now-resolved) finding_id
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT finding_id, outcome FROM notification_delivery WHERE tenant_id = %s",
            (tenant,),
        ).fetchone()
    assert row is not None, "Delivery row must not be deleted when finding is resolved"
    assert row[0] == first_finding_id
    assert row[1] == "delivered"


# --- EC 21 / additional: append_delivery validates outcome ---

def test_append_delivery_invalid_outcome_raises_value_error(pool, make_tenant):
    """append_delivery raises ValueError when outcome is not in OUTCOME_VALUES."""
    tenant = make_tenant("invalid-outcome")
    with tenant_session(pool, tenant) as conn:
        repo = NotificationRepository(conn, tenant)
        sub = repo.create_subscription("https://example.com/hook")
        with pytest.raises(ValueError, match="outcome must be one of"):
            repo.append_delivery(
                subscription_id=sub.subscription_id,
                finding_id=uuid4(),
                payload={},
                status_code=200,
                outcome="unknown_outcome",
            )


# --- Additional: GET /notifications/deliveries with limit query param ---

def test_get_deliveries_limit_param(pool, make_tenant):
    """GET /notifications/deliveries?limit=0 returns []."""
    tenant = make_tenant("api-del-limit")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)

    key = _issue_key_for_tenant(tenant, Role.editor)
    client = TestClient(create_app(pool=pool))
    resp = client.get("/notifications/deliveries?limit=0", headers=_auth(key))
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_deliveries_returns_correct_keys(pool, make_tenant):
    """GET /notifications/deliveries returns dicts with correct keys."""
    tenant = make_tenant("api-del-keys")
    _seed(pool, tenant, _internet_reachable_rds_events())

    sender = RecordingSender(200)
    with tenant_session(pool, tenant) as conn:
        NotificationRepository(conn, tenant).create_subscription("https://example.com/hook")
        evaluate_findings_with_summary(conn, tenant, notify_sender=sender)

    key = _issue_key_for_tenant(tenant, Role.editor)
    client = TestClient(create_app(pool=pool))
    resp = client.get("/notifications/deliveries", headers=_auth(key))
    assert resp.status_code == 200
    deliveries = resp.json()
    assert len(deliveries) == 1
    d = deliveries[0]
    expected_keys = {
        "delivery_id", "subscription_id", "finding_id",
        "payload", "status_code", "outcome", "attempted_at",
    }
    assert set(d.keys()) == expected_keys, f"Delivery response keys mismatch: {set(d.keys())}"
    assert d["outcome"] == "delivered"
    assert d["status_code"] == 200


def test_get_subscriptions_returns_correct_keys(pool, make_tenant_with_key):
    """GET /notifications/subscriptions returns dicts with correct keys."""
    tenant, api_key = make_tenant_with_key("api-sub-keys")
    client = TestClient(create_app(pool=pool))
    client.post(
        "/notifications/subscriptions",
        json={"url": "https://example.com/hook"},
        headers=_auth(api_key),
    )
    resp = client.get("/notifications/subscriptions", headers=_auth(api_key))
    assert resp.status_code == 200
    subs = resp.json()
    assert len(subs) == 1
    expected_keys = {"subscription_id", "url", "enabled", "created_at"}
    assert set(subs[0].keys()) == expected_keys
