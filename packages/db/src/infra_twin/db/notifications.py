"""Notification subscription and delivery repository.

Operates on a connection already bound to a tenant by
:func:`infra_twin.db.session.tenant_session`; Row-Level Security scopes every
statement, so ``tenant_id`` is used only to stamp inserts, never as a query
filter — exactly like :class:`infra_twin.db.repositories.CIRepository`.

Both tables are append-only: no method issues UPDATE or DELETE.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

OUTCOME_VALUES: tuple[str, ...] = ("delivered", "failed", "dead_letter")
SUBSCRIPTION_KIND_VALUES: tuple[str, ...] = ("webhook", "slack")


@dataclass(frozen=True)
class NotificationSubscription:
    subscription_id: UUID
    tenant_id: UUID
    url: str
    enabled: bool
    kind: str
    created_at: datetime


@dataclass(frozen=True)
class NotificationDelivery:
    delivery_id: UUID
    tenant_id: UUID
    subscription_id: UUID
    finding_id: UUID
    payload: dict[str, Any]
    status_code: int | None
    outcome: str
    attempt: int
    attempted_at: datetime


class NotificationRepository:
    """Append-only store for notification subscriptions and deliveries, scoped to one tenant."""

    def __init__(self, conn: psycopg.Connection, tenant_id: UUID) -> None:
        self._conn = conn
        self._tenant_id = tenant_id

    def _cur(self):
        return self._conn.cursor(row_factory=dict_row)

    def create_subscription(
        self, url: str, *, enabled: bool = True, kind: str = "webhook"
    ) -> NotificationSubscription:
        """INSERT one subscription row; ``subscription_id`` and ``created_at`` come from DB DEFAULTs.

        Raises ``ValueError`` if ``kind`` is not in ``SUBSCRIPTION_KIND_VALUES``.
        The caller must not commit; the surrounding ``tenant_session`` owns the transaction.
        """
        if kind not in SUBSCRIPTION_KIND_VALUES:
            raise ValueError(f"kind must be one of {SUBSCRIPTION_KIND_VALUES!r}, got {kind!r}")
        with self._cur() as cur:
            row = cur.execute(
                "INSERT INTO notification_subscription (tenant_id, url, enabled, kind) "
                "VALUES (%s, %s, %s, %s) "
                "RETURNING subscription_id, tenant_id, url, enabled, kind, created_at",
                (self._tenant_id, url, enabled, kind),
            ).fetchone()
        return NotificationSubscription(
            subscription_id=row["subscription_id"],
            tenant_id=row["tenant_id"],
            url=row["url"],
            enabled=row["enabled"],
            kind=row["kind"],
            created_at=row["created_at"],
        )

    def list_subscriptions(self) -> list[NotificationSubscription]:
        """All subscriptions visible to this tenant, newest-first."""
        with self._cur() as cur:
            rows = cur.execute(
                "SELECT subscription_id, tenant_id, url, enabled, kind, created_at "
                "FROM notification_subscription "
                "ORDER BY created_at DESC, subscription_id DESC",
            ).fetchall()
        return [
            NotificationSubscription(
                subscription_id=r["subscription_id"],
                tenant_id=r["tenant_id"],
                url=r["url"],
                enabled=r["enabled"],
                kind=r["kind"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def list_enabled_subscriptions(self) -> list[NotificationSubscription]:
        """Enabled subscriptions visible to this tenant, newest-first."""
        with self._cur() as cur:
            rows = cur.execute(
                "SELECT subscription_id, tenant_id, url, enabled, kind, created_at "
                "FROM notification_subscription "
                "WHERE enabled IS TRUE "
                "ORDER BY created_at DESC, subscription_id DESC",
            ).fetchall()
        return [
            NotificationSubscription(
                subscription_id=r["subscription_id"],
                tenant_id=r["tenant_id"],
                url=r["url"],
                enabled=r["enabled"],
                kind=r["kind"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def append_delivery(
        self,
        *,
        subscription_id: UUID,
        finding_id: UUID,
        payload: dict[str, Any],
        status_code: int | None,
        outcome: str,
        attempt: int = 1,
    ) -> NotificationDelivery:
        """INSERT one delivery row; ``delivery_id`` and ``attempted_at`` come from DB DEFAULTs.

        Raises ``ValueError`` if ``outcome`` is not in ``OUTCOME_VALUES``.
        The caller must not commit; the surrounding ``tenant_session`` owns the transaction.
        """
        if outcome not in OUTCOME_VALUES:
            raise ValueError(f"outcome must be one of {OUTCOME_VALUES!r}, got {outcome!r}")
        with self._cur() as cur:
            row = cur.execute(
                "INSERT INTO notification_delivery "
                "(tenant_id, subscription_id, finding_id, payload, status_code, outcome, attempt) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) "
                "RETURNING delivery_id, tenant_id, subscription_id, finding_id, "
                "payload, status_code, outcome, attempt, attempted_at",
                (
                    self._tenant_id,
                    subscription_id,
                    finding_id,
                    Jsonb(payload),
                    status_code,
                    outcome,
                    attempt,
                ),
            ).fetchone()
        return NotificationDelivery(
            delivery_id=row["delivery_id"],
            tenant_id=row["tenant_id"],
            subscription_id=row["subscription_id"],
            finding_id=row["finding_id"],
            payload=dict(row["payload"]),
            status_code=row["status_code"],
            outcome=row["outcome"],
            attempt=row["attempt"],
            attempted_at=row["attempted_at"],
        )

    def list_deliveries(self, *, limit: int = 200) -> list[NotificationDelivery]:
        """All deliveries visible to this tenant, newest-first.

        Negative ``limit`` values are clamped to 0.
        """
        effective_limit = max(0, limit)
        with self._cur() as cur:
            rows = cur.execute(
                "SELECT delivery_id, tenant_id, subscription_id, finding_id, "
                "payload, status_code, outcome, attempt, attempted_at "
                "FROM notification_delivery "
                "ORDER BY attempted_at DESC, delivery_id DESC "
                "LIMIT %s",
                (effective_limit,),
            ).fetchall()
        return [
            NotificationDelivery(
                delivery_id=r["delivery_id"],
                tenant_id=r["tenant_id"],
                subscription_id=r["subscription_id"],
                finding_id=r["finding_id"],
                payload=dict(r["payload"]),
                status_code=r["status_code"],
                outcome=r["outcome"],
                attempt=r["attempt"],
                attempted_at=r["attempted_at"],
            )
            for r in rows
        ]
