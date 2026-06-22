"""Outbound webhook and Slack notification dispatch for risk findings.

This module owns payload-building and dispatch logic for notifying enabled
subscriptions when the findings evaluator opens a new finding.

The HTTP sender is injected as a callable so no real network dependency enters
the static import graph of services/reconciliation.  Tests pass a recording
in-memory sender; production callers that want real HTTP pass their own sender.

The sleep seam (``Sleeper``) is similarly injected: tests inject a recording
callable; production callers use the default ``time.sleep``.

Module-boundary note: this module MUST NOT import ``infra_twin.query`` at the
top level (mirrors the constraint in findings.py).
"""

from __future__ import annotations

import time
from typing import Any, Callable

from infra_twin.core_model import CI, Finding
from infra_twin.db.notifications import NotificationDelivery, NotificationRepository

# Type alias for the injected HTTP sender seam.
# Returns the HTTP status code on a completed request; may raise on transport failure.
HttpSender = Callable[[str, dict[str, Any]], int]  # (url, json_payload) -> status_code

# Type alias for the injected sleep seam.
# Accepts delay in seconds; returns None.
Sleeper = Callable[[float], None]  # (delay_seconds) -> None

# Default maximum delivery attempts per subscription.
MAX_ATTEMPTS: int = 3

# Base backoff delay in seconds; actual delay = BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)).
BACKOFF_BASE_SECONDS: float = 1.0


def build_finding_payload(finding: Finding, subject_ci: CI | None) -> dict[str, Any]:
    """Deterministic JSON payload for a finding notification (raw webhook shape)."""
    return {
        "finding_id": str(finding.id),
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "subject": {
            "id": str(finding.subject_ci_id),
            "type": subject_ci.type.value if subject_ci is not None else None,
            "name": subject_ci.name if subject_ci is not None else None,
        },
        "evidence": finding.evidence,
    }


def format_payload(
    kind: str, finding: Finding, subject_ci: CI | None
) -> dict[str, Any]:
    """Return the notification payload shaped for ``kind``.

    ``kind == "webhook"`` returns the raw ``build_finding_payload`` shape.
    ``kind == "slack"`` returns a Slack-message-shaped dict with ``text`` and ``blocks``.
    Any other value raises ``ValueError``.
    """
    if kind == "webhook":
        return build_finding_payload(finding, subject_ci)
    if kind == "slack":
        ci_id = str(finding.subject_ci_id)
        ci_type = subject_ci.type.value if subject_ci is not None else "unknown"
        ci_name = subject_ci.name if subject_ci is not None else "unknown"
        summary = (
            f"[{finding.severity}] {finding.rule_id} on {ci_type} {ci_name} ({ci_id})"
        )
        block_text = (
            f"*Rule:* {finding.rule_id}\n"
            f"*Severity:* {finding.severity}\n"
            f"*CI ID:* {ci_id}\n"
            f"*CI Type:* {ci_type}\n"
            f"*CI Name:* {ci_name}"
        )
        return {
            "text": summary,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": block_text,
                    },
                }
            ],
        }
    raise ValueError(f"kind must be one of ('webhook', 'slack'), got {kind!r}")


def notify_finding_opened(
    repo: NotificationRepository,
    finding: Finding,
    subject_ci: CI | None,
    *,
    send: HttpSender,
    sleep: Sleeper = time.sleep,
    max_attempts: int = MAX_ATTEMPTS,
) -> list[NotificationDelivery]:
    """POST the payload to each enabled subscription for the tenant and record each attempt.

    Implements a bounded, synchronous retry loop with exponential backoff.
    Returns ALL delivery rows recorded across all subscriptions and all attempts,
    in the order they were written (one element per appended row).

    Per subscription:
    - The payload is computed once from ``sub.kind`` via ``format_payload``.
    - Attempts run from 1 to ``max_attempts`` inclusive.
    - 2xx response: append a ``delivered`` row and stop retrying.
    - Non-2xx response: append a ``failed`` row and continue.
    - Exception from ``send``: swallow it, append a ``failed`` row (status_code=None) and continue.
    - After each failed attempt that is not the last: sleep for the backoff delay.
    - If all attempts fail: append one terminal ``dead_letter`` row (attempt = max_attempts + 1).

    One subscription's failures never block the others; each subscription is
    fully wrapped so no exception escapes this function.
    """
    subs = repo.list_enabled_subscriptions()
    deliveries: list[NotificationDelivery] = []

    for sub in subs:
        try:
            payload = format_payload(sub.kind, finding, subject_ci)
            last_status_code: int | None = None
            succeeded = False

            for attempt in range(1, max_attempts + 1):
                try:
                    code = send(sub.url, payload)
                    if 200 <= code < 300:
                        delivery = repo.append_delivery(
                            subscription_id=sub.subscription_id,
                            finding_id=finding.id,
                            payload=payload,
                            status_code=code,
                            outcome="delivered",
                            attempt=attempt,
                        )
                        deliveries.append(delivery)
                        succeeded = True
                        break
                    else:
                        last_status_code = code
                        delivery = repo.append_delivery(
                            subscription_id=sub.subscription_id,
                            finding_id=finding.id,
                            payload=payload,
                            status_code=code,
                            outcome="failed",
                            attempt=attempt,
                        )
                        deliveries.append(delivery)
                except Exception:
                    last_status_code = None
                    delivery = repo.append_delivery(
                        subscription_id=sub.subscription_id,
                        finding_id=finding.id,
                        payload=payload,
                        status_code=None,
                        outcome="failed",
                        attempt=attempt,
                    )
                    deliveries.append(delivery)

                # Sleep before the next attempt, but not after the last attempt
                if not succeeded and attempt < max_attempts:
                    delay = BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                    sleep(delay)

            if not succeeded:
                # Terminal dead_letter row
                delivery = repo.append_delivery(
                    subscription_id=sub.subscription_id,
                    finding_id=finding.id,
                    payload=payload,
                    status_code=last_status_code,
                    outcome="dead_letter",
                    attempt=max_attempts + 1,
                )
                deliveries.append(delivery)

        except Exception:
            # One subscription's failure must never block others or escape this function
            pass

    return deliveries
