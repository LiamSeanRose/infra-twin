"""Change feed derived from bitemporal validity intervals.

Within a window, each version row opened in the window is either a ``created`` (no prior
version) or an ``updated`` (a prior version closed exactly when this one opened). Each version
closed in the window with no successor is a ``removed``. This avoids double-counting: an
update is one event (the new row), not a close plus an open.

Reads are RLS-scoped to the session tenant.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg


@dataclass
class ChangeEvent:
    entity: str  # 'ci' | 'edge'
    kind: str  # 'created' | 'updated' | 'removed'
    at: datetime
    id: UUID
    type: str
    name: str | None = None
    from_id: UUID | None = None
    to_id: UUID | None = None


_CI_SQL = """
SELECT CASE WHEN EXISTS (SELECT 1 FROM cis p WHERE p.id = c.id AND p.valid_to = c.valid_from)
            THEN 'updated' ELSE 'created' END AS kind,
       c.id, c.type, c.name, c.valid_from AS at
FROM cis c
WHERE c.valid_from >= %(since)s AND c.valid_from < %(until)s
UNION ALL
SELECT 'removed', c.id, c.type, c.name, c.valid_to AS at
FROM cis c
WHERE c.valid_to >= %(since)s AND c.valid_to < %(until)s
  AND NOT EXISTS (SELECT 1 FROM cis s WHERE s.id = c.id AND s.valid_from = c.valid_to)
"""

_EDGE_SQL = """
SELECT CASE WHEN EXISTS (SELECT 1 FROM edges p WHERE p.id = e.id AND p.valid_to = e.valid_from)
            THEN 'updated' ELSE 'created' END AS kind,
       e.id, e.type, e.from_id, e.to_id, e.valid_from AS at
FROM edges e
WHERE e.valid_from >= %(since)s AND e.valid_from < %(until)s
UNION ALL
SELECT 'removed', e.id, e.type, e.from_id, e.to_id, e.valid_to AS at
FROM edges e
WHERE e.valid_to >= %(since)s AND e.valid_to < %(until)s
  AND NOT EXISTS (SELECT 1 FROM edges s WHERE s.id = e.id AND s.valid_from = e.valid_to)
"""


def change_feed(
    conn: psycopg.Connection,
    tenant_id: UUID,
    *,
    days: int = 7,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[ChangeEvent]:
    until = until or datetime.now(timezone.utc)
    since = since or (until - timedelta(days=days))
    params = {"since": since, "until": until}

    events: list[ChangeEvent] = []
    for kind, cid, ctype, name, at in conn.execute(_CI_SQL, params).fetchall():
        events.append(ChangeEvent("ci", kind, at, cid, ctype, name=name))
    for kind, eid, etype, from_id, to_id, at in conn.execute(_EDGE_SQL, params).fetchall():
        events.append(
            ChangeEvent("edge", kind, at, eid, etype, from_id=from_id, to_id=to_id)
        )

    events.sort(key=lambda e: e.at, reverse=True)
    return events
