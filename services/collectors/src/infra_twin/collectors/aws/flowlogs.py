"""Pure VPC Flow Log parser.

Converts pre-parsed VPC Flow Log records (dicts) into a :class:`ConnectorDelta` containing
inferred CONNECTS_TO edges.  No I/O, no boto3, no database access — deterministic for a
given input.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Iterable

from infra_twin.connector_sdk import CIRef, ConnectorDelta, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence

FLOWLOG_SOURCE: str = "aws-flowlogs"
DEFAULT_FLOW_CONFIDENCE: float = 0.6


class FlowLogParseError(ValueError):
    """Missing required field or malformed value on a flow record."""


def parse_flow_logs(
    records: Iterable[dict],
    *,
    resolve: Callable[[str], "CIRef | None"],
) -> ConnectorDelta:
    """Parse an iterable of VPC Flow Log record dicts into a ConnectorDelta.

    Only ACCEPT flows whose both endpoints resolve to known CIs produce edges.
    Duplicate (src, dst) pairs are collapsed into a single edge. Direction matters:
    A->B and B->A are distinct edges.

    Raises :class:`FlowLogParseError` (a :class:`ValueError` subclass) on any record
    that has a missing/empty required field or a non-coercible numeric value.  The error
    is raised before any edge is appended to the output, but after iteration has reached
    that record — callers that need atomicity should catch the error and discard the
    partial result.
    """
    # Ordered dict preserves first-seen order of distinct edge keys.
    seen: dict[tuple, DiscoveredEdge] = {}

    for record in records:
        # Step 1: action is required; missing or empty is an error.
        action = record.get("action")
        if action is None or action == "":
            raise FlowLogParseError(
                f"flow record missing required field 'action': {record!r}"
            )

        # Step 2: non-ACCEPT actions are silently skipped.
        if action != "ACCEPT":
            continue

        # Step 3: srcaddr and dstaddr required.
        srcaddr = record.get("srcaddr")
        dstaddr = record.get("dstaddr")
        if not srcaddr:
            raise FlowLogParseError(
                f"flow record missing required field 'srcaddr': {record!r}"
            )
        if not dstaddr:
            raise FlowLogParseError(
                f"flow record missing required field 'dstaddr': {record!r}"
            )

        # Step 4: resolve endpoints; skip if either is unknown.
        src_ref = resolve(srcaddr)
        dst_ref = resolve(dstaddr)
        if src_ref is None or dst_ref is None:
            continue

        # Step 5: validate and coerce dstport, protocol, start, end.
        dstport = record.get("dstport")
        protocol = record.get("protocol")
        start = record.get("start")
        end = record.get("end")

        for field_name, value in (
            ("dstport", dstport),
            ("protocol", protocol),
            ("start", start),
            ("end", end),
        ):
            if value is None or value == "":
                raise FlowLogParseError(
                    f"flow record missing required field {field_name!r}: {record!r}"
                )
            try:
                int(value)
            except (TypeError, ValueError):
                raise FlowLogParseError(
                    f"flow record field {field_name!r} is not coercible to int"
                    f" (got {value!r}): {record!r}"
                )

        end_int = int(end)
        start_int = int(start)
        dstport_int = int(dstport)
        protocol_int = int(protocol)

        # Step 6: dedup key; direction-preserving.
        key = (
            src_ref.type,
            src_ref.external_id,
            dst_ref.type,
            dst_ref.external_id,
        )

        if key in seen:
            # Step 8 (repeated key): collapse / skip — one edge per ordered pair.
            continue

        # Step 7: build Evidence.
        end_dt = datetime.fromtimestamp(end_int, tz=timezone.utc)
        start_dt = datetime.fromtimestamp(start_int, tz=timezone.utc)
        detail = (
            f"dstport={dstport_int} protocol={protocol_int}"
            f" window={start_dt.isoformat()}/{end_dt.isoformat()}"
        )
        evidence = [Evidence(source=FLOWLOG_SOURCE, observed_at=end_dt, detail=detail)]

        # Step 8 (first sight): create edge.
        edge = DiscoveredEdge(
            type=EdgeType.CONNECTS_TO,
            from_ref=src_ref,
            to_ref=dst_ref,
            source=EdgeSource.inferred,
            confidence=DEFAULT_FLOW_CONFIDENCE,
            evidence=evidence,
        )
        seen[key] = edge

    # Step 10: return delta; removed_cis and removed_edges always empty.
    return ConnectorDelta(upserts=list(seen.values()))
