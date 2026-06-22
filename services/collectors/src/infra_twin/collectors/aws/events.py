"""CloudTrail/EventBridge AWS event parser.

Maps a single recorded CloudTrail event record (the shape inside ``Records[i]``,
equivalently the ``detail`` of an EventBridge ``aws.ec2`` event) into a
:class:`infra_twin.connector_sdk.ConnectorDelta`.

This module is intentionally PURE — no I/O, no boto3, no DB.  Deterministic for
a given input.
"""

from __future__ import annotations

from datetime import datetime, timezone

from infra_twin.connector_sdk import (
    CIRef,
    ConnectorDelta,
    DiscoveredCI,
    DiscoveredEdge,
    EdgeEndpointRef,
)
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence

EVENT_SOURCE: str = "aws-events"


class UnsupportedEventError(ValueError):
    """Raised when ``parse_event`` receives an ``eventName`` it does not map."""


def _parse_event_time(raw: str) -> datetime:
    """Parse an ISO-8601 event time string to a tz-aware datetime.

    AWS CloudTrail uses a trailing ``Z`` (e.g. ``"2024-01-15T10:30:00Z"``).
    Python 3.10 accepts the ``Z`` suffix via ``fromisoformat``; earlier releases
    do not, so we normalise it to ``+00:00`` first.
    """
    normalised = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(normalised)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid eventTime: {raw!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _make_evidence(event_name: str, event_id: str, event_time: datetime) -> list[Evidence]:
    return [
        Evidence(
            source=EVENT_SOURCE,
            observed_at=event_time,
            detail=f"{event_name} (eventID={event_id})",
        )
    ]


def _get_required(record: dict, field: str) -> str:
    value = record.get(field)
    if not value:
        raise ValueError(f"record missing {field}")
    return value


# ---------------------------------------------------------------------------
# Per-event handlers
# ---------------------------------------------------------------------------


def _handle_run_instances(
    record: dict, event_name: str, event_id: str, event_time: datetime
) -> ConnectorDelta:
    response = record.get("responseElements") or {}
    instances_set = response.get("instancesSet") or {}
    items = instances_set.get("items") or []

    if not isinstance(items, list):
        items = [items]

    upserts: list = []

    for item in items:
        instance_id = item.get("instanceId")
        if not instance_id:
            raise ValueError("RunInstances item missing instanceId")

        instance_type = item.get("instanceType")
        subnet_id = item.get("subnetId")
        vpc_id = item.get("vpcId")

        # state comes from currentState.name (RunInstances) or instanceState.name (fallback).
        current_state = item.get("currentState") or item.get("instanceState") or {}
        state = current_state.get("name")

        upserts.append(
            DiscoveredCI(
                type=CIType.ec2_instance,
                external_id=instance_id,
                name=None,
                attributes={
                    "instance_type": instance_type,
                    "state": state,
                    "subnet": subnet_id,
                    "vpc": vpc_id,
                },
            )
        )

        evidence = _make_evidence(event_name, event_id, event_time)

        if subnet_id:
            upserts.append(
                DiscoveredEdge(
                    type=EdgeType.CONTAINS,
                    from_ref=CIRef(type=CIType.subnet, external_id=subnet_id),
                    to_ref=CIRef(type=CIType.ec2_instance, external_id=instance_id),
                    source=EdgeSource.declared,
                    confidence=1.0,
                    evidence=evidence,
                )
            )

        group_set = item.get("groupSet") or {}
        group_items = group_set.get("items") or []
        if not isinstance(group_items, list):
            group_items = [group_items]

        for group in group_items:
            group_id = group.get("groupId")
            if group_id:
                upserts.append(
                    DiscoveredEdge(
                        type=EdgeType.MEMBER_OF,
                        from_ref=CIRef(type=CIType.ec2_instance, external_id=instance_id),
                        to_ref=CIRef(type=CIType.security_group, external_id=group_id),
                        source=EdgeSource.declared,
                        confidence=1.0,
                        evidence=_make_evidence(event_name, event_id, event_time),
                    )
                )

    return ConnectorDelta(upserts=upserts)


def _handle_terminate_instances(
    record: dict, event_name: str, event_id: str, event_time: datetime
) -> ConnectorDelta:
    # Instance ids may appear in requestParameters or responseElements.
    removed_cis: list[CIRef] = []
    seen: set[str] = set()

    for section_key in ("requestParameters", "responseElements"):
        section = record.get(section_key) or {}
        instances_set = section.get("instancesSet") or {}
        items = instances_set.get("items") or []
        if not isinstance(items, list):
            items = [items]
        for item in items:
            instance_id = item.get("instanceId")
            if instance_id and instance_id not in seen:
                seen.add(instance_id)
                removed_cis.append(CIRef(type=CIType.ec2_instance, external_id=instance_id))

    return ConnectorDelta(removed_cis=removed_cis)


def _handle_create_security_group(
    record: dict, event_name: str, event_id: str, event_time: datetime
) -> ConnectorDelta:
    response = record.get("responseElements") or {}
    group_id = response.get("groupId")
    if not group_id:
        raise ValueError("CreateSecurityGroup missing groupId")

    request = record.get("requestParameters") or {}
    group_name = request.get("groupName")
    group_description = request.get("groupDescription")
    vpc_id = request.get("vpcId")

    upserts: list = [
        DiscoveredCI(
            type=CIType.security_group,
            external_id=group_id,
            name=group_name,
            attributes={
                "description": group_description,
                "vpc": vpc_id,
            },
        )
    ]

    if vpc_id:
        upserts.append(
            DiscoveredEdge(
                type=EdgeType.CONTAINS,
                from_ref=CIRef(type=CIType.vpc, external_id=vpc_id),
                to_ref=CIRef(type=CIType.security_group, external_id=group_id),
                source=EdgeSource.declared,
                confidence=1.0,
                evidence=_make_evidence(event_name, event_id, event_time),
            )
        )

    return ConnectorDelta(upserts=upserts)


def _extract_sg_source_pairs(
    record: dict, target_group_field: str
) -> tuple[str, list[tuple[str, str]]]:
    """Return (target_group_id, [(source_group_id, target_group_id), ...]) for SG-sourced rules.

    Raises ValueError when the target groupId is missing.
    Skips permission entries that have no source group items (CIDR-only; out of scope).
    Skips individual group entries missing a groupId.
    De-duplicates (source, target) pairs.
    """
    request = record.get("requestParameters") or {}
    target_group_id = request.get(target_group_field)
    if not target_group_id:
        raise ValueError(
            f"AuthorizeSecurityGroupIngress/RevokeSecurityGroupIngress missing {target_group_field}"
        )

    ip_permissions = request.get("ipPermissions") or {}
    permission_items = ip_permissions.get("items") or []
    if not isinstance(permission_items, list):
        permission_items = [permission_items]

    seen: set[tuple[str, str]] = set()
    pairs: list[tuple[str, str]] = []

    for permission in permission_items:
        groups = permission.get("groups") or {}
        group_items = groups.get("items") or []
        if not isinstance(group_items, list):
            group_items = [group_items]

        for group in group_items:
            source_group_id = group.get("groupId")
            if not source_group_id:
                continue
            pair = (source_group_id, target_group_id)
            if pair not in seen:
                seen.add(pair)
                pairs.append(pair)

    return target_group_id, pairs


def _handle_authorize_sg_ingress(
    record: dict, event_name: str, event_id: str, event_time: datetime
) -> ConnectorDelta:
    _target_group_id, pairs = _extract_sg_source_pairs(record, "groupId")

    if not pairs:
        return ConnectorDelta()

    evidence = _make_evidence(event_name, event_id, event_time)
    upserts: list = [
        DiscoveredEdge(
            type=EdgeType.CONNECTS_TO,
            from_ref=CIRef(type=CIType.security_group, external_id=src),
            to_ref=CIRef(type=CIType.security_group, external_id=tgt),
            source=EdgeSource.declared,
            confidence=1.0,
            evidence=_make_evidence(event_name, event_id, event_time),
        )
        for src, tgt in pairs
    ]
    return ConnectorDelta(upserts=upserts)


def _handle_revoke_sg_ingress(
    record: dict, event_name: str, event_id: str, event_time: datetime
) -> ConnectorDelta:
    _target_group_id, pairs = _extract_sg_source_pairs(record, "groupId")

    if not pairs:
        return ConnectorDelta()

    removed_edges: list[EdgeEndpointRef] = [
        EdgeEndpointRef(
            type=EdgeType.CONNECTS_TO,
            from_ref=CIRef(type=CIType.security_group, external_id=src),
            to_ref=CIRef(type=CIType.security_group, external_id=tgt),
        )
        for src, tgt in pairs
    ]
    return ConnectorDelta(removed_edges=removed_edges)


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_HANDLERS = {
    "RunInstances": _handle_run_instances,
    "TerminateInstances": _handle_terminate_instances,
    "CreateSecurityGroup": _handle_create_security_group,
    "AuthorizeSecurityGroupIngress": _handle_authorize_sg_ingress,
    "RevokeSecurityGroupIngress": _handle_revoke_sg_ingress,
}


def parse_event(record: dict) -> ConnectorDelta:
    """Map a single CloudTrail event record to a :class:`ConnectorDelta`.

    Parameters
    ----------
    record:
        A single CloudTrail event record (``Records[i]`` shape, or the ``detail``
        field from an EventBridge ``aws.ec2`` event).  Must contain at minimum
        ``eventName``, ``eventID``, ``eventTime``, ``eventSource``, ``awsRegion``,
        ``requestParameters``, and ``responseElements``.

    Returns
    -------
    ConnectorDelta
        The incremental change set derived from this event.

    Raises
    ------
    ValueError
        For missing or malformed required fields.
    UnsupportedEventError
        When ``eventName`` is not one of the mapped event names.
    """
    event_name = record.get("eventName")
    if not event_name:
        raise ValueError("record missing eventName")

    event_id = record.get("eventID")
    if not event_id:
        raise ValueError("record missing eventID")

    raw_time = record.get("eventTime")
    if not raw_time:
        raise ValueError("record missing eventTime")

    event_time = _parse_event_time(raw_time)

    handler = _HANDLERS.get(event_name)
    if handler is None:
        raise UnsupportedEventError(f"unsupported eventName: {event_name}")

    return handler(record, event_name, event_id, event_time)
