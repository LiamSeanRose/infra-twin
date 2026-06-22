"""Kubernetes watch-event parser.

Maps a single Kubernetes WATCH event (the shape emitted by a ``kubectl get --watch``
stream or a client-go watch response) into a
:class:`infra_twin.connector_sdk.ConnectorDelta`.

This module is intentionally PURE — no I/O, no kubernetes library, no DB.
Deterministic for a given input.

Single-object scope: only edges derivable from this one object in isolation are emitted.
Cross-object correlation edges (cluster->namespace CONTAINS, service ROUTES_TO/EXPOSES
pod, pod MEMBER_OF workload via selector/ownerReference) are NOT emitted here because
they require information from other objects.  The reconciliation layer resolves endpoint
refs by (type, external_id); namespace and node refs are named by their metadata.name
(not uid) because a single watch event does not carry the parent object's uid.
"""

from __future__ import annotations

from datetime import datetime, timezone

from infra_twin.connector_sdk import CIRef, ConnectorDelta, DiscoveredCI, DiscoveredEdge, EdgeEndpointRef
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence

EVENT_SOURCE: str = "k8s-events"


class UnsupportedEventError(ValueError):
    """Raised when parse_watch_event receives a watch type or kind it does not map."""


def _parse_creation_timestamp(raw: str) -> datetime:
    """Parse an ISO-8601 creationTimestamp string to a tz-aware datetime.

    Kubernetes uses a trailing ``Z`` (e.g. ``"2024-01-15T10:30:00Z"``).
    Python 3.10 accepts the ``Z`` suffix via ``fromisoformat``; earlier releases
    do not, so we normalise it to ``+00:00`` first.
    """
    normalised = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(normalised)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid creationTimestamp: {raw!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _make_evidence(wtype: str, kind: str, uid: str, observed_at: datetime) -> list[Evidence]:
    return [
        Evidence(
            source=EVENT_SOURCE,
            observed_at=observed_at,
            detail=f"{wtype} {kind} (uid={uid})",
        )
    ]


# ---------------------------------------------------------------------------
# Kind -> CIType mapping
# ---------------------------------------------------------------------------

_KIND_TO_CI_TYPE: dict[str, CIType] = {
    "Namespace": CIType.k8s_namespace,
    "Node": CIType.k8s_node,
    "Deployment": CIType.k8s_workload,
    "Service": CIType.k8s_service,
    "Pod": CIType.k8s_pod,
}


# ---------------------------------------------------------------------------
# Helpers for building CIs and edges per kind
# ---------------------------------------------------------------------------


def _build_ci(kind: str, ci_type: CIType, uid: str, meta: dict, obj: dict) -> DiscoveredCI:
    name_val: str = meta.get("name") or uid
    ns: str = meta.get("namespace") or ""

    if kind == "Namespace":
        return DiscoveredCI(
            type=ci_type,
            external_id=uid,
            name=name_val,
            attributes={},
        )

    if kind == "Node":
        return DiscoveredCI(
            type=ci_type,
            external_id=uid,
            name=name_val,
            attributes={"node_name": name_val},
        )

    if kind == "Deployment":
        spec = obj.get("spec") or {}
        selector_obj = spec.get("selector") or {}
        match_labels: dict = selector_obj.get("matchLabels") or {}
        return DiscoveredCI(
            type=ci_type,
            external_id=uid,
            name=f"{ns}/{name_val}" if ns else name_val,
            attributes={
                "namespace": ns,
                "kind": "Deployment",
                "selector": match_labels,
            },
        )

    if kind == "Service":
        spec = obj.get("spec") or {}
        selector: dict = spec.get("selector") or {}
        return DiscoveredCI(
            type=ci_type,
            external_id=uid,
            name=f"{ns}/{name_val}" if ns else name_val,
            attributes={
                "namespace": ns,
                "selector": selector,
            },
        )

    if kind == "Pod":
        spec = obj.get("spec") or {}
        status = obj.get("status") or {}
        pod_labels: dict = meta.get("labels") or {}
        node_name_val: str | None = spec.get("nodeName")
        return DiscoveredCI(
            type=ci_type,
            external_id=uid,
            name=f"{ns}/{name_val}" if ns else name_val,
            attributes={
                "namespace": ns,
                "node_name": node_name_val,
                "phase": status.get("phase"),
                "labels": pod_labels,
            },
        )

    # Should not reach here given _KIND_TO_CI_TYPE guards
    raise UnsupportedEventError(f"unsupported kind: {kind}")


def _build_edges(
    wtype: str,
    kind: str,
    ci_type: CIType,
    uid: str,
    meta: dict,
    obj: dict,
    observed_at: datetime,
) -> list[DiscoveredEdge]:
    """Return any edges derivable from this single object."""
    edges: list[DiscoveredEdge] = []

    if kind in ("Deployment", "Service"):
        ns: str = meta.get("namespace") or ""
        if ns:
            evidence = _make_evidence(wtype, kind, uid, observed_at)
            edges.append(
                DiscoveredEdge(
                    type=EdgeType.CONTAINS,
                    from_ref=CIRef(type=CIType.k8s_namespace, external_id=ns),
                    to_ref=CIRef(type=ci_type, external_id=uid),
                    source=EdgeSource.declared,
                    confidence=1.0,
                    evidence=evidence,
                )
            )

    elif kind == "Pod":
        spec = obj.get("spec") or {}
        node_name_val: str | None = spec.get("nodeName")
        if node_name_val:
            evidence = _make_evidence(wtype, kind, uid, observed_at)
            edges.append(
                DiscoveredEdge(
                    type=EdgeType.RUNS_ON,
                    from_ref=CIRef(type=CIType.k8s_pod, external_id=uid),
                    to_ref=CIRef(type=CIType.k8s_node, external_id=node_name_val),
                    source=EdgeSource.declared,
                    confidence=1.0,
                    evidence=evidence,
                )
            )

    # Namespace and Node emit no edges in single-object scope.
    return edges


def _build_removed_edges(
    kind: str,
    ci_type: CIType,
    uid: str,
    meta: dict,
    obj: dict,
) -> list[EdgeEndpointRef]:
    """Return the EdgeEndpointRefs for edges the parser would have emitted on ADD."""
    removed: list[EdgeEndpointRef] = []

    if kind in ("Deployment", "Service"):
        ns: str = meta.get("namespace") or ""
        if ns:
            removed.append(
                EdgeEndpointRef(
                    type=EdgeType.CONTAINS,
                    from_ref=CIRef(type=CIType.k8s_namespace, external_id=ns),
                    to_ref=CIRef(type=ci_type, external_id=uid),
                )
            )

    elif kind == "Pod":
        spec = obj.get("spec") or {}
        node_name_val: str | None = spec.get("nodeName")
        if node_name_val:
            removed.append(
                EdgeEndpointRef(
                    type=EdgeType.RUNS_ON,
                    from_ref=CIRef(type=CIType.k8s_pod, external_id=uid),
                    to_ref=CIRef(type=CIType.k8s_node, external_id=node_name_val),
                )
            )

    return removed


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_watch_event(event: dict, *, observed_at: datetime | None = None) -> ConnectorDelta:
    """Map a single Kubernetes watch event to a :class:`ConnectorDelta`.

    Parameters
    ----------
    event:
        A single Kubernetes watch event with shape
        ``{"type": "ADDED"|"MODIFIED"|"DELETED", "object": {<k8s object>}}``.
        The object must carry ``apiVersion``, ``kind``, and ``metadata`` (with
        at minimum ``uid``).
    observed_at:
        Injected fallback timestamp used when the object carries no
        ``metadata.creationTimestamp``.  Must be tz-aware.  If both the object
        timestamp and this argument are absent, ``ValueError`` is raised.

    Returns
    -------
    ConnectorDelta
        The incremental change set derived from this watch event.

    Raises
    ------
    ValueError
        For missing or malformed required fields, or when no observed_at can
        be resolved.
    UnsupportedEventError
        When ``type`` is not ADDED/MODIFIED/DELETED or ``kind`` is not in the
        supported kind map.
    """
    wtype = event.get("type")
    if not wtype:
        raise ValueError("event missing type")

    obj = event.get("object")
    if not obj or not isinstance(obj, dict):
        raise ValueError("event missing object")

    kind = obj.get("kind")
    if not kind:
        raise ValueError("object missing kind")

    meta: dict = obj.get("metadata") or {}
    uid = meta.get("uid")
    if not uid:
        raise ValueError("object metadata missing uid")

    ci_type = _KIND_TO_CI_TYPE.get(kind)
    if ci_type is None:
        raise UnsupportedEventError(f"unsupported kind: {kind}")

    # Resolve observed_at: prefer the object's creationTimestamp, then the injected arg.
    raw_ts: str | None = meta.get("creationTimestamp")
    if raw_ts:
        resolved_at = _parse_creation_timestamp(raw_ts)
    elif observed_at is not None:
        resolved_at = observed_at
    else:
        raise ValueError("no observed_at available")

    if wtype not in {"ADDED", "MODIFIED", "DELETED"}:
        raise UnsupportedEventError(f"unsupported type: {wtype}")

    if wtype == "DELETED":
        removed_cis = [CIRef(type=ci_type, external_id=uid)]
        removed_edges = _build_removed_edges(kind, ci_type, uid, meta, obj)
        return ConnectorDelta(removed_cis=removed_cis, removed_edges=removed_edges)

    # ADDED or MODIFIED — identical treatment.
    ci = _build_ci(kind, ci_type, uid, meta, obj)
    edges = _build_edges(wtype, kind, ci_type, uid, meta, obj, resolved_at)
    return ConnectorDelta(upserts=[ci, *edges])
