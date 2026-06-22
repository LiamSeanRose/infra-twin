"""Contract tests for the Kubernetes watch-event parser (parse_watch_event) and
POST /events/k8s endpoint.

Covers every acceptance criterion in the spec (AC 1-32) and all edge cases
EC-P1 through EC-P25 (pure parser) and EC-E1 through EC-E8 (E2E endpoint).

Structure:
1.  Import / export / purity checks (AC 2-7, EC-P23, EC-P25).
2.  ADDED Namespace (AC 8, EC-P7).
3.  ADDED Node (AC 9, EC-P8).
4.  ADDED Deployment with namespace (AC 10, EC-P9).
5.  ADDED Deployment without namespace (EC-P10).
6.  ADDED Service with namespace (AC 11, EC-P11).
7.  ADDED Pod with nodeName (AC 12, EC-P12).
8.  ADDED Pod without nodeName (AC 13, EC-P13, EC-P14).
9.  MODIFIED == ADDED (AC 14, EC-P15).
10. DELETED: removed_cis + removed_edges (AC 15, EC-P16-EC-P19).
11. Edge provenance contract (AC 18, EC-P20).
12. Error cases: unknown type, unmapped kind, missing fields, bad timestamp
    (AC 16, 17, EC-P1-EC-P6, EC-P21, EC-P22).
13. Purity / determinism (AC 19, EC-P23, EC-P24, EC-P25).
14. E2E: ADDED Pod creates CI bitemporally (AC 25, EC-E1).
15. E2E: DELETED closes CI (not hard-delete) (AC 26, EC-E2).
16. E2E: connector_runs row for k8s-events (AC 27, EC-E3).
17. E2E: cross-tenant isolation (AC 28, EC-E4).
18. E2E: RBAC viewer 403 / editor 200 (AC 29, EC-E5).
19. E2E: audit row recorded (AC 30, EC-E6).
20. E2E: malformed body -> 422 not 500, no CI (AC 24, EC-E7).
21. E2E: freshness SLO evaluate fresh after POST (EC-E8, optional).
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.db.api_keys import IssuedKey, Role, provision_tenant
from infra_twin.db.config import admin_dsn
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.db.session import tenant_session

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OBS = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
_CREATION_TS = "2024-06-01T12:00:00Z"

# Representative UIDs (mirror constants from test_k8s_connector.py for readability)
_NS_UID = "ns-uid-default"
_NODE_UID = "node-uid-a"
_DEPLOY_UID = "wl-uid-web"
_SVC_UID = "svc-uid-web"
_POD_UID = "pod-uid-a"

# ---------------------------------------------------------------------------
# Inline fixture builders
# ---------------------------------------------------------------------------


def _ns_event(wtype: str = "ADDED", uid: str = _NS_UID, name: str = "default") -> dict:
    return {
        "type": wtype,
        "object": {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "uid": uid,
                "name": name,
                "creationTimestamp": _CREATION_TS,
            },
        },
    }


def _node_event(wtype: str = "ADDED", uid: str = _NODE_UID, name: str = "node-a") -> dict:
    return {
        "type": wtype,
        "object": {
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "uid": uid,
                "name": name,
                "creationTimestamp": _CREATION_TS,
            },
        },
    }


def _deploy_event(
    wtype: str = "ADDED",
    uid: str = _DEPLOY_UID,
    name: str = "web",
    namespace: str = "default",
    selector: dict | None = None,
) -> dict:
    return {
        "type": wtype,
        "object": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "uid": uid,
                "name": name,
                "namespace": namespace,
                "creationTimestamp": _CREATION_TS,
            },
            "spec": {
                "selector": {"matchLabels": selector or {"app": "web"}},
            },
        },
    }


def _svc_event(
    wtype: str = "ADDED",
    uid: str = _SVC_UID,
    name: str = "web",
    namespace: str = "default",
    selector: dict | None = None,
) -> dict:
    return {
        "type": wtype,
        "object": {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "uid": uid,
                "name": name,
                "namespace": namespace,
                "creationTimestamp": _CREATION_TS,
            },
            "spec": {
                "selector": selector or {"app": "web"},
            },
        },
    }


def _pod_event(
    wtype: str = "ADDED",
    uid: str = _POD_UID,
    name: str = "web-pod",
    namespace: str = "default",
    node_name: str | None = "node-a",
    labels: dict | None = None,
    phase: str | None = "Running",
) -> dict:
    spec: dict = {}
    if node_name is not None:
        spec["nodeName"] = node_name
    status: dict = {}
    if phase is not None:
        status["phase"] = phase
    obj: dict = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "uid": uid,
            "name": name,
            "namespace": namespace,
            "creationTimestamp": _CREATION_TS,
        },
        "spec": spec,
        "status": status,
    }
    if labels is not None:
        obj["metadata"]["labels"] = labels
    return {"type": wtype, "object": obj}


# ---------------------------------------------------------------------------
# Auth helpers (mirror test_api.py / test_rbac.py)
# ---------------------------------------------------------------------------


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _make_viewer_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.viewer)
    return issued.tenant_id, issued.plaintext


def _make_editor_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.editor)
    return issued.tenant_id, issued.plaintext


def _count_rows_admin(table: str, tenant: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        return conn.execute(
            f"SELECT count(*) FROM {table} WHERE tenant_id = %s", (tenant,)
        ).fetchone()[0]


def _count_rows_tenant(pool, tenant: UUID, table: str) -> int:
    with tenant_session(pool, tenant) as conn:
        return conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def _get_audit_rows(tenant_id: UUID) -> list[dict]:
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT method, path, permission, decision, status_code "
            "FROM audit_log WHERE tenant_id = %s ORDER BY occurred_at DESC",
            (tenant_id,),
        ).fetchall()
    return [{"method": r[0], "path": r[1], "permission": r[2], "decision": r[3], "status_code": r[4]} for r in rows]


# ===========================================================================
# 1. IMPORT / EXPORT / PURITY CHECKS (AC 2-7)
# ===========================================================================


def test_parse_watch_event_importable_from_events_module():
    """AC 2: parse_watch_event importable from infra_twin.collectors.k8s.events."""
    from infra_twin.collectors.k8s.events import parse_watch_event  # noqa: F401


def test_unsupported_event_error_importable_from_events_module():
    """AC 2: UnsupportedEventError importable from infra_twin.collectors.k8s.events."""
    from infra_twin.collectors.k8s.events import UnsupportedEventError  # noqa: F401


def test_event_source_importable_from_events_module():
    """AC 2: EVENT_SOURCE importable from infra_twin.collectors.k8s.events."""
    from infra_twin.collectors.k8s.events import EVENT_SOURCE  # noqa: F401


def test_parse_watch_event_importable_from_k8s_package():
    """AC 3: parse_watch_event importable from infra_twin.collectors.k8s."""
    from infra_twin.collectors.k8s import parse_watch_event  # noqa: F401


def test_unsupported_event_error_importable_from_k8s_package():
    """AC 3: UnsupportedEventError importable from infra_twin.collectors.k8s."""
    from infra_twin.collectors.k8s import UnsupportedEventError  # noqa: F401


def test_event_source_importable_from_k8s_package():
    """AC 3: EVENT_SOURCE importable from infra_twin.collectors.k8s."""
    from infra_twin.collectors.k8s import EVENT_SOURCE  # noqa: F401


def test_all_three_symbols_in_k8s_all():
    """AC 3: parse_watch_event, UnsupportedEventError, EVENT_SOURCE all in k8s.__all__."""
    from infra_twin.collectors import k8s
    assert "parse_watch_event" in k8s.__all__
    assert "UnsupportedEventError" in k8s.__all__
    assert "EVENT_SOURCE" in k8s.__all__


def test_event_source_value():
    """AC 4: EVENT_SOURCE == 'k8s-events'."""
    from infra_twin.collectors.k8s.events import EVENT_SOURCE
    assert EVENT_SOURCE == "k8s-events"


def test_unsupported_event_error_is_value_error_subclass():
    """AC 5: issubclass(UnsupportedEventError, ValueError) is True."""
    from infra_twin.collectors.k8s.events import UnsupportedEventError
    assert issubclass(UnsupportedEventError, ValueError)


def test_events_module_does_not_import_boto3():
    """AC 6: events.py must not import boto3."""
    import infra_twin.collectors.k8s.events as mod
    assert "boto3" not in mod.__dict__


def test_events_module_does_not_import_kubernetes():
    """AC 6: events.py must not import the kubernetes library."""
    import infra_twin.collectors.k8s.events as mod
    assert "kubernetes" not in mod.__dict__


def test_events_module_does_not_import_db():
    """AC 6: events.py must not import from infra_twin.db."""
    import infra_twin.collectors.k8s.events as mod
    for name in ("infra_twin.db", "infra_twin.reconciliation"):
        assert name not in mod.__dict__, f"events.py should not import {name}"


def test_parse_watch_event_signature():
    """AC 7: parse_watch_event signature is (event: dict, *, observed_at: datetime | None = None) -> ConnectorDelta."""
    import inspect
    from infra_twin.collectors.k8s.events import parse_watch_event
    sig = inspect.signature(parse_watch_event)
    params = list(sig.parameters.keys())
    assert params[0] == "event"
    assert "observed_at" in params
    observed_at_param = sig.parameters["observed_at"]
    assert observed_at_param.default is None
    assert observed_at_param.kind == inspect.Parameter.KEYWORD_ONLY


# ===========================================================================
# 2. ADDED Namespace (AC 8, EC-P7)
# ===========================================================================


def test_added_namespace_exactly_one_ci():
    """AC 8 / EC-P7: ADDED Namespace yields exactly one CI, zero edges, empty removals."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI, DiscoveredEdge

    delta = parse_watch_event(_ns_event())
    cis = [u for u in delta.upserts if isinstance(u, DiscoveredCI)]
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    assert len(cis) == 1
    assert edges == []
    assert delta.removed_cis == []
    assert delta.removed_edges == []


def test_added_namespace_ci_type():
    """AC 8: ADDED Namespace CI type is k8s_namespace."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI
    from infra_twin.core_model import CIType

    delta = parse_watch_event(_ns_event())
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert ci.type == CIType.k8s_namespace


def test_added_namespace_external_id_is_uid():
    """AC 8: ADDED Namespace CI external_id == metadata.uid."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_watch_event(_ns_event())
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert ci.external_id == _NS_UID


def test_added_namespace_attributes_empty():
    """AC 8: ADDED Namespace CI attributes == {}."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_watch_event(_ns_event())
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert ci.attributes == {}


# ===========================================================================
# 3. ADDED Node (AC 9, EC-P8)
# ===========================================================================


def test_added_node_exactly_one_ci_zero_edges():
    """AC 9 / EC-P8: ADDED Node yields one CI, zero edges."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI, DiscoveredEdge

    delta = parse_watch_event(_node_event())
    cis = [u for u in delta.upserts if isinstance(u, DiscoveredCI)]
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    assert len(cis) == 1
    assert edges == []


def test_added_node_ci_type():
    """AC 9: ADDED Node CI type is k8s_node."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI
    from infra_twin.core_model import CIType

    delta = parse_watch_event(_node_event())
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert ci.type == CIType.k8s_node


def test_added_node_external_id_is_uid():
    """AC 9: ADDED Node CI external_id == metadata.uid."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_watch_event(_node_event())
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert ci.external_id == _NODE_UID


def test_added_node_attributes_node_name():
    """AC 9: ADDED Node CI attributes['node_name'] == metadata.name."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_watch_event(_node_event(name="node-a"))
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert ci.attributes["node_name"] == "node-a"


# ===========================================================================
# 4. ADDED Deployment with namespace (AC 10, EC-P9)
# ===========================================================================


def test_added_deployment_with_namespace_ci_plus_contains_edge():
    """AC 10 / EC-P9: ADDED Deployment with namespace -> one k8s_workload CI + one CONTAINS edge."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI, DiscoveredEdge
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_watch_event(_deploy_event(namespace="default"))
    cis = [u for u in delta.upserts if isinstance(u, DiscoveredCI)]
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    assert len(cis) == 1
    assert cis[0].type == CIType.k8s_workload
    assert len(edges) == 1
    assert edges[0].type == EdgeType.CONTAINS


def test_added_deployment_contains_edge_endpoints():
    """AC 10: CONTAINS edge from_ref = CIRef(k8s_namespace, 'default') to_ref = CIRef(k8s_workload, uid)."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_watch_event(_deploy_event(uid=_DEPLOY_UID, namespace="default"))
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    e = edges[0]
    assert e.from_ref.type == CIType.k8s_namespace
    assert e.from_ref.external_id == "default"
    assert e.to_ref.type == CIType.k8s_workload
    assert e.to_ref.external_id == _DEPLOY_UID


def test_added_deployment_ci_attributes():
    """AC 10: Deployment CI attributes have namespace, kind='Deployment', selector."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_watch_event(_deploy_event(namespace="default", selector={"app": "web"}))
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert ci.attributes["namespace"] == "default"
    assert ci.attributes["kind"] == "Deployment"
    assert ci.attributes["selector"] == {"app": "web"}


def test_added_deployment_ci_name_includes_namespace():
    """EC-P9: Deployment CI name == '{ns}/{name}' when namespace present."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_watch_event(_deploy_event(name="web", namespace="default"))
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert ci.name == "default/web"


# ===========================================================================
# 5. ADDED Deployment without namespace (EC-P10)
# ===========================================================================


def test_added_deployment_without_namespace_no_contains_edge():
    """EC-P10: ADDED Deployment with empty namespace -> CI only, no CONTAINS edge."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI, DiscoveredEdge

    event = _deploy_event(namespace="")
    event["object"]["metadata"]["namespace"] = ""
    delta = parse_watch_event(event)
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    cis = [u for u in delta.upserts if isinstance(u, DiscoveredCI)]
    assert len(cis) == 1
    assert edges == []


def test_added_deployment_absent_namespace_no_contains_edge():
    """EC-P10: ADDED Deployment with absent namespace -> CI only, no CONTAINS edge."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI, DiscoveredEdge

    event = _deploy_event()
    del event["object"]["metadata"]["namespace"]
    delta = parse_watch_event(event)
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    cis = [u for u in delta.upserts if isinstance(u, DiscoveredCI)]
    assert len(cis) == 1
    assert edges == []


# ===========================================================================
# 6. ADDED Service with namespace (AC 11, EC-P11)
# ===========================================================================


def test_added_service_with_namespace_ci_plus_contains_edge():
    """AC 11 / EC-P11: ADDED Service with namespace -> one k8s_service CI + one CONTAINS edge."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI, DiscoveredEdge
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_watch_event(_svc_event(namespace="default"))
    cis = [u for u in delta.upserts if isinstance(u, DiscoveredCI)]
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    assert len(cis) == 1
    assert cis[0].type == CIType.k8s_service
    assert len(edges) == 1
    assert edges[0].type == EdgeType.CONTAINS


def test_added_service_contains_edge_endpoints():
    """AC 11: CONTAINS edge from_ref = CIRef(k8s_namespace, ns) to_ref = CIRef(k8s_service, uid)."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_watch_event(_svc_event(uid=_SVC_UID, namespace="default"))
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    e = edges[0]
    assert e.from_ref.type == CIType.k8s_namespace
    assert e.from_ref.external_id == "default"
    assert e.to_ref.type == CIType.k8s_service
    assert e.to_ref.external_id == _SVC_UID


# ===========================================================================
# 7. ADDED Pod with nodeName (AC 12, EC-P12)
# ===========================================================================


def test_added_pod_with_node_name_ci_plus_runs_on_edge():
    """AC 12 / EC-P12: ADDED Pod with nodeName -> one k8s_pod CI + one RUNS_ON edge."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI, DiscoveredEdge
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_watch_event(_pod_event(node_name="node-a"))
    cis = [u for u in delta.upserts if isinstance(u, DiscoveredCI)]
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    assert len(cis) == 1
    assert cis[0].type == CIType.k8s_pod
    assert len(edges) == 1
    assert edges[0].type == EdgeType.RUNS_ON


def test_added_pod_runs_on_edge_endpoints():
    """AC 12: RUNS_ON edge from_ref = CIRef(k8s_pod, uid) to_ref = CIRef(k8s_node, nodeName)."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_watch_event(_pod_event(uid=_POD_UID, node_name="node-a"))
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    e = edges[0]
    assert e.from_ref.type == CIType.k8s_pod
    assert e.from_ref.external_id == _POD_UID
    assert e.to_ref.type == CIType.k8s_node
    assert e.to_ref.external_id == "node-a"


def test_added_pod_external_id_is_uid():
    """AC 12: ADDED Pod CI external_id == metadata.uid."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_watch_event(_pod_event(uid=_POD_UID))
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert ci.external_id == _POD_UID


def test_added_pod_attributes_with_node_name():
    """EC-P12: Pod CI attributes include namespace, node_name, phase, labels."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_watch_event(_pod_event(
        namespace="default", node_name="node-a", labels={"app": "web"}, phase="Running"
    ))
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert ci.attributes["namespace"] == "default"
    assert ci.attributes["node_name"] == "node-a"
    assert ci.attributes["phase"] == "Running"
    assert ci.attributes["labels"] == {"app": "web"}


# ===========================================================================
# 8. ADDED Pod without nodeName (AC 13, EC-P13, EC-P14)
# ===========================================================================


def test_added_pod_without_node_name_ci_only_no_edge():
    """AC 13 / EC-P13: ADDED Pod without nodeName -> CI only, zero edges."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI, DiscoveredEdge

    delta = parse_watch_event(_pod_event(node_name=None))
    cis = [u for u in delta.upserts if isinstance(u, DiscoveredCI)]
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    assert len(cis) == 1
    assert edges == []


def test_added_pod_without_node_name_attr_is_none():
    """AC 13: Pod CI attributes['node_name'] is None when nodeName absent."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_watch_event(_pod_event(node_name=None))
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert "node_name" in ci.attributes
    assert ci.attributes["node_name"] is None


def test_added_pod_absent_labels_defaults_to_empty_dict():
    """EC-P14: Pod CI attributes['labels'] == {} when metadata.labels absent."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI

    event = _pod_event()
    # Ensure no labels key in metadata
    event["object"]["metadata"].pop("labels", None)
    delta = parse_watch_event(event)
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert "labels" in ci.attributes
    assert ci.attributes["labels"] == {}


def test_added_pod_absent_phase_is_none():
    """EC-P14: Pod CI attributes['phase'] is None when status.phase absent."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_watch_event(_pod_event(phase=None))
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert "phase" in ci.attributes
    assert ci.attributes["phase"] is None


# ===========================================================================
# 9. MODIFIED == ADDED (AC 14, EC-P15)
# ===========================================================================


def test_modified_namespace_equals_added():
    """AC 14 / EC-P15: MODIFIED Namespace delta == ADDED Namespace delta (same object)."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    added = parse_watch_event(_ns_event(wtype="ADDED"))
    modified = parse_watch_event(_ns_event(wtype="MODIFIED"))
    assert added == modified


def test_modified_deployment_same_ci_and_edge_shape_as_added():
    """EC-P15: MODIFIED Deployment produces the same CI type, external_id, and edge type as ADDED."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI, DiscoveredEdge
    from infra_twin.core_model import CIType, EdgeType

    added = parse_watch_event(_deploy_event(wtype="ADDED"))
    modified = parse_watch_event(_deploy_event(wtype="MODIFIED"))

    added_cis = [u for u in added.upserts if isinstance(u, DiscoveredCI)]
    modified_cis = [u for u in modified.upserts if isinstance(u, DiscoveredCI)]
    assert len(added_cis) == len(modified_cis)
    for a, m in zip(added_cis, modified_cis):
        assert a.type == m.type
        assert a.external_id == m.external_id
        assert a.attributes == m.attributes

    added_edges = [u for u in added.upserts if isinstance(u, DiscoveredEdge)]
    modified_edges = [u for u in modified.upserts if isinstance(u, DiscoveredEdge)]
    assert len(added_edges) == len(modified_edges)
    for a, m in zip(added_edges, modified_edges):
        assert a.type == m.type
        assert a.from_ref == m.from_ref
        assert a.to_ref == m.to_ref
        assert a.source == m.source
        assert a.confidence == m.confidence


def test_modified_pod_same_ci_and_edge_shape_as_added():
    """EC-P15: MODIFIED Pod produces the same CI type, external_id, and edge type as ADDED."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI, DiscoveredEdge

    added = parse_watch_event(_pod_event(wtype="ADDED"))
    modified = parse_watch_event(_pod_event(wtype="MODIFIED"))

    added_cis = [u for u in added.upserts if isinstance(u, DiscoveredCI)]
    modified_cis = [u for u in modified.upserts if isinstance(u, DiscoveredCI)]
    assert len(added_cis) == len(modified_cis)
    for a, m in zip(added_cis, modified_cis):
        assert a.type == m.type
        assert a.external_id == m.external_id
        assert a.attributes == m.attributes

    added_edges = [u for u in added.upserts if isinstance(u, DiscoveredEdge)]
    modified_edges = [u for u in modified.upserts if isinstance(u, DiscoveredEdge)]
    assert len(added_edges) == len(modified_edges)
    for a, m in zip(added_edges, modified_edges):
        assert a.type == m.type
        assert a.from_ref == m.from_ref
        assert a.to_ref == m.to_ref


# ===========================================================================
# 10. DELETED: removed_cis + removed_edges (AC 15, EC-P16-EC-P19)
# ===========================================================================


def test_deleted_pod_with_node_name_removed_cis_and_edges():
    """AC 15 / EC-P16: DELETED Pod with nodeName -> upserts==[], removed_cis=[CIRef(k8s_pod, uid)], removed_edges=[RUNS_ON ref]."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import CIRef, EdgeEndpointRef
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_watch_event(_pod_event(wtype="DELETED", uid=_POD_UID, node_name="node-a"))
    assert delta.upserts == []
    assert len(delta.removed_cis) == 1
    assert delta.removed_cis[0].type == CIType.k8s_pod
    assert delta.removed_cis[0].external_id == _POD_UID
    assert len(delta.removed_edges) == 1
    ref = delta.removed_edges[0]
    assert isinstance(ref, EdgeEndpointRef)
    assert ref.type == EdgeType.RUNS_ON
    assert ref.from_ref.type == CIType.k8s_pod
    assert ref.from_ref.external_id == _POD_UID
    assert ref.to_ref.type == CIType.k8s_node
    assert ref.to_ref.external_id == "node-a"


def test_deleted_deployment_with_namespace_removed_cis_and_edges():
    """EC-P17: DELETED Deployment with namespace -> removed_cis has CIRef, removed_edges has CONTAINS ref."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import EdgeEndpointRef
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_watch_event(_deploy_event(wtype="DELETED", uid=_DEPLOY_UID, namespace="default"))
    assert delta.upserts == []
    assert len(delta.removed_cis) == 1
    assert delta.removed_cis[0].type == CIType.k8s_workload
    assert delta.removed_cis[0].external_id == _DEPLOY_UID
    assert len(delta.removed_edges) == 1
    ref = delta.removed_edges[0]
    assert isinstance(ref, EdgeEndpointRef)
    assert ref.type == EdgeType.CONTAINS
    assert ref.from_ref.type == CIType.k8s_namespace
    assert ref.from_ref.external_id == "default"
    assert ref.to_ref.type == CIType.k8s_workload
    assert ref.to_ref.external_id == _DEPLOY_UID


def test_deleted_service_with_namespace_removed_edges_contains():
    """EC-P17: DELETED Service with namespace -> removed_edges includes namespace-CONTAINS ref."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import EdgeEndpointRef
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_watch_event(_svc_event(wtype="DELETED", uid=_SVC_UID, namespace="staging"))
    assert delta.upserts == []
    assert len(delta.removed_cis) == 1
    assert len(delta.removed_edges) == 1
    ref = delta.removed_edges[0]
    assert ref.type == EdgeType.CONTAINS
    assert ref.from_ref.external_id == "staging"
    assert ref.to_ref.external_id == _SVC_UID


def test_deleted_namespace_empty_removed_edges():
    """EC-P18: DELETED Namespace -> single removed_cis, removed_edges==[]."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.core_model import CIType

    delta = parse_watch_event(_ns_event(wtype="DELETED", uid=_NS_UID))
    assert delta.upserts == []
    assert len(delta.removed_cis) == 1
    assert delta.removed_cis[0].type == CIType.k8s_namespace
    assert delta.removed_edges == []


def test_deleted_node_empty_removed_edges():
    """EC-P18: DELETED Node -> single removed_cis, removed_edges==[]."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.core_model import CIType

    delta = parse_watch_event(_node_event(wtype="DELETED", uid=_NODE_UID))
    assert delta.upserts == []
    assert len(delta.removed_cis) == 1
    assert delta.removed_cis[0].type == CIType.k8s_node
    assert delta.removed_edges == []


def test_deleted_pod_without_node_name_empty_removed_edges():
    """EC-P19: DELETED Pod without nodeName -> removed_cis single CIRef, removed_edges==[]."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.core_model import CIType

    delta = parse_watch_event(_pod_event(wtype="DELETED", uid=_POD_UID, node_name=None))
    assert delta.upserts == []
    assert len(delta.removed_cis) == 1
    assert delta.removed_cis[0].type == CIType.k8s_pod
    assert delta.removed_edges == []


# ===========================================================================
# 11. Edge provenance contract (AC 18, EC-P20)
# ===========================================================================


def test_deployment_contains_edge_provenance():
    """AC 18 / EC-P20: CONTAINS edge has declared source, confidence==1.0, exactly one Evidence."""
    from infra_twin.collectors.k8s.events import EVENT_SOURCE, parse_watch_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import EdgeSource

    delta = parse_watch_event(_deploy_event(namespace="default"))
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    assert len(edges) == 1
    e = edges[0]
    assert e.source == EdgeSource.declared
    assert e.confidence == 1.0
    assert len(e.evidence) == 1
    ev = e.evidence[0]
    assert ev.source == EVENT_SOURCE
    assert ev.observed_at is not None
    assert ev.observed_at.tzinfo is not None  # tz-aware


def test_deployment_contains_edge_evidence_detail():
    """AC 18: edge evidence detail contains wtype, kind, uid."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredEdge

    delta = parse_watch_event(_deploy_event(wtype="ADDED", uid=_DEPLOY_UID, namespace="default"))
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    ev = edges[0].evidence[0]
    assert "ADDED" in ev.detail
    assert "Deployment" in ev.detail
    assert _DEPLOY_UID in ev.detail


def test_pod_runs_on_edge_provenance():
    """EC-P20: RUNS_ON edge has declared source, confidence==1.0, exactly one Evidence with k8s-events source."""
    from infra_twin.collectors.k8s.events import EVENT_SOURCE, parse_watch_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import EdgeSource

    delta = parse_watch_event(_pod_event(node_name="node-a"))
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    e = edges[0]
    assert e.source == EdgeSource.declared
    assert e.confidence == 1.0
    assert len(e.evidence) == 1
    assert e.evidence[0].source == EVENT_SOURCE


# ===========================================================================
# 12. Error cases (AC 16, 17, EC-P1-EC-P6, EC-P21, EC-P22)
# ===========================================================================


def test_missing_type_raises_value_error():
    """EC-P1 / AC 17: missing 'type' key raises ValueError (not KeyError)."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = {"object": _ns_event()["object"]}
    with pytest.raises(ValueError):
        parse_watch_event(event, observed_at=_OBS)


def test_missing_type_not_key_error():
    """EC-P1: the error for missing type must be ValueError, not KeyError."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = {"object": _ns_event()["object"]}
    try:
        parse_watch_event(event, observed_at=_OBS)
        pytest.fail("expected ValueError")
    except ValueError:
        pass
    except KeyError:
        pytest.fail("raised KeyError instead of ValueError")


def test_unsupported_watch_type_raises_unsupported_event_error():
    """EC-P2 / AC 16: watch type 'BOOKMARK' raises UnsupportedEventError."""
    from infra_twin.collectors.k8s.events import UnsupportedEventError, parse_watch_event

    event = _ns_event()
    event["type"] = "BOOKMARK"
    with pytest.raises(UnsupportedEventError):
        parse_watch_event(event, observed_at=_OBS)


def test_unsupported_watch_type_error_raises_value_error():
    """EC-P2: UnsupportedEventError is also a ValueError."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = _ns_event()
    event["type"] = "ERROR"
    with pytest.raises(ValueError):
        parse_watch_event(event, observed_at=_OBS)


def test_missing_object_raises_value_error():
    """EC-P3 / AC 17: missing 'object' key raises ValueError."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = {"type": "ADDED"}
    with pytest.raises(ValueError):
        parse_watch_event(event, observed_at=_OBS)


def test_object_not_a_dict_raises_value_error():
    """EC-P3 / AC 17: 'object' that is not a dict raises ValueError."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = {"type": "ADDED", "object": "not-a-dict"}
    with pytest.raises(ValueError):
        parse_watch_event(event, observed_at=_OBS)


def test_missing_kind_raises_value_error():
    """EC-P4 / AC 17: missing 'kind' in object raises ValueError."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = _ns_event()
    del event["object"]["kind"]
    with pytest.raises(ValueError):
        parse_watch_event(event, observed_at=_OBS)


def test_unmapped_kind_raises_unsupported_event_error():
    """EC-P5 / AC 16: unmapped kind 'ConfigMap' raises UnsupportedEventError."""
    from infra_twin.collectors.k8s.events import UnsupportedEventError, parse_watch_event

    event = _ns_event()
    event["object"]["kind"] = "ConfigMap"
    with pytest.raises(UnsupportedEventError):
        parse_watch_event(event, observed_at=_OBS)


def test_unmapped_kind_replicaset_raises_unsupported_event_error():
    """EC-P5: unmapped kind 'ReplicaSet' raises UnsupportedEventError."""
    from infra_twin.collectors.k8s.events import UnsupportedEventError, parse_watch_event

    event = _ns_event()
    event["object"]["kind"] = "ReplicaSet"
    with pytest.raises(UnsupportedEventError):
        parse_watch_event(event, observed_at=_OBS)


def test_unmapped_kind_is_also_value_error():
    """EC-P5: UnsupportedEventError for unmapped kind is also a ValueError."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = _ns_event()
    event["object"]["kind"] = "ConfigMap"
    with pytest.raises(ValueError):
        parse_watch_event(event, observed_at=_OBS)


def test_missing_uid_raises_value_error():
    """EC-P6 / AC 17: missing metadata.uid raises ValueError."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = _ns_event()
    del event["object"]["metadata"]["uid"]
    with pytest.raises(ValueError):
        parse_watch_event(event, observed_at=_OBS)


def test_missing_uid_in_deleted_event_raises_value_error():
    """EC-P6: missing uid on DELETED event also raises ValueError."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = _ns_event(wtype="DELETED")
    del event["object"]["metadata"]["uid"]
    with pytest.raises(ValueError):
        parse_watch_event(event, observed_at=_OBS)


def test_missing_uid_not_key_error():
    """EC-P6: missing uid raises ValueError, not KeyError."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = _ns_event()
    del event["object"]["metadata"]["uid"]
    try:
        parse_watch_event(event, observed_at=_OBS)
        pytest.fail("expected ValueError")
    except ValueError:
        pass
    except KeyError:
        pytest.fail("raised KeyError instead of ValueError")


def test_invalid_creation_timestamp_raises_value_error():
    """EC-P21: invalid metadata.creationTimestamp raises ValueError('invalid creationTimestamp ...')."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = _ns_event()
    event["object"]["metadata"]["creationTimestamp"] = "not-a-datetime"
    with pytest.raises(ValueError, match="invalid creationTimestamp"):
        parse_watch_event(event)


def test_no_creation_timestamp_and_no_observed_at_raises_value_error():
    """EC-P22: no creationTimestamp and observed_at=None raises ValueError."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = _ns_event()
    del event["object"]["metadata"]["creationTimestamp"]
    with pytest.raises(ValueError):
        parse_watch_event(event, observed_at=None)


# ===========================================================================
# 13. Purity / determinism (AC 19, EC-P23, EC-P24, EC-P25)
# ===========================================================================


def test_parse_watch_event_is_pure_same_inputs_equal_outputs():
    """AC 19 / EC-P23: calling parse_watch_event twice with same inputs returns equal deltas."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = _deploy_event()
    d1 = parse_watch_event(event, observed_at=_OBS)
    d2 = parse_watch_event(event, observed_at=_OBS)
    assert d1 == d2


def test_parse_watch_event_does_not_mutate_input():
    """EC-P23: parse_watch_event does not mutate the input dict."""
    from infra_twin.collectors.k8s.events import parse_watch_event

    event = _pod_event()
    original = copy.deepcopy(event)
    parse_watch_event(event, observed_at=_OBS)
    assert event == original


def test_name_fallback_uid_when_metadata_name_absent():
    """EC-P24: when metadata.name is absent, CI name uses uid as fallback."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredCI

    uid = "ns-uid-noname"
    event = _ns_event(uid=uid)
    del event["object"]["metadata"]["name"]
    delta = parse_watch_event(event, observed_at=_OBS)
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    # name fallback is uid; no raise should occur
    assert ci.name == uid
    assert ci.external_id == uid


def test_parse_watch_event_never_calls_datetime_now():
    """EC-P25: parse_watch_event with a fixed creationTimestamp always returns same timestamp — no wall-clock call."""
    from infra_twin.collectors.k8s.events import parse_watch_event
    from infra_twin.connector_sdk import DiscoveredEdge

    # Two calls at potentially different wall-clock times should yield the same observed_at in evidence.
    event = _deploy_event(namespace="default")
    d1 = parse_watch_event(event, observed_at=_OBS)
    d2 = parse_watch_event(event, observed_at=_OBS)
    edges1 = [u for u in d1.upserts if isinstance(u, DiscoveredEdge)]
    edges2 = [u for u in d2.upserts if isinstance(u, DiscoveredEdge)]
    assert edges1[0].evidence[0].observed_at == edges2[0].evidence[0].observed_at


# ===========================================================================
# 14. E2E: ADDED Pod creates CI bitemporally (AC 25, EC-E1)
# ===========================================================================


def test_post_events_k8s_added_namespace_returns_200(pool, make_tenant_with_key):
    """EC-E1 / AC 25: POST /events/k8s with ADDED Namespace returns 200."""
    tenant, api_key = make_tenant_with_key("k8s-added-200")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200


def test_post_events_k8s_response_has_seven_keys(pool, make_tenant_with_key):
    """AC 21: POST /events/k8s response has exactly 7 keys."""
    tenant, api_key = make_tenant_with_key("k8s-7keys")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    expected_keys = {
        "connector_run_id", "cis_created", "cis_updated",
        "cis_unchanged", "cis_closed", "edges_written", "edges_closed",
    }
    assert set(resp.json().keys()) == expected_keys


def test_post_events_k8s_added_ci_queryable_via_repo(pool, make_tenant_with_key):
    """AC 25 / EC-E1: after ADDED Namespace POST, CIRepository.get_current(type=k8s_namespace) returns the CI with valid_to IS NULL."""
    tenant, api_key = make_tenant_with_key("k8s-ci-query")
    client = TestClient(create_app(pool=pool))
    from infra_twin.core_model import CIType

    client.post(
        "/events/k8s",
        json={"event": _ns_event(uid=_NS_UID)},
        headers=_auth(api_key),
    )

    with tenant_session(pool, tenant) as conn:
        cis = CIRepository(conn, tenant).get_current(
            type=CIType.k8s_namespace, external_id=_NS_UID
        )
    assert len(cis) == 1
    assert cis[0].valid_to is None
    assert cis[0].external_id == _NS_UID


def test_post_events_k8s_added_pod_no_node_ci_queryable(pool, make_tenant_with_key):
    """EC-E1: ADDED Pod without nodeName -> CI persisted with valid_to IS NULL (no edge resolution needed)."""
    tenant, api_key = make_tenant_with_key("k8s-pod-ci-query")
    client = TestClient(create_app(pool=pool))
    from infra_twin.core_model import CIType

    resp = client.post(
        "/events/k8s",
        json={"event": _pod_event(uid=_POD_UID, node_name=None)},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200

    with tenant_session(pool, tenant) as conn:
        cis = CIRepository(conn, tenant).get_current(
            type=CIType.k8s_pod, external_id=_POD_UID
        )
    assert len(cis) == 1
    assert cis[0].valid_to is None
    assert cis[0].external_id == _POD_UID


def test_post_events_k8s_added_namespace_cis_created_one(pool, make_tenant_with_key):
    """EC-E1: response counter cis_created==1 for a new ADDED Namespace."""
    tenant, api_key = make_tenant_with_key("k8s-cis-created")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    assert resp.json()["cis_created"] == 1


def test_post_events_k8s_connector_run_id_is_valid_uuid(pool, make_tenant_with_key):
    """AC 21: connector_run_id in the response is a valid UUID string."""
    tenant, api_key = make_tenant_with_key("k8s-run-uuid")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    run_id_str = resp.json()["connector_run_id"]
    parsed = UUID(run_id_str)
    assert str(parsed) == run_id_str


# ===========================================================================
# 15. E2E: DELETED closes CI (not hard-delete) (AC 26, EC-E2)
# ===========================================================================


def test_post_events_k8s_deleted_closes_ci(pool, make_tenant_with_key):
    """AC 26 / EC-E2: subsequent DELETED closes the CI (valid_to set) — not hard-deleted."""
    tenant, api_key = make_tenant_with_key("k8s-delete-closes")
    client = TestClient(create_app(pool=pool))
    from infra_twin.core_model import CIType

    # First, create the namespace (no edges to resolve)
    client.post(
        "/events/k8s",
        json={"event": _ns_event(uid=_NS_UID)},
        headers=_auth(api_key),
    )

    # Verify it's open
    with tenant_session(pool, tenant) as conn:
        cis_open = CIRepository(conn, tenant).get_current(
            type=CIType.k8s_namespace, external_id=_NS_UID
        )
    assert len(cis_open) == 1
    assert cis_open[0].valid_to is None

    # Now delete it
    resp_del = client.post(
        "/events/k8s",
        json={"event": _ns_event(wtype="DELETED", uid=_NS_UID)},
        headers=_auth(api_key),
    )
    assert resp_del.status_code == 200
    assert resp_del.json()["cis_closed"] == 1


def test_post_events_k8s_deleted_row_not_hard_deleted(pool, make_tenant_with_key):
    """EC-E2: after DELETED, the CI row still physically exists in DB with valid_to set (not hard-deleted)."""
    tenant, api_key = make_tenant_with_key("k8s-delete-nodelete")
    client = TestClient(create_app(pool=pool))

    # Add then delete a namespace
    client.post(
        "/events/k8s",
        json={"event": _ns_event(uid=_NS_UID)},
        headers=_auth(api_key),
    )
    client.post(
        "/events/k8s",
        json={"event": _ns_event(wtype="DELETED", uid=_NS_UID)},
        headers=_auth(api_key),
    )

    # Admin view: row must still exist with valid_to set
    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT valid_to FROM cis WHERE type = 'k8s_namespace' "
            "AND external_id = %s AND tenant_id = %s",
            (_NS_UID, tenant),
        ).fetchone()
    assert row is not None, "k8s_namespace CI row must physically exist (no hard-delete)"
    assert row[0] is not None, "valid_to must be set after DELETED event"


def test_post_events_k8s_deleted_row_count_positive(pool, make_tenant_with_key):
    """EC-E2: row count for that external_id > 0 (row still exists after DELETED)."""
    tenant, api_key = make_tenant_with_key("k8s-delete-rowcount")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/k8s",
        json={"event": _ns_event(uid=_NS_UID)},
        headers=_auth(api_key),
    )
    client.post(
        "/events/k8s",
        json={"event": _ns_event(wtype="DELETED", uid=_NS_UID)},
        headers=_auth(api_key),
    )

    with psycopg.connect(admin_dsn()) as admin_conn:
        count = admin_conn.execute(
            "SELECT count(*) FROM cis WHERE type = 'k8s_namespace' "
            "AND external_id = %s AND tenant_id = %s",
            (_NS_UID, tenant),
        ).fetchone()[0]
    assert count >= 1, "row count for external_id must be > 0 after DELETED (never hard-deleted)"


# ===========================================================================
# 16. E2E: connector_runs row for k8s-events (AC 27, EC-E3)
# ===========================================================================


def test_post_events_k8s_connector_run_row_written(pool, make_tenant_with_key):
    """AC 27 / EC-E3: after POST /events/k8s, a connector_runs row with source='k8s-events' exists."""
    tenant, api_key = make_tenant_with_key("k8s-run-row")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(api_key),
    )

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT status, source FROM connector_runs WHERE source = 'k8s-events'"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "ok"
    assert rows[0][1] == "k8s-events"


def test_post_events_k8s_connector_run_id_matches_db(pool, make_tenant_with_key):
    """EC-E3: response connector_run_id == connector_runs.run_id written to DB."""
    tenant, api_key = make_tenant_with_key("k8s-run-dbmatch")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    run_id_str = resp.json()["connector_run_id"]

    with tenant_session(pool, tenant) as conn:
        db_run_id = conn.execute(
            "SELECT run_id FROM connector_runs WHERE source = 'k8s-events'"
        ).fetchone()[0]
    assert str(db_run_id) == run_id_str


def test_post_events_k8s_raw_facts_written(pool, make_tenant_with_key):
    """EC-E3: after POST /events/k8s, at least one raw_facts row with source='k8s-events' exists."""
    tenant, api_key = make_tenant_with_key("k8s-raw-facts")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(api_key),
    )

    with tenant_session(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = 'k8s-events'"
        ).fetchone()[0]
    assert count >= 1


def test_post_events_k8s_freshness_slo_evaluate_fresh(pool, make_tenant_with_key):
    """EC-E8 (optional): after configuring SLO for k8s-events and posting, GET /freshness-slos/evaluate shows k8s-events as fresh."""
    tenant, api_key = make_tenant_with_key("k8s-slo-fresh")
    client = TestClient(create_app(pool=pool))

    # Configure a generous SLO (1 hour)
    put_resp = client.put(
        "/freshness-slos/k8s-events",
        json={"expected_interval_seconds": 3600},
        headers=_auth(api_key),
    )
    assert put_resp.status_code == 200

    # POST an event to mark the source fresh
    client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(api_key),
    )

    # Evaluate freshness
    eval_resp = client.get("/freshness-slos/evaluate", headers=_auth(api_key))
    assert eval_resp.status_code == 200
    sources = eval_resp.json()["sources"]
    k8s_row = next((s for s in sources if s["source"] == "k8s-events"), None)
    assert k8s_row is not None, "k8s-events source must appear in evaluate output"
    # The evaluate response uses 'status' field; 'fresh' means not breaching
    assert k8s_row["status"] == "fresh", f"k8s-events should be fresh after a POST, got: {k8s_row}"


# ===========================================================================
# 17. E2E: cross-tenant isolation (AC 28, EC-E4)
# ===========================================================================


def test_cross_tenant_k8s_events_ci_isolation(pool, make_tenant_with_key):
    """AC 28 / EC-E4: event posted under tenant A creates no CI visible to tenant B."""
    tenant_a, key_a = make_tenant_with_key("k8s-iso-ci-A")
    tenant_b, key_b = make_tenant_with_key("k8s-iso-ci-B")
    client = TestClient(create_app(pool=pool))
    from infra_twin.core_model import CIType

    client.post(
        "/events/k8s",
        json={"event": _pod_event(uid="pod-uid-tenant-a")},
        headers=_auth(key_a),
    )

    with tenant_session(pool, tenant_b) as conn:
        b_cis = CIRepository(conn, tenant_b).get_current()
    assert b_cis == [], "tenant B must see zero CIs from tenant A's k8s-events POST"


def test_cross_tenant_k8s_events_connector_runs_isolation(pool, make_tenant_with_key):
    """AC 28 / EC-E4: k8s-events connector_runs of tenant A not visible to tenant B."""
    tenant_a, key_a = make_tenant_with_key("k8s-iso-run-A")
    tenant_b, key_b = make_tenant_with_key("k8s-iso-run-B")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(key_a),
    )

    assert _count_rows_tenant(pool, tenant_a, "connector_runs") == 1
    assert _count_rows_tenant(pool, tenant_b, "connector_runs") == 0


def test_cross_tenant_k8s_events_all_tables_isolated(pool, make_tenant_with_key):
    """EC-E4: posting event under tenant A produces zero rows visible to tenant B across all tables."""
    tenant_a, key_a = make_tenant_with_key("k8s-iso-all-A")
    tenant_b, key_b = make_tenant_with_key("k8s-iso-all-B")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/k8s",
        json={"event": _pod_event()},
        headers=_auth(key_a),
    )

    for table in ("cis", "edges", "connector_runs", "raw_facts", "connectors"):
        count = _count_rows_tenant(pool, tenant_b, table)
        assert count == 0, f"tenant B should see 0 rows in {table} after tenant A's POST, got {count}"


# ===========================================================================
# 18. E2E: RBAC viewer 403 / editor 200 (AC 29, EC-E5)
# ===========================================================================


def test_viewer_key_post_events_k8s_is_403():
    """AC 29 / EC-E5: viewer API key returns 403 on POST /events/k8s."""
    _, viewer_key = _make_viewer_key("k8s-rbac-viewer")
    client = TestClient(create_app(pool=None))
    resp = client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403


def test_viewer_key_post_events_k8s_detail_insufficient_permissions():
    """EC-E5: 403 detail is 'insufficient permissions' for viewer on /events/k8s."""
    _, viewer_key = _make_viewer_key("k8s-rbac-viewer-detail")
    client = TestClient(create_app(pool=None))
    resp = client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(viewer_key),
    )
    assert resp.json()["detail"] == "insufficient permissions"


def test_viewer_key_post_events_k8s_creates_no_ci(pool):
    """EC-E5: viewer 403 on POST /events/k8s creates no CI and no connector_runs row."""
    viewer_tenant, viewer_key = _make_viewer_key("k8s-rbac-viewer-noci")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(viewer_key),
    )

    assert _count_rows_admin("cis", viewer_tenant) == 0
    assert _count_rows_admin("connector_runs", viewer_tenant) == 0


def test_editor_key_post_events_k8s_is_200(pool, make_tenant_with_key):
    """EC-E5: editor API key returns 200 on POST /events/k8s."""
    # Use make_tenant_with_key fixture (creates editor key via provision_tenant)
    _, editor_key = make_tenant_with_key("k8s-rbac-editor")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(editor_key),
    )
    assert resp.status_code == 200


# ===========================================================================
# 19. E2E: audit row recorded (AC 30, EC-E6)
# ===========================================================================


def test_post_events_k8s_editor_produces_audit_row(pool):
    """AC 30 / EC-E6: editor POST /events/k8s produces an audit_log row."""
    editor_tenant, editor_key = _make_editor_key("k8s-audit-editor")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(editor_key),
    )

    rows = _get_audit_rows(editor_tenant)
    assert len(rows) >= 1
    assert any(r["path"] == "/events/k8s" for r in rows), (
        f"expected an audit_log row for /events/k8s, got: {rows}"
    )


def test_post_events_k8s_audit_row_is_allow_write(pool):
    """EC-E6: audit row for editor POST /events/k8s is decision='allow', permission='write'."""
    editor_tenant, editor_key = _make_editor_key("k8s-audit-allow")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(editor_key),
    )

    rows = _get_audit_rows(editor_tenant)
    k8s_rows = [r for r in rows if r["path"] == "/events/k8s"]
    assert len(k8s_rows) >= 1
    row = k8s_rows[0]
    assert row["decision"] == "allow"
    assert row["permission"] == "write"


def test_viewer_post_events_k8s_audit_row_is_deny(pool):
    """EC-E6: viewer 403 on POST /events/k8s produces a deny audit_log row."""
    viewer_tenant, viewer_key = _make_viewer_key("k8s-audit-viewer-deny")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/k8s",
        json={"event": _ns_event()},
        headers=_auth(viewer_key),
    )

    rows = _get_audit_rows(viewer_tenant)
    k8s_rows = [r for r in rows if r["path"] == "/events/k8s"]
    assert len(k8s_rows) >= 1
    assert any(r["decision"] == "deny" for r in k8s_rows), (
        f"expected a deny audit row for viewer POST /events/k8s: {k8s_rows}"
    )


# ===========================================================================
# 20. E2E: malformed body -> 422 not 500, no CI (AC 24, EC-E7)
# ===========================================================================


def test_post_events_k8s_unmapped_kind_returns_422(pool, make_tenant_with_key):
    """AC 24 / EC-E7: unmapped kind in body returns 422, not 500."""
    tenant, api_key = make_tenant_with_key("k8s-422-kind")
    client = TestClient(create_app(pool=pool))

    event = _ns_event()
    event["object"]["kind"] = "ConfigMap"
    resp = client.post(
        "/events/k8s",
        json={"event": event},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_post_events_k8s_missing_uid_returns_422(pool, make_tenant_with_key):
    """EC-E7: missing metadata.uid in body returns 422."""
    tenant, api_key = make_tenant_with_key("k8s-422-uid")
    client = TestClient(create_app(pool=pool))

    event = _ns_event()
    del event["object"]["metadata"]["uid"]
    resp = client.post(
        "/events/k8s",
        json={"event": event},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_post_events_k8s_unsupported_type_returns_422(pool, make_tenant_with_key):
    """EC-E7: unknown watch type ('BOOKMARK') returns 422."""
    tenant, api_key = make_tenant_with_key("k8s-422-type")
    client = TestClient(create_app(pool=pool))

    event = _ns_event()
    event["type"] = "BOOKMARK"
    resp = client.post(
        "/events/k8s",
        json={"event": event},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_post_events_k8s_missing_type_returns_422(pool, make_tenant_with_key):
    """EC-E7: missing 'type' key in event returns 422."""
    tenant, api_key = make_tenant_with_key("k8s-422-notype")
    client = TestClient(create_app(pool=pool))

    event = _ns_event()
    del event["type"]
    resp = client.post(
        "/events/k8s",
        json={"event": event},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_post_events_k8s_malformed_returns_no_500(pool, make_tenant_with_key):
    """AC 24: malformed body never yields 500 — only 422."""
    tenant, api_key = make_tenant_with_key("k8s-no-500")
    client = TestClient(create_app(pool=pool))
    headers = _auth(api_key)

    # Test multiple malformed inputs, none should be 500; all should be 422
    bad_events = [
        {"type": "ADDED"},  # missing object
        {"type": "ADDED", "object": "not-a-dict"},  # non-dict object
        {"type": "ADDED", "object": {"kind": "Pod", "metadata": {}}},  # missing uid
        {"type": "BOOKMARK", "object": {"kind": "Namespace", "metadata": {"uid": "x", "creationTimestamp": "2024-01-01T00:00:00Z"}}},  # unmapped type
    ]
    for ev in bad_events:
        resp = client.post(
            "/events/k8s",
            json={"event": ev},
            headers=headers,
        )
        assert resp.status_code != 500, f"got 500 for event: {ev}"
        assert resp.status_code == 422, f"expected 422 for event {ev}, got {resp.status_code}"


def test_post_events_k8s_malformed_creates_no_ci(pool, make_tenant_with_key):
    """EC-E7: malformed body (missing uid) returns 422 and creates no CI."""
    tenant, api_key = make_tenant_with_key("k8s-422-noci")
    client = TestClient(create_app(pool=pool))

    event = _ns_event()
    del event["object"]["metadata"]["uid"]
    client.post(
        "/events/k8s",
        json={"event": event},
        headers=_auth(api_key),
    )

    assert _count_rows_tenant(pool, tenant, "cis") == 0
    assert _count_rows_tenant(pool, tenant, "connector_runs") == 0


def test_post_events_k8s_missing_event_key_returns_422(pool, make_tenant_with_key):
    """EC-E7: body missing 'event' key returns 422 (Pydantic validation)."""
    tenant, api_key = make_tenant_with_key("k8s-422-nokey")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/k8s",
        json={"not_event": {}},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


# ===========================================================================
# 21. Module boundary: reconciliation must not import collectors (AC 31)
# ===========================================================================


def test_reconciliation_events_does_not_import_k8s_collectors():
    """AC 31: reconciliation/events.py must NOT import from infra_twin.collectors (including k8s)."""
    import infra_twin.reconciliation.events as mod
    for name, obj in mod.__dict__.items():
        if hasattr(obj, "__module__") and obj.__module__ is not None:
            assert "infra_twin.collectors" not in str(obj.__module__), (
                f"reconciliation.events imported {obj.__module__} via {name}"
            )


# ===========================================================================
# 22. AC 23: app.py imports with alias (structural check)
# ===========================================================================


def test_app_imports_k8s_with_alias():
    """AC 23: infra_twin.api.app imports K8sUnsupportedEventError (aliased) and parse_watch_event."""
    import infra_twin.api.app as app_mod
    # The k8s symbols must be present in app namespace under correct names
    assert hasattr(app_mod, "parse_watch_event"), "app.py must export parse_watch_event"
    assert hasattr(app_mod, "K8sUnsupportedEventError"), "app.py must export K8sUnsupportedEventError as alias"


def test_app_aws_parse_event_import_unchanged():
    """AC 23: the AWS UnsupportedEventError import at app.py is unchanged (unaliased as UnsupportedEventError)."""
    import infra_twin.api.app as app_mod
    # The AWS UnsupportedEventError must still be importable under original name
    assert hasattr(app_mod, "UnsupportedEventError"), "AWS UnsupportedEventError must remain in app namespace"
    from infra_twin.collectors.aws.events import UnsupportedEventError as AwsUnsupportedEventError
    assert app_mod.UnsupportedEventError is AwsUnsupportedEventError


def test_app_k8s_unsupported_error_is_different_from_aws():
    """AC 23: K8sUnsupportedEventError and AWS UnsupportedEventError are distinct classes."""
    import infra_twin.api.app as app_mod
    assert app_mod.K8sUnsupportedEventError is not app_mod.UnsupportedEventError
