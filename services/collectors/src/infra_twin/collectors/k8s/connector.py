"""Read-only Kubernetes discovery connector.

Discovers a representative Kubernetes resource set (namespaces, nodes, deployments as
workloads, services, pods) via an injected K8sClient and emits canonical discovery events.

The connector holds no internal ids, never mutates the cluster, and never raises on missing
optional keys — all accesses use .get() chains.

A ``K8sClient`` is injected so the same code runs against a real cluster (via the
``kubernetes`` library adapter in the CLI) and against an in-memory fake in tests.
"""

from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable

from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge, DiscoveryEvent
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence


@runtime_checkable
class K8sClient(Protocol):
    """Minimal read-only Kubernetes API surface required by KubernetesConnector.

    Each method returns a list of plain dicts with the normalized Kubernetes object shape.
    Production implementations wrap the ``kubernetes`` library; test fakes return
    in-memory fixtures.
    """

    def list_namespaces(self) -> list[dict]: ...
    def list_nodes(self) -> list[dict]: ...
    def list_deployments(self) -> list[dict]: ...
    def list_services(self) -> list[dict]: ...
    def list_pods(self) -> list[dict]: ...


_CI_TYPES: frozenset[CIType] = frozenset(
    {
        CIType.k8s_cluster,
        CIType.k8s_namespace,
        CIType.k8s_node,
        CIType.k8s_workload,
        CIType.k8s_pod,
        CIType.k8s_service,
    }
)

_EDGE_TYPES: frozenset[EdgeType] = frozenset(
    {
        EdgeType.CONTAINS,
        EdgeType.MEMBER_OF,
        EdgeType.RUNS_ON,
        EdgeType.ROUTES_TO,
        EdgeType.EXPOSES,
    }
)


class KubernetesConnector:
    """Discovers a representative Kubernetes resource set from a single cluster."""

    source: str = "kubernetes"
    ci_types: frozenset[CIType] = _CI_TYPES
    edge_types: frozenset[EdgeType] = _EDGE_TYPES

    def __init__(
        self,
        client: K8sClient,
        cluster_id: str,
        cluster_name: str | None = None,
    ) -> None:
        self._client = client
        self._cluster_id = cluster_id
        self._cluster_name = cluster_name or cluster_id

    # -- helpers -----------------------------------------------------------------

    def _evidence(self, detail: str) -> list[Evidence]:
        return [Evidence(source="kubernetes", detail=detail)]

    def _edge(
        self,
        etype: EdgeType,
        from_ref: CIRef,
        to_ref: CIRef,
        detail: str,
    ) -> DiscoveredEdge:
        return DiscoveredEdge(
            type=etype,
            from_ref=from_ref,
            to_ref=to_ref,
            source=EdgeSource.declared,
            confidence=1.0,
            evidence=self._evidence(detail),
        )

    # -- discovery ---------------------------------------------------------------

    def discover(self) -> Iterator[DiscoveryEvent]:
        cluster_ref = CIRef(type=CIType.k8s_cluster, external_id=self._cluster_id)

        # 1. Cluster CI.
        yield DiscoveredCI(
            type=CIType.k8s_cluster,
            external_id=self._cluster_id,
            name=self._cluster_name,
        )

        # 2. Nodes — build node_name -> node_uid index for pod placement.
        node_uid_by_name: dict[str, str] = {}
        for node in self._client.list_nodes():
            meta = node.get("metadata") or {}
            uid: str | None = meta.get("uid")
            if not uid:
                continue
            node_name: str = meta.get("name") or uid
            node_uid_by_name[node_name] = uid
            yield DiscoveredCI(
                type=CIType.k8s_node,
                external_id=uid,
                name=node_name,
                attributes={"node_name": node_name},
            )

        # 3. Namespaces — build ns_name -> ns_uid index.
        ns_uid_by_name: dict[str, str] = {}
        for ns in self._client.list_namespaces():
            meta = ns.get("metadata") or {}
            uid = meta.get("uid")
            if not uid:
                continue
            ns_name: str = meta.get("name") or uid
            ns_uid_by_name[ns_name] = uid
            yield DiscoveredCI(
                type=CIType.k8s_namespace,
                external_id=uid,
                name=ns_name,
            )
            yield self._edge(
                EdgeType.CONTAINS,
                cluster_ref,
                CIRef(type=CIType.k8s_namespace, external_id=uid),
                "k8s:cluster:namespace",
            )

        # 4. Workloads (Deployments) — build wl_uid set for ownerReference resolution.
        wl_uid_set: set[str] = set()
        # uid -> selector matchLabels (may be None/empty)
        wl_selector_by_uid: dict[str, dict[str, str]] = {}
        for deployment in self._client.list_deployments():
            meta = deployment.get("metadata") or {}
            uid = meta.get("uid")
            if not uid:
                continue
            wl_name: str = meta.get("name") or uid
            ns: str = meta.get("namespace") or ""
            spec = deployment.get("spec") or {}
            selector_obj = spec.get("selector") or {}
            match_labels: dict[str, str] = selector_obj.get("matchLabels") or {}

            wl_uid_set.add(uid)
            wl_selector_by_uid[uid] = match_labels

            yield DiscoveredCI(
                type=CIType.k8s_workload,
                external_id=uid,
                name=f"{ns}/{wl_name}" if ns else wl_name,
                attributes={
                    "namespace": ns,
                    "kind": "Deployment",
                    "selector": match_labels,
                },
            )

            ns_uid = ns_uid_by_name.get(ns) if ns else None
            if ns_uid:
                yield self._edge(
                    EdgeType.CONTAINS,
                    CIRef(type=CIType.k8s_namespace, external_id=ns_uid),
                    CIRef(type=CIType.k8s_workload, external_id=uid),
                    "k8s:namespace:workload",
                )

        # 5. Services — collect for selector matching after pods are known.
        services: list[dict] = self._client.list_services()
        svc_uid_by_obj: list[tuple[str, dict, str]] = []  # (uid, selector_dict, ns_uid)
        for svc in services:
            meta = svc.get("metadata") or {}
            uid = meta.get("uid")
            if not uid:
                continue
            svc_name: str = meta.get("name") or uid
            ns = meta.get("namespace") or ""
            spec = svc.get("spec") or {}
            selector: dict[str, str] = spec.get("selector") or {}

            yield DiscoveredCI(
                type=CIType.k8s_service,
                external_id=uid,
                name=f"{ns}/{svc_name}" if ns else svc_name,
                attributes={
                    "namespace": ns,
                    "selector": selector,
                },
            )

            ns_uid = ns_uid_by_name.get(ns) if ns else None
            if ns_uid:
                yield self._edge(
                    EdgeType.CONTAINS,
                    CIRef(type=CIType.k8s_namespace, external_id=ns_uid),
                    CIRef(type=CIType.k8s_service, external_id=uid),
                    "k8s:namespace:service",
                )

            svc_uid_by_obj.append((uid, selector, ns_uid or ""))

        # 6. Pods.
        for pod in self._client.list_pods():
            meta = pod.get("metadata") or {}
            uid = meta.get("uid")
            if not uid:
                continue
            pod_name: str = meta.get("name") or uid
            ns = meta.get("namespace") or ""
            spec = pod.get("spec") or {}
            status = pod.get("status") or {}
            pod_labels: dict[str, str] = meta.get("labels") or {}
            node_name_val: str | None = spec.get("nodeName")

            yield DiscoveredCI(
                type=CIType.k8s_pod,
                external_id=uid,
                name=f"{ns}/{pod_name}" if ns else pod_name,
                attributes={
                    "namespace": ns,
                    "node_name": node_name_val,
                    "phase": status.get("phase"),
                    "labels": pod_labels,
                },
            )

            pod_ref = CIRef(type=CIType.k8s_pod, external_id=uid)

            # RUNS_ON: only if nodeName resolves to a discovered node.
            if node_name_val:
                node_uid = node_uid_by_name.get(node_name_val)
                if node_uid:
                    yield self._edge(
                        EdgeType.RUNS_ON,
                        pod_ref,
                        CIRef(type=CIType.k8s_node, external_id=node_uid),
                        "k8s:pod:nodeName",
                    )

            # MEMBER_OF: selector-based attribution (authoritative).
            for wl_uid, match_labels in wl_selector_by_uid.items():
                if match_labels and _labels_match(match_labels, pod_labels):
                    yield self._edge(
                        EdgeType.MEMBER_OF,
                        pod_ref,
                        CIRef(type=CIType.k8s_workload, external_id=wl_uid),
                        "k8s:workload:selector",
                    )

            # MEMBER_OF: ownerReferences path (supplementary — only for discovered wl uids).
            owner_refs = meta.get("ownerReferences") or []
            for ref in owner_refs:
                if (ref.get("kind") == "Deployment"):
                    ref_uid: str | None = ref.get("uid")
                    if ref_uid and ref_uid in wl_uid_set:
                        # Only emit if selector path did not already cover this workload.
                        sel = wl_selector_by_uid.get(ref_uid) or {}
                        if not (sel and _labels_match(sel, pod_labels)):
                            yield self._edge(
                                EdgeType.MEMBER_OF,
                                pod_ref,
                                CIRef(type=CIType.k8s_workload, external_id=ref_uid),
                                "k8s:pod:ownerReference",
                            )

            # ROUTES_TO + EXPOSES: service selector matching.
            for svc_uid, svc_selector, _ns_uid in svc_uid_by_obj:
                if svc_selector and _labels_match(svc_selector, pod_labels):
                    svc_ref = CIRef(type=CIType.k8s_service, external_id=svc_uid)
                    yield self._edge(
                        EdgeType.ROUTES_TO,
                        svc_ref,
                        pod_ref,
                        "k8s:service:selector",
                    )
                    yield self._edge(
                        EdgeType.EXPOSES,
                        svc_ref,
                        pod_ref,
                        "k8s:service:selector",
                    )


def _labels_match(selector: dict[str, str], labels: dict[str, str]) -> bool:
    """Return True iff every (k, v) in selector is present and equal in labels.

    An empty selector selects nothing (returns False per spec §4.3).
    """
    if not selector:
        return False
    return all(labels.get(k) == v for k, v in selector.items())
