"""Read-only SaaS API discovery connector.

Discovers a SaaS account hierarchy (apps -> accounts/users -> resources) and
declared access-grant HAS_ACCESS_TO edges and resource DEPENDS_ON edges via an
injected SaasDiscoveryClient and emits canonical discovery events.

The connector holds no internal ids, never mutates the SaaS side, and never
raises on missing optional keys — all accesses use .get() chains.

A ``SaasDiscoveryClient`` is injected so the same code runs against a real SaaS
HTTP/SDK layer (in the CLI) and against an in-memory fake in tests.
"""

from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable

from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge, DiscoveryEvent
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence


@runtime_checkable
class SaasDiscoveryClient(Protocol):
    """Minimal read-only surface required by SaasDiscoveryConnector.

    Production wraps a real SaaS HTTP/SDK layer. Test fakes return in-memory
    fixtures. Each method returns a list of plain dicts.
    """

    def list_apps(self) -> list[dict]: ...           # SaaS applications
    def list_accounts(self) -> list[dict]: ...       # accounts/users
    def list_resources(self) -> list[dict]: ...      # resources owned by apps
    def list_access_grants(self) -> list[dict]: ...  # account -> resource grants


_CI_TYPES: frozenset[CIType] = frozenset(
    {
        CIType.saas_app,
        CIType.saas_account,
        CIType.saas_resource,
    }
)

_EDGE_TYPES: frozenset[EdgeType] = frozenset(
    {
        EdgeType.CONTAINS,
        EdgeType.HAS_ACCESS_TO,
        EdgeType.DEPENDS_ON,
    }
)


class SaasDiscoveryConnector:
    """Discovers a SaaS account's applications, accounts/users, and resources."""

    source: str = "saas"
    ci_types: frozenset[CIType] = _CI_TYPES
    edge_types: frozenset[EdgeType] = _EDGE_TYPES

    def __init__(
        self,
        client: SaasDiscoveryClient,
        account_id: str,
        account_name: str | None = None,
    ) -> None:
        self._client = client
        self._account_id = account_id
        self._account_name = account_name

    # -- helpers -----------------------------------------------------------------

    def _evidence(self, detail: str) -> list[Evidence]:
        return [Evidence(source="saas", detail=detail)]

    def _edge(
        self,
        etype: EdgeType,
        from_ref: CIRef,
        to_ref: CIRef,
        detail: str,
        edge_key: str = "",
    ) -> DiscoveredEdge:
        return DiscoveredEdge(
            type=etype,
            from_ref=from_ref,
            to_ref=to_ref,
            source=EdgeSource.declared,
            confidence=1.0,
            evidence=self._evidence(detail),
            edge_key=edge_key,
        )

    # -- discovery ---------------------------------------------------------------

    def discover(self) -> Iterator[DiscoveryEvent]:
        account_id = self._account_id

        # 1. Apps — emit CIs, track discovered set.
        discovered_apps: dict[str, str] = {}  # app_id -> external_id
        for app in self._client.list_apps():
            app_id: str | None = app.get("id")
            if not app_id:
                continue
            app_external_id = f"{account_id}/{app_id}"
            yield DiscoveredCI(
                type=CIType.saas_app,
                external_id=app_external_id,
                name=app.get("name") or app_id,
                attributes={
                    "app_id": app_id,
                    "vendor": app.get("vendor"),
                    "category": app.get("category"),
                },
            )
            discovered_apps[app_id] = app_external_id

        # 2. Accounts — emit CIs, CONTAINS app->account when app resolves, track set.
        discovered_accounts: dict[str, str] = {}  # native_id -> external_id
        for account in self._client.list_accounts():
            native_id: str | None = account.get("id")
            if not native_id:
                continue
            acc_external_id = f"{account_id}/{native_id}"
            yield DiscoveredCI(
                type=CIType.saas_account,
                external_id=acc_external_id,
                name=account.get("name") or native_id,
                attributes={
                    "account_id": native_id,
                    "email": account.get("email"),
                    "kind": account.get("kind"),
                },
            )
            app_id_for_account: str | None = account.get("app_id")
            if app_id_for_account and app_id_for_account in discovered_apps:
                yield self._edge(
                    EdgeType.CONTAINS,
                    CIRef(type=CIType.saas_app, external_id=discovered_apps[app_id_for_account]),
                    CIRef(type=CIType.saas_account, external_id=acc_external_id),
                    "saas:app:account",
                )
            discovered_accounts[native_id] = acc_external_id

        # 3. Resources — emit CIs, CONTAINS app->resource and DEPENDS_ON when applicable.
        discovered_resources: dict[str, str] = {}  # resource_id -> external_id
        for resource in self._client.list_resources():
            resource_id: str | None = resource.get("id")
            if not resource_id:
                continue
            app_id_for_resource: str | None = resource.get("app_id")
            res_external_id = f"{account_id}/{app_id_for_resource}/{resource_id}"
            yield DiscoveredCI(
                type=CIType.saas_resource,
                external_id=res_external_id,
                name=resource.get("name") or resource_id,
                attributes={
                    "app_id": app_id_for_resource,
                    "resource_id": resource_id,
                    "kind": resource.get("kind"),
                    "external_handle": resource.get("external_handle"),
                },
            )
            if app_id_for_resource and app_id_for_resource in discovered_apps:
                yield self._edge(
                    EdgeType.CONTAINS,
                    CIRef(type=CIType.saas_app, external_id=discovered_apps[app_id_for_resource]),
                    CIRef(type=CIType.saas_resource, external_id=res_external_id),
                    "saas:app:resource",
                )
            external_handle: str | None = resource.get("external_handle")
            if external_handle:
                yield self._edge(
                    EdgeType.DEPENDS_ON,
                    CIRef(type=CIType.saas_resource, external_id=res_external_id),
                    CIRef(type=CIType.saas_resource, external_id=external_handle),
                    f"saas:resource:depends_on:{external_handle}",
                    edge_key=external_handle,
                )
            discovered_resources[resource_id] = res_external_id

        # 4. Access grants — emit HAS_ACCESS_TO when both endpoints are discovered.
        for grant in self._client.list_access_grants():
            account_native_id: str | None = grant.get("account_id")
            resource_id_for_grant: str | None = grant.get("resource_id")
            if not account_native_id or not resource_id_for_grant:
                continue
            if account_native_id not in discovered_accounts or resource_id_for_grant not in discovered_resources:
                continue
            grant_key: str = grant.get("id") or grant.get("scope") or "<unnamed>"
            edge_key: str = grant.get("id") or grant.get("scope") or ""
            yield self._edge(
                EdgeType.HAS_ACCESS_TO,
                CIRef(type=CIType.saas_account, external_id=discovered_accounts[account_native_id]),
                CIRef(type=CIType.saas_resource, external_id=discovered_resources[resource_id_for_grant]),
                f"saas:grant:{grant_key} (scope={grant.get('scope')})",
                edge_key=edge_key,
            )
