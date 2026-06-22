"""Authentication dependencies for the infra-twin API.

- require_bootstrap_admin: authorizes POST /tenants via a shared env secret.
- make_tenant_dependency: factory returning a FastAPI dependency that resolves
  an API key or OIDC token from the Authorization header and returns the owning
  tenant UUID.
- make_permission_dependency: factory returning a require_permission(perm) callable
  that layers role-based authorization on top of principal resolution.

The admin pool (BYPASSRLS superuser connection) is created lazily, cached on
app.state.admin_pool, and used only for key resolution, IdP config lookup, and
tenant provisioning.  It is never used for ordinary tenant-data queries.

Auth dispatch
-------------
Bearer token routing (after stripping "Bearer "):
1. Starts with KEY_PREFIX ("itw_") -> API-key path (existing behaviour).
2. Looks like a JWT (3 segments, no empty parts) -> OIDC path.
3. Anything else -> API-key path (gets API-key error messaging).
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from uuid import UUID

from fastapi import Header, HTTPException, Request
from fastapi.routing import APIRoute
from psycopg_pool import ConnectionPool

from infra_twin.db.api_keys import KEY_PREFIX, ResolvedKey, Role, resolve
from infra_twin.db.audit import record_access
from infra_twin.db.config import admin_dsn
from infra_twin.db.idp_config import find_idp_config
from infra_twin.db.scim_users import get_current_user_by_username, resolve_scim_token
from infra_twin.db.session import tenant_session
from infra_twin.db.usage import count_usage_in_window, current_calendar_month_start, record_usage
from infra_twin.api.oidc import OidcError, looks_like_jwt, verify_oidc_token

BOOTSTRAP_ADMIN_TOKEN_ENV: str = "INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN"


@dataclass(frozen=True)
class Principal:
    tenant_id: UUID
    role: Role
    auth_method: str          # "api_key" | "oidc"
    api_key_id: UUID | None   # set for api_key, None for oidc


def _admin_pool(app) -> ConnectionPool:
    """Lazily create and cache an admin-role connection pool on app.state."""
    if not hasattr(app.state, "admin_pool") or app.state.admin_pool is None:
        app.state.admin_pool = ConnectionPool(admin_dsn(), open=True)
    return app.state.admin_pool


def require_bootstrap_admin(
    authorization: str | None = Header(default=None),
) -> None:
    """FastAPI dependency that guards POST /tenants with a shared env secret.

    Raises HTTPException:
    - 503 if the env var is unset or empty (bootstrap admin not configured).
    - 401 if the Authorization header is missing or has the wrong token.
    """
    env_token = os.environ.get(BOOTSTRAP_ADMIN_TOKEN_ENV, "")
    if not env_token:
        raise HTTPException(
            status_code=503,
            detail="bootstrap admin is not configured",
        )

    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="missing bootstrap admin token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    supplied = authorization[len("Bearer "):]
    if not hmac.compare_digest(supplied, env_token):
        raise HTTPException(
            status_code=401,
            detail="invalid bootstrap admin token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _default_oidc_key_resolver(issuer: str, kid: str | None) -> object:
    """Production key resolver stub.

    Live JWKS fetching is a follow-up task.  Until it lands, OIDC tokens will
    fail at key resolution unless a real resolver is injected (e.g. in tests).
    Raises OidcError so callers surface a clean 401 rather than an unhandled
    exception.
    """
    raise OidcError("JWKS key resolver is not configured")


def _resolve_principal_or_401(app, authorization: str | None) -> Principal:
    """Parse and verify the Bearer token, raising 401 on any failure.

    Dispatches between the API-key path and the OIDC path based on the token
    shape (see module docstring).  Both paths converge on a Principal.
    """
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="missing API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[len("Bearer "):]

    if token.startswith(KEY_PREFIX):
        # API-key path (unchanged behaviour).
        pool = _admin_pool(app)
        with pool.connection() as conn:
            resolved: ResolvedKey | None = resolve(conn, token)

        if resolved is None:
            raise HTTPException(
                status_code=401,
                detail="invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return Principal(
            tenant_id=resolved.tenant_id,
            role=resolved.role,
            auth_method="api_key",
            api_key_id=resolved.api_key_id,
        )

    elif looks_like_jwt(token):
        # OIDC path.
        key_resolver = getattr(app.state, "oidc_key_resolver", None) or _default_oidc_key_resolver

        pool = _admin_pool(app)

        def _find_config(issuer: str, audience: str):
            with pool.connection() as conn:
                return find_idp_config(conn, issuer, audience)

        try:
            oidc_principal = verify_oidc_token(
                token,
                find_config=_find_config,
                key_resolver=key_resolver,
            )
        except OidcError:
            raise HTTPException(
                status_code=401,
                detail="invalid OIDC token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # SCIM deactivation enforcement and role override.
        # Only consults scim_user when a subject was resolved from the token.
        # Lookup is always tenant-scoped (tenant_session sets app.tenant_id GUC).
        resolved_role = oidc_principal.role
        if oidc_principal.subject:
            with tenant_session(app.state.pool, oidc_principal.tenant_id) as scim_conn:
                scim_user = get_current_user_by_username(
                    scim_conn, oidc_principal.tenant_id, oidc_principal.subject
                )
            if scim_user is not None:
                if not scim_user.active:
                    raise HTTPException(
                        status_code=401,
                        detail="user deactivated",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                # Active SCIM user: its role overrides the OIDC-mapped role.
                resolved_role = scim_user.role

        return Principal(
            tenant_id=oidc_principal.tenant_id,
            role=resolved_role,
            auth_method="oidc",
            api_key_id=None,
        )

    else:
        # Non-JWT junk: keep API-key error messaging.
        raise HTTPException(
            status_code=401,
            detail="invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _role_grants(role: Role, perm: str) -> bool:
    """Return True if role grants the requested permission.

    read  -> viewer and editor
    write -> editor only
    """
    if perm == "read":
        return True  # both roles can read
    if perm == "write":
        return role == Role.editor
    return False


def _audit(
    app,
    principal: Principal,
    method: str,
    path: str,
    permission: str | None,
    decision: str,
    status_code: int,
) -> None:
    """Write one audit_log row in its own committed tenant_session.

    Opening a separate tenant_session guarantees the row commits regardless of
    what happens after this call (e.g. the deny path raises HTTPException after
    this function returns).
    """
    with tenant_session(app.state.pool, principal.tenant_id) as conn:
        record_access(
            conn,
            principal.tenant_id,
            api_key_id=principal.api_key_id,
            role=principal.role.value,
            method=method,
            path=path,
            permission=permission,
            decision=decision,
            status_code=status_code,
            auth_method=principal.auth_method,
        )


def _route_success_status(request: Request) -> int:
    """Return the declared success status code for the matched route, defaulting to 200.

    FastAPI leaves ``APIRoute.status_code`` as ``None`` when no ``status_code``
    argument is supplied to the decorator (the framework defaults to 200 later);
    treat ``None`` as 200 here.
    """
    route = request.scope.get("route")
    if isinstance(route, APIRoute) and route.status_code is not None:
        return route.status_code
    return 200


def make_tenant_dependency(app):
    """Return a FastAPI dependency that resolves an API key or OIDC token to a tenant UUID.

    The returned callable closes over `app` so it can access the admin pool
    lazily via app.state, mirroring how _resolve_planner closes over app.
    """

    def tenant_from_bearer(
        authorization: str | None = Header(default=None),
    ) -> UUID:
        """Resolve Authorization: Bearer <token> to the owning tenant_id."""
        return _resolve_principal_or_401(app, authorization).tenant_id

    return tenant_from_bearer


def make_scim_tenant_dependency(app):
    """Return a FastAPI dependency that resolves a SCIM bearer token to a tenant UUID.

    The dependency is independent of the API-key / OIDC dispatch and never
    calls _resolve_principal_or_401.  Only tokens with the ``scim_`` prefix
    are accepted; all other tokens (itw_ API keys, JWTs, junk) are rejected
    with 401.

    Steps:
    1. Require Authorization: Bearer <token>.
    2. Call resolve_scim_token on the admin pool (returns None for any failure).
    3. Return the tenant UUID on success; raise 401 otherwise.
    """

    def scim_tenant_from_bearer(
        authorization: str | None = Header(default=None),
    ) -> UUID:
        """Resolve a SCIM Bearer token to the owning tenant_id."""
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="missing SCIM token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = authorization[len("Bearer "):]

        admin_pool = _admin_pool(app)
        with admin_pool.connection() as conn:
            tenant_id = resolve_scim_token(conn, token)

        if tenant_id is None:
            raise HTTPException(
                status_code=401,
                detail="invalid SCIM token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return tenant_id

    return scim_tenant_from_bearer


def _meter_and_audit_allow(
    app,
    principal: Principal,
    request: Request,
    perm: str,
    success_status: int,
) -> bool:
    """Open one tenant_session and perform metering + allow-path audit.

    Returns True when the request is under quota and both the usage row and the
    allow audit row have been committed.  Returns False when the tenant's quota
    is exhausted; in that case NO writes are made (neither usage nor audit).

    Callers MUST handle the False case by committing a deny-429 audit row (via
    the existing ``_audit`` helper) and raising HTTPException(429) OUTSIDE this
    function — after the session has closed — so the transaction is not rolled
    back.
    """
    period_start = current_calendar_month_start()
    with tenant_session(app.state.pool, principal.tenant_id) as conn:
        quota_row = conn.execute(
            "SELECT monthly_request_quota FROM tenants WHERE tenant_id = %s",
            (principal.tenant_id,),
        ).fetchone()
        quota: int = quota_row[0]
        used = count_usage_in_window(conn, principal.tenant_id, period_start)
        if used >= quota:
            return False
        # Under quota: write usage row and allow audit row atomically.
        record_usage(
            conn,
            principal.tenant_id,
            api_key_id=principal.api_key_id,
            method=request.method,
            path=request.url.path,
            permission=perm,
        )
        record_access(
            conn,
            principal.tenant_id,
            api_key_id=principal.api_key_id,
            role=principal.role.value,
            method=request.method,
            path=request.url.path,
            permission=perm,
            decision="allow",
            status_code=success_status,
            auth_method=principal.auth_method,
        )
    return True


def make_permission_dependency(app):
    """Return a factory: require_permission(perm: str) -> FastAPI dependency.

    Usage in create_app:
        require_permission = make_permission_dependency(app)
        _read  = Depends(require_permission("read"))
        _write = Depends(require_permission("write"))

    Each returned dependency resolves the Bearer token (401 on failure) then
    checks the role (403 on insufficient permission) and returns the tenant UUID.

    One audit_log row is written per call: ``allow`` when the role grants the
    permission, ``deny`` (committed before raising) when it does not.  No audit
    row is written on 401 (principal unresolved).

    Usage metering runs on the allow branch only: one ``usage_event`` row is
    written atomically with the allow audit row.  When the tenant's monthly
    quota is exhausted a ``deny`` audit row with ``status_code=429`` is
    committed (before raising) and HTTP 429 is returned; no usage row is written.
    """

    def require_permission(perm: str):  # perm in {"read", "write"}
        def _dep(
            request: Request,
            authorization: str | None = Header(default=None),
        ) -> UUID:
            principal = _resolve_principal_or_401(app, authorization)
            if not _role_grants(principal.role, perm):
                # Deny path: commit the audit row BEFORE raising so it persists
                # even though the request ultimately returns 403.
                _audit(
                    app,
                    principal,
                    method=request.method,
                    path=request.url.path,
                    permission=perm,
                    decision="deny",
                    status_code=403,
                )
                raise HTTPException(
                    status_code=403, detail="insufficient permissions"
                )

            # Allow path: meter usage and audit in one committed transaction.
            success_status = _route_success_status(request)
            allowed = _meter_and_audit_allow(
                app, principal, request, perm, success_status
            )
            if not allowed:
                # Quota exhausted: commit deny-429 audit row BEFORE raising.
                _audit(
                    app,
                    principal,
                    method=request.method,
                    path=request.url.path,
                    permission=perm,
                    decision="deny",
                    status_code=429,
                )
                raise HTTPException(
                    status_code=429, detail="monthly request quota exceeded"
                )
            return principal.tenant_id

        return _dep

    return require_permission
