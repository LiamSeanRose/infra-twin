"""The query API.

Endpoints are tenant-scoped via API-key Bearer authentication.  Each request
resolves the API key to a tenant UUID and opens a tenant session so Row-Level
Security applies to every statement.  The app is built by a factory so tests
can inject a pool and ``uvicorn`` can run it via ``--factory``.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, field_validator
from strawberry.fastapi import GraphQLRouter

from infra_twin.api.auth import make_permission_dependency, make_scim_tenant_dependency, make_tenant_dependency, require_bootstrap_admin
from infra_twin.api.graphql_schema import schema as graphql_schema
from infra_twin.api.nlquery import ClaudePlanner, Planner, answer_question
from infra_twin.onboarding import render_aws_cloudformation
from infra_twin.collectors.aws.events import UnsupportedEventError, parse_event
from infra_twin.collectors.aws.flowlogs import FlowLogParseError, parse_flow_logs
from infra_twin.collectors.k8s.events import (
    UnsupportedEventError as K8sUnsupportedEventError,
    parse_watch_event,
)
from infra_twin.connector_sdk import CIRef, ConnectorDelta
from infra_twin.core_model import CIType
from infra_twin.db.api_keys import IssuedKey, Role, provision_tenant
from infra_twin.db.audit import list_audit
from infra_twin.db.config import admin_dsn
from infra_twin.db.connector_health import ConnectorRunRepository
from infra_twin.db.connectors import Connector as RegisteredConnector
from infra_twin.db.connectors import ConnectorRegistry
from infra_twin.db.idp_config import find_idp_config, upsert_idp_config
from infra_twin.db.scim_users import (
    create_or_replace_user,
    deactivate_user,
    get_current_user_by_username,
    get_user_by_id,
    issue_scim_token,
    list_users,
)
from infra_twin.api.scim_models import ScimPatchBody, ScimTokenBody, ScimUserCreateBody, ScimUserPutBody
from infra_twin.db.pool import make_pool
from infra_twin.db.repositories import CIRepository
from infra_twin.db.session import tenant_session
from infra_twin.db.usage import count_usage_in_window, current_calendar_month_start
from infra_twin.query import blast_radius, change_feed, reachability, topology
from infra_twin.query.rca import RcaResult, root_cause
from infra_twin.query.whatif import (
    WHATIF_CHANGE_KINDS,
    UnknownChangeKindError,
    WhatIfEdgeHop,
    WhatIfImpact,
    what_if_impact,
)
from infra_twin.reconciliation import age_inferred_edges, apply_event_delta, sweep_history
from infra_twin.reconciliation.candidates import (
    CandidateAlreadyResolvedError,
    CandidateNotFoundError,
    accept_candidate,
    dismiss_candidate,
    generate_candidates,
)
from infra_twin.reconciliation.unmerge import (
    MergeAlreadyReversedError,
    MergeNotFoundError,
    unmerge,
)
from infra_twin.reconciliation.findings import evaluate_findings_with_summary
from infra_twin.reconciliation.anomalies import (
    DEFAULT_SCAN_WINDOW,
    RULE_PUBLIC_IP_ON_DATABASE,
    RULE_SECURITY_GROUP_OPENED_TO_WORLD,
    evaluate_anomalies_with_summary,
)
from infra_twin.db.findings import FindingRepository
from infra_twin.db.freshness import FreshnessSloRepository
from infra_twin.db.retention import RetentionPolicyRepository
from infra_twin.db.merges import MergeReviewRepository
from infra_twin.db.notifications import NotificationRepository

STALE_AFTER_SECONDS = 24 * 60 * 60

_DEFAULT_CORS = "http://localhost:5173,http://127.0.0.1:5173"


class CreateTenantBody(BaseModel):
    name: str
    role: Role = Role.editor
    monthly_request_quota: int | None = None

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("name must not be empty or whitespace")
        return v

    @field_validator("monthly_request_quota")
    @classmethod
    def quota_positive(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("monthly_request_quota must be >= 1")
        return v


class AskBody(BaseModel):
    question: str


class RegisterConnectorBody(BaseModel):
    type: str
    display_name: str
    config: dict = {}
    enabled: bool = True


class AwsEventBody(BaseModel):
    record: dict


class K8sEventBody(BaseModel):
    # One watch event per request; the live long-poll loop and batch intake are out of scope.
    event: dict


class FlowLogRecord(BaseModel):
    srcaddr: str
    dstaddr: str
    srcport: int
    dstport: int
    protocol: int
    action: str
    start: int
    end: int


class FlowLogsBody(BaseModel):
    records: list[FlowLogRecord]


class RcaBody(BaseModel):
    target_id: UUID
    incident_at: datetime
    lookback_hours: float = 24.0
    max_depth: int = 3

    @field_validator("lookback_hours")
    @classmethod
    def lookback_positive(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("lookback_hours must be > 0")
        return v

    @field_validator("max_depth")
    @classmethod
    def depth_in_range(cls, v: int) -> int:
        if v < 1 or v > 10:
            raise ValueError("max_depth must be between 1 and 10")
        return v


class WhatIfBody(BaseModel):
    change_kind: str
    max_depth: int = 4
    min_confidence: float = 0.0
    max_fanout: int = 1000

    @field_validator("change_kind")
    @classmethod
    def kind_in_whitelist(cls, v: str) -> str:
        if v not in WHATIF_CHANGE_KINDS:
            raise ValueError(f"change_kind must be one of {sorted(WHATIF_CHANGE_KINDS)}")
        return v

    @field_validator("max_depth")
    @classmethod
    def depth_in_range(cls, v: int) -> int:
        if v < 1 or v > 10:
            raise ValueError("max_depth must be between 1 and 10")
        return v

    @field_validator("min_confidence")
    @classmethod
    def conf_in_range(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("min_confidence must be between 0.0 and 1.0")
        return v

    @field_validator("max_fanout")
    @classmethod
    def fanout_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_fanout must be >= 1")
        return v


class AnomalyEvaluateBody(BaseModel):
    since: datetime | None = None
    until: datetime | None = None


class CreateSubscriptionBody(BaseModel):
    url: str
    enabled: bool = True
    kind: str = "webhook"

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("url must not be empty or whitespace")
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("url must be an http(s) URL")
        return v

    @field_validator("kind")
    @classmethod
    def kind_valid(cls, v: str) -> str:
        if v not in ("webhook", "slack"):
            raise ValueError("kind must be one of ('webhook', 'slack')")
        return v


class IdpConfigBody(BaseModel):
    issuer: str
    audience: str
    role_claim: str = "role"
    role_claim_map: dict[str, str] = {}
    default_role: Role = Role.viewer

    @field_validator("issuer", "audience")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be empty or whitespace")
        return v

    @field_validator("role_claim_map")
    @classmethod
    def map_values_valid(cls, v: dict[str, str]) -> dict[str, str]:
        valid = {"viewer", "editor"}
        for key, val in v.items():
            if val not in valid:
                raise ValueError(
                    f"role_claim_map value {val!r} is not valid; must be one of {valid}"
                )
        return v


class MergeRecordResponse(BaseModel):
    merge_id: UUID
    canonical_ci_id: UUID
    merged_source: str
    merged_external_id: str
    matched_alias_key: str
    evidence: str
    merged_at: datetime


class UnmergeResponse(BaseModel):
    unmerge_id: UUID
    original_merge_id: UUID
    canonical_ci_id: UUID
    restored_ci_id: UUID
    restored_source: str
    restored_external_id: str
    evidence: str
    unmerged_at: datetime


class AliasKeyBindingResponse(BaseModel):
    alias_key: str
    ci_type: str
    source: str
    observed_at: datetime


class CIMergeProvenanceResponse(BaseModel):
    canonical_ci_id: UUID
    merges: list[MergeRecordResponse]
    alias_keys: list[AliasKeyBindingResponse]


class MergeCandidateResponse(BaseModel):
    candidate_id: UUID
    ci_id_a: UUID
    ci_id_b: UUID
    ci_type: str
    confidence: float
    evidence: str
    status: str
    resolved_merge_id: UUID | None
    generated_at: datetime
    resolved_at: datetime | None


class AcceptCandidateResponse(BaseModel):
    candidate_id: UUID
    merge_id: UUID
    canonical_ci_id: UUID
    merged_ci_id: UUID
    merged_source: str
    merged_external_id: str
    confidence: float
    evidence: str
    resolved_at: datetime


class FreshnessSloBody(BaseModel):
    expected_interval_seconds: int

    @field_validator("expected_interval_seconds")
    @classmethod
    def positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("expected_interval_seconds must be >= 1")
        return v


class RetentionPolicyBody(BaseModel):
    retain_closed_days: int
    enabled: bool = True

    @field_validator("retain_closed_days")
    @classmethod
    def positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("retain_closed_days must be >= 1")
        return v


# Source labels reserved for internal connectors and event/telemetry pipelines.
# The webhook endpoint rejects any caller-supplied source whose stripped, lower-cased
# form matches one of these names so that per-source freshness SLO rows stamped by
# the webhook cannot collide with — or silently override — the internal connector
# lineage tracked under these names.
#
# Discovery-connector source names come from the ``source`` constant each connector
# declares (aws, azure, gcp, kubernetes, saas, db).  Event/telemetry source names are
# the literal strings passed to ``apply_event_delta`` by the existing handlers:
# "aws-events" (ingest_aws_event), "k8s-events" (ingest_k8s_event),
# "aws-flowlogs" (ingest_flowlogs).
_RESERVED_WEBHOOK_SOURCES: frozenset[str] = frozenset({
    "aws", "azure", "gcp", "kubernetes", "saas", "db",   # discovery-connector source names
    "aws-events", "k8s-events", "aws-flowlogs",          # internal event/telemetry sources
})


class WebhookEventBody(BaseModel):
    """Request body for POST /events/webhook.

    ``source`` is a tenant-assigned label (e.g. "github-actions", "my-cmdb") that
    becomes the connector_runs.source / raw_facts.source value and drives per-source
    freshness SLO evaluation.  The following source names are reserved for internal
    connectors and telemetry pipelines and will be rejected with HTTP 422:

        Discovery connectors: aws, azure, gcp, kubernetes, saas, db
        Event/telemetry sources: aws-events, k8s-events, aws-flowlogs

    The match is case-insensitive and whitespace-trimmed so "AWS", " aws ", etc. are
    also rejected.

    ``delta`` carries the already-canonical ConnectorDelta — no provider-specific parsing
    is performed by this endpoint.

    ``observed_at`` is an optional ISO-8601 timestamp; when absent it defaults to
    datetime.now(timezone.utc).  Naive datetimes are normalised to UTC.
    """

    source: str
    delta: ConnectorDelta
    observed_at: datetime | None = None


def _connector_dict(c: RegisteredConnector) -> dict:
    """Serialize a registry Connector to the public response shape (no tenant_id)."""
    return {
        "connector_id": str(c.connector_id),
        "type": c.type,
        "display_name": c.display_name,
        "config": c.config,
        "enabled": c.enabled,
        "created_at": c.created_at.isoformat(),
    }


def create_app(
    pool: ConnectionPool | None = None,
    planner: Planner | None = None,
    oidc_key_resolver=None,
) -> FastAPI:
    app = FastAPI(title="infra-twin", version="0.1.0")
    app.state.pool = pool or make_pool()
    app.state.planner = planner
    app.state.admin_pool = None  # lazily created by auth._admin_pool
    app.state.oidc_key_resolver = oidc_key_resolver  # injectable for tests

    origins = [o for o in os.environ.get("INFRA_TWIN_CORS_ORIGINS", _DEFAULT_CORS).split(",") if o]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Build the tenant dependency and permission dependency factory once,
    # closing over this app instance.
    _tenant = make_tenant_dependency(app)
    require_permission = make_permission_dependency(app)
    _read = Depends(require_permission("read"))
    _write = Depends(require_permission("write"))
    _scim_tenant = Depends(make_scim_tenant_dependency(app))

    # -----------------------------------------------------------------------
    # GraphQL surface (POST /graphql, GET /graphql)
    # -----------------------------------------------------------------------

    read_dep = require_permission("read")

    async def get_graphql_context(tenant: UUID = Depends(read_dep)) -> dict:
        return {"tenant_id": tenant, "pool": app.state.pool}

    graphql_router = GraphQLRouter(graphql_schema, context_getter=get_graphql_context, graphql_ide="graphiql")
    app.include_router(graphql_router, prefix="/graphql")

    def _resolve_planner() -> Planner:
        if app.state.planner is not None:
            return app.state.planner
        if os.environ.get("ANTHROPIC_API_KEY"):
            app.state.planner = ClaudePlanner()
            return app.state.planner
        raise HTTPException(
            status_code=503, detail="NL query is not configured (set ANTHROPIC_API_KEY)"
        )

    # -----------------------------------------------------------------------
    # Unauthenticated routes
    # -----------------------------------------------------------------------

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    # -----------------------------------------------------------------------
    # Bootstrap-admin route: create tenant + issue first API key
    # -----------------------------------------------------------------------

    @app.post("/tenants", status_code=201, dependencies=[Depends(require_bootstrap_admin)])
    def create_tenant(body: CreateTenantBody) -> dict:
        from infra_twin.api.auth import _admin_pool

        with _admin_pool(app).connection() as conn:
            issued: IssuedKey = provision_tenant(
                conn,
                body.name,
                role=body.role,
                monthly_request_quota=body.monthly_request_quota,
            )

        return {
            "tenant_id": str(issued.tenant_id),
            "name": body.name,
            "created_at": issued.created_at.isoformat(),
            "role": issued.role.value,
            "api_key": issued.plaintext,
        }

    def _idp_config_dict(cfg) -> dict:
        """Serialize a TenantIdpConfig to the no-secret response shape."""
        return {
            "idp_config_id": str(cfg.idp_config_id),
            "tenant_id": str(cfg.tenant_id),
            "issuer": cfg.issuer,
            "audience": cfg.audience,
            "role_claim": cfg.role_claim,
            "role_claim_map": cfg.role_claim_map,
            "default_role": cfg.default_role.value,
            "created_at": cfg.created_at.isoformat(),
            "disabled_at": cfg.disabled_at.isoformat() if cfg.disabled_at else None,
        }

    @app.put("/tenants/{tenant_id}/idp-config", dependencies=[Depends(require_bootstrap_admin)])
    def put_idp_config(tenant_id: UUID, body: IdpConfigBody) -> dict:
        from infra_twin.api.auth import _admin_pool

        with _admin_pool(app).connection() as conn:
            cfg = upsert_idp_config(
                conn,
                tenant_id=tenant_id,
                issuer=body.issuer,
                audience=body.audience,
                role_claim=body.role_claim,
                role_claim_map=body.role_claim_map,
                default_role=body.default_role,
            )
        return _idp_config_dict(cfg)

    @app.get("/tenants/{tenant_id}/idp-config", dependencies=[Depends(require_bootstrap_admin)])
    def get_idp_config(tenant_id: UUID) -> list[dict]:
        from infra_twin.api.auth import _admin_pool

        with _admin_pool(app).connection() as conn:
            rows = conn.execute(
                """
                SELECT
                    idp_config_id, tenant_id, issuer, audience,
                    role_claim, role_claim_map, default_role, created_at, disabled_at
                FROM tenant_idp_config
                WHERE tenant_id = %s
                ORDER BY created_at ASC
                """,
                (tenant_id,),
            ).fetchall()

        from infra_twin.db.idp_config import _row_to_config
        return [_idp_config_dict(_row_to_config(r)) for r in rows]

    # -----------------------------------------------------------------------
    # Tenant-scoped routes (all use API-key Bearer auth)
    # -----------------------------------------------------------------------

    # READ endpoints (viewer + editor)

    @app.get("/cis")
    def list_cis(type: str | None = None, tenant: UUID = _read) -> list[dict]:
        ci_type = CIType(type) if type else None
        with tenant_session(app.state.pool, tenant) as conn:
            cis = CIRepository(conn, tenant).get_current(type=ci_type)
        return [ci.model_dump(mode="json") for ci in cis]

    @app.get("/graph")
    def graph(limit: int = 500, tenant: UUID = _read) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            topo = topology(conn, tenant, limit=limit)
        return {
            "nodes": [
                {"id": str(n.id), "type": n.type, "external_id": n.external_id, "name": n.name}
                for n in topo.nodes
            ],
            "edges": [
                {
                    "id": str(e.id),
                    "type": e.type,
                    "from_id": str(e.from_id),
                    "to_id": str(e.to_id),
                    "source": e.source,
                    "confidence": e.confidence,
                }
                for e in topo.edges
            ],
        }

    @app.get("/cis/{ci_id}/blast-radius")
    def blast(
        ci_id: UUID,
        max_depth: int = 4,
        min_confidence: float = 0.0,
        max_fanout: int = 1000,
        tenant: UUID = _read,
    ) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            if CIRepository(conn, tenant).get_current_by_id(ci_id) is None:
                raise HTTPException(status_code=404, detail="CI not found")
            result = blast_radius(
                conn,
                tenant,
                ci_id,
                max_depth=max_depth,
                min_confidence=min_confidence,
                max_fanout=max_fanout,
            )
        return {
            "source_id": str(result.source_id),
            "max_depth": result.max_depth,
            "impacted": [
                {
                    "id": str(i.id),
                    "type": i.type,
                    "name": i.name,
                    "distance": i.distance,
                }
                for i in result.impacted
            ],
            "truncated_supernodes": [
                {"id": str(s.id), "degree": s.degree, "depth": s.depth}
                for s in result.truncated_supernodes
            ],
        }

    @app.get("/cis/{ci_id}/reachability")
    def reach(
        ci_id: UUID,
        max_depth: int = 6,
        min_confidence: float = 0.0,
        max_fanout: int = 1000,
        tenant: UUID = _read,
    ) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            if CIRepository(conn, tenant).get_current_by_id(ci_id) is None:
                raise HTTPException(status_code=404, detail="CI not found")
            result = reachability(
                conn,
                tenant,
                ci_id,
                max_depth=max_depth,
                min_confidence=min_confidence,
                max_fanout=max_fanout,
            )
        return {
            "target_id": str(result.target_id),
            "max_depth": result.max_depth,
            "reached_by_internet": result.reached_by_internet,
            "sources": [
                {
                    "id": str(s.id),
                    "type": s.type,
                    "name": s.name,
                    "distance": s.distance,
                    "is_internet": s.is_internet,
                    "path": [
                        {
                            "from_id": str(h.from_id),
                            "to_id": str(h.to_id),
                            "edge_type": h.edge_type,
                            "evidence": h.evidence,
                        }
                        for h in s.path
                    ],
                }
                for s in result.sources
            ],
            "truncated_supernodes": [
                {"id": str(sn.id), "degree": sn.degree, "depth": sn.depth}
                for sn in result.truncated_supernodes
            ],
        }

    @app.get("/changes")
    def changes(days: int = 7, tenant: UUID = _read) -> list[dict]:
        with tenant_session(app.state.pool, tenant) as conn:
            events = change_feed(conn, tenant, days=days)
        return [
            {
                "entity": e.entity,
                "kind": e.kind,
                "at": e.at.isoformat(),
                "id": str(e.id),
                "type": e.type,
                "name": e.name,
                "from_id": str(e.from_id) if e.from_id else None,
                "to_id": str(e.to_id) if e.to_id else None,
            }
            for e in events
        ]

    @app.post("/rca")
    def rca(body: RcaBody, tenant: UUID = _read) -> dict:
        incident_at = body.incident_at
        if incident_at.tzinfo is None:
            incident_at = incident_at.replace(tzinfo=timezone.utc)
        with tenant_session(app.state.pool, tenant) as conn:
            if CIRepository(conn, tenant).get_current_by_id(body.target_id) is None:
                raise HTTPException(status_code=404, detail="CI not found")
            result: RcaResult = root_cause(
                conn,
                tenant,
                target_id=body.target_id,
                incident_at=incident_at,
                lookback=timedelta(hours=body.lookback_hours),
                max_depth=body.max_depth,
            )

        def _event_dict(e) -> dict:
            return {
                "entity": e.entity,
                "kind": e.kind,
                "at": e.at.isoformat(),
                "id": str(e.id),
                "type": e.type,
                "name": e.name,
                "from_id": str(e.from_id) if e.from_id else None,
                "to_id": str(e.to_id) if e.to_id else None,
            }

        return {
            "target_id": str(result.target_id),
            "incident_at": result.incident_at.isoformat(),
            "since": result.since.isoformat(),
            "until": result.until.isoformat(),
            "max_depth": result.max_depth,
            "candidates": [
                {
                    "event": _event_dict(c.event),
                    "distance": c.distance,
                    "score": c.score,
                    "evidence": c.evidence,
                }
                for c in result.candidates
            ],
        }

    @app.post("/cis/{ci_id}/whatif")
    def whatif(ci_id: UUID, body: WhatIfBody, tenant: UUID = _read) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            if CIRepository(conn, tenant).get_current_by_id(ci_id) is None:
                raise HTTPException(status_code=404, detail="CI not found")
            try:
                result: WhatIfImpact = what_if_impact(
                    conn,
                    tenant,
                    ci_id,
                    change_kind=body.change_kind,
                    max_depth=body.max_depth,
                    min_confidence=body.min_confidence,
                    max_fanout=body.max_fanout,
                )
            except UnknownChangeKindError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "target_id": str(result.target_id),
            "change_kind": result.change_kind,
            "method": result.method,
            "disclaimer": result.disclaimer,
            "max_depth": result.max_depth,
            "impacted": [
                {
                    "id": str(i.id),
                    "type": i.type,
                    "external_id": i.external_id,
                    "name": i.name,
                    "distance": i.distance,
                    "confidence": i.confidence,
                    "evidence": [
                        {
                            "from_id": str(h.from_id),
                            "to_id": str(h.to_id),
                            "edge_type": h.edge_type,
                            "source": h.source,
                            "confidence": h.confidence,
                        }
                        for h in i.evidence
                    ],
                }
                for i in result.impacted
            ],
            "truncated_supernodes": [
                {"id": str(s.id), "degree": s.degree, "depth": s.depth}
                for s in result.truncated_supernodes
            ],
        }

    @app.post("/ask")
    def ask(body: AskBody, tenant: UUID = _read) -> dict:
        planner = _resolve_planner()
        with tenant_session(app.state.pool, tenant) as conn:
            answer = answer_question(conn, tenant, body.question, planner)
        return {
            "question": answer.question,
            "answered": answer.answered,
            "template": answer.template,
            "params": answer.params,
            "summary": answer.summary,
            "data": answer.data,
        }

    @app.get("/connector-health/runs")
    def connector_health_runs(tenant: UUID = _read) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            summaries = ConnectorRunRepository(conn, tenant).latest_per_source()
        sources = [
            {
                "source": s.source,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at is not None else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at is not None else None,
                "error": s.error,
                "age_seconds": s.age_seconds,
                "stale": s.age_seconds is None or s.age_seconds > STALE_AFTER_SECONDS,
            }
            for s in summaries
        ]
        return {"sources": sources}

    @app.get("/connectors")
    def list_connectors(tenant: UUID = _read) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            connectors = ConnectorRegistry(conn, tenant).list()
        return {"connectors": [_connector_dict(c) for c in connectors]}

    @app.get("/audit-log")
    def get_audit_log(limit: int = 200, tenant: UUID = _read) -> list[dict]:
        with tenant_session(app.state.pool, tenant) as conn:
            entries = list_audit(conn, limit=limit)
        return [
            {
                "audit_id": str(e.audit_id),
                "api_key_id": str(e.api_key_id) if e.api_key_id else None,
                "role": e.role,
                "method": e.method,
                "path": e.path,
                "permission": e.permission,
                "decision": e.decision,
                "status_code": e.status_code,
                "occurred_at": e.occurred_at.isoformat(),
                "auth_method": e.auth_method,
            }
            for e in entries
        ]

    @app.get("/usage")
    def get_usage(tenant: UUID = _read) -> dict:
        period_start = current_calendar_month_start()
        with tenant_session(app.state.pool, tenant) as conn:
            quota_row = conn.execute(
                "SELECT monthly_request_quota FROM tenants WHERE tenant_id = %s",
                (tenant,),
            ).fetchone()
            quota: int = quota_row[0]
            used_this_month = count_usage_in_window(conn, tenant, period_start)
        return {
            "quota": quota,
            "used_this_month": used_this_month,
            "remaining": max(0, quota - used_this_month),
            "period_start": period_start.isoformat(),
        }

    @app.get("/onboarding/aws-cloudformation")
    def get_aws_cloudformation(tenant: UUID = _read) -> Response:
        truster_role_arn = os.environ.get("INFRA_TWIN_AWS_TRUSTER_ROLE_ARN", "").strip()
        truster_account_id = os.environ.get("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", "").strip()

        if not truster_role_arn and not truster_account_id:
            raise HTTPException(
                status_code=503,
                detail="AWS onboarding is not configured",
            )

        rendered = render_aws_cloudformation(
            external_id=str(tenant),
            truster_role_arn=truster_role_arn or None,
            truster_account_id=truster_account_id or None,
        )
        return Response(content=rendered, media_type="text/yaml")

    # WRITE endpoints (editor only)

    @app.post("/connectors", status_code=201)
    def register_connector(
        body: RegisterConnectorBody, tenant: UUID = _write
    ) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            connector = ConnectorRegistry(conn, tenant).register(
                type=body.type,
                display_name=body.display_name,
                config=body.config,
                enabled=body.enabled,
            )
        return _connector_dict(connector)

    @app.post("/connectors/{connector_id}/enable")
    def enable_connector(connector_id: UUID, tenant: UUID = _write) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            connector = ConnectorRegistry(conn, tenant).set_enabled(connector_id, True)
        if connector is None:
            raise HTTPException(status_code=404, detail="Connector not found")
        return _connector_dict(connector)

    @app.post("/connectors/{connector_id}/disable")
    def disable_connector(connector_id: UUID, tenant: UUID = _write) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            connector = ConnectorRegistry(conn, tenant).set_enabled(connector_id, False)
        if connector is None:
            raise HTTPException(status_code=404, detail="Connector not found")
        return _connector_dict(connector)

    @app.post("/events/aws")
    def ingest_aws_event(body: AwsEventBody, tenant: UUID = _write) -> dict:
        raw_time = body.record.get("eventTime")
        observed_at: datetime
        if raw_time:
            try:
                normalised = raw_time.replace("Z", "+00:00") if raw_time.endswith("Z") else raw_time
                dt = datetime.fromisoformat(normalised)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                observed_at = dt
            except (ValueError, TypeError):
                observed_at = datetime.now(timezone.utc)
        else:
            observed_at = datetime.now(timezone.utc)

        try:
            delta = parse_event(body.record)
        except UnsupportedEventError as exc:
            raise HTTPException(status_code=422, detail=f"unsupported event: {exc}") from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        try:
            result = apply_event_delta(app.state.pool, tenant, delta, observed_at=observed_at)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        return {
            "connector_run_id": str(result.connector_run_id),
            "cis_created": result.cis_created,
            "cis_updated": result.cis_updated,
            "cis_unchanged": result.cis_unchanged,
            "cis_closed": result.cis_closed,
            "edges_written": result.edges_written,
            "edges_closed": result.edges_closed,
        }

    @app.post("/events/k8s")
    def ingest_k8s_event(body: K8sEventBody, tenant: UUID = _write) -> dict:
        # Derive observed_at from metadata.creationTimestamp when present (normalise
        # trailing Z to +00:00), otherwise fall back to now().
        observed_at: datetime
        obj = body.event.get("object")
        meta: dict = (obj.get("metadata") or {}) if isinstance(obj, dict) else {}
        raw_ts: str | None = meta.get("creationTimestamp")
        if raw_ts:
            try:
                normalised = raw_ts.replace("Z", "+00:00") if raw_ts.endswith("Z") else raw_ts
                dt = datetime.fromisoformat(normalised)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                observed_at = dt
            except (ValueError, TypeError):
                observed_at = datetime.now(timezone.utc)
        else:
            observed_at = datetime.now(timezone.utc)

        try:
            delta = parse_watch_event(body.event, observed_at=observed_at)
        except K8sUnsupportedEventError as exc:
            raise HTTPException(status_code=422, detail=f"unsupported event: {exc}") from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        try:
            result = apply_event_delta(
                app.state.pool, tenant, delta, observed_at=observed_at, source="k8s-events"
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        return {
            "connector_run_id": str(result.connector_run_id),
            "cis_created": result.cis_created,
            "cis_updated": result.cis_updated,
            "cis_unchanged": result.cis_unchanged,
            "cis_closed": result.cis_closed,
            "edges_written": result.edges_written,
            "edges_closed": result.edges_closed,
        }

    @app.post("/events/webhook")
    def ingest_webhook_event(body: WebhookEventBody, tenant: UUID = _write) -> dict:
        """Accept a pre-parsed ConnectorDelta from any external system.

        Unlike /events/aws and /events/k8s this endpoint performs no provider-specific
        parsing — the caller supplies an already-canonical ConnectorDelta together with a
        tenant-assigned source label.  The label must not be empty/whitespace and must not
        shadow an internal connector or event/telemetry source (see _RESERVED_WEBHOOK_SOURCES).

        Reserved source names (case-insensitive, whitespace-trimmed):
            Discovery connectors: aws, azure, gcp, kubernetes, saas, db
            Event/telemetry sources: aws-events, k8s-events, aws-flowlogs

        Status codes:
            200  success
            401  missing/invalid API key
            403  viewer key (insufficient permissions)
            422  empty/blank source, reserved source, malformed ConnectorDelta,
                 or ValueError from apply_event_delta
        """
        # Validate source.
        if not body.source.strip():
            raise HTTPException(status_code=422, detail="source must not be empty or whitespace")
        if body.source.strip().lower() in _RESERVED_WEBHOOK_SOURCES:
            raise HTTPException(
                status_code=422,
                detail=f"source {body.source!r} is reserved for an internal connector",
            )

        # Resolve observed_at; normalise naive datetimes to UTC.
        observed_at: datetime
        if body.observed_at is not None:
            dt = body.observed_at
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            observed_at = dt
        else:
            observed_at = datetime.now(timezone.utc)

        try:
            result = apply_event_delta(
                app.state.pool, tenant, body.delta, observed_at=observed_at, source=body.source
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        return {
            "connector_run_id": str(result.connector_run_id),
            "cis_created": result.cis_created,
            "cis_updated": result.cis_updated,
            "cis_unchanged": result.cis_unchanged,
            "cis_closed": result.cis_closed,
            "edges_written": result.edges_written,
            "edges_closed": result.edges_closed,
        }

    @app.post("/telemetry/flowlogs")
    def ingest_flowlogs(body: FlowLogsBody, tenant: UUID = _write) -> dict:
        # Compute observed_at = max end across records, falling back to now.
        observed_at: datetime
        try:
            max_end = max((r.end for r in body.records), default=None)
            if max_end is not None:
                observed_at = datetime.fromtimestamp(max_end, tz=timezone.utc)
            else:
                observed_at = datetime.now(timezone.utc)
        except (TypeError, ValueError, OSError):
            observed_at = datetime.now(timezone.utc)

        # Build the tenant-scoped IP->CIRef resolver from current ec2_instance CIs.
        with tenant_session(app.state.pool, tenant) as conn:
            ec2_cis = CIRepository(conn, tenant).get_current(type=CIType.ec2_instance)

        ip_to_ref: dict[str, CIRef] = {}
        for ci in ec2_cis:
            ip = ci.attributes.get("private_ip")
            if not ip:
                continue
            # Deterministic on duplicate IPs: keep lexicographically smallest external_id.
            if ip not in ip_to_ref or ci.external_id < ip_to_ref[ip].external_id:
                ip_to_ref[ip] = CIRef(type=CIType.ec2_instance, external_id=ci.external_id)

        def resolver(ip: str) -> CIRef | None:
            return ip_to_ref.get(ip)

        records_as_dicts = [r.model_dump() for r in body.records]

        try:
            delta = parse_flow_logs(records_as_dicts, resolve=resolver)
        except (FlowLogParseError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        try:
            result = apply_event_delta(
                app.state.pool, tenant, delta, observed_at=observed_at, source="aws-flowlogs"
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        return {
            "connector_run_id": str(result.connector_run_id),
            "cis_created": result.cis_created,
            "cis_updated": result.cis_updated,
            "cis_unchanged": result.cis_unchanged,
            "cis_closed": result.cis_closed,
            "edges_written": result.edges_written,
            "edges_closed": result.edges_closed,
        }

    @app.post("/findings/evaluate")
    def evaluate(tenant: UUID = _write) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            summary, _ = evaluate_findings_with_summary(conn, tenant)
        return {
            "evaluated": summary.evaluated,
            "opened": summary.opened,
            "resolved": summary.resolved,
            "open_count": summary.open_count,
        }

    @app.get("/findings")
    def list_findings(rule_id: str | None = None, tenant: UUID = _read) -> list[dict]:
        with tenant_session(app.state.pool, tenant) as conn:
            repo = FindingRepository(conn, tenant)
            findings = repo.get_open(rule_id=rule_id)
            ci_repo = CIRepository(conn, tenant)
            out = []
            for f in findings:
                ci = ci_repo.get_current_by_id(f.subject_ci_id)
                out.append({
                    "id": str(f.id),
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "subject_ci_id": str(f.subject_ci_id),
                    "subject_ci_type": ci.type.value if ci else None,
                    "subject_ci_name": ci.name if ci else None,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "status": f.status,
                    "detected_at": f.detected_at.isoformat(),
                })
        return out

    @app.post("/anomalies/evaluate")
    def evaluate_anomalies_endpoint(body: AnomalyEvaluateBody, tenant: UUID = _write) -> dict:
        # Normalize until
        if body.until is None:
            until = datetime.now(timezone.utc)
        elif body.until.tzinfo is None:
            until = body.until.replace(tzinfo=timezone.utc)
        else:
            until = body.until
        # Normalize since
        if body.since is None:
            since = until - DEFAULT_SCAN_WINDOW
        elif body.since.tzinfo is None:
            since = body.since.replace(tzinfo=timezone.utc)
        else:
            since = body.since
        if since >= until:
            raise HTTPException(status_code=422, detail="since must be before until")
        with tenant_session(app.state.pool, tenant) as conn:
            summary, _ = evaluate_anomalies_with_summary(conn, tenant, since=since, until=until)
        return {
            "scanned_events": summary.scanned_events,
            "opened": summary.opened,
            "resolved": summary.resolved,
            "open_count": summary.open_count,
            "since": since.isoformat(),
            "until": until.isoformat(),
        }

    @app.get("/anomalies")
    def list_anomalies(rule_id: str | None = None, tenant: UUID = _read) -> list[dict]:
        with tenant_session(app.state.pool, tenant) as conn:
            repo = FindingRepository(conn, tenant)
            if rule_id is not None:
                findings = repo.get_open(rule_id=rule_id)
            else:
                # Return only anomaly-rule findings; never include risk findings from findings.py
                findings = (
                    repo.get_open(rule_id=RULE_PUBLIC_IP_ON_DATABASE)
                    + repo.get_open(rule_id=RULE_SECURITY_GROUP_OPENED_TO_WORLD)
                )
                findings.sort(key=lambda f: (f.detected_at, str(f.id)), reverse=True)
            ci_repo = CIRepository(conn, tenant)
            out = []
            for f in findings:
                ci = ci_repo.get_current_by_id(f.subject_ci_id)
                out.append({
                    "id": str(f.id),
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "subject_ci_id": str(f.subject_ci_id),
                    "subject_ci_type": ci.type.value if ci else None,
                    "subject_ci_name": ci.name if ci else None,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "status": f.status,
                    "detected_at": f.detected_at.isoformat(),
                })
        return out

    @app.get("/merges")
    def list_merges(tenant: UUID = _read) -> list[MergeRecordResponse]:
        with tenant_session(app.state.pool, tenant) as conn:
            records = MergeReviewRepository(conn, tenant).list_merges()
        return [
            MergeRecordResponse(
                merge_id=r.merge_id,
                canonical_ci_id=r.canonical_ci_id,
                merged_source=r.merged_source,
                merged_external_id=r.merged_external_id,
                matched_alias_key=r.matched_alias_key,
                evidence=r.evidence,
                merged_at=r.merged_at,
            )
            for r in records
        ]

    @app.get("/merges/{ci_id}")
    def get_merges_for_ci(ci_id: UUID, tenant: UUID = _read) -> CIMergeProvenanceResponse:
        with tenant_session(app.state.pool, tenant) as conn:
            if CIRepository(conn, tenant).get_current_by_id(ci_id) is None:
                raise HTTPException(status_code=404, detail="CI not found")
            prov = MergeReviewRepository(conn, tenant).get_merges_for_ci(ci_id)
        return CIMergeProvenanceResponse(
            canonical_ci_id=ci_id,
            merges=[
                MergeRecordResponse(
                    merge_id=r.merge_id,
                    canonical_ci_id=r.canonical_ci_id,
                    merged_source=r.merged_source,
                    merged_external_id=r.merged_external_id,
                    matched_alias_key=r.matched_alias_key,
                    evidence=r.evidence,
                    merged_at=r.merged_at,
                )
                for r in prov.merges
            ],
            alias_keys=[
                AliasKeyBindingResponse(
                    alias_key=a.alias_key,
                    ci_type=a.ci_type,
                    source=a.source,
                    observed_at=a.observed_at,
                )
                for a in prov.alias_keys
            ],
        )

    @app.post("/merges/{merge_id}/unmerge")
    def unmerge_merge(merge_id: UUID, tenant: UUID = _write) -> UnmergeResponse:
        with tenant_session(app.state.pool, tenant) as conn:
            try:
                outcome = unmerge(conn, tenant, merge_id)
            except MergeNotFoundError:
                raise HTTPException(status_code=404, detail="merge not found")
            except MergeAlreadyReversedError:
                raise HTTPException(status_code=409, detail="merge already reversed")
        return UnmergeResponse(
            unmerge_id=outcome.unmerge_id,
            original_merge_id=outcome.original_merge_id,
            canonical_ci_id=outcome.canonical_ci_id,
            restored_ci_id=outcome.restored_ci_id,
            restored_source=outcome.restored_source,
            restored_external_id=outcome.restored_external_id,
            evidence=outcome.evidence,
            unmerged_at=outcome.unmerged_at,
        )

    @app.get("/unmerges")
    def list_unmerges(tenant: UUID = _read) -> list[UnmergeResponse]:
        with tenant_session(app.state.pool, tenant) as conn:
            records = MergeReviewRepository(conn, tenant).list_unmerges()
        return [
            UnmergeResponse(
                unmerge_id=r.unmerge_id,
                original_merge_id=r.original_merge_id,
                canonical_ci_id=r.canonical_ci_id,
                restored_ci_id=r.restored_ci_id,
                restored_source=r.restored_source,
                restored_external_id=r.restored_external_id,
                evidence=r.evidence,
                unmerged_at=r.unmerged_at,
            )
            for r in records
        ]

    # -----------------------------------------------------------------------
    # Merge-candidate routes (fuzzy entity-resolution suggestions)
    # -----------------------------------------------------------------------

    _VALID_CANDIDATE_STATUSES = frozenset({"pending", "accepted", "dismissed"})

    @app.post("/merge-candidates/generate")
    def generate_merge_candidates(tenant: UUID = _write) -> list[MergeCandidateResponse]:
        """Generate/refresh fuzzy merge candidates for the tenant.

        Editor permission required (mutation: writes ci_merge_candidates rows).
        Returns candidates generated or refreshed this run, newest-first.
        Never auto-merges: only produces candidate suggestions.
        """
        with tenant_session(app.state.pool, tenant) as conn:
            cands = generate_candidates(conn, tenant)
        return [
            MergeCandidateResponse(
                candidate_id=c.candidate_id,
                ci_id_a=c.ci_id_a,
                ci_id_b=c.ci_id_b,
                ci_type=c.ci_type,
                confidence=c.confidence,
                evidence=c.evidence,
                status=c.status,
                resolved_merge_id=c.resolved_merge_id,
                generated_at=c.generated_at,
                resolved_at=c.resolved_at,
            )
            for c in cands
        ]

    @app.get("/merge-candidates")
    def list_merge_candidates(
        status: str | None = "pending", tenant: UUID = _read
    ) -> list[MergeCandidateResponse]:
        """List merge candidates for the tenant.

        Viewer permission sufficient (read-only).
        status param filters by status; None returns all statuses.
        Invalid status value -> 422.
        """
        if status is not None and status not in _VALID_CANDIDATE_STATUSES:
            raise HTTPException(
                status_code=422,
                detail=f"status must be one of {sorted(_VALID_CANDIDATE_STATUSES)} or null",
            )
        with tenant_session(app.state.pool, tenant) as conn:
            records = MergeReviewRepository(conn, tenant).list_merge_candidates(status=status)
        return [
            MergeCandidateResponse(
                candidate_id=r.candidate_id,
                ci_id_a=r.ci_id_a,
                ci_id_b=r.ci_id_b,
                ci_type=r.ci_type,
                confidence=r.confidence,
                evidence=r.evidence,
                status=r.status,
                resolved_merge_id=r.resolved_merge_id,
                generated_at=r.generated_at,
                resolved_at=r.resolved_at,
            )
            for r in records
        ]

    @app.post("/merge-candidates/{candidate_id}/accept")
    def accept_merge_candidate(
        candidate_id: UUID, tenant: UUID = _write
    ) -> AcceptCandidateResponse:
        """Accept a pending fuzzy merge candidate.

        Editor permission required. Fuses the two CIs via the existing reversible merge
        provenance path (_record_merge), producing a real ci_merges row that can be
        reversed via POST /merges/{merge_id}/unmerge.
        404 if candidate not found; 409 if already resolved.
        """
        with tenant_session(app.state.pool, tenant) as conn:
            try:
                outcome = accept_candidate(conn, tenant, candidate_id)
            except CandidateNotFoundError:
                raise HTTPException(status_code=404, detail="candidate not found")
            except CandidateAlreadyResolvedError:
                raise HTTPException(status_code=409, detail="candidate already resolved")
        return AcceptCandidateResponse(
            candidate_id=outcome.candidate_id,
            merge_id=outcome.merge_id,
            canonical_ci_id=outcome.canonical_ci_id,
            merged_ci_id=outcome.merged_ci_id,
            merged_source=outcome.merged_source,
            merged_external_id=outcome.merged_external_id,
            confidence=outcome.confidence,
            evidence=outcome.evidence,
            resolved_at=outcome.resolved_at,
        )

    @app.post("/merge-candidates/{candidate_id}/dismiss")
    def dismiss_merge_candidate(
        candidate_id: UUID, tenant: UUID = _write
    ) -> MergeCandidateResponse:
        """Dismiss a pending fuzzy merge candidate.

        Editor permission required. Sets status='dismissed'; graph unchanged.
        404 if candidate not found; 409 if already resolved.
        """
        with tenant_session(app.state.pool, tenant) as conn:
            try:
                candidate = dismiss_candidate(conn, tenant, candidate_id)
            except CandidateNotFoundError:
                raise HTTPException(status_code=404, detail="candidate not found")
            except CandidateAlreadyResolvedError:
                raise HTTPException(status_code=409, detail="candidate already resolved")
        return MergeCandidateResponse(
            candidate_id=candidate.candidate_id,
            ci_id_a=candidate.ci_id_a,
            ci_id_b=candidate.ci_id_b,
            ci_type=candidate.ci_type,
            confidence=candidate.confidence,
            evidence=candidate.evidence,
            status=candidate.status,
            resolved_merge_id=candidate.resolved_merge_id,
            generated_at=candidate.generated_at,
            resolved_at=candidate.resolved_at,
        )

    @app.post("/telemetry/maintenance/age-inferred-edges")
    def age_edges(tenant: UUID = _write) -> dict:
        """Decay or TTL-close stale inferred edges for the tenant.

        No request body. Runs one full aging sweep and returns counters plus
        the connector-run id.  Always returns 200 (even if all counters are 0).
        """
        result = age_inferred_edges(
            app.state.pool, tenant, now=datetime.now(timezone.utc)
        )
        return {
            "connector_run_id": str(result.connector_run_id),
            "decayed": result.decayed,
            "closed": result.closed,
            "untouched": result.untouched,
        }

    # -----------------------------------------------------------------------
    # Notification routes
    # -----------------------------------------------------------------------

    def _subscription_dict(s) -> dict:
        return {
            "subscription_id": str(s.subscription_id),
            "url": s.url,
            "enabled": s.enabled,
            "kind": s.kind,
            "created_at": s.created_at.isoformat(),
        }

    def _delivery_dict(d) -> dict:
        return {
            "delivery_id": str(d.delivery_id),
            "subscription_id": str(d.subscription_id),
            "finding_id": str(d.finding_id),
            "payload": d.payload,
            "status_code": d.status_code,
            "outcome": d.outcome,
            "attempt": d.attempt,
            "attempted_at": d.attempted_at.isoformat(),
        }

    @app.post("/notifications/subscriptions", status_code=201)
    def create_subscription(body: CreateSubscriptionBody, tenant: UUID = _write) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            s = NotificationRepository(conn, tenant).create_subscription(
                body.url, enabled=body.enabled, kind=body.kind
            )
        return _subscription_dict(s)

    @app.get("/notifications/subscriptions")
    def list_subscriptions(tenant: UUID = _read) -> list[dict]:
        with tenant_session(app.state.pool, tenant) as conn:
            subs = NotificationRepository(conn, tenant).list_subscriptions()
        return [_subscription_dict(s) for s in subs]

    @app.get("/notifications/deliveries")
    def list_deliveries(limit: int = 200, tenant: UUID = _read) -> list[dict]:
        with tenant_session(app.state.pool, tenant) as conn:
            deliveries = NotificationRepository(conn, tenant).list_deliveries(limit=limit)
        return [_delivery_dict(d) for d in deliveries]

    # -----------------------------------------------------------------------
    # Bootstrap-admin route: issue SCIM bearer token for a tenant
    # -----------------------------------------------------------------------

    def _scim_user_response(user) -> dict:
        """Serialize a ScimUser to the SCIM-shaped response dict."""
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": str(user.scim_user_id),
            "externalId": user.external_id,
            "userName": user.user_name,
            "active": user.active,
            "roles": [{"value": user.role.value}],
            "meta": {
                "resourceType": "User",
                "created": user.created_at.isoformat(),
                "lastModified": user.valid_from.isoformat(),
                "location": f"/scim/v2/Users/{user.scim_user_id}",
            },
        }

    def _scim_error(status_code: int, detail: str) -> dict:
        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(status_code),
            "detail": detail,
        }

    def _parse_role_from_scim_roles(roles: list[dict] | None) -> Role:
        """Extract a Role from the first SCIM roles entry, defaulting to viewer."""
        if not roles:
            return Role.viewer
        first = roles[0]
        val = first.get("value", "")
        try:
            return Role(val)
        except ValueError:
            return Role.viewer

    def _parse_scim_filter(filter_str: str) -> str | None:
        """Parse 'userName eq "VALUE"' and return VALUE, or None if unsupported."""
        import re
        m = re.fullmatch(
            r'\s*userName\s+eq\s+"([^"]*)"\s*',
            filter_str,
            re.IGNORECASE,
        )
        if m is None:
            return None
        return m.group(1)

    @app.post("/tenants/{tenant_id}/scim-token", status_code=201, dependencies=[Depends(require_bootstrap_admin)])
    def issue_tenant_scim_token(tenant_id: UUID, body: ScimTokenBody) -> dict:
        from infra_twin.api.auth import _admin_pool as _get_admin_pool

        with _get_admin_pool(app).connection() as conn:
            generated = issue_scim_token(conn, tenant_id, name=body.name)
            conn.commit()

        return {
            "tenant_id": str(tenant_id),
            "name": body.name,
            "scim_token": generated.plaintext,
        }

    # -----------------------------------------------------------------------
    # SCIM 2.0 /scim/v2/Users routes (SCIM bearer token auth)
    # -----------------------------------------------------------------------

    @app.post("/scim/v2/Users", status_code=201)
    def scim_create_user(body: ScimUserCreateBody, tenant: UUID = _scim_tenant) -> dict:
        import psycopg

        role = _parse_role_from_scim_roles(body.roles)
        try:
            with tenant_session(app.state.pool, tenant) as conn:
                user = create_or_replace_user(
                    conn,
                    tenant_id=tenant,
                    user_name=body.userName,
                    external_id=body.externalId,
                    role=role,
                    active=body.active,
                )
        except psycopg.errors.UniqueViolation:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=409,
                content=_scim_error(409, "externalId already in use"),
            )

        return _scim_user_response(user)

    @app.get("/scim/v2/Users/{scim_user_id}")
    def scim_get_user(scim_user_id: UUID, tenant: UUID = _scim_tenant) -> dict:
        from fastapi.responses import JSONResponse

        with tenant_session(app.state.pool, tenant) as conn:
            user = get_user_by_id(conn, tenant, scim_user_id)

        if user is None:
            return JSONResponse(
                status_code=404,
                content=_scim_error(404, "User not found"),
            )

        return _scim_user_response(user)

    @app.get("/scim/v2/Users")
    def scim_list_users(filter: str | None = None, tenant: UUID = _scim_tenant) -> dict:
        from fastapi.responses import JSONResponse

        user_name_filter: str | None = None
        if filter is not None:
            user_name_filter = _parse_scim_filter(filter)
            if user_name_filter is None:
                return JSONResponse(
                    status_code=400,
                    content=_scim_error(400, "unsupported filter"),
                )

        with tenant_session(app.state.pool, tenant) as conn:
            users = list_users(conn, tenant, user_name=user_name_filter)

        resources = [_scim_user_response(u) for u in users]
        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(resources),
            "Resources": resources,
        }

    @app.patch("/scim/v2/Users/{scim_user_id}")
    def scim_patch_user(scim_user_id: UUID, body: ScimPatchBody, tenant: UUID = _scim_tenant) -> dict:
        import psycopg
        from fastapi.responses import JSONResponse

        if not body.Operations:
            return JSONResponse(
                status_code=400,
                content=_scim_error(400, "unsupported PATCH operation"),
            )

        # Process the first meaningful operation: replace active true/false.
        new_active: bool | None = None
        for op in body.Operations:
            if op.op.lower() != "replace":
                continue
            # Determine whether this op targets 'active'.
            if op.path is not None and op.path.lower() == "active":
                # value is the active boolean directly.
                if isinstance(op.value, bool):
                    new_active = op.value
                elif isinstance(op.value, str):
                    new_active = op.value.lower() not in ("false", "0", "no")
                break
            elif op.path is None and isinstance(op.value, dict):
                # value is a dict, e.g. {"active": false}.
                if "active" in op.value:
                    raw = op.value["active"]
                    if isinstance(raw, bool):
                        new_active = raw
                    elif isinstance(raw, str):
                        new_active = raw.lower() not in ("false", "0", "no")
                    break

        if new_active is None:
            return JSONResponse(
                status_code=400,
                content=_scim_error(400, "unsupported PATCH operation"),
            )

        with tenant_session(app.state.pool, tenant) as conn:
            # Fetch current row to check existence and get attributes for reactivation.
            current = get_user_by_id(conn, tenant, scim_user_id)
            if current is None:
                return JSONResponse(
                    status_code=404,
                    content=_scim_error(404, "User not found"),
                )

            if not new_active:
                user = deactivate_user(conn, tenant, scim_user_id)
                if user is None:
                    return JSONResponse(
                        status_code=404,
                        content=_scim_error(404, "User not found"),
                    )
            else:
                # Reactivate: close+open with active=True, preserving attributes.
                user = create_or_replace_user(
                    conn,
                    tenant_id=tenant,
                    user_name=current.user_name,
                    external_id=current.external_id,
                    role=current.role,
                    active=True,
                )

        return _scim_user_response(user)

    @app.put("/scim/v2/Users/{scim_user_id}")
    def scim_put_user(scim_user_id: UUID, body: ScimUserPutBody, tenant: UUID = _scim_tenant) -> dict:
        import psycopg
        from fastapi.responses import JSONResponse

        with tenant_session(app.state.pool, tenant) as conn:
            existing = get_user_by_id(conn, tenant, scim_user_id)
            if existing is None:
                return JSONResponse(
                    status_code=404,
                    content=_scim_error(404, "User not found"),
                )

            role = _parse_role_from_scim_roles(body.roles)

            if not body.active:
                # Deactivate: close+open preserving userName; role/externalId updated via close+open.
                # First ensure the current row reflects new attributes then deactivate.
                # We do a full replace (close+open) then deactivate.
                try:
                    user = create_or_replace_user(
                        conn,
                        tenant_id=tenant,
                        user_name=body.userName,
                        external_id=body.externalId,
                        role=role,
                        active=False,
                    )
                except psycopg.errors.UniqueViolation:
                    return JSONResponse(
                        status_code=409,
                        content=_scim_error(409, "externalId already in use"),
                    )
            else:
                try:
                    user = create_or_replace_user(
                        conn,
                        tenant_id=tenant,
                        user_name=body.userName,
                        external_id=body.externalId,
                        role=role,
                        active=True,
                    )
                except psycopg.errors.UniqueViolation:
                    return JSONResponse(
                        status_code=409,
                        content=_scim_error(409, "externalId already in use"),
                    )

        return _scim_user_response(user)

    # -----------------------------------------------------------------------
    # Freshness SLO routes
    # -----------------------------------------------------------------------

    def _slo_dict(slo) -> dict:
        """Serialize a FreshnessSlo to the public response shape (no tenant_id)."""
        return {
            "id": str(slo.id),
            "source": slo.source,
            "expected_interval_seconds": slo.expected_interval_seconds,
            "created_at": slo.created_at.isoformat(),
            "updated_at": slo.updated_at.isoformat(),
        }

    @app.put("/freshness-slos/{source}")
    def put_freshness_slo(source: str, body: FreshnessSloBody, tenant: UUID = _write) -> dict:
        if not source.strip():
            raise HTTPException(status_code=422, detail="source must not be blank or whitespace")
        with tenant_session(app.state.pool, tenant) as conn:
            slo = FreshnessSloRepository(conn, tenant).upsert_slo(
                source=source,
                expected_interval_seconds=body.expected_interval_seconds,
            )
        return _slo_dict(slo)

    @app.get("/freshness-slos")
    def list_freshness_slos(tenant: UUID = _read) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            slos = FreshnessSloRepository(conn, tenant).list_slos()
        return {"slos": [_slo_dict(s) for s in slos]}

    @app.get("/freshness-slos/evaluate")
    def evaluate_freshness_slos(tenant: UUID = _read) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            evaluations = FreshnessSloRepository(conn, tenant).evaluate()
        return {
            "sources": [
                {
                    "source": e.source,
                    "expected_interval_seconds": e.expected_interval_seconds,
                    "age_seconds": e.age_seconds,
                    "last_run_status": e.last_run_status,
                    "status": e.status,
                }
                for e in evaluations
            ]
        }

    # -----------------------------------------------------------------------
    # History retention routes
    # -----------------------------------------------------------------------

    def _policy_dict(policy) -> dict:
        """Serialize a RetentionPolicy to the public response shape (no tenant_id)."""
        return {
            "retain_closed_days": policy.retain_closed_days,
            "enabled": policy.enabled,
            "created_at": policy.created_at.isoformat(),
            "updated_at": policy.updated_at.isoformat(),
        }

    @app.put("/retention-policy")
    def put_retention_policy(body: RetentionPolicyBody, tenant: UUID = _write) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            policy = RetentionPolicyRepository(conn, tenant).upsert_policy(
                retain_closed_days=body.retain_closed_days,
                enabled=body.enabled,
            )
        return _policy_dict(policy)

    @app.get("/retention-policy")
    def get_retention_policy(tenant: UUID = _read) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            policy = RetentionPolicyRepository(conn, tenant).get_policy()
        if policy is None:
            return {
                "retain_closed_days": None,
                "enabled": False,
                "created_at": None,
                "updated_at": None,
            }
        return _policy_dict(policy)

    @app.post("/retention/sweep")
    def retention_sweep(tenant: UUID = _write) -> dict:
        """Run the history retention sweep for the tenant.

        No request body.  Always returns 200, even when all counters are 0 or
        the sweep is a no-op (disabled/no policy).
        """
        report = sweep_history(app.state.pool, tenant, now=datetime.now(timezone.utc))
        return {
            "swept": report.swept,
            "connector_run_id": str(report.connector_run_id) if report.connector_run_id else None,
            "ci": {
                "versions_collapsed": report.ci.versions_collapsed,
                "aggregates_written": report.ci.aggregates_written,
                "retained_current": report.ci.retained_current,
                "retained_boundary": report.ci.retained_boundary,
                "eligible": report.ci.eligible,
            },
            "edge": {
                "versions_collapsed": report.edge.versions_collapsed,
                "aggregates_written": report.edge.aggregates_written,
                "retained_current": report.edge.retained_current,
                "retained_boundary": report.edge.retained_boundary,
                "eligible": report.edge.eligible,
            },
        }

    @app.get("/history-aggregates")
    def list_history_aggregates(limit: int = 200, tenant: UUID = _read) -> dict:
        with tenant_session(app.state.pool, tenant) as conn:
            aggregates = RetentionPolicyRepository(conn, tenant).list_aggregates(limit=limit)
        return {
            "aggregates": [
                {
                    "aggregate_id": str(a.aggregate_id),
                    "entity_kind": a.entity_kind,
                    "entity_id": str(a.entity_id),
                    "version_count": a.version_count,
                    "earliest_valid_from": a.earliest_valid_from.isoformat(),
                    "latest_valid_to": a.latest_valid_to.isoformat(),
                    "rollup": a.rollup,
                    "created_at": a.created_at.isoformat(),
                }
                for a in aggregates
            ]
        }

    return app
