"""Tenant-scoped, bitemporal access layer over PostgreSQL + Apache AGE."""

from infra_twin.db.audit import AuditEntry, list_audit, record_access
from infra_twin.db.connector_health import (
    ConnectorRunRepository,
    ConnectorRunSummary,
    RawFactRepository,
)
from infra_twin.db.connectors import Connector as _Connector
from infra_twin.db.connectors import ConnectorRegistry
from infra_twin.db.findings import FindingRepository
from infra_twin.db.freshness import FreshnessEvaluation, FreshnessSlo, FreshnessSloRepository
from infra_twin.db.idp_config import TenantIdpConfig, find_idp_config, upsert_idp_config
from infra_twin.db.merges import (
    AliasKeyBinding,
    CIMergeProvenance,
    MergeRecord,
    MergeReviewRepository,
)
from infra_twin.db.notifications import (
    OUTCOME_VALUES,
    SUBSCRIPTION_KIND_VALUES,
    NotificationDelivery,
    NotificationRepository,
    NotificationSubscription,
)
from infra_twin.db.pool import make_pool
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.db.retention import HistoryAggregate, RetentionPolicy, RetentionPolicyRepository
from infra_twin.db.scim_users import (
    GeneratedScimToken,
    SCIM_TOKEN_PREFIX,
    ScimUser,
    create_or_replace_user,
    deactivate_user,
    get_current_user_by_username,
    get_user_by_id,
    issue_scim_token,
    list_users,
    resolve_scim_token,
)
from infra_twin.db.session import tenant_session
from infra_twin.db.usage import count_usage_in_window, current_calendar_month_start, record_usage

# Alias to disambiguate from infra_twin.connector_sdk.Connector (the live-connector Protocol).
RegisteredConnector = _Connector

__all__ = [
    "AliasKeyBinding",
    "AuditEntry",
    "CIMergeProvenance",
    "CIRepository",
    "ConnectorRegistry",
    "ConnectorRunRepository",
    "ConnectorRunSummary",
    "EdgeRepository",
    "FindingRepository",
    "FreshnessEvaluation",
    "FreshnessSlo",
    "FreshnessSloRepository",
    "GeneratedScimToken",
    "HistoryAggregate",
    "MergeRecord",
    "MergeReviewRepository",
    "NotificationDelivery",
    "NotificationRepository",
    "NotificationSubscription",
    "OUTCOME_VALUES",
    "RawFactRepository",
    "RegisteredConnector",
    "RetentionPolicy",
    "RetentionPolicyRepository",
    "SCIM_TOKEN_PREFIX",
    "SUBSCRIPTION_KIND_VALUES",
    "ScimUser",
    "TenantIdpConfig",
    "count_usage_in_window",
    "create_or_replace_user",
    "current_calendar_month_start",
    "deactivate_user",
    "find_idp_config",
    "get_current_user_by_username",
    "get_user_by_id",
    "issue_scim_token",
    "list_audit",
    "list_users",
    "make_pool",
    "record_access",
    "record_usage",
    "resolve_scim_token",
    "tenant_session",
    "upsert_idp_config",
]
