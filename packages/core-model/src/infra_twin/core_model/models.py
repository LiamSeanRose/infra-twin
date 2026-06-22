"""Typed CI and edge models.

These models are the canonical shape every other module agrees on. The hard rules from
the project charter are encoded here at the type boundary:

- Bitemporal: every CI and edge carries ``valid_from`` / ``valid_to``.
- Tenant-scoped: every row carries ``tenant_id``.
- Edge provenance: every edge carries ``source``, ``confidence`` and non-empty ``evidence``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    """Timezone-aware current time. Used as the default validity start / observation time."""
    return datetime.now(timezone.utc)


class CIType(str, Enum):
    """Configuration Item types. Spans AWS and Kubernetes sources."""

    cloud_account = "cloud_account"
    region = "region"
    vpc = "vpc"
    subnet = "subnet"
    security_group = "security_group"
    ec2_instance = "ec2_instance"
    elb = "elb"
    rds = "rds"
    s3_bucket = "s3_bucket"
    iam_role = "iam_role"
    iam_user = "iam_user"
    eks_cluster = "eks_cluster"
    internet = "internet"
    dns_name = "dns_name"
    k8s_cluster = "k8s_cluster"
    k8s_namespace = "k8s_namespace"
    k8s_node = "k8s_node"
    k8s_workload = "k8s_workload"
    k8s_pod = "k8s_pod"
    k8s_service = "k8s_service"
    azure_subscription = "azure_subscription"
    azure_resource_group = "azure_resource_group"
    azure_vnet = "azure_vnet"
    azure_subnet = "azure_subnet"
    azure_nsg = "azure_nsg"
    azure_vm = "azure_vm"
    gcp_project = "gcp_project"
    gcp_network = "gcp_network"
    gcp_subnetwork = "gcp_subnetwork"
    gcp_firewall = "gcp_firewall"
    gcp_instance = "gcp_instance"
    db_instance = "db_instance"
    db_database = "db_database"
    db_schema = "db_schema"
    db_table = "db_table"
    saas_app = "saas_app"
    saas_account = "saas_account"
    saas_resource = "saas_resource"


class EdgeType(str, Enum):
    """Relationship types between CIs."""

    CONTAINS = "CONTAINS"
    RUNS_ON = "RUNS_ON"
    CONNECTS_TO = "CONNECTS_TO"
    DEPENDS_ON = "DEPENDS_ON"
    ROUTES_TO = "ROUTES_TO"
    HAS_ACCESS_TO = "HAS_ACCESS_TO"
    OWNS = "OWNS"
    EXPOSES = "EXPOSES"
    MEMBER_OF = "MEMBER_OF"
    RESOLVES_TO = "RESOLVES_TO"


class EdgeSource(str, Enum):
    """How a relationship was derived. ``declared`` = read from config; ``inferred`` = guessed."""

    declared = "declared"
    inferred = "inferred"


class Evidence(BaseModel):
    """A single piece of provenance backing an edge."""

    source: str
    observed_at: datetime = Field(default_factory=utcnow)
    detail: str | None = None


class CI(BaseModel):
    """A Configuration Item — one node in the graph, one version of one real-world thing."""

    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    type: CIType
    external_id: str
    name: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    valid_from: datetime = Field(default_factory=utcnow)
    valid_to: datetime | None = None


class Edge(BaseModel):
    """A relationship between two CIs.

    ``source``, ``confidence`` and a non-empty ``evidence`` list are required: an edge can
    never be constructed without its provenance.
    """

    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    type: EdgeType
    from_id: UUID
    to_id: UUID
    edge_key: str = ""
    source: EdgeSource
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence] = Field(min_length=1)
    valid_from: datetime = Field(default_factory=utcnow)
    valid_to: datetime | None = None


class SourceKey(BaseModel):
    """Maps a provider-native identity to an internal CI — the seam for entity resolution."""

    tenant_id: UUID
    source: str
    native_id: str
    ci_id: UUID
    observed_at: datetime = Field(default_factory=utcnow)


class Finding(BaseModel):
    """A risk finding derived from graph analysis. Bitemporal, append-only, tenant-scoped."""

    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    rule_id: str
    severity: str                       # one of VALID_SEVERITIES
    subject_ci_id: UUID
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    status: str = "open"                # one of VALID_STATUSES
    detected_at: datetime = Field(default_factory=utcnow)
    valid_from: datetime = Field(default_factory=utcnow)
    valid_to: datetime | None = None
