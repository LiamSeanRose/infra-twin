"""Reconciliation: turn discovery events into a versioned, projected graph."""

from infra_twin.reconciliation.aging import AgingResult, age_inferred_edges
from infra_twin.reconciliation.candidates import (
    CANDIDATE_THRESHOLD,
    AcceptOutcome,
    CandidateAlreadyResolvedError,
    CandidateError,
    CandidateNotFoundError,
    MergeCandidate,
    accept_candidate,
    dismiss_candidate,
    generate_candidates,
)
from infra_twin.reconciliation.events import apply_event_delta
from infra_twin.reconciliation.anomalies import (
    AnomalyEvaluateResult,
    RULE_PUBLIC_IP_ON_DATABASE,
    RULE_SECURITY_GROUP_OPENED_TO_WORLD,
    evaluate_anomalies,
    evaluate_anomalies_with_summary,
)
from infra_twin.reconciliation.findings import (
    DATABASE_CI_TYPES,
    EvaluateResult,
    FINDINGS_SOURCE,
    INTERNET_DB_SEVERITY,
    RULE_INTERNET_REACHABLE_DATABASE,
    VALID_SEVERITIES,
    VALID_STATUSES,
    evaluate_findings,
    evaluate_findings_with_summary,
)
from infra_twin.reconciliation.reconcile import (
    DeltaResult,
    ReconcileResult,
    apply_delta,
    reconcile,
)
from infra_twin.reconciliation.retention import (
    RETENTION_SOURCE,
    RetentionKindReport,
    RetentionReport,
    sweep_history,
)
from infra_twin.reconciliation.run import discover_and_reconcile
from infra_twin.reconciliation.unmerge import (
    MergeAlreadyReversedError,
    MergeNotFoundError,
    UnmergeError,
    UnmergeOutcome,
    unmerge,
)

__all__ = [
    "AcceptOutcome",
    "AgingResult",
    "AnomalyEvaluateResult",
    "CANDIDATE_THRESHOLD",
    "CandidateAlreadyResolvedError",
    "CandidateError",
    "CandidateNotFoundError",
    "DATABASE_CI_TYPES",
    "DeltaResult",
    "EvaluateResult",
    "FINDINGS_SOURCE",
    "INTERNET_DB_SEVERITY",
    "MergeAlreadyReversedError",
    "MergeCandidate",
    "MergeNotFoundError",
    "RULE_INTERNET_REACHABLE_DATABASE",
    "RULE_PUBLIC_IP_ON_DATABASE",
    "RULE_SECURITY_GROUP_OPENED_TO_WORLD",
    "ReconcileResult",
    "RETENTION_SOURCE",
    "RetentionKindReport",
    "RetentionReport",
    "VALID_SEVERITIES",
    "VALID_STATUSES",
    "UnmergeError",
    "UnmergeOutcome",
    "accept_candidate",
    "age_inferred_edges",
    "apply_delta",
    "apply_event_delta",
    "discover_and_reconcile",
    "dismiss_candidate",
    "evaluate_anomalies",
    "evaluate_anomalies_with_summary",
    "evaluate_findings",
    "evaluate_findings_with_summary",
    "generate_candidates",
    "reconcile",
    "sweep_history",
    "unmerge",
]
