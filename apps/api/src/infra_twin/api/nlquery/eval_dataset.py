"""Typed golden dataset for the NL eval harness.

Each GoldenCase pairs a natural-language question with the expected template name and,
optionally, the expected args dict. The dataset covers every whitelisted template in
REGISTRY plus several genuinely-unanswerable questions routed to UNSUPPORTED.
"""

from __future__ import annotations

from dataclasses import dataclass

from infra_twin.api.nlquery.planner import UNSUPPORTED

# Sentinel re-exported for callers that need to reference it symbolically.
UNSUPPORTED_EXPECTED: str = UNSUPPORTED  # == "unsupported"


@dataclass(frozen=True)
class GoldenCase:
    question: str
    expected_template: str          # a key in REGISTRY, or UNSUPPORTED_EXPECTED
    expected_args: dict | None = None   # None => only the template name is graded, not args


GOLDEN_DATASET: tuple[GoldenCase, ...] = (
    # ---- inventory ---------------------------------------------------------------
    GoldenCase(
        question="what EC2 instances do I have",
        expected_template="inventory",
        expected_args={"type": "ec2_instance"},
    ),
    GoldenCase(
        question="list my VPCs",
        expected_template="inventory",
        expected_args={"type": "vpc"},
    ),
    GoldenCase(
        question="show me all my S3 buckets",
        expected_template="inventory",
        expected_args={"type": "s3_bucket"},
    ),
    GoldenCase(
        question="what infrastructure resources are currently running?",
        expected_template="inventory",
        expected_args=None,         # args not graded; any valid inventory args accepted
    ),

    # ---- count_by_type -----------------------------------------------------------
    GoldenCase(
        question="how many of each resource do I have",
        expected_template="count_by_type",
        expected_args={},
    ),
    GoldenCase(
        question="give me an inventory summary",
        expected_template="count_by_type",
        expected_args={},
    ),
    GoldenCase(
        question="how many resources are in my account broken down by type",
        expected_template="count_by_type",
        expected_args=None,
    ),

    # ---- blast_radius ------------------------------------------------------------
    GoldenCase(
        question="what breaks if vpc-123 goes down",
        expected_template="blast_radius",
        expected_args={"external_id": "vpc-123"},
    ),
    GoldenCase(
        question="what depends on i-0abc",
        expected_template="blast_radius",
        expected_args={"external_id": "i-0abc"},
    ),
    GoldenCase(
        question="if my RDS instance rds-prod failed, which services would be affected",
        expected_template="blast_radius",
        expected_args={"external_id": "rds-prod"},
    ),

    # ---- recent_changes ----------------------------------------------------------
    GoldenCase(
        question="what changed this week",
        expected_template="recent_changes",
        expected_args={"days": 7},
    ),
    GoldenCase(
        question="show changes in the last 14 days",
        expected_template="recent_changes",
        expected_args={"days": 14},
    ),
    GoldenCase(
        question="show me infrastructure changes from the past month",
        expected_template="recent_changes",
        expected_args={"days": 30},
    ),

    # ---- reachability ------------------------------------------------------------
    GoldenCase(
        question="can the internet reach i-1",
        expected_template="reachability",
        expected_args={"external_id": "i-1"},
    ),
    GoldenCase(
        question="is sg-123 publicly accessible",
        expected_template="reachability",
        expected_args={"external_id": "sg-123"},
    ),
    GoldenCase(
        question="what can reach my load balancer elb-prod",
        expected_template="reachability",
        expected_args={"external_id": "elb-prod"},
    ),

    # ---- unsupported (>= 4 cases) ------------------------------------------------
    GoldenCase(
        question="what's the weather in San Francisco",
        expected_template=UNSUPPORTED_EXPECTED,
        expected_args=None,
    ),
    GoldenCase(
        question="write me a poem about clouds",
        expected_template=UNSUPPORTED_EXPECTED,
        expected_args=None,
    ),
    GoldenCase(
        question="delete my VPC",
        expected_template=UNSUPPORTED_EXPECTED,
        expected_args=None,
    ),
    GoldenCase(
        question="what is the CEO's salary",
        expected_template=UNSUPPORTED_EXPECTED,
        expected_args=None,
    ),
    GoldenCase(
        question="translate 'hello world' to French",
        expected_template=UNSUPPORTED_EXPECTED,
        expected_args=None,
    ),
)
