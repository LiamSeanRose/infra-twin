"""AWS-specific onboarding artifacts: least-privilege read-only IAM role rendering."""

from __future__ import annotations

import yaml

# Canonical, ordered, immutable allow-list of read-only IAM actions.
# Sorted ascending for determinism. Derived from the exact API calls made by the
# AWS connector in services/collectors (iam, s3, ec2, elbv2, rds, eks) plus
# sts:GetCallerIdentity for identity confirmation.
READONLY_ACTIONS: tuple[str, ...] = (
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSubnets",
    "ec2:DescribeVpcs",
    "eks:DescribeCluster",
    "eks:ListClusters",
    "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:DescribeTargetHealth",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:GetRolePolicy",
    "iam:GetUserPolicy",
    "iam:ListAttachedRolePolicies",
    "iam:ListAttachedUserPolicies",
    "iam:ListRolePolicies",
    "iam:ListRoles",
    "iam:ListUserPolicies",
    "iam:ListUsers",
    "rds:DescribeDBInstances",
    "s3:GetBucketLocation",
    "s3:ListAllMyBuckets",
    "sts:GetCallerIdentity",
)

DEFAULT_ROLE_NAME: str = "InfraTwinReadOnlyRole"
DEFAULT_ROLE_PATH: str = "/"


def render_aws_cloudformation(
    *,
    external_id: str,
    truster_account_id: str | None = None,
    truster_role_arn: str | None = None,
    role_name: str = DEFAULT_ROLE_NAME,
    path: str = DEFAULT_ROLE_PATH,
) -> str:
    """Render a per-tenant CloudFormation document as a YAML string.

    The returned document is fully resolved (all values baked in; no unbound
    CloudFormation Parameters are required to deploy it).

    Args:
        external_id: Per-tenant STS external ID to embed in the trust policy.
            Must be non-empty and non-whitespace.
        truster_account_id: infra-twin AWS account id. Used to build the trust
            principal ``arn:aws:iam::<id>:root`` when ``truster_role_arn`` is
            not provided.
        truster_role_arn: Optional specific infra-twin role ARN. When non-empty,
            takes precedence over ``truster_account_id``.
        role_name: Name of the IAM role resource. Defaults to
            ``DEFAULT_ROLE_NAME``.
        path: IAM path. Defaults to ``DEFAULT_ROLE_PATH``.

    Returns:
        A string containing a complete CloudFormation YAML document that parses
        cleanly via ``yaml.safe_load``.

    Raises:
        ValueError: If ``external_id`` is empty/whitespace, or if neither
            ``truster_account_id`` nor ``truster_role_arn`` is non-empty.
    """
    # Validate external_id.
    if not external_id or not external_id.strip():
        raise ValueError("external_id must be a non-empty, non-whitespace string")

    # Resolve the trust principal.
    _role_arn = (truster_role_arn or "").strip()
    _account_id = (truster_account_id or "").strip()

    if _role_arn:
        principal = _role_arn
    elif _account_id:
        principal = f"arn:aws:iam::{_account_id}:root"
    else:
        raise ValueError(
            "at least one of truster_account_id or truster_role_arn must be a non-empty string"
        )

    doc: dict = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "InfraTwinReadOnlyRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "Path": path,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRole",
                                "Principal": {"AWS": principal},
                                "Condition": {
                                    "StringEquals": {"sts:ExternalId": external_id}
                                },
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "InfraTwinReadOnlyPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": list(READONLY_ACTIONS),
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                },
            }
        },
        "Outputs": {
            "RoleArn": {
                "Description": "ARN of the created infra-twin read-only role.",
                "Value": {"Fn::GetAtt": ["InfraTwinReadOnlyRole", "Arn"]},
            }
        },
    }

    return yaml.safe_dump(doc, sort_keys=False)
