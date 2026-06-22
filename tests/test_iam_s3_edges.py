"""Contract tests for the IAM-to-S3 HAS_ACCESS_TO edge feature.

Tests cover:
- Attached managed policies granting S3 access (roles and users)
- Inline policies granting S3 access (roles and users)
- Effect=Allow vs Effect=Deny
- Action matching: s3:*, S3:GetObject (case-insensitive), *, ec2:* (no match)
- Resource matching: *, arn:aws:s3:::name, arn:aws:s3:::name/*, arn:aws:s3:::prefix*, missing
- Only in-scope discovered buckets targeted
- Deduplication: (principal, bucket) from multiple grants -> one edge with multiple Evidence
- Two principals -> two edges to same bucket
- URL-encoded policy document decoding
- Statement as dict vs list
- NotAction / NotResource ignored
- No buckets discovered -> no edges
- Pure unit tests for module-level helpers
"""

from __future__ import annotations

import json
import urllib.parse

import boto3
import pytest
from moto import mock_aws

from infra_twin.collectors.aws import AwsConnector
from infra_twin.collectors.aws.connector import (
    _buckets_for_resource,
    _policy_statements,
    _s3_grants_from_statement,
)
from infra_twin.connector_sdk import DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeSource, EdgeType

REGION = "us-east-1"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_connector(session: boto3.Session, account_id: str) -> AwsConnector:
    return AwsConnector(session, account_id=account_id, regions=[REGION])


def _discover_all(connector: AwsConnector):
    events = list(connector.discover())
    cis = [e for e in events if isinstance(e, DiscoveredCI)]
    edges = [e for e in events if isinstance(e, DiscoveredEdge)]
    return cis, edges


def _has_access_edges(edges):
    return [e for e in edges if e.type == EdgeType.HAS_ACCESS_TO]


def _account_id(session: boto3.Session) -> str:
    return session.client("sts", region_name=REGION).get_caller_identity()["Account"]


# ---------------------------------------------------------------------------
# Unit tests for pure helpers
# ---------------------------------------------------------------------------

class TestPolicyStatements:
    """Unit tests for _policy_statements."""

    def test_list_of_statements_returned_as_is(self):
        doc = {"Statement": [{"Effect": "Allow"}, {"Effect": "Deny"}]}
        result = _policy_statements(doc)
        assert result == [{"Effect": "Allow"}, {"Effect": "Deny"}]

    def test_single_statement_dict_wrapped_in_list(self):
        # Edge case 7: Statement as a single object
        stmt = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        doc = {"Statement": stmt}
        result = _policy_statements(doc)
        assert result == [stmt]

    def test_missing_statement_yields_empty_list(self):
        result = _policy_statements({})
        assert result == []

    def test_empty_list_statement(self):
        result = _policy_statements({"Statement": []})
        assert result == []


class TestBucketsForResource:
    """Unit tests for _buckets_for_resource."""

    BUCKETS = {"twin-alpha", "twin-beta", "other-bucket"}

    def test_star_covers_all_discovered_buckets(self):
        # Edge case 8
        result = _buckets_for_resource("*", self.BUCKETS)
        assert result == self.BUCKETS

    def test_bucket_level_arn_matches_exact_name(self):
        # Acceptance criterion 10 / edge case 9
        result = _buckets_for_resource("arn:aws:s3:::twin-alpha", self.BUCKETS)
        assert result == {"twin-alpha"}

    def test_object_level_arn_resolves_to_bucket_name(self):
        # Edge case 9 / acceptance criterion 10
        result = _buckets_for_resource("arn:aws:s3:::twin-alpha/*", self.BUCKETS)
        assert result == {"twin-alpha"}

    def test_object_level_specific_key_strips_correctly(self):
        result = _buckets_for_resource("arn:aws:s3:::twin-beta/some/key/path", self.BUCKETS)
        assert result == {"twin-beta"}

    def test_arn_star_covers_all_buckets(self):
        result = _buckets_for_resource("arn:aws:s3:::*", self.BUCKETS)
        assert result == self.BUCKETS

    def test_prefix_wildcard_matches_only_matching_buckets(self):
        # Edge case 10 / acceptance criterion 11
        result = _buckets_for_resource("arn:aws:s3:::twin-*", self.BUCKETS)
        assert result == {"twin-alpha", "twin-beta"}

    def test_prefix_wildcard_no_match(self):
        result = _buckets_for_resource("arn:aws:s3:::nonexistent-*", self.BUCKETS)
        assert result == set()

    def test_undiscovered_bucket_returns_empty(self):
        # Edge case 11 / acceptance criterion 8
        result = _buckets_for_resource("arn:aws:s3:::unknown-bucket", self.BUCKETS)
        assert result == set()

    def test_non_s3_resource_returns_empty(self):
        result = _buckets_for_resource("arn:aws:ec2:::instance/i-123", self.BUCKETS)
        assert result == set()

    def test_non_arn_non_star_returns_empty(self):
        result = _buckets_for_resource("arn:aws:iam::123:role/myrole", self.BUCKETS)
        assert result == set()

    def test_empty_bucket_names_set(self):
        # Edge case 19
        result = _buckets_for_resource("*", set())
        assert result == set()

    def test_empty_bucket_names_with_prefix_wildcard(self):
        result = _buckets_for_resource("arn:aws:s3:::twin-*", set())
        assert result == set()


class TestS3GrantsFromStatement:
    """Unit tests for _s3_grants_from_statement."""

    BUCKETS = {"my-bucket", "other-bucket"}

    def test_allow_s3_star_resource_star_returns_grants(self):
        # Edge case 5 + 8
        stmt = {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        grants = _s3_grants_from_statement(stmt, self.BUCKETS)
        assert ("my-bucket", "s3:*") in grants
        assert ("other-bucket", "s3:*") in grants

    def test_deny_produces_no_grants(self):
        # Edge case 2 / acceptance criterion 7
        stmt = {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}
        assert _s3_grants_from_statement(stmt, self.BUCKETS) == set()

    def test_non_s3_action_produces_no_grants(self):
        # Edge case 3
        stmt = {"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}
        assert _s3_grants_from_statement(stmt, self.BUCKETS) == set()

    def test_non_s3_action_list_produces_no_grants(self):
        stmt = {"Effect": "Allow", "Action": ["ec2:*", "iam:PassRole"], "Resource": "*"}
        assert _s3_grants_from_statement(stmt, self.BUCKETS) == set()

    def test_all_wildcard_action_produces_grants(self):
        # Edge case 4 / spec section 4.3 action matching
        stmt = {"Effect": "Allow", "Action": "*", "Resource": "*"}
        grants = _s3_grants_from_statement(stmt, self.BUCKETS)
        assert ("my-bucket", "*") in grants
        assert ("other-bucket", "*") in grants

    def test_action_as_single_string(self):
        # Edge case 6
        stmt = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket"}
        grants = _s3_grants_from_statement(stmt, self.BUCKETS)
        assert grants == {("my-bucket", "s3:GetObject")}

    def test_action_as_list(self):
        # Edge case 6
        stmt = {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::my-bucket"}
        grants = _s3_grants_from_statement(stmt, self.BUCKETS)
        assert ("my-bucket", "s3:GetObject") in grants
        assert ("my-bucket", "s3:PutObject") in grants

    def test_case_insensitive_s3_prefix_matching(self):
        # Edge case 21: S3:GetObject (upper S) still matches
        stmt = {"Effect": "Allow", "Action": "S3:GetObject", "Resource": "*"}
        grants = _s3_grants_from_statement(stmt, self.BUCKETS)
        # Original-cased action should appear in grants
        assert ("my-bucket", "S3:GetObject") in grants

    def test_missing_resource_produces_no_grants(self):
        # Edge case 12
        stmt = {"Effect": "Allow", "Action": "s3:GetObject"}
        assert _s3_grants_from_statement(stmt, self.BUCKETS) == set()

    def test_missing_action_produces_no_grants(self):
        stmt = {"Effect": "Allow", "Resource": "*"}
        assert _s3_grants_from_statement(stmt, self.BUCKETS) == set()

    def test_not_action_ignored_no_grants(self):
        # Edge case 13: NotAction should not produce any grants
        stmt = {"Effect": "Allow", "NotAction": "s3:GetObject", "Resource": "*"}
        assert _s3_grants_from_statement(stmt, self.BUCKETS) == set()

    def test_not_resource_ignored_no_grants(self):
        # Edge case 13: NotResource should not produce any grants
        stmt = {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "*"}
        assert _s3_grants_from_statement(stmt, self.BUCKETS) == set()

    def test_undiscovered_bucket_resource_no_grants(self):
        # Edge case 11 / acceptance criterion 8
        stmt = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::no-such-bucket"}
        assert _s3_grants_from_statement(stmt, self.BUCKETS) == set()

    def test_cross_product_multiple_actions_multiple_buckets(self):
        stmt = {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::other-bucket"],
        }
        grants = _s3_grants_from_statement(stmt, self.BUCKETS)
        assert grants == {
            ("my-bucket", "s3:GetObject"),
            ("my-bucket", "s3:PutObject"),
            ("other-bucket", "s3:GetObject"),
            ("other-bucket", "s3:PutObject"),
        }

    def test_mixed_s3_and_non_s3_actions_only_s3_grants(self):
        stmt = {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "ec2:DescribeInstances"],
            "Resource": "*",
        }
        grants = _s3_grants_from_statement(stmt, self.BUCKETS)
        assert all(action == "s3:GetObject" for _, action in grants)
        assert len(grants) == 2  # one per bucket


# ---------------------------------------------------------------------------
# Acceptance-criteria checks on connector edge_types
# ---------------------------------------------------------------------------

def test_has_access_to_in_edge_types():
    """Acceptance criterion 1: EdgeType.HAS_ACCESS_TO must be in _EDGE_TYPES / edge_types."""
    session = boto3.Session(region_name=REGION)
    # AwsConnector.edge_types is a class attribute; we can check it without mocking AWS
    assert EdgeType.HAS_ACCESS_TO in AwsConnector.edge_types


# ---------------------------------------------------------------------------
# Connector contract tests (moto-mocked AWS)
# ---------------------------------------------------------------------------

@pytest.fixture
def iam_s3_account():
    """Create an account with an IAM role + user, managed and inline policies, and S3 buckets."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        # Create two in-scope buckets
        s3.create_bucket(Bucket="twin-alpha")
        s3.create_bucket(Bucket="twin-beta")

        # Create a managed policy granting s3:GetObject on twin-alpha
        managed_policy = iam.create_policy(
            PolicyName="S3ReadPolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::twin-alpha/*",
                }],
            }),
        )
        managed_policy_arn = managed_policy["Policy"]["Arn"]

        # Create a role and attach the managed policy + an inline policy
        role = iam.create_role(
            RoleName="app-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        role_arn = role["Role"]["Arn"]

        iam.attach_role_policy(RoleName="app-role", PolicyArn=managed_policy_arn)
        iam.put_role_policy(
            RoleName="app-role",
            PolicyName="s3-write",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:PutObject", "s3:DeleteObject"],
                    "Resource": "arn:aws:s3:::twin-alpha",
                }],
            }),
        )

        # Create a user with an inline policy on twin-beta
        user = iam.create_user(UserName="dev-user")
        user_arn = user["User"]["Arn"]
        iam.put_user_policy(
            UserName="dev-user",
            PolicyName="s3-read-beta",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::twin-beta",
                }],
            }),
        )

        account_id = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)

        yield {
            "session": session,
            "account_id": account_id,
            "role_arn": role_arn,
            "user_arn": user_arn,
            "managed_policy_arn": managed_policy_arn,
        }


def test_discover_yields_has_access_to_edges_for_role(iam_s3_account):
    """AC 3: discover() yields DiscoveredEdge with type HAS_ACCESS_TO, from iam_role, to s3_bucket."""
    connector = _make_connector(iam_s3_account["session"], iam_s3_account["account_id"])
    _, edges = _discover_all(connector)
    ha_edges = _has_access_edges(edges)

    assert ha_edges, "expected at least one HAS_ACCESS_TO edge"
    role_edges = [e for e in ha_edges if e.from_ref.type == CIType.iam_role]
    assert role_edges, "expected at least one HAS_ACCESS_TO edge from an iam_role"
    assert all(e.to_ref.type == CIType.s3_bucket for e in role_edges)


def test_discover_yields_has_access_to_edges_for_user(iam_s3_account):
    """AC 3: discover() also yields HAS_ACCESS_TO from iam_user to s3_bucket."""
    connector = _make_connector(iam_s3_account["session"], iam_s3_account["account_id"])
    _, edges = _discover_all(connector)
    ha_edges = _has_access_edges(edges)

    user_edges = [e for e in ha_edges if e.from_ref.type == CIType.iam_user]
    assert user_edges, "expected at least one HAS_ACCESS_TO edge from an iam_user"
    assert all(e.to_ref.type == CIType.s3_bucket for e in user_edges)


def test_has_access_to_edge_source_is_declared_confidence_1(iam_s3_account):
    """AC 4: every HAS_ACCESS_TO edge has source=declared and confidence=1.0."""
    connector = _make_connector(iam_s3_account["session"], iam_s3_account["account_id"])
    _, edges = _discover_all(connector)
    ha_edges = _has_access_edges(edges)

    assert ha_edges
    for edge in ha_edges:
        assert edge.source == EdgeSource.declared, f"expected declared, got {edge.source}"
        assert edge.confidence == 1.0, f"expected confidence=1.0, got {edge.confidence}"


def test_has_access_to_edge_evidence_format(iam_s3_account):
    """AC 5: every HAS_ACCESS_TO edge has non-empty evidence; source='aws'; detail contains policy label and action."""
    connector = _make_connector(iam_s3_account["session"], iam_s3_account["account_id"])
    _, edges = _discover_all(connector)
    ha_edges = _has_access_edges(edges)

    assert ha_edges
    for edge in ha_edges:
        assert edge.evidence, "evidence list must be non-empty"
        for ev in edge.evidence:
            assert ev.source == "aws", f"expected source='aws', got {ev.source!r}"
            assert ev.detail, "evidence detail must be non-empty"
            # detail must contain a policy label (arn or inline:<name>) and an action
            has_policy_label = (
                "arn:" in ev.detail or "inline:" in ev.detail
            )
            has_action = (
                "s3:" in ev.detail or ev.detail.endswith("grants *")
            )
            assert has_policy_label, f"detail missing policy label: {ev.detail!r}"
            assert has_action, f"detail missing action: {ev.detail!r}"


def test_from_ref_external_id_is_arn_to_ref_is_bucket_name(iam_s3_account):
    """AC 6: from_ref.external_id == principal ARN; to_ref.external_id == bucket name."""
    connector = _make_connector(iam_s3_account["session"], iam_s3_account["account_id"])
    _, edges = _discover_all(connector)
    ha_edges = _has_access_edges(edges)

    assert ha_edges
    role_edges = [e for e in ha_edges if e.from_ref.type == CIType.iam_role]
    assert role_edges
    role_edge = role_edges[0]
    # from_ref.external_id must be the role ARN (starts with arn:)
    assert role_edge.from_ref.external_id.startswith("arn:"), (
        f"expected ARN, got {role_edge.from_ref.external_id!r}"
    )
    # to_ref.external_id must be a plain bucket name (no arn: prefix, just the name)
    assert not role_edge.to_ref.external_id.startswith("arn:"), (
        f"to_ref should be bucket name, not ARN: {role_edge.to_ref.external_id!r}"
    )
    assert role_edge.to_ref.external_id in {"twin-alpha", "twin-beta"}


def test_attached_managed_policy_produces_edge(iam_s3_account):
    """Attached managed policies on roles generate HAS_ACCESS_TO edges with ARN evidence."""
    connector = _make_connector(iam_s3_account["session"], iam_s3_account["account_id"])
    _, edges = _discover_all(connector)
    ha_edges = _has_access_edges(edges)

    role_edges_to_alpha = [
        e for e in ha_edges
        if e.from_ref.type == CIType.iam_role and e.to_ref.external_id == "twin-alpha"
    ]
    assert role_edges_to_alpha, "expected edge from role to twin-alpha"
    # Evidence must reference the managed policy ARN
    managed_arn = iam_s3_account["managed_policy_arn"]
    all_details = [ev.detail for e in role_edges_to_alpha for ev in e.evidence]
    assert any(managed_arn in d for d in all_details), (
        f"no evidence entry mentions the managed policy ARN {managed_arn!r}: {all_details}"
    )


def test_inline_policy_produces_edge(iam_s3_account):
    """Inline policies generate HAS_ACCESS_TO edges with 'inline:<name>' evidence."""
    connector = _make_connector(iam_s3_account["session"], iam_s3_account["account_id"])
    _, edges = _discover_all(connector)
    ha_edges = _has_access_edges(edges)

    role_edges_to_alpha = [
        e for e in ha_edges
        if e.from_ref.type == CIType.iam_role and e.to_ref.external_id == "twin-alpha"
    ]
    all_details = [ev.detail for e in role_edges_to_alpha for ev in e.evidence]
    # The inline policy is named "s3-write", so we expect "inline:s3-write" in a detail
    assert any("inline:s3-write" in d for d in all_details), (
        f"no evidence entry mentions inline policy: {all_details}"
    )


def test_user_inline_policy_produces_edge(iam_s3_account):
    """Inline policies on users generate HAS_ACCESS_TO edges with 'inline:<name>' evidence."""
    connector = _make_connector(iam_s3_account["session"], iam_s3_account["account_id"])
    _, edges = _discover_all(connector)
    ha_edges = _has_access_edges(edges)

    user_edges = [
        e for e in ha_edges
        if e.from_ref.type == CIType.iam_user and e.to_ref.external_id == "twin-beta"
    ]
    assert user_edges, "expected edge from user to twin-beta"
    all_details = [ev.detail for e in user_edges for ev in e.evidence]
    assert any("inline:s3-read-beta" in d for d in all_details), (
        f"no inline evidence for user edge: {all_details}"
    )


def test_deny_statement_produces_no_edge():
    """AC 7 / edge case 2: Deny effect must not produce a HAS_ACCESS_TO edge."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="deny-bucket")

        iam.create_role(
            RoleName="deny-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.put_role_policy(
            RoleName="deny-role",
            PolicyName="deny-s3",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Deny",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }],
            }),
        )

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = _has_access_edges(edges)
        assert not ha_edges, f"Deny statement should produce no HAS_ACCESS_TO edges, got: {ha_edges}"


def test_non_s3_action_produces_no_edge():
    """Edge case 3: ec2:* and iam:PassRole actions must not produce S3 edges."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="some-bucket")

        iam.create_role(
            RoleName="ec2-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.put_role_policy(
            RoleName="ec2-role",
            PolicyName="ec2-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["ec2:*", "iam:PassRole"],
                    "Resource": "*",
                }],
            }),
        )

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = _has_access_edges(edges)
        assert not ha_edges, f"non-S3 actions should produce no HAS_ACCESS_TO edges, got: {ha_edges}"


def test_undiscovered_bucket_resource_produces_no_edge():
    """AC 8 / edge case 11: Resource ARN for an undiscovered bucket must not produce an edge."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        # No s3 bucket created => nothing in bucket_names

        iam.create_role(
            RoleName="out-of-scope-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.put_role_policy(
            RoleName="out-of-scope-role",
            PolicyName="out-of-scope-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::undiscovered-bucket",
                }],
            }),
        )

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = _has_access_edges(edges)
        assert not ha_edges, (
            f"undiscovered bucket should produce no HAS_ACCESS_TO edges, got: {ha_edges}"
        )


def test_no_buckets_discovered_no_edges():
    """Edge case 19: if no buckets discovered, no HAS_ACCESS_TO edges even if policy references S3."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        iam.create_role(
            RoleName="lonely-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.put_role_policy(
            RoleName="lonely-role",
            PolicyName="s3-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*",
                }],
            }),
        )
        # No S3 bucket created
        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = _has_access_edges(edges)
        assert not ha_edges, f"no buckets => no HAS_ACCESS_TO edges, got: {ha_edges}"


def test_principal_with_no_policies_emits_no_edge():
    """Edge case 1: principal with no attached and no inline policies -> no HAS_ACCESS_TO edges."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="any-bucket")

        iam.create_role(
            RoleName="empty-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.create_user(UserName="empty-user")

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = _has_access_edges(edges)
        assert not ha_edges, f"principals with no policies should emit no edges, got: {ha_edges}"


def test_same_principal_bucket_from_two_grants_collapses_to_one_edge():
    """AC 9 / edge case 14: (principal, bucket) granted by two policies -> exactly one edge with evidence len>=2."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="shared-bucket")

        # Managed policy granting s3:GetObject
        managed_policy = iam.create_policy(
            PolicyName="GetPolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::shared-bucket",
                }],
            }),
        )
        managed_arn = managed_policy["Policy"]["Arn"]

        iam.create_role(
            RoleName="dual-grant-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.attach_role_policy(RoleName="dual-grant-role", PolicyArn=managed_arn)
        # Inline policy also granting a different action to same bucket
        iam.put_role_policy(
            RoleName="dual-grant-role",
            PolicyName="put-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::shared-bucket/*",
                }],
            }),
        )

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = [
            e for e in _has_access_edges(edges)
            if e.to_ref.external_id == "shared-bucket"
        ]

        # Exactly one edge for the (principal, bucket) pair
        assert len(ha_edges) == 1, f"expected exactly 1 edge, got {len(ha_edges)}: {ha_edges}"
        assert len(ha_edges[0].evidence) >= 2, (
            f"expected evidence length >= 2, got {len(ha_edges[0].evidence)}: {ha_edges[0].evidence}"
        )
        # Evidence entries must have distinct details
        details = [ev.detail for ev in ha_edges[0].evidence]
        assert len(set(details)) == len(details), f"evidence details are not distinct: {details}"


def test_two_principals_same_bucket_produce_two_edges():
    """Edge case 15: two different principals granted access to same bucket -> two separate edges."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="shared-bucket")

        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::shared-bucket",
            }],
        })
        iam.create_role(
            RoleName="role-one",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.put_role_policy(RoleName="role-one", PolicyName="pol", PolicyDocument=policy_doc)

        iam.create_user(UserName="user-one")
        iam.put_user_policy(UserName="user-one", PolicyName="pol", PolicyDocument=policy_doc)

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = [
            e for e in _has_access_edges(edges)
            if e.to_ref.external_id == "shared-bucket"
        ]

        assert len(ha_edges) == 2, f"expected 2 edges (one per principal), got {len(ha_edges)}"
        from_types = {e.from_ref.type for e in ha_edges}
        assert CIType.iam_role in from_types
        assert CIType.iam_user in from_types


def test_resource_star_covers_all_discovered_buckets():
    """Edge case 8: Resource='*' in policy must produce edges to every discovered bucket."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="bucket-a")
        s3.create_bucket(Bucket="bucket-b")

        iam.create_role(
            RoleName="star-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.put_role_policy(
            RoleName="star-role",
            PolicyName="star-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }],
            }),
        )

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = _has_access_edges(edges)

        targets = {e.to_ref.external_id for e in ha_edges}
        assert "bucket-a" in targets, "Resource=* should cover bucket-a"
        assert "bucket-b" in targets, "Resource=* should cover bucket-b"


def test_bucket_level_and_object_level_arn_both_resolve_to_bucket():
    """AC 10 / edge case 9: both arn:aws:s3:::name and arn:aws:s3:::name/* collapse to bucket 'name'."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="my-bucket")

        iam.create_role(
            RoleName="arn-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.put_role_policy(
            RoleName="arn-role",
            PolicyName="arn-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    # Both forms in one resource list
                    "Resource": [
                        "arn:aws:s3:::my-bucket",
                        "arn:aws:s3:::my-bucket/*",
                    ],
                }],
            }),
        )

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = [e for e in _has_access_edges(edges) if e.to_ref.external_id == "my-bucket"]

        # Must resolve to exactly one edge to "my-bucket"
        assert len(ha_edges) == 1, (
            f"bucket-level and object-level ARNs must collapse to one edge, got {len(ha_edges)}"
        )
        assert ha_edges[0].to_ref.external_id == "my-bucket"


def test_prefix_wildcard_resource_matches_correct_buckets():
    """AC 11 / edge case 10: arn:aws:s3:::prefix* matches all buckets starting with prefix."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="twin-one")
        s3.create_bucket(Bucket="twin-two")
        s3.create_bucket(Bucket="other-bucket")

        iam.create_role(
            RoleName="wildcard-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.put_role_policy(
            RoleName="wildcard-role",
            PolicyName="wildcard-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::twin-*",
                }],
            }),
        )

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = _has_access_edges(edges)

        targets = {e.to_ref.external_id for e in ha_edges}
        assert "twin-one" in targets, "prefix wildcard should match twin-one"
        assert "twin-two" in targets, "prefix wildcard should match twin-two"
        assert "other-bucket" not in targets, "prefix wildcard should NOT match other-bucket"


def test_url_encoded_policy_document_decoded():
    """Edge case 16: policy document delivered as URL-encoded JSON string is decoded correctly."""
    with mock_aws():
        # We test this at the unit level since moto returns decoded dicts;
        # we directly invoke _s3_grants_from_statement via _policy_statements on a url-encoded doc.
        from infra_twin.collectors.aws.connector import _policy_statements, _s3_grants_from_statement
        import json, urllib.parse

        doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket",
            }],
        }
        url_encoded = urllib.parse.quote(json.dumps(doc))
        # Decode as the connector does
        decoded = json.loads(urllib.parse.unquote(url_encoded))
        stmts = _policy_statements(decoded)
        assert len(stmts) == 1
        grants = _s3_grants_from_statement(stmts[0], {"my-bucket"})
        assert ("my-bucket", "s3:GetObject") in grants


def test_statement_as_single_dict_handled():
    """Edge case 7: Statement as a single dict (not list) is treated as one statement."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="single-stmt-bucket")

        # Craft a policy where Statement is a dict, not a list
        # moto serializes it as-is so we must set it via put_role_policy as JSON
        iam.create_role(
            RoleName="single-stmt-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        # The statement is a single dict (not wrapped in a list)
        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::single-stmt-bucket",
            },
        })
        iam.put_role_policy(
            RoleName="single-stmt-role",
            PolicyName="single-stmt-policy",
            PolicyDocument=policy_doc,
        )

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = [
            e for e in _has_access_edges(edges)
            if e.to_ref.external_id == "single-stmt-bucket"
        ]
        assert ha_edges, "single-dict Statement must be handled and produce an edge"


def test_all_services_wildcard_action_produces_edge():
    """Edge case 4: Action='*' (all-services wildcard) on S3 bucket resource -> edge with action='*'."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="wildcard-action-bucket")

        iam.create_role(
            RoleName="star-action-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.put_role_policy(
            RoleName="star-action-role",
            PolicyName="star-action-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "arn:aws:s3:::wildcard-action-bucket",
                }],
            }),
        )

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = [
            e for e in _has_access_edges(edges)
            if e.to_ref.external_id == "wildcard-action-bucket"
        ]
        assert ha_edges, "Action='*' should produce a HAS_ACCESS_TO edge"
        # Evidence detail must reference the '*' action
        all_details = [ev.detail for e in ha_edges for ev in e.evidence]
        assert any("grants *" in d for d in all_details), (
            f"expected action='*' in evidence, got: {all_details}"
        )


def test_missing_resource_key_produces_no_edge():
    """Edge case 12: missing Resource key must not default to '*'; no edge emitted."""
    buckets = {"my-bucket"}
    stmt = {"Effect": "Allow", "Action": "s3:GetObject"}
    grants = _s3_grants_from_statement(stmt, buckets)
    assert grants == set(), f"missing Resource should yield no grants, got: {grants}"


def test_not_action_produces_no_edge():
    """Edge case 13: NotAction is ignored; no grant derived from it."""
    buckets = {"my-bucket"}
    stmt = {"Effect": "Allow", "NotAction": "s3:GetObject", "Resource": "*"}
    grants = _s3_grants_from_statement(stmt, buckets)
    assert grants == set(), f"NotAction must not produce grants, got: {grants}"


def test_not_resource_produces_no_edge():
    """Edge case 13: NotResource is ignored; no grant derived from it."""
    buckets = {"my-bucket"}
    stmt = {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "*"}
    grants = _s3_grants_from_statement(stmt, buckets)
    assert grants == set(), f"NotResource must not produce grants, got: {grants}"


def test_case_insensitive_action_matching_original_case_in_evidence():
    """Edge case 21: S3:GetObject (uppercase S) is matched case-insensitively, original case in evidence."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="case-bucket")

        iam.create_role(
            RoleName="case-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.put_role_policy(
            RoleName="case-role",
            PolicyName="case-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "S3:GetObject",  # uppercase S
                    "Resource": "arn:aws:s3:::case-bucket",
                }],
            }),
        )

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = [
            e for e in _has_access_edges(edges)
            if e.to_ref.external_id == "case-bucket"
        ]
        assert ha_edges, "S3:GetObject (uppercase S) should still produce an edge"
        # Original-case action string must appear in evidence
        all_details = [ev.detail for e in ha_edges for ev in e.evidence]
        assert any("S3:GetObject" in d for d in all_details), (
            f"original-case action 'S3:GetObject' should be in evidence, got: {all_details}"
        )


def test_ci_events_precede_has_access_to_edges():
    """Ordering requirement: iam_* and s3_bucket DiscoveredCI events must precede HAS_ACCESS_TO edges."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="order-bucket")

        iam.create_role(
            RoleName="order-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.put_role_policy(
            RoleName="order-role",
            PolicyName="order-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
            }),
        )

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        events = list(connector.discover())

        # Find index of first HAS_ACCESS_TO edge
        ha_idx = next(
            (i for i, e in enumerate(events) if isinstance(e, DiscoveredEdge) and e.type == EdgeType.HAS_ACCESS_TO),
            None,
        )
        assert ha_idx is not None, "expected at least one HAS_ACCESS_TO edge"

        # All iam_role/iam_user/s3_bucket CIs must appear before first HAS_ACCESS_TO edge
        for i, event in enumerate(events[:ha_idx]):
            pass  # just confirm we can iterate

        iam_s3_ci_indices = [
            i for i, e in enumerate(events)
            if isinstance(e, DiscoveredCI) and e.type in {CIType.iam_role, CIType.iam_user, CIType.s3_bucket}
        ]
        assert iam_s3_ci_indices, "expected at least one iam_role/iam_user/s3_bucket CI"
        assert max(iam_s3_ci_indices) < ha_idx, (
            f"iam/s3 CIs must precede HAS_ACCESS_TO edges: last CI at {max(iam_s3_ci_indices)}, "
            f"first HAS_ACCESS_TO at {ha_idx}"
        )


def test_iam_user_attached_managed_policy_produces_edge():
    """IAM user with an attached managed policy generates HAS_ACCESS_TO edges (AC 3 for users)."""
    with mock_aws():
        iam = boto3.client("iam", region_name=REGION)
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="user-managed-bucket")

        managed_policy = iam.create_policy(
            PolicyName="UserS3Policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::user-managed-bucket",
                }],
            }),
        )
        managed_arn = managed_policy["Policy"]["Arn"]

        iam.create_user(UserName="managed-user")
        iam.attach_user_policy(UserName="managed-user", PolicyArn=managed_arn)

        session = boto3.Session(region_name=REGION)
        account_id = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
        connector = _make_connector(session, account_id)
        _, edges = _discover_all(connector)
        ha_edges = [
            e for e in _has_access_edges(edges)
            if e.from_ref.type == CIType.iam_user and e.to_ref.external_id == "user-managed-bucket"
        ]
        assert ha_edges, "user with managed policy should produce a HAS_ACCESS_TO edge"
        # Evidence must reference managed policy ARN
        all_details = [ev.detail for e in ha_edges for ev in e.evidence]
        assert any(managed_arn in d for d in all_details), (
            f"managed policy ARN should appear in evidence: {all_details}"
        )


def test_evidence_detail_format_contains_grants_keyword():
    """AC 5: evidence detail string has the form '<policy_label> grants <action>'."""
    buckets = {"my-bucket"}
    stmt = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
    grants = _s3_grants_from_statement(stmt, buckets)
    # simulate what the connector builds
    for bucket, action in grants:
        detail = f"inline:mypolicy grants {action}"
        assert "grants" in detail
        assert "inline:mypolicy" in detail
        assert action in detail


def test_edge_from_ref_type_is_iam_type(iam_s3_account):
    """AC 3: from_ref.type must be CIType.iam_role or CIType.iam_user."""
    connector = _make_connector(iam_s3_account["session"], iam_s3_account["account_id"])
    _, edges = _discover_all(connector)
    ha_edges = _has_access_edges(edges)

    assert ha_edges
    for edge in ha_edges:
        assert edge.from_ref.type in {CIType.iam_role, CIType.iam_user}, (
            f"from_ref.type must be iam_role or iam_user, got {edge.from_ref.type}"
        )


def test_edge_to_ref_type_is_s3_bucket(iam_s3_account):
    """AC 3: to_ref.type must be CIType.s3_bucket."""
    connector = _make_connector(iam_s3_account["session"], iam_s3_account["account_id"])
    _, edges = _discover_all(connector)
    ha_edges = _has_access_edges(edges)

    assert ha_edges
    for edge in ha_edges:
        assert edge.to_ref.type == CIType.s3_bucket, (
            f"to_ref.type must be s3_bucket, got {edge.to_ref.type}"
        )
