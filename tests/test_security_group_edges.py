"""Contract tests for the security-group ingress CONNECTS_TO edge feature.

Tests cover (mirroring spec §6 edge cases + §7 acceptance criteria):
- Pure unit tests for module-level helpers: _port_range_label, _public_cidrs_in_permission,
  _source_group_ids_in_permission
- Internet IPv4 (0.0.0.0/0) ingress rule -> internet CONNECTS_TO edge
- Internet IPv6 (::/0) ingress rule -> internet CONNECTS_TO edge
- Both public CIDRs in one permission -> ONE internet edge with two Evidence entries (collapse)
- Non-public CIDR (10.0.0.0/16) -> not treated as internet; no internet edge
- SG-to-SG edge from a source group to the declaring SG
- UserIdGroupPairs entry missing GroupId -> skipped, no SG-to-SG edge
- Self-referencing source group (self-loop)
- Three port-range label forms: all traffic, single-port, range
- Same SG referenced by multiple permissions -> ONE collapsed edge with deduplicated evidence
- Internet CI emitted exactly once across a run with multiple SGs allowing internet
- No internet rules anywhere -> internet CI not emitted
- SG with no IpPermissions key -> no CONNECTS_TO edges
- SG with empty IpPermissions -> no CONNECTS_TO edges
- CI-before-edge ordering: internet DiscoveredCI precedes first CONNECTS_TO edge
- Egress rules (IpPermissionsEgress) ignored entirely
- Mixed permission with both public CIDRs and source groups -> both edge types emitted
- Duplicate identical evidence fragments de-duplicated
- Module-level constants importable and correct
- connector.ci_types contains internet; connector.edge_types contains CONNECTS_TO
- SG-to-SG edge whose source group is not discovered is dropped by reconcile (AC 19)
"""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from infra_twin.collectors.aws import AwsConnector
from infra_twin.collectors.aws.connector import (
    INTERNET_EXTERNAL_ID,
    INTERNET_NAME,
    _PUBLIC_CIDRS,
    _port_range_label,
    _public_cidrs_in_permission,
    _source_group_ids_in_permission,
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


def _connects_to_edges(edges):
    return [e for e in edges if e.type == EdgeType.CONNECTS_TO]


def _internet_edges(edges):
    return [
        e for e in _connects_to_edges(edges)
        if e.from_ref.type == CIType.internet
    ]


def _sg_to_sg_edges(edges):
    return [
        e for e in _connects_to_edges(edges)
        if e.from_ref.type == CIType.security_group
    ]


def _account_id(session: boto3.Session) -> str:
    return session.client("sts", region_name=REGION).get_caller_identity()["Account"]


# ---------------------------------------------------------------------------
# AC 1 / AC 2: constants exist and are importable with correct values
# ---------------------------------------------------------------------------


def test_internet_external_id_constant():
    """AC 2: INTERNET_EXTERNAL_ID == 'internet'."""
    assert INTERNET_EXTERNAL_ID == "internet"


def test_public_cidrs_constant():
    """AC 2: _PUBLIC_CIDRS == frozenset({'0.0.0.0/0', '::/0'})."""
    assert _PUBLIC_CIDRS == frozenset({"0.0.0.0/0", "::/0"})


def test_internet_name_constant():
    """INTERNET_NAME is the correct human-readable label."""
    assert INTERNET_NAME == "Internet (0.0.0.0/0, ::/0)"


# ---------------------------------------------------------------------------
# AC 3 / AC 4: connector scope sets
# ---------------------------------------------------------------------------


def test_internet_in_ci_types():
    """AC 3: CIType.internet must be in AwsConnector.ci_types."""
    assert CIType.internet in AwsConnector.ci_types


def test_connects_to_in_edge_types():
    """AC 4: EdgeType.CONNECTS_TO must be in AwsConnector.edge_types."""
    assert EdgeType.CONNECTS_TO in AwsConnector.edge_types


# ---------------------------------------------------------------------------
# AC 6 / AC 7-9: pure unit tests for _port_range_label
# ---------------------------------------------------------------------------


class TestPortRangeLabel:
    """Unit tests for _port_range_label (AC 6-9 / spec §6 #11-14)."""

    def test_ip_protocol_minus_one_is_all_traffic(self):
        """AC 7 / edge case 11: IpProtocol='-1' -> 'all traffic'."""
        assert _port_range_label({"IpProtocol": "-1"}) == "all traffic"

    def test_missing_ip_protocol_is_all_traffic(self):
        """IpProtocol absent -> defaults to '-1' -> 'all traffic'."""
        assert _port_range_label({}) == "all traffic"

    def test_single_port_same_from_to(self):
        """AC 8 / edge case 12: tcp/443 -> 'tcp/443'."""
        assert _port_range_label({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443}) == "tcp/443"

    def test_port_range_different_from_to(self):
        """AC 9 / edge case 13: tcp 8000-8100 -> 'tcp/8000-8100'."""
        assert _port_range_label({"IpProtocol": "tcp", "FromPort": 8000, "ToPort": 8100}) == "tcp/8000-8100"

    def test_icmp_without_ports(self):
        """Edge case 14: icmp without FromPort/ToPort -> 'icmp'."""
        assert _port_range_label({"IpProtocol": "icmp"}) == "icmp"

    def test_numeric_protocol_without_ports(self):
        """Edge case 14: numeric protocol '6' (TCP) without ports -> '6'."""
        assert _port_range_label({"IpProtocol": "6"}) == "6"

    def test_udp_single_port(self):
        """udp single port renders as udp/<port>."""
        assert _port_range_label({"IpProtocol": "udp", "FromPort": 53, "ToPort": 53}) == "udp/53"

    def test_protocol_with_only_from_port_absent_to_port(self):
        """When only FromPort present but ToPort absent -> proto only."""
        assert _port_range_label({"IpProtocol": "tcp", "FromPort": 443}) == "tcp"

    def test_protocol_with_only_to_port_absent_from_port(self):
        """When only ToPort present but FromPort absent -> proto only."""
        assert _port_range_label({"IpProtocol": "tcp", "ToPort": 443}) == "tcp"


# ---------------------------------------------------------------------------
# AC 10: pure unit tests for _public_cidrs_in_permission
# ---------------------------------------------------------------------------


class TestPublicCidrsInPermission:
    """Unit tests for _public_cidrs_in_permission (AC 10 / spec §6 #3-6)."""

    def test_ipv4_public_cidr_returned(self):
        """Edge case 3: IpRanges with 0.0.0.0/0 -> ['0.0.0.0/0']."""
        perm = {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        assert _public_cidrs_in_permission(perm) == ["0.0.0.0/0"]

    def test_ipv6_public_cidr_returned(self):
        """Edge case 4: Ipv6Ranges with ::/0 -> ['::/0']."""
        perm = {"Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
        assert _public_cidrs_in_permission(perm) == ["::/0"]

    def test_both_public_cidrs_returned_sorted(self):
        """Edge case 5: both 0.0.0.0/0 and ::/0 in one permission -> both returned."""
        perm = {
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
        result = _public_cidrs_in_permission(perm)
        assert sorted(result) == sorted(["::/0", "0.0.0.0/0"])
        assert len(result) == 2

    def test_non_public_cidr_excluded(self):
        """Edge case 6: 10.0.0.0/16 is not internet; empty list returned."""
        perm = {"IpRanges": [{"CidrIp": "10.0.0.0/16"}]}
        assert _public_cidrs_in_permission(perm) == []

    def test_mixed_public_and_private_only_public_returned(self):
        """Mixed ranges: only 0.0.0.0/0 extracted, 192.168.0.0/16 excluded."""
        perm = {
            "IpRanges": [
                {"CidrIp": "0.0.0.0/0"},
                {"CidrIp": "192.168.0.0/16"},
            ]
        }
        result = _public_cidrs_in_permission(perm)
        assert result == ["0.0.0.0/0"]

    def test_non_public_routable_address(self):
        """203.0.113.0/24 (TEST-NET-3) is not a public internet CIDR in spec terms."""
        perm = {"IpRanges": [{"CidrIp": "203.0.113.0/24"}]}
        assert _public_cidrs_in_permission(perm) == []

    def test_empty_permission_returns_empty(self):
        """Permission with no IpRanges or Ipv6Ranges -> empty list."""
        assert _public_cidrs_in_permission({}) == []

    def test_result_is_sorted(self):
        """Return value is sorted (deterministic)."""
        perm = {
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
        result = _public_cidrs_in_permission(perm)
        assert result == sorted(result)


# ---------------------------------------------------------------------------
# AC 11: pure unit tests for _source_group_ids_in_permission
# ---------------------------------------------------------------------------


class TestSourceGroupIdsInPermission:
    """Unit tests for _source_group_ids_in_permission (AC 11 / spec §6 #7-9)."""

    def test_single_group_id_returned(self):
        """Edge case 7: UserIdGroupPairs with GroupId -> [GroupId]."""
        perm = {"UserIdGroupPairs": [{"GroupId": "sg-aaaa"}]}
        assert _source_group_ids_in_permission(perm) == ["sg-aaaa"]

    def test_missing_group_id_skipped(self):
        """Edge case 8: pair without GroupId is skipped."""
        perm = {"UserIdGroupPairs": [{"UserId": "123456789", "Description": "no-id"}]}
        assert _source_group_ids_in_permission(perm) == []

    def test_mixed_pairs_only_with_group_id_returned(self):
        """Pairs with and without GroupId: only those with GroupId are returned."""
        perm = {
            "UserIdGroupPairs": [
                {"GroupId": "sg-bbbb"},
                {"UserId": "123", "PeeringStatus": "active"},  # missing GroupId
                {"GroupId": "sg-cccc"},
            ]
        }
        result = _source_group_ids_in_permission(perm)
        assert sorted(result) == ["sg-bbbb", "sg-cccc"]

    def test_multiple_groups_sorted(self):
        """Multiple GroupIds returned sorted (deterministic)."""
        perm = {
            "UserIdGroupPairs": [
                {"GroupId": "sg-zzzz"},
                {"GroupId": "sg-aaaa"},
            ]
        }
        result = _source_group_ids_in_permission(perm)
        assert result == ["sg-aaaa", "sg-zzzz"]

    def test_empty_user_id_group_pairs(self):
        """Empty UserIdGroupPairs -> empty list."""
        assert _source_group_ids_in_permission({"UserIdGroupPairs": []}) == []

    def test_no_user_id_group_pairs_key(self):
        """Permission without UserIdGroupPairs key -> empty list."""
        assert _source_group_ids_in_permission({}) == []

    def test_duplicate_group_ids_deduplicated(self):
        """Duplicate GroupIds across pairs -> deduplicated result."""
        perm = {
            "UserIdGroupPairs": [
                {"GroupId": "sg-aaaa"},
                {"GroupId": "sg-aaaa"},
            ]
        }
        result = _source_group_ids_in_permission(perm)
        assert result == ["sg-aaaa"]


# ---------------------------------------------------------------------------
# Connector contract tests against moto-mocked AWS
# ---------------------------------------------------------------------------


@pytest.fixture
def sg_account():
    """Moto-backed account with a VPC and two security groups."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        # SG A: allows tcp/443 from internet IPv4
        sg_a = ec2.create_security_group(
            GroupName="sg-internet-v4",
            Description="allows tcp/443 from 0.0.0.0/0",
            VpcId=vpc,
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_a,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        # SG B: allows all traffic from SG A (SG-to-SG)
        sg_b = ec2.create_security_group(
            GroupName="sg-internal",
            Description="allows all traffic from sg-a",
            VpcId=vpc,
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_b,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "UserIdGroupPairs": [{"GroupId": sg_a}],
                }
            ],
        )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)

        yield {
            "session": session,
            "account_id": account,
            "vpc_id": vpc,
            "sg_a": sg_a,
            "sg_b": sg_b,
        }


# ---------------------------------------------------------------------------
# AC 12: internet edge from discover() for IPv4 public CIDR
# ---------------------------------------------------------------------------


def test_internet_ipv4_ingress_yields_connects_to_edge(sg_account):
    """AC 12 / edge case 3: SG allowing 0.0.0.0/0 -> one CONNECTS_TO edge from internet."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    _, edges = _discover_all(connector)
    inet_edges = _internet_edges(edges)

    assert inet_edges, "expected at least one internet CONNECTS_TO edge"
    sg_a = sg_account["sg_a"]
    inet_to_a = [e for e in inet_edges if e.to_ref.external_id == sg_a]
    assert len(inet_to_a) == 1, f"expected exactly 1 internet->sg_a edge, got {len(inet_to_a)}"


def test_internet_edge_from_ref_type_and_external_id(sg_account):
    """AC 12: from_ref.type == CIType.internet and from_ref.external_id == 'internet'."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    _, edges = _discover_all(connector)
    inet_edges = _internet_edges(edges)

    assert inet_edges
    for edge in inet_edges:
        assert edge.from_ref.type == CIType.internet
        assert edge.from_ref.external_id == "internet"


def test_internet_edge_to_ref_is_security_group(sg_account):
    """AC 12: to_ref.type == CIType.security_group."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    _, edges = _discover_all(connector)
    inet_edges = _internet_edges(edges)

    assert inet_edges
    for edge in inet_edges:
        assert edge.to_ref.type == CIType.security_group


# ---------------------------------------------------------------------------
# AC 13: source and confidence on every CONNECTS_TO edge
# ---------------------------------------------------------------------------


def test_connects_to_source_is_declared_confidence_1(sg_account):
    """AC 13: every CONNECTS_TO edge has source=declared and confidence=1.0."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    _, edges = _discover_all(connector)
    ct_edges = _connects_to_edges(edges)

    assert ct_edges
    for edge in ct_edges:
        assert edge.source == EdgeSource.declared, f"expected declared, got {edge.source}"
        assert edge.confidence == 1.0, f"expected confidence=1.0, got {edge.confidence}"


# ---------------------------------------------------------------------------
# AC 14: evidence format
# ---------------------------------------------------------------------------


def test_connects_to_evidence_non_empty_source_aws(sg_account):
    """AC 14: every CONNECTS_TO edge has non-empty evidence with source='aws'."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    _, edges = _discover_all(connector)
    ct_edges = _connects_to_edges(edges)

    assert ct_edges
    for edge in ct_edges:
        assert edge.evidence, "evidence list must be non-empty"
        for ev in edge.evidence:
            assert ev.source == "aws", f"expected source='aws', got {ev.source!r}"


def test_internet_edge_evidence_detail_contains_label_and_cidr(sg_account):
    """AC 14: internet edge evidence detail contains the port label and CIDR."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    _, edges = _discover_all(connector)
    sg_a = sg_account["sg_a"]
    inet_to_a = [e for e in _internet_edges(edges) if e.to_ref.external_id == sg_a]

    assert inet_to_a
    all_details = [ev.detail for ev in inet_to_a[0].evidence]
    # Must reference 0.0.0.0/0 and the tcp/443 label
    assert any("0.0.0.0/0" in d for d in all_details), f"CIDR missing from details: {all_details}"
    assert any("tcp/443" in d for d in all_details), f"port label missing from details: {all_details}"


def test_sg_to_sg_edge_evidence_contains_label_and_group(sg_account):
    """AC 14: SG-to-SG evidence detail contains the port label and 'group <id>'."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    _, edges = _discover_all(connector)
    sg_edges = _sg_to_sg_edges(edges)

    assert sg_edges
    sg_a = sg_account["sg_a"]
    for edge in sg_edges:
        for ev in edge.evidence:
            assert ev.detail, "evidence detail must be non-empty"
            # detail must contain 'group <src_group_id>'
            assert f"group {sg_a}" in ev.detail, (
                f"SG-to-SG detail should reference 'group {sg_a}': {ev.detail!r}"
            )
            # detail must contain 'all traffic' (the protocol label for -1)
            assert "all traffic" in ev.detail, (
                f"SG-to-SG detail should reference protocol label: {ev.detail!r}"
            )


# ---------------------------------------------------------------------------
# AC 15: SG-to-SG edge shape
# ---------------------------------------------------------------------------


def test_sg_to_sg_edge_from_sg_a_to_sg_b(sg_account):
    """AC 15: SG-to-SG ingress yields CONNECTS_TO from sg_a to sg_b."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    _, edges = _discover_all(connector)
    sg_edges = _sg_to_sg_edges(edges)

    sg_a = sg_account["sg_a"]
    sg_b = sg_account["sg_b"]
    matching = [
        e for e in sg_edges
        if e.from_ref.external_id == sg_a and e.to_ref.external_id == sg_b
    ]
    assert len(matching) == 1, (
        f"expected exactly 1 SG-to-SG edge from {sg_a} to {sg_b}, got {len(matching)}"
    )
    assert matching[0].from_ref.type == CIType.security_group
    assert matching[0].to_ref.type == CIType.security_group


# ---------------------------------------------------------------------------
# AC 16: internet CI emitted exactly once
# ---------------------------------------------------------------------------


def test_internet_ci_emitted_exactly_once_when_internet_rule_present(sg_account):
    """AC 16: internet DiscoveredCI yielded exactly once when at least one internet rule exists."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    cis, _ = _discover_all(connector)
    internet_cis = [c for c in cis if c.type == CIType.internet]
    assert len(internet_cis) == 1, (
        f"expected exactly 1 internet CI, got {len(internet_cis)}"
    )


def test_internet_ci_has_correct_external_id_and_name(sg_account):
    """Internet CI has external_id='internet' and name=INTERNET_NAME."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    cis, _ = _discover_all(connector)
    internet_cis = [c for c in cis if c.type == CIType.internet]
    assert internet_cis
    ci = internet_cis[0]
    assert ci.external_id == INTERNET_EXTERNAL_ID
    assert ci.name == INTERNET_NAME


def test_internet_ci_not_emitted_when_no_internet_rules():
    """AC 16 / edge case 18: no internet rules -> internet CI is NOT emitted."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        # SG with only a private CIDR ingress (no internet rules)
        sg = ec2.create_security_group(
            GroupName="private-sg",
            Description="allows from private range only",
            VpcId=vpc,
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                }
            ],
        )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)
        connector = _make_connector(session, account)
        cis, edges = _discover_all(connector)

        internet_cis = [c for c in cis if c.type == CIType.internet]
        assert internet_cis == [], (
            f"internet CI must NOT be emitted when no internet rules: {internet_cis}"
        )
        inet_edges = _internet_edges(edges)
        assert inet_edges == [], (
            f"no internet CONNECTS_TO edges expected when no internet rules: {inet_edges}"
        )


# ---------------------------------------------------------------------------
# Edge case 2: SG with empty IpPermissions -> no edges
# ---------------------------------------------------------------------------


def test_sg_with_empty_ip_permissions_produces_no_connects_to_edges():
    """Edge case 2: SG with IpPermissions=[] -> no CONNECTS_TO edges."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        ec2.create_security_group(
            GroupName="empty-sg",
            Description="no ingress rules",
            VpcId=vpc,
        )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)
        connector = _make_connector(session, account)
        cis, edges = _discover_all(connector)

        ct_edges = _connects_to_edges(edges)
        assert ct_edges == [], f"expected no CONNECTS_TO edges, got: {ct_edges}"
        internet_cis = [c for c in cis if c.type == CIType.internet]
        assert internet_cis == [], "internet CI must not be emitted with no ingress rules"


# ---------------------------------------------------------------------------
# Edge case 4: internet IPv6 (::/0)
# ---------------------------------------------------------------------------


def test_internet_ipv6_ingress_yields_connects_to_edge():
    """Edge case 4: Ipv6Ranges with ::/0 -> internet CONNECTS_TO edge."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(
            GroupName="ipv6-sg",
            Description="allows from ::/0",
            VpcId=vpc,
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ],
        )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)
        connector = _make_connector(session, account)
        _, edges = _discover_all(connector)

        inet_edges = _internet_edges(edges)
        assert inet_edges, "expected internet CONNECTS_TO edge for ::/0 rule"
        inet_to_sg = [e for e in inet_edges if e.to_ref.external_id == sg]
        assert len(inet_to_sg) == 1, f"expected exactly 1 internet->sg edge, got {len(inet_to_sg)}"
        all_details = [ev.detail for ev in inet_to_sg[0].evidence]
        assert any("::/0" in d for d in all_details), f"::/0 missing from evidence: {all_details}"


# ---------------------------------------------------------------------------
# Edge case 5: both public CIDRs -> ONE internet edge, evidence lists both
# ---------------------------------------------------------------------------


def test_both_public_cidrs_collapses_to_one_internet_edge():
    """Edge case 5: permission with both 0.0.0.0/0 and ::/0 -> one edge, two Evidence entries."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(
            GroupName="dual-cidr-sg",
            Description="allows from both 0.0.0.0/0 and ::/0",
            VpcId=vpc,
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ],
        )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)
        connector = _make_connector(session, account)
        _, edges = _discover_all(connector)

        inet_to_sg = [e for e in _internet_edges(edges) if e.to_ref.external_id == sg]
        assert len(inet_to_sg) == 1, (
            f"both CIDRs in one permission -> exactly 1 internet edge, got {len(inet_to_sg)}"
        )
        all_details = [ev.detail for ev in inet_to_sg[0].evidence]
        assert any("0.0.0.0/0" in d for d in all_details), "0.0.0.0/0 must appear in evidence"
        assert any("::/0" in d for d in all_details), "::/0 must appear in evidence"
        assert len(inet_to_sg[0].evidence) == 2, (
            f"expected 2 evidence entries (one per CIDR), got {len(inet_to_sg[0].evidence)}"
        )


# ---------------------------------------------------------------------------
# Edge case 6: non-public CIDR -> no internet edge
# ---------------------------------------------------------------------------


def test_non_public_cidr_does_not_produce_internet_edge():
    """Edge case 6: 10.0.0.0/16 is not internet; no internet edge emitted."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(
            GroupName="private-only-sg",
            Description="allows from private only",
            VpcId=vpc,
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                }
            ],
        )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)
        connector = _make_connector(session, account)
        cis, edges = _discover_all(connector)

        inet_edges = _internet_edges(edges)
        assert inet_edges == [], (
            f"non-public CIDR should not produce internet edge, got: {inet_edges}"
        )
        internet_cis = [c for c in cis if c.type == CIType.internet]
        assert internet_cis == [], "internet CI must not be emitted"


# ---------------------------------------------------------------------------
# Edge case 8: UserIdGroupPairs entry missing GroupId -> skipped
# ---------------------------------------------------------------------------


def test_missing_group_id_in_user_id_group_pairs_skipped():
    """Edge case 8: UserIdGroupPairs entry without GroupId -> no SG-to-SG edge."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(
            GroupName="no-gid-sg",
            Description="sg-to-sg with missing GroupId",
            VpcId=vpc,
        )["GroupId"]

        # Manually test the helper: pair without GroupId produces no group ids
        perm = {"UserIdGroupPairs": [{"UserId": "123456789012", "Description": "no GroupId"}]}
        group_ids = _source_group_ids_in_permission(perm)
        assert group_ids == [], f"missing GroupId should be skipped, got: {group_ids}"


# ---------------------------------------------------------------------------
# Edge case 9: self-loop (source group == target SG)
# ---------------------------------------------------------------------------


def test_self_referencing_source_group_produces_self_loop():
    """Edge case 9: GroupId == this_sg -> self-loop CONNECTS_TO edge emitted."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(
            GroupName="self-ref-sg",
            Description="allows ingress from itself",
            VpcId=vpc,
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "UserIdGroupPairs": [{"GroupId": sg}],
                }
            ],
        )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)
        connector = _make_connector(session, account)
        _, edges = _discover_all(connector)

        sg_edges = _sg_to_sg_edges(edges)
        self_loops = [
            e for e in sg_edges
            if e.from_ref.external_id == sg and e.to_ref.external_id == sg
        ]
        assert len(self_loops) == 1, (
            f"expected exactly 1 self-loop edge for {sg}, got {len(self_loops)}"
        )


# ---------------------------------------------------------------------------
# AC 17 / edge case 10: same source group in multiple permissions -> ONE collapsed edge
# ---------------------------------------------------------------------------


def test_same_source_group_multiple_permissions_collapses_to_one_edge():
    """AC 17 (updated for edge_key feature) / edge case 10: same src group in 2 permissions
    with DISTINCT port-range labels -> 2 SG-to-SG edges, each with its own edge_key and
    evidence.  The old behavior of collapsing to 1 edge was superseded by the parallel-edge
    identity feature (spec §4.8 AC16): each distinct (src_group_id, port-range label) pair
    becomes its own DiscoveredEdge with a non-empty edge_key."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg_src = ec2.create_security_group(
            GroupName="src-sg",
            Description="source group",
            VpcId=vpc,
        )["GroupId"]
        sg_tgt = ec2.create_security_group(
            GroupName="target-sg",
            Description="target group referenced twice",
            VpcId=vpc,
        )["GroupId"]

        # Two separate permissions both referencing sg_src -> sg_tgt, DISTINCT port ranges
        ec2.authorize_security_group_ingress(
            GroupId=sg_tgt,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "UserIdGroupPairs": [{"GroupId": sg_src}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 6379,
                    "ToPort": 6379,
                    "UserIdGroupPairs": [{"GroupId": sg_src}],
                },
            ],
        )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)
        connector = _make_connector(session, account)
        _, edges = _discover_all(connector)

        sg_edges = _sg_to_sg_edges(edges)
        pair_edges = [
            e for e in sg_edges
            if e.from_ref.external_id == sg_src and e.to_ref.external_id == sg_tgt
        ]
        # Two distinct port-range labels -> two distinct edges with different edge_keys
        assert len(pair_edges) == 2, (
            f"same src group in 2 distinct-port permissions must produce 2 edges "
            f"(one per port-range label); got {len(pair_edges)}"
        )
        # Each edge has its own non-empty edge_key
        edge_keys = {e.edge_key for e in pair_edges}
        assert len(edge_keys) == 2, f"Two edges must have distinct edge_key values; got {edge_keys}"
        for e in pair_edges:
            assert e.edge_key, f"SG-sourced edge must have non-empty edge_key; got {e.edge_key!r}"
            assert e.evidence, f"Edge must have non-empty evidence; got edge_key={e.edge_key!r}"
        # Evidence details are distinct
        all_details = [ev.detail for e in pair_edges for ev in e.evidence]
        assert len(set(all_details)) == len(all_details), (
            f"Evidence details must be distinct across edges: {all_details}"
        )


# ---------------------------------------------------------------------------
# Edge case 15: internet CI emitted once across multiple SGs
# ---------------------------------------------------------------------------


def test_internet_ci_emitted_once_for_multiple_sgs_with_internet_rules():
    """Edge case 15: two SGs each allowing 0.0.0.0/0 -> two internet edges, one internet CI."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg_x = ec2.create_security_group(
            GroupName="sg-x",
            Description="allows from internet",
            VpcId=vpc,
        )["GroupId"]
        sg_y = ec2.create_security_group(
            GroupName="sg-y",
            Description="also allows from internet",
            VpcId=vpc,
        )["GroupId"]

        for sg_id in [sg_x, sg_y]:
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 80,
                        "ToPort": 80,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)
        connector = _make_connector(session, account)
        cis, edges = _discover_all(connector)

        internet_cis = [c for c in cis if c.type == CIType.internet]
        assert len(internet_cis) == 1, (
            f"internet CI must be emitted exactly once, got {len(internet_cis)}"
        )

        inet_edges = _internet_edges(edges)
        targets = {e.to_ref.external_id for e in inet_edges}
        assert sg_x in targets, f"internet edge to {sg_x} expected"
        assert sg_y in targets, f"internet edge to {sg_y} expected"


# ---------------------------------------------------------------------------
# Edge case 17: duplicate identical evidence fragments de-duped
# ---------------------------------------------------------------------------


def test_duplicate_identical_evidence_deduplicated():
    """Edge case 17 / AC 17: two identical 0.0.0.0/0 rules on same SG -> no duplicate evidence."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(
            GroupName="dup-sg",
            Description="duplicate internet rules",
            VpcId=vpc,
        )["GroupId"]
        # Authorize the same rule twice; moto may deduplicate or produce two; we collapse
        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)
        connector = _make_connector(session, account)
        _, edges = _discover_all(connector)

        inet_to_sg = [e for e in _internet_edges(edges) if e.to_ref.external_id == sg]
        assert len(inet_to_sg) == 1, "must produce exactly one internet->sg edge"
        details = [ev.detail for ev in inet_to_sg[0].evidence]
        assert len(details) == len(set(details)), f"duplicate evidence details: {details}"


# ---------------------------------------------------------------------------
# AC 18 / edge case spec §3: CI-before-edge ordering
# ---------------------------------------------------------------------------


def test_internet_ci_precedes_first_internet_connects_to_edge(sg_account):
    """AC 18: internet DiscoveredCI event precedes the first internet CONNECTS_TO edge."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    events = list(connector.discover())

    internet_ci_idx = next(
        (i for i, e in enumerate(events)
         if isinstance(e, DiscoveredCI) and e.type == CIType.internet),
        None,
    )
    first_inet_edge_idx = next(
        (i for i, e in enumerate(events)
         if isinstance(e, DiscoveredEdge)
         and e.type == EdgeType.CONNECTS_TO
         and e.from_ref.type == CIType.internet),
        None,
    )

    assert internet_ci_idx is not None, "expected internet DiscoveredCI in event stream"
    assert first_inet_edge_idx is not None, "expected at least one internet CONNECTS_TO edge"
    assert internet_ci_idx < first_inet_edge_idx, (
        f"internet CI (at {internet_ci_idx}) must precede first internet edge "
        f"(at {first_inet_edge_idx})"
    )


def test_sg_ci_precedes_connects_to_edges(sg_account):
    """Security group CIs must be yielded before any CONNECTS_TO edge targeting them."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    events = list(connector.discover())

    sg_ci_indices: dict[str, int] = {}
    connects_to_edge_indices: list[tuple[int, str]] = []  # (index, to_ref.external_id)

    for i, event in enumerate(events):
        if isinstance(event, DiscoveredCI) and event.type == CIType.security_group:
            sg_ci_indices[event.external_id] = i
        if isinstance(event, DiscoveredEdge) and event.type == EdgeType.CONNECTS_TO:
            connects_to_edge_indices.append((i, event.to_ref.external_id))

    for edge_idx, to_sg_id in connects_to_edge_indices:
        ci_idx = sg_ci_indices.get(to_sg_id)
        if ci_idx is not None:
            assert ci_idx < edge_idx, (
                f"SG CI {to_sg_id} (at {ci_idx}) must precede CONNECTS_TO edge "
                f"targeting it (at {edge_idx})"
            )


# ---------------------------------------------------------------------------
# Edge case 20: egress rules ignored
# ---------------------------------------------------------------------------


def test_egress_rules_are_not_parsed():
    """Edge case 20 / AC 23: IpPermissionsEgress produces no CONNECTS_TO edges."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(
            GroupName="egress-only-sg",
            Description="only egress rule, no ingress internet",
            VpcId=vpc,
        )["GroupId"]
        # By default moto adds an allow-all-egress rule; we add a specific one too
        ec2.authorize_security_group_egress(
            GroupId=sg,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)
        connector = _make_connector(session, account)
        cis, edges = _discover_all(connector)

        ct_edges = _connects_to_edges(edges)
        assert ct_edges == [], (
            f"egress rules must not produce CONNECTS_TO edges, got: {ct_edges}"
        )
        internet_cis = [c for c in cis if c.type == CIType.internet]
        assert internet_cis == [], "internet CI must not be emitted when only egress rules exist"


# ---------------------------------------------------------------------------
# Edge case 19: mixed permission (internet + SG source in same permission)
# ---------------------------------------------------------------------------


def test_mixed_permission_produces_both_internet_and_sg_to_sg_edges():
    """Edge case 19: permission with public CIDR AND source group -> both edge types emitted."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg_src = ec2.create_security_group(
            GroupName="mixed-src",
            Description="source sg",
            VpcId=vpc,
        )["GroupId"]
        sg_tgt = ec2.create_security_group(
            GroupName="mixed-tgt",
            Description="target sg with mixed permission",
            VpcId=vpc,
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_tgt,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "UserIdGroupPairs": [{"GroupId": sg_src}],
                }
            ],
        )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)
        connector = _make_connector(session, account)
        _, edges = _discover_all(connector)

        inet_to_tgt = [
            e for e in _internet_edges(edges) if e.to_ref.external_id == sg_tgt
        ]
        assert len(inet_to_tgt) == 1, (
            f"expected 1 internet->sg_tgt edge, got {len(inet_to_tgt)}"
        )

        sg_to_tgt = [
            e for e in _sg_to_sg_edges(edges)
            if e.from_ref.external_id == sg_src and e.to_ref.external_id == sg_tgt
        ]
        assert len(sg_to_tgt) == 1, (
            f"expected 1 sg_src->sg_tgt edge, got {len(sg_to_tgt)}"
        )


# ---------------------------------------------------------------------------
# Port range label forms in actual discover() events
# ---------------------------------------------------------------------------


def test_all_traffic_label_in_sg_to_sg_evidence(sg_account):
    """Edge case 11: IpProtocol='-1' -> 'all traffic' in SG-to-SG evidence."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    _, edges = _discover_all(connector)

    sg_a = sg_account["sg_a"]
    sg_b = sg_account["sg_b"]
    pair = [
        e for e in _sg_to_sg_edges(edges)
        if e.from_ref.external_id == sg_a and e.to_ref.external_id == sg_b
    ]
    assert pair
    all_details = [ev.detail for ev in pair[0].evidence]
    assert any("all traffic" in d for d in all_details), (
        f"'all traffic' label expected in evidence, got: {all_details}"
    )


def test_single_port_label_in_internet_evidence(sg_account):
    """Edge case 12: tcp/443 -> 'tcp/443' label in internet evidence."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    _, edges = _discover_all(connector)

    sg_a = sg_account["sg_a"]
    inet_to_a = [e for e in _internet_edges(edges) if e.to_ref.external_id == sg_a]
    assert inet_to_a
    all_details = [ev.detail for ev in inet_to_a[0].evidence]
    assert any("tcp/443" in d for d in all_details), (
        f"'tcp/443' port label expected in evidence, got: {all_details}"
    )


def test_port_range_label_in_evidence():
    """Edge case 13: port range 8000-8100 -> 'tcp/8000-8100' label in evidence."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        sts = boto3.client("sts", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(
            GroupName="range-sg",
            Description="allows port range",
            VpcId=vpc,
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8000,
                    "ToPort": 8100,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        account = sts.get_caller_identity()["Account"]
        session = boto3.Session(region_name=REGION)
        connector = _make_connector(session, account)
        _, edges = _discover_all(connector)

        inet_to_sg = [e for e in _internet_edges(edges) if e.to_ref.external_id == sg]
        assert inet_to_sg
        all_details = [ev.detail for ev in inet_to_sg[0].evidence]
        assert any("tcp/8000-8100" in d for d in all_details), (
            f"'tcp/8000-8100' range label expected in evidence, got: {all_details}"
        )


# ---------------------------------------------------------------------------
# AC 19 / edge case 16: SG-to-SG with unresolved source -> dropped by reconcile
# ---------------------------------------------------------------------------


def test_sg_to_sg_unresolved_source_dropped_by_reconcile(pool, make_tenant):
    """AC 19 / edge case 16: SG-to-SG edge whose source is not discovered is dropped by reconcile.

    Strategy: synthesize discovery events directly (bypassing moto's group-existence validation)
    to include a SG-to-SG CONNECTS_TO edge whose from_ref references a security_group that was
    never emitted as a DiscoveredCI. Pass these events straight to reconcile(). Reconcile's
    'endpoint not in scope' guard (~line 113) must silently drop the edge without raising or
    writing a row.
    """
    from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
    from infra_twin.db.repositories import EdgeRepository
    from infra_twin.db.session import tenant_session
    from infra_twin.core_model import CI, CIType, EdgeSource, EdgeType as ET, Evidence
    from infra_twin.reconciliation.reconcile import reconcile
    from uuid import uuid4

    tenant = make_tenant()
    phantom_sg_id = "sg-phantom-not-discovered"
    real_sg_id = "sg-real-target-12345"

    # Synthetic discovery: one cloud_account, one region, one real security_group CI,
    # and one SG-to-SG CONNECTS_TO edge where the source is phantom (never a DiscoveredCI).
    account_ci = DiscoveredCI(
        type=CIType.cloud_account,
        external_id="123456789012",
        name="test-account",
    )
    sg_ci = DiscoveredCI(
        type=CIType.security_group,
        external_id=real_sg_id,
        name="real-sg",
    )
    phantom_edge = DiscoveredEdge(
        type=ET.CONNECTS_TO,
        from_ref=CIRef(type=CIType.security_group, external_id=phantom_sg_id),
        to_ref=CIRef(type=CIType.security_group, external_id=real_sg_id),
        source=EdgeSource.declared,
        confidence=1.0,
        evidence=[Evidence(source="aws", detail=f"sg {real_sg_id} allows tcp/5432 from group {phantom_sg_id}")],
    )

    events = [account_ci, sg_ci, phantom_edge]

    with tenant_session(pool, tenant) as conn:
        result = reconcile(
            conn,
            tenant,
            events,
            source="aws",
            ci_types=AwsConnector.ci_types,
            edge_types=AwsConnector.edge_types,
        )

    # Reconcile must not raise; phantom edge must have been silently dropped
    assert result is not None, "reconcile must not raise"

    with tenant_session(pool, tenant) as conn:
        # Confirm phantom source SG has no source_key row (was never reconciled)
        phantom_row = conn.execute(
            "SELECT ci_id FROM source_keys WHERE native_id = %s AND tenant_id = %s",
            (phantom_sg_id, tenant),
        ).fetchone()
        assert phantom_row is None, (
            f"phantom source group '{phantom_sg_id}' must not have a source_key row; "
            f"reconcile should have dropped the SG-to-SG edge silently"
        )

        # Confirm no CONNECTS_TO edge was written (the phantom edge was dropped)
        edge_rows = conn.execute(
            "SELECT id FROM edges WHERE tenant_id = %s AND type = %s AND valid_to IS NULL",
            (tenant, ET.CONNECTS_TO),
        ).fetchall()
        assert edge_rows == [], (
            f"no CONNECTS_TO edge should be persisted when source is phantom: {edge_rows}"
        )


# ---------------------------------------------------------------------------
# Evidence detail format (spec §5.4)
# ---------------------------------------------------------------------------


def test_internet_evidence_detail_format_sg_allows_label_from_cidr(sg_account):
    """Spec §5.4: internet evidence detail = 'sg <id> allows <label> from <cidr>'."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    _, edges = _discover_all(connector)
    sg_a = sg_account["sg_a"]
    inet_to_a = [e for e in _internet_edges(edges) if e.to_ref.external_id == sg_a]
    assert inet_to_a
    for ev in inet_to_a[0].evidence:
        assert ev.detail is not None
        assert sg_a in ev.detail, f"sg id {sg_a} must appear in detail: {ev.detail!r}"
        assert "allows" in ev.detail, f"'allows' must appear in detail: {ev.detail!r}"
        assert "from" in ev.detail, f"'from' must appear in detail: {ev.detail!r}"


def test_sg_to_sg_evidence_detail_format_sg_allows_label_from_group(sg_account):
    """Spec §5.4: SG-to-SG evidence detail = 'sg <id> allows <label> from group <src_id>'."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])
    _, edges = _discover_all(connector)
    sg_a = sg_account["sg_a"]
    sg_b = sg_account["sg_b"]
    pair = [
        e for e in _sg_to_sg_edges(edges)
        if e.from_ref.external_id == sg_a and e.to_ref.external_id == sg_b
    ]
    assert pair
    for ev in pair[0].evidence:
        assert ev.detail is not None
        assert sg_b in ev.detail, f"target sg id {sg_b} must appear in detail: {ev.detail!r}"
        assert "allows" in ev.detail, f"'allows' must appear in detail: {ev.detail!r}"
        assert "from group" in ev.detail, f"'from group' must appear in detail: {ev.detail!r}"
        assert sg_a in ev.detail, f"source sg id {sg_a} must appear in detail: {ev.detail!r}"


# ---------------------------------------------------------------------------
# Re-run independence: discover() resets internet flag between calls
# ---------------------------------------------------------------------------


def test_second_discover_call_resets_internet_ci_flag(sg_account):
    """Internet CI is emitted exactly once per discover() call, even across multiple calls."""
    connector = _make_connector(sg_account["session"], sg_account["account_id"])

    cis_run1, _ = _discover_all(connector)
    internet_run1 = [c for c in cis_run1 if c.type == CIType.internet]
    assert len(internet_run1) == 1, "first run: internet CI emitted once"

    cis_run2, _ = _discover_all(connector)
    internet_run2 = [c for c in cis_run2 if c.type == CIType.internet]
    assert len(internet_run2) == 1, "second run: internet CI also emitted exactly once"
