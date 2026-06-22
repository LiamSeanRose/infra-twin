"""Contract tests for the CloudTrail event parser (parse_event).

Covers every acceptance criterion in the spec (AC 1-13) and all edge cases
E-PARSE-1 through E-PARSE-17 from specs.md §6.

Structure:
1. Module-level import and export checks (AC 1, 2, 3).
2. RunInstances single instance (AC 4, E-PARSE-16, E-PARSE-17).
3. RunInstances multi-instance (AC 5, E-PARSE-5).
4. RunInstances no subnetId (E-PARSE-6).
5. RunInstances empty/absent groupSet (E-PARSE-7).
6. RunInstances missing instanceId (E-PARSE-8).
7. TerminateInstances (AC 6, E-PARSE-9).
8. CreateSecurityGroup (AC 7, E-PARSE-10, E-PARSE-11).
9. AuthorizeSecurityGroupIngress SG-source (AC 8).
10. AuthorizeSecurityGroupIngress CIDR-only (AC 9, E-PARSE-12).
11. RevokeSecurityGroupIngress (AC 10).
12. Unsupported event (AC 11, E-PARSE-1).
13. Missing/malformed field errors (E-PARSE-2, E-PARSE-3, E-PARSE-4).
14. Deduplication across permissions (E-PARSE-14).
15. Group entry missing groupId skipped (E-PARSE-15).
16. Parser purity (E-PARSE-17).
"""

from __future__ import annotations

import copy
import json
import pathlib
from datetime import datetime, timezone

import pytest

# ---------------------------------------------------------------------------
# Fixture loader
# ---------------------------------------------------------------------------

_FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "fixtures" / "cloudtrail"


def _load(name: str) -> dict:
    return json.loads((_FIXTURE_DIR / name).read_text())


# ===========================================================================
# 1. MODULE-LEVEL IMPORT AND EXPORT CHECKS (AC 1, 2, 3)
# ===========================================================================


def test_parse_event_importable_from_events_module():
    """AC 1/2: parse_event importable from infra_twin.collectors.aws.events."""
    from infra_twin.collectors.aws.events import parse_event  # noqa: F401


def test_unsupported_event_error_importable_from_events_module():
    """AC 1/2: UnsupportedEventError importable from infra_twin.collectors.aws.events."""
    from infra_twin.collectors.aws.events import UnsupportedEventError  # noqa: F401


def test_event_source_importable_from_events_module():
    """AC 1/2: EVENT_SOURCE importable from infra_twin.collectors.aws.events."""
    from infra_twin.collectors.aws.events import EVENT_SOURCE  # noqa: F401


def test_parse_event_importable_from_aws_package():
    """AC 2: parse_event importable via infra_twin.collectors.aws (package __init__)."""
    from infra_twin.collectors.aws import parse_event  # noqa: F401


def test_unsupported_event_error_importable_from_aws_package():
    """AC 2: UnsupportedEventError importable via infra_twin.collectors.aws."""
    from infra_twin.collectors.aws import UnsupportedEventError  # noqa: F401


def test_event_source_in_aws_all():
    """AC 2: EVENT_SOURCE in infra_twin.collectors.aws.__all__."""
    from infra_twin.collectors import aws
    assert "EVENT_SOURCE" in aws.__all__


def test_parse_event_in_aws_all():
    """AC 2: parse_event in infra_twin.collectors.aws.__all__."""
    from infra_twin.collectors import aws
    assert "parse_event" in aws.__all__


def test_unsupported_event_error_in_aws_all():
    """AC 2: UnsupportedEventError in infra_twin.collectors.aws.__all__."""
    from infra_twin.collectors import aws
    assert "UnsupportedEventError" in aws.__all__


def test_event_source_value():
    """AC 3: EVENT_SOURCE == 'aws-events'."""
    from infra_twin.collectors.aws.events import EVENT_SOURCE
    assert EVENT_SOURCE == "aws-events"


def test_unsupported_event_error_is_value_error_subclass():
    """AC 3: UnsupportedEventError is a subclass of ValueError."""
    from infra_twin.collectors.aws.events import UnsupportedEventError
    assert issubclass(UnsupportedEventError, ValueError)


def test_events_module_does_not_import_boto3():
    """AC 2: events.py must not import boto3."""
    import infra_twin.collectors.aws.events as mod
    import sys
    # After import, boto3 should NOT have been dragged in by events.py
    # We check the module's globals for any boto3 reference.
    assert "boto3" not in mod.__dict__


def test_events_module_does_not_import_db():
    """AC 2: events.py must not import from infra_twin.db or infra_twin.reconciliation."""
    import infra_twin.collectors.aws.events as mod
    # No db or reconciliation import in the module namespace
    for name in ("infra_twin.db", "infra_twin.reconciliation"):
        assert name not in mod.__dict__, f"events.py imported {name}"


# ===========================================================================
# 2. RunInstances — SINGLE INSTANCE (AC 4, E-PARSE-16, E-PARSE-17)
# ===========================================================================


def test_run_instances_single_ci_type_and_external_id():
    """AC 4: RunInstances returns exactly one DiscoveredCI of type ec2_instance."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredCI
    from infra_twin.core_model import CIType

    delta = parse_event(_load("run_instances.json"))
    cis = [u for u in delta.upserts if isinstance(u, DiscoveredCI)]
    assert len(cis) == 1
    ci = cis[0]
    assert ci.type == CIType.ec2_instance
    assert ci.external_id == "i-0abc123def456"


def test_run_instances_ci_attributes_keys():
    """AC 4: DiscoveredCI attributes keys are exactly {instance_type, state, subnet, vpc}."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_event(_load("run_instances.json"))
    cis = [u for u in delta.upserts if isinstance(u, DiscoveredCI)]
    assert set(cis[0].attributes.keys()) == {"instance_type", "state", "subnet", "vpc"}


def test_run_instances_ci_attributes_values():
    """AC 4: CI attributes carry correct values from the fixture."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_event(_load("run_instances.json"))
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert ci.attributes["instance_type"] == "t3.micro"
    assert ci.attributes["state"] == "pending"
    assert ci.attributes["subnet"] == "subnet-0aaa1111"
    assert ci.attributes["vpc"] == "vpc-0bbb2222"


def test_run_instances_contains_edge():
    """AC 4: single RunInstances yields one CONTAINS edge from subnet to ec2_instance."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_event(_load("run_instances.json"))
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    contains_edges = [e for e in edges if e.type == EdgeType.CONTAINS]
    assert len(contains_edges) == 1
    e = contains_edges[0]
    assert e.from_ref.type == CIType.subnet
    assert e.from_ref.external_id == "subnet-0aaa1111"
    assert e.to_ref.type == CIType.ec2_instance
    assert e.to_ref.external_id == "i-0abc123def456"


def test_run_instances_member_of_edge():
    """AC 4: single RunInstances yields one MEMBER_OF edge from ec2_instance to security_group."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_event(_load("run_instances.json"))
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    member_edges = [e for e in edges if e.type == EdgeType.MEMBER_OF]
    assert len(member_edges) == 1
    e = member_edges[0]
    assert e.from_ref.type == CIType.ec2_instance
    assert e.from_ref.external_id == "i-0abc123def456"
    assert e.to_ref.type == CIType.security_group
    assert e.to_ref.external_id == "sg-0ccc3333"


def test_run_instances_empty_removals():
    """AC 4: RunInstances leaves removed_cis and removed_edges empty."""
    from infra_twin.collectors.aws.events import parse_event

    delta = parse_event(_load("run_instances.json"))
    assert delta.removed_cis == []
    assert delta.removed_edges == []


def test_run_instances_evidence_contract(
):
    """AC 12 / E-PARSE-16: every DiscoveredEdge has exactly one Evidence with correct fields."""
    from infra_twin.collectors.aws.events import EVENT_SOURCE, parse_event
    from infra_twin.connector_sdk import DiscoveredEdge

    record = _load("run_instances.json")
    delta = parse_event(record)

    event_name = record["eventName"]
    event_id = record["eventID"]
    expected_ts = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))

    for item in delta.upserts:
        if isinstance(item, DiscoveredEdge):
            assert len(item.evidence) == 1, "each edge must have exactly one Evidence element"
            ev = item.evidence[0]
            assert ev.source == EVENT_SOURCE
            assert event_name in ev.detail
            assert event_id in ev.detail
            assert ev.observed_at == expected_ts


def test_run_instances_evidence_observed_at_tz_aware():
    """E-PARSE-16: evidence observed_at is tz-aware (UTC)."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge

    delta = parse_event(_load("run_instances.json"))
    for item in delta.upserts:
        if isinstance(item, DiscoveredEdge):
            assert item.evidence[0].observed_at.tzinfo is not None


# E-PARSE-17: purity — calling twice on the same record yields equal deltas
def test_parse_event_is_pure():
    """E-PARSE-17: parse_event is pure — twice on the same record yields equal deltas."""
    from infra_twin.collectors.aws.events import parse_event

    record = _load("run_instances.json")
    d1 = parse_event(record)
    d2 = parse_event(record)
    assert d1 == d2


# ===========================================================================
# 3. RunInstances — MULTIPLE INSTANCES (AC 5, E-PARSE-5)
# ===========================================================================


def test_run_instances_multi_produces_two_cis():
    """AC 5 / E-PARSE-5: RunInstances with two instances returns two DiscoveredCI."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredCI
    from infra_twin.core_model import CIType

    delta = parse_event(_load("run_instances_multi.json"))
    cis = [u for u in delta.upserts if isinstance(u, DiscoveredCI) and u.type == CIType.ec2_instance]
    assert len(cis) == 2
    ids = {ci.external_id for ci in cis}
    assert ids == {"i-0multi001", "i-0multi002"}


def test_run_instances_multi_produces_edges_per_instance():
    """AC 5 / E-PARSE-5: two instances each have a CONTAINS and a MEMBER_OF edge."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import EdgeType

    delta = parse_event(_load("run_instances_multi.json"))
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    contains = [e for e in edges if e.type == EdgeType.CONTAINS]
    member_of = [e for e in edges if e.type == EdgeType.MEMBER_OF]
    assert len(contains) == 2
    assert len(member_of) == 2


# ===========================================================================
# 4. RunInstances — NO SUBNET (E-PARSE-6)
# ===========================================================================


def test_run_instances_no_subnet_produces_no_contains_edge():
    """E-PARSE-6: RunInstances instance with no subnetId -> no CONTAINS edge."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import EdgeType

    record = _load("run_instances.json")
    # Remove subnetId from the instance
    record["responseElements"]["instancesSet"]["items"][0].pop("subnetId", None)

    delta = parse_event(record)
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    contains = [e for e in edges if e.type == EdgeType.CONTAINS]
    assert contains == []


def test_run_instances_no_subnet_ci_attributes_subnet_is_none():
    """E-PARSE-6: when subnetId absent, CI attribute 'subnet' is None (not missing)."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredCI

    record = _load("run_instances.json")
    record["responseElements"]["instancesSet"]["items"][0].pop("subnetId", None)

    delta = parse_event(record)
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert "subnet" in ci.attributes
    assert ci.attributes["subnet"] is None


# ===========================================================================
# 5. RunInstances — EMPTY/ABSENT groupSet (E-PARSE-7)
# ===========================================================================


def test_run_instances_no_group_set_produces_no_member_of_edge():
    """E-PARSE-7: RunInstances instance with empty/absent groupSet -> no MEMBER_OF edges."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import EdgeType

    record = _load("run_instances.json")
    record["responseElements"]["instancesSet"]["items"][0].pop("groupSet", None)

    delta = parse_event(record)
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    member_of = [e for e in edges if e.type == EdgeType.MEMBER_OF]
    assert member_of == []


def test_run_instances_empty_group_items_produces_no_member_of_edge():
    """E-PARSE-7: empty items list in groupSet -> no MEMBER_OF edges."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import EdgeType

    record = _load("run_instances.json")
    record["responseElements"]["instancesSet"]["items"][0]["groupSet"] = {"items": []}

    delta = parse_event(record)
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    member_of = [e for e in edges if e.type == EdgeType.MEMBER_OF]
    assert member_of == []


# ===========================================================================
# 6. RunInstances — MISSING instanceId (E-PARSE-8, AC 13)
# ===========================================================================


def test_run_instances_missing_instance_id_raises_value_error():
    """E-PARSE-8 / AC 13: RunInstances item missing instanceId raises ValueError (not KeyError)."""
    from infra_twin.collectors.aws.events import parse_event

    record = _load("run_instances.json")
    record["responseElements"]["instancesSet"]["items"][0].pop("instanceId", None)

    with pytest.raises(ValueError):
        parse_event(record)


def test_run_instances_missing_instance_id_is_not_key_error():
    """E-PARSE-8: the error for missing instanceId must be ValueError, not KeyError."""
    from infra_twin.collectors.aws.events import parse_event

    record = _load("run_instances.json")
    record["responseElements"]["instancesSet"]["items"][0].pop("instanceId", None)

    try:
        parse_event(record)
        pytest.fail("expected ValueError")
    except ValueError:
        pass  # correct
    except KeyError:
        pytest.fail("raised KeyError instead of ValueError")


# ===========================================================================
# 7. TerminateInstances (AC 6, E-PARSE-9)
# ===========================================================================


def test_terminate_instances_empty_upserts():
    """AC 6: TerminateInstances returns upserts == []."""
    from infra_twin.collectors.aws.events import parse_event

    delta = parse_event(_load("terminate_instances.json"))
    assert delta.upserts == []


def test_terminate_instances_empty_removed_edges():
    """AC 6: TerminateInstances returns removed_edges == []."""
    from infra_twin.collectors.aws.events import parse_event

    delta = parse_event(_load("terminate_instances.json"))
    assert delta.removed_edges == []


def test_terminate_instances_removed_cis_correct():
    """AC 6: TerminateInstances removed_cis contains CIRef(ec2_instance, instanceId)."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.core_model import CIType

    delta = parse_event(_load("terminate_instances.json"))
    assert len(delta.removed_cis) == 1
    ref = delta.removed_cis[0]
    assert ref.type == CIType.ec2_instance
    assert ref.external_id == "i-0abc123def456"


def test_terminate_instances_multi_ids_each_gets_removed_ci():
    """E-PARSE-9: multiple instanceIds -> one removed_cis entry each."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.core_model import CIType

    record = _load("terminate_instances.json")
    # Inject a second instance id into requestParameters only (to confirm de-dup)
    record["requestParameters"]["instancesSet"]["items"].append({"instanceId": "i-0second"})

    delta = parse_event(record)
    ids = {r.external_id for r in delta.removed_cis}
    assert "i-0abc123def456" in ids
    assert "i-0second" in ids


def test_terminate_instances_deduplicates_across_sections():
    """E-PARSE-9: same instanceId appearing in both requestParameters and responseElements
    is de-duplicated to exactly one removed_cis entry."""
    from infra_twin.collectors.aws.events import parse_event

    delta = parse_event(_load("terminate_instances.json"))
    # The fixture already has the same id in both sections.
    ids = [r.external_id for r in delta.removed_cis]
    assert ids.count("i-0abc123def456") == 1


# ===========================================================================
# 8. CreateSecurityGroup (AC 7, E-PARSE-10, E-PARSE-11)
# ===========================================================================


def test_create_security_group_ci_type_and_id():
    """AC 7: CreateSecurityGroup returns security_group CI with groupId as external_id."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredCI
    from infra_twin.core_model import CIType

    delta = parse_event(_load("create_security_group.json"))
    cis = [u for u in delta.upserts if isinstance(u, DiscoveredCI)]
    assert len(cis) == 1
    ci = cis[0]
    assert ci.type == CIType.security_group
    assert ci.external_id == "sg-0newgroup"


def test_create_security_group_ci_name():
    """AC 7: CreateSecurityGroup CI name == groupName from requestParameters."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_event(_load("create_security_group.json"))
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert ci.name == "my-web-sg"


def test_create_security_group_ci_attributes():
    """AC 7: CreateSecurityGroup CI attributes have exactly {description, vpc}."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredCI

    delta = parse_event(_load("create_security_group.json"))
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert set(ci.attributes.keys()) == {"description", "vpc"}
    assert ci.attributes["description"] == "Web tier security group"
    assert ci.attributes["vpc"] == "vpc-0bbb2222"


def test_create_security_group_contains_edge():
    """AC 7: CreateSecurityGroup with vpcId yields CONTAINS edge vpc->security_group."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_event(_load("create_security_group.json"))
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    assert len(edges) == 1
    e = edges[0]
    assert e.type == EdgeType.CONTAINS
    assert e.from_ref.type == CIType.vpc
    assert e.from_ref.external_id == "vpc-0bbb2222"
    assert e.to_ref.type == CIType.security_group
    assert e.to_ref.external_id == "sg-0newgroup"


def test_create_security_group_missing_group_id_raises_value_error():
    """E-PARSE-10 / AC 13: CreateSecurityGroup missing responseElements.groupId raises ValueError."""
    from infra_twin.collectors.aws.events import parse_event

    record = _load("create_security_group.json")
    record["responseElements"].pop("groupId")

    with pytest.raises(ValueError, match="groupId"):
        parse_event(record)


def test_create_security_group_no_vpc_no_edge():
    """E-PARSE-11: CreateSecurityGroup without vpcId produces CI only, no CONTAINS edge."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge

    record = _load("create_security_group.json")
    record["requestParameters"].pop("vpcId")

    delta = parse_event(record)
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    assert edges == []


def test_create_security_group_no_vpc_vpc_attr_is_none():
    """E-PARSE-11: without vpcId, CI attribute 'vpc' is None (not missing)."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredCI

    record = _load("create_security_group.json")
    record["requestParameters"].pop("vpcId")

    delta = parse_event(record)
    ci = [u for u in delta.upserts if isinstance(u, DiscoveredCI)][0]
    assert "vpc" in ci.attributes
    assert ci.attributes["vpc"] is None


# ===========================================================================
# 9. AuthorizeSecurityGroupIngress — SG SOURCE (AC 8)
# ===========================================================================


def test_authorize_sg_ingress_sg_source_single_edge():
    """AC 8: AuthorizeSecurityGroupIngress with SG source returns exactly one CONNECTS_TO edge."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import EdgeType

    delta = parse_event(_load("authorize_sg_ingress_sg_source.json"))
    assert delta.removed_cis == []
    assert delta.removed_edges == []
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    assert len(edges) == 1
    assert edges[0].type == EdgeType.CONNECTS_TO


def test_authorize_sg_ingress_sg_source_from_to():
    """AC 8: CONNECTS_TO edge from=source sg, to=target sg."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_event(_load("authorize_sg_ingress_sg_source.json"))
    edge = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)][0]
    assert edge.from_ref.type == CIType.security_group
    assert edge.from_ref.external_id == "sg-0source"
    assert edge.to_ref.type == CIType.security_group
    assert edge.to_ref.external_id == "sg-0target"


def test_authorize_sg_ingress_sg_source_evidence():
    """AC 12 / E-PARSE-16: authorize edge evidence is correctly formed."""
    from infra_twin.collectors.aws.events import EVENT_SOURCE, parse_event
    from infra_twin.connector_sdk import DiscoveredEdge

    record = _load("authorize_sg_ingress_sg_source.json")
    delta = parse_event(record)
    edge = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)][0]
    ev = edge.evidence[0]
    assert ev.source == EVENT_SOURCE
    assert "AuthorizeSecurityGroupIngress" in ev.detail
    assert record["eventID"] in ev.detail
    expected_ts = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
    assert ev.observed_at == expected_ts


# ===========================================================================
# 10. AuthorizeSecurityGroupIngress — CIDR ONLY (AC 9, E-PARSE-12)
# ===========================================================================


def test_authorize_sg_ingress_cidr_only_returns_empty_delta():
    """AC 9 / E-PARSE-12: CIDR-only authorize returns empty delta (upserts, removed_cis, removed_edges all empty)."""
    from infra_twin.collectors.aws.events import parse_event

    delta = parse_event(_load("authorize_sg_ingress_cidr_only.json"))
    assert delta.upserts == []
    assert delta.removed_cis == []
    assert delta.removed_edges == []


def test_authorize_sg_ingress_cidr_only_no_exception():
    """E-PARSE-12: CIDR-only authorize raises no exception."""
    from infra_twin.collectors.aws.events import parse_event
    # Should not raise
    parse_event(_load("authorize_sg_ingress_cidr_only.json"))


# ===========================================================================
# 11. RevokeSecurityGroupIngress (AC 10)
# ===========================================================================


def test_revoke_sg_ingress_sg_source_removed_edges():
    """AC 10: RevokeSecurityGroupIngress returns one EdgeEndpointRef in removed_edges."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import EdgeEndpointRef
    from infra_twin.core_model import CIType, EdgeType

    delta = parse_event(_load("revoke_sg_ingress_sg_source.json"))
    assert delta.upserts == []
    assert len(delta.removed_edges) == 1
    ref = delta.removed_edges[0]
    assert isinstance(ref, EdgeEndpointRef)
    assert ref.type == EdgeType.CONNECTS_TO
    assert ref.from_ref.type == CIType.security_group
    assert ref.from_ref.external_id == "sg-0source"
    assert ref.to_ref.type == CIType.security_group
    assert ref.to_ref.external_id == "sg-0target"


def test_revoke_sg_ingress_empty_removed_cis():
    """AC 10: RevokeSecurityGroupIngress returns removed_cis == []."""
    from infra_twin.collectors.aws.events import parse_event

    delta = parse_event(_load("revoke_sg_ingress_sg_source.json"))
    assert delta.removed_cis == []


# ===========================================================================
# 12. UNSUPPORTED EVENT (AC 11, E-PARSE-1)
# ===========================================================================


def test_unsupported_event_raises_unsupported_event_error():
    """AC 11 / E-PARSE-1: unsupported eventName raises UnsupportedEventError."""
    from infra_twin.collectors.aws.events import UnsupportedEventError, parse_event

    with pytest.raises(UnsupportedEventError):
        parse_event(_load("unsupported_event.json"))


def test_unsupported_event_error_is_value_error():
    """E-PARSE-1: UnsupportedEventError is also a ValueError (is-a relationship)."""
    from infra_twin.collectors.aws.events import UnsupportedEventError, parse_event

    with pytest.raises(ValueError):
        parse_event(_load("unsupported_event.json"))


def test_unsupported_event_error_message_contains_event_name():
    """E-PARSE-1: error message contains the unsupported eventName."""
    from infra_twin.collectors.aws.events import UnsupportedEventError, parse_event

    with pytest.raises(UnsupportedEventError, match="DescribeInstances"):
        parse_event(_load("unsupported_event.json"))


# ===========================================================================
# 13. MISSING / MALFORMED FIELDS (E-PARSE-2, -3, -4, AC 13)
# ===========================================================================


def test_missing_event_name_raises_value_error():
    """E-PARSE-2 / AC 13: missing eventName raises ValueError (not KeyError)."""
    from infra_twin.collectors.aws.events import parse_event

    record = _load("run_instances.json")
    record.pop("eventName")

    with pytest.raises(ValueError, match="eventName"):
        parse_event(record)


def test_missing_event_id_raises_value_error():
    """E-PARSE-3 / AC 13: missing eventID raises ValueError naming the field."""
    from infra_twin.collectors.aws.events import parse_event

    record = _load("run_instances.json")
    record.pop("eventID")

    with pytest.raises(ValueError, match="eventID"):
        parse_event(record)


def test_missing_event_time_raises_value_error():
    """E-PARSE-3 / AC 13: missing eventTime raises ValueError naming the field."""
    from infra_twin.collectors.aws.events import parse_event

    record = _load("run_instances.json")
    record.pop("eventTime")

    with pytest.raises(ValueError, match="eventTime"):
        parse_event(record)


def test_invalid_event_time_raises_value_error():
    """E-PARSE-4 / AC 13: non-ISO-8601 eventTime raises ValueError('invalid eventTime: ...')."""
    from infra_twin.collectors.aws.events import parse_event

    record = _load("run_instances.json")
    record["eventTime"] = "not-a-datetime"

    with pytest.raises(ValueError, match="invalid eventTime"):
        parse_event(record)


def test_event_time_trailing_z_accepted():
    """E-PARSE-4: trailing Z in eventTime is accepted and parsed as UTC."""
    from infra_twin.collectors.aws.events import parse_event

    # run_instances.json already uses trailing Z format — should not raise
    record = _load("run_instances.json")
    assert record["eventTime"].endswith("Z")
    delta = parse_event(record)  # must not raise
    assert delta is not None


def test_authorize_missing_target_group_id_raises_value_error():
    """E-PARSE-13 / AC 13: AuthorizeSecurityGroupIngress missing groupId raises ValueError."""
    from infra_twin.collectors.aws.events import parse_event

    record = _load("authorize_sg_ingress_sg_source.json")
    record["requestParameters"].pop("groupId")

    with pytest.raises(ValueError):
        parse_event(record)


def test_revoke_missing_target_group_id_raises_value_error():
    """E-PARSE-13 / AC 13: RevokeSecurityGroupIngress missing groupId raises ValueError."""
    from infra_twin.collectors.aws.events import parse_event

    record = _load("revoke_sg_ingress_sg_source.json")
    record["requestParameters"].pop("groupId")

    with pytest.raises(ValueError):
        parse_event(record)


# ===========================================================================
# 14. DEDUPLICATION ACROSS PERMISSIONS (E-PARSE-14)
# ===========================================================================


def test_authorize_deduplicates_duplicate_source_group_pairs():
    """E-PARSE-14: duplicate (source, target) sg pairs across permissions -> exactly one edge."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge

    record = _load("authorize_sg_ingress_sg_source.json")
    # Duplicate the permission item so the same pair appears twice
    original_item = record["requestParameters"]["ipPermissions"]["items"][0]
    record["requestParameters"]["ipPermissions"]["items"] = [
        original_item,
        copy.deepcopy(original_item),
    ]

    delta = parse_event(record)
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    assert len(edges) == 1, "duplicate (source, target) pair must collapse to one edge"


def test_revoke_deduplicates_duplicate_source_group_pairs():
    """E-PARSE-14: duplicate (source, target) pairs in revoke -> exactly one EdgeEndpointRef."""
    from infra_twin.collectors.aws.events import parse_event

    record = _load("revoke_sg_ingress_sg_source.json")
    original_item = record["requestParameters"]["ipPermissions"]["items"][0]
    record["requestParameters"]["ipPermissions"]["items"] = [
        original_item,
        copy.deepcopy(original_item),
    ]

    delta = parse_event(record)
    assert len(delta.removed_edges) == 1, "duplicate pair must collapse to one EdgeEndpointRef"


# ===========================================================================
# 15. GROUP ENTRY MISSING groupId IS SKIPPED (E-PARSE-15)
# ===========================================================================


def test_authorize_group_entry_missing_group_id_skipped():
    """E-PARSE-15: group entry with no groupId is skipped (mirrors discovery behavior)."""
    from infra_twin.collectors.aws.events import parse_event
    from infra_twin.connector_sdk import DiscoveredEdge

    record = _load("authorize_sg_ingress_sg_source.json")
    # Insert an entry with no groupId before the valid one
    record["requestParameters"]["ipPermissions"]["items"][0]["groups"]["items"] = [
        {"userId": "123456789012"},   # missing groupId — should be skipped
        {"groupId": "sg-0source", "userId": "123456789012"},
    ]

    delta = parse_event(record)
    edges = [u for u in delta.upserts if isinstance(u, DiscoveredEdge)]
    # The bad entry is skipped, one valid edge remains
    assert len(edges) == 1
    assert edges[0].from_ref.external_id == "sg-0source"
