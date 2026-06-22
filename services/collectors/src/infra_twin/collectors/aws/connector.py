"""Read-only AWS discovery.

Discovers the Phase 1 resource set via the AWS APIs and emits canonical discovery events.
The connector holds no internal ids and never mutates the account — it only describes.

A ``boto3.Session`` is injected so the same code runs against a real assume-role session in
production and against a moto-mocked session in tests.
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass
from typing import Iterator

import boto3

from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge, DiscoveryEvent
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence

INTERNET_EXTERNAL_ID: str = "internet"
INTERNET_NAME: str = "Internet (0.0.0.0/0, ::/0)"
_PUBLIC_CIDRS: frozenset[str] = frozenset({"0.0.0.0/0", "::/0"})

_CI_TYPES = frozenset(
    {
        CIType.cloud_account,
        CIType.region,
        CIType.vpc,
        CIType.subnet,
        CIType.security_group,
        CIType.ec2_instance,
        CIType.elb,
        CIType.rds,
        CIType.s3_bucket,
        CIType.iam_role,
        CIType.iam_user,
        CIType.eks_cluster,
        CIType.internet,
        CIType.dns_name,
    }
)
_EDGE_TYPES = frozenset(
    {
        EdgeType.CONTAINS,
        EdgeType.MEMBER_OF,
        EdgeType.ROUTES_TO,
        EdgeType.OWNS,
        EdgeType.HAS_ACCESS_TO,
        EdgeType.CONNECTS_TO,
        EdgeType.EXPOSES,
        EdgeType.RESOLVES_TO,
    }
)


@dataclass(frozen=True)
class _Principal:
    ci_type: CIType  # CIType.iam_role or CIType.iam_user
    external_id: str  # the role/user ARN
    name: str  # RoleName / UserName, used for IAM API calls


# ---------------------------------------------------------------------------
# Pure module-level helpers
# ---------------------------------------------------------------------------


def _policy_statements(document: dict) -> list[dict]:
    """Normalize a policy document into the list of its statements."""
    raw = document.get("Statement", [])
    if isinstance(raw, dict):
        return [raw]
    return list(raw)


def _buckets_for_resource(resource: str, bucket_names: set[str]) -> set[str]:
    """Match a single policy Resource ARN string against discovered bucket names.

    Supports the ``*`` global wildcard and ``arn:aws:s3:::<prefix>*`` prefix wildcards.
    Only returns bucket names that are present in ``bucket_names``.
    """
    if resource == "*":
        return set(bucket_names)

    prefix = "arn:aws:s3:::"
    if not resource.startswith(prefix):
        return set()

    bucket_part = resource[len(prefix):]
    # Strip any key suffix (everything after the first /)
    bucket_part = bucket_part.split("/")[0]

    if bucket_part == "*":
        return set(bucket_names)

    if bucket_part.endswith("*"):
        name_prefix = bucket_part[:-1]
        return {b for b in bucket_names if b.startswith(name_prefix)}

    if bucket_part in bucket_names:
        return {bucket_part}

    return set()


def _s3_grants_from_statement(
    statement: dict, bucket_names: set[str]
) -> set[tuple[str, str]]:
    """Given one statement and the set of discovered bucket names, return the set of
    (bucket_name, action) pairs that are GRANTED to S3 by this statement.
    """
    if statement.get("Effect") != "Allow":
        return set()

    raw_action = statement.get("Action")
    if raw_action is None:
        return set()

    actions: list[str] = [raw_action] if isinstance(raw_action, str) else list(raw_action)

    s3_actions: list[str] = []
    for action in actions:
        lower = action.lower()
        if lower == "*" or lower == "s3:*" or lower.startswith("s3:"):
            s3_actions.append(action)

    if not s3_actions:
        return set()

    raw_resource = statement.get("Resource")
    if raw_resource is None:
        return set()

    resources: list[str] = (
        [raw_resource] if isinstance(raw_resource, str) else list(raw_resource)
    )

    matched_buckets: set[str] = set()
    for resource in resources:
        matched_buckets |= _buckets_for_resource(resource, bucket_names)

    if not matched_buckets:
        return set()

    return {
        (bucket, action)
        for bucket in matched_buckets
        for action in s3_actions
    }


def _tag_name(tags: list[dict] | None) -> str | None:
    for tag in tags or []:
        if tag.get("Key") == "Name":
            return tag.get("Value")
    return None


def _port_range_label(permission: dict) -> str:
    """Render a rule's protocol + port range as a stable evidence fragment.

    - IpProtocol "-1" (or missing) -> "all traffic".
    - IpProtocol present, FromPort == ToPort -> "<proto>/<port>"      (e.g. "tcp/443").
    - IpProtocol present, FromPort != ToPort -> "<proto>/<from>-<to>" (e.g. "tcp/8000-8100").
    - IpProtocol present, FromPort/ToPort absent -> "<proto>"          (e.g. "tcp").
    Protocols other than -1 render verbatim (e.g. "icmp", "udp", "6").
    """
    proto = permission.get("IpProtocol", "-1")
    if proto == "-1":
        return "all traffic"
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None or to_port is None:
        return proto
    if from_port == to_port:
        return f"{proto}/{from_port}"
    return f"{proto}/{from_port}-{to_port}"


def _public_cidrs_in_permission(permission: dict) -> list[str]:
    """Sorted list of public CIDRs (those in _PUBLIC_CIDRS) cited by this permission, scanning
    both IpRanges[].CidrIp (IPv4) and Ipv6Ranges[].CidrIpv6 (IPv6). Empty list if none.
    """
    found: set[str] = set()
    for entry in permission.get("IpRanges", []):
        cidr = entry.get("CidrIp", "")
        if cidr in _PUBLIC_CIDRS:
            found.add(cidr)
    for entry in permission.get("Ipv6Ranges", []):
        cidr = entry.get("CidrIpv6", "")
        if cidr in _PUBLIC_CIDRS:
            found.add(cidr)
    return sorted(found)


def _source_group_ids_in_permission(permission: dict) -> list[str]:
    """Sorted, de-duplicated list of source security-group ids referenced by this permission
    via UserIdGroupPairs[].GroupId. Pairs lacking a GroupId are skipped.
    """
    found: set[str] = set()
    for pair in permission.get("UserIdGroupPairs", []):
        gid = pair.get("GroupId")
        if gid:
            found.add(gid)
    return sorted(found)


class AwsConnector:
    """Discovers a focused AWS resource set across one or more regions."""

    source = "aws"
    ci_types = _CI_TYPES
    edge_types = _EDGE_TYPES

    def __init__(
        self, session: boto3.Session, account_id: str, regions: list[str]
    ) -> None:
        self._session = session
        self._account_id = account_id
        self._regions = regions
        self._internet_ci_emitted: bool = False

    # -- helpers -----------------------------------------------------------------

    def _evidence(self, detail: str) -> list[Evidence]:
        return [Evidence(source=self.source, detail=detail)]

    def _edge(
        self, etype: EdgeType, from_ref: CIRef, to_ref: CIRef, detail: str
    ) -> DiscoveredEdge:
        return DiscoveredEdge(
            type=etype,
            from_ref=from_ref,
            to_ref=to_ref,
            source=EdgeSource.declared,
            evidence=self._evidence(detail),
        )

    @property
    def _account_ref(self) -> CIRef:
        return CIRef(type=CIType.cloud_account, external_id=self._account_id)

    # -- discovery ---------------------------------------------------------------

    def discover(self) -> Iterator[DiscoveryEvent]:
        # Run-level flag: internet pseudo-CI emitted at most once per discover() run.
        self._internet_ci_emitted: bool = False

        yield DiscoveredCI(
            type=CIType.cloud_account,
            external_id=self._account_id,
            name=self._account_id,
        )

        principals: list[_Principal] = []
        yield from self._discover_iam(principals)

        bucket_names: set[str] = set()
        yield from self._discover_s3(bucket_names)

        yield from self._discover_iam_s3_access(principals, bucket_names)

        for region in self._regions:
            yield DiscoveredCI(type=CIType.region, external_id=region, name=region)
            yield self._edge(
                EdgeType.CONTAINS,
                self._account_ref,
                CIRef(type=CIType.region, external_id=region),
                "aws:account:region",
            )
            yield from self._discover_region(region)

    def _discover_iam(self, principals: list[_Principal]) -> Iterator[DiscoveryEvent]:
        iam = self._session.client("iam")
        for role in iam.list_roles().get("Roles", []):
            arn = role["Arn"]
            role_name = role.get("RoleName", "")
            yield DiscoveredCI(
                type=CIType.iam_role,
                external_id=arn,
                name=role_name,
                attributes={"role_id": role.get("RoleId")},
            )
            yield self._edge(
                EdgeType.OWNS,
                self._account_ref,
                CIRef(type=CIType.iam_role, external_id=arn),
                "aws:iam:list_roles",
            )
            principals.append(
                _Principal(ci_type=CIType.iam_role, external_id=arn, name=role_name)
            )
        for user in iam.list_users().get("Users", []):
            arn = user["Arn"]
            user_name = user.get("UserName", "")
            yield DiscoveredCI(
                type=CIType.iam_user,
                external_id=arn,
                name=user_name,
                attributes={"user_id": user.get("UserId")},
            )
            yield self._edge(
                EdgeType.OWNS,
                self._account_ref,
                CIRef(type=CIType.iam_user, external_id=arn),
                "aws:iam:list_users",
            )
            principals.append(
                _Principal(ci_type=CIType.iam_user, external_id=arn, name=user_name)
            )

    def _discover_s3(self, bucket_names: set[str]) -> Iterator[DiscoveryEvent]:
        s3 = self._session.client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            try:
                loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            except Exception:
                loc = None
            bucket_names.add(name)
            yield DiscoveredCI(
                type=CIType.s3_bucket,
                external_id=name,
                name=name,
                attributes={"region": loc or "us-east-1"},
            )
            yield self._edge(
                EdgeType.OWNS,
                self._account_ref,
                CIRef(type=CIType.s3_bucket, external_id=name),
                "aws:s3:list_buckets",
            )

    def _discover_iam_s3_access(
        self, principals: list[_Principal], bucket_names: set[str]
    ) -> Iterator[DiscoveredEdge]:
        """Emit HAS_ACCESS_TO edges from IAM principals to in-scope S3 buckets.

        Reads attached managed and inline policies for every role and user; parses Allow
        statements for S3 actions and resolves resource ARNs to discovered bucket names.
        Yields at most one edge per (principal, bucket) pair, with all granting
        (policy_label, action) pairs collapsed into the evidence list.
        """
        if not bucket_names:
            return

        iam = self._session.client("iam")

        # Sort principals for deterministic output.
        for principal in sorted(principals, key=lambda p: p.external_id):
            # Map (bucket_name) -> set of (policy_label, action) pairs.
            grants: dict[str, set[tuple[str, str]]] = {}

            policies: list[tuple[str, dict]] = []

            if principal.ci_type == CIType.iam_role:
                # Attached managed policies
                try:
                    attached = iam.list_attached_role_policies(
                        RoleName=principal.name
                    ).get("AttachedPolicies", [])
                except Exception:
                    attached = []
                for ap in attached:
                    policy_arn: str = ap["PolicyArn"]
                    try:
                        version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"][
                            "DefaultVersionId"
                        ]
                        doc = iam.get_policy_version(
                            PolicyArn=policy_arn, VersionId=version_id
                        )["PolicyVersion"]["Document"]
                        policies.append((policy_arn, doc))
                    except Exception:
                        continue

                # Inline policies
                try:
                    inline_names = iam.list_role_policies(
                        RoleName=principal.name
                    ).get("PolicyNames", [])
                except Exception:
                    inline_names = []
                for policy_name in inline_names:
                    try:
                        doc = iam.get_role_policy(
                            RoleName=principal.name, PolicyName=policy_name
                        )["PolicyDocument"]
                        policies.append((f"inline:{policy_name}", doc))
                    except Exception:
                        continue

            else:  # iam_user
                # Attached managed policies
                try:
                    attached = iam.list_attached_user_policies(
                        UserName=principal.name
                    ).get("AttachedPolicies", [])
                except Exception:
                    attached = []
                for ap in attached:
                    policy_arn = ap["PolicyArn"]
                    try:
                        version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"][
                            "DefaultVersionId"
                        ]
                        doc = iam.get_policy_version(
                            PolicyArn=policy_arn, VersionId=version_id
                        )["PolicyVersion"]["Document"]
                        policies.append((policy_arn, doc))
                    except Exception:
                        continue

                # Inline policies
                try:
                    inline_names = iam.list_user_policies(
                        UserName=principal.name
                    ).get("PolicyNames", [])
                except Exception:
                    inline_names = []
                for policy_name in inline_names:
                    try:
                        doc = iam.get_user_policy(
                            UserName=principal.name, PolicyName=policy_name
                        )["PolicyDocument"]
                        policies.append((f"inline:{policy_name}", doc))
                    except Exception:
                        continue

            for policy_label, raw_doc in policies:
                try:
                    if isinstance(raw_doc, str):
                        document: dict = json.loads(urllib.parse.unquote(raw_doc))
                    else:
                        document = raw_doc

                    for stmt in _policy_statements(document):
                        for bucket_name, action in _s3_grants_from_statement(
                            stmt, bucket_names
                        ):
                            grants.setdefault(bucket_name, set()).add(
                                (policy_label, action)
                            )
                except Exception:
                    continue

            # Emit one edge per (principal, bucket), sorted by bucket name.
            for bucket_name in sorted(grants):
                evidence_pairs = sorted(grants[bucket_name])  # sorted (label, action)
                evidence = [
                    Evidence(
                        source="aws",
                        detail=f"{label} grants {action}",
                    )
                    for label, action in evidence_pairs
                ]
                yield DiscoveredEdge(
                    type=EdgeType.HAS_ACCESS_TO,
                    from_ref=CIRef(
                        type=principal.ci_type, external_id=principal.external_id
                    ),
                    to_ref=CIRef(
                        type=CIType.s3_bucket, external_id=bucket_name
                    ),
                    source=EdgeSource.declared,
                    confidence=1.0,
                    evidence=evidence,
                )

    def _discover_region(self, region: str) -> Iterator[DiscoveryEvent]:
        region_ref = CIRef(type=CIType.region, external_id=region)
        ec2 = self._session.client("ec2", region_name=region)

        for vpc in ec2.describe_vpcs().get("Vpcs", []):
            vpc_id = vpc["VpcId"]
            yield DiscoveredCI(
                type=CIType.vpc,
                external_id=vpc_id,
                name=_tag_name(vpc.get("Tags")),
                attributes={
                    "cidr": vpc.get("CidrBlock"),
                    "is_default": vpc.get("IsDefault"),
                    "region": region,
                },
            )
            yield self._edge(
                EdgeType.CONTAINS,
                region_ref,
                CIRef(type=CIType.vpc, external_id=vpc_id),
                "aws:ec2:describe_vpcs",
            )

        for subnet in ec2.describe_subnets().get("Subnets", []):
            subnet_id = subnet["SubnetId"]
            yield DiscoveredCI(
                type=CIType.subnet,
                external_id=subnet_id,
                name=_tag_name(subnet.get("Tags")),
                attributes={
                    "cidr": subnet.get("CidrBlock"),
                    "az": subnet.get("AvailabilityZone"),
                    "vpc": subnet.get("VpcId"),
                },
            )
            if subnet.get("VpcId"):
                yield self._edge(
                    EdgeType.CONTAINS,
                    CIRef(type=CIType.vpc, external_id=subnet["VpcId"]),
                    CIRef(type=CIType.subnet, external_id=subnet_id),
                    "aws:ec2:describe_subnets",
                )

        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            sg_id = sg["GroupId"]
            yield DiscoveredCI(
                type=CIType.security_group,
                external_id=sg_id,
                name=sg.get("GroupName"),
                attributes={"description": sg.get("Description"), "vpc": sg.get("VpcId")},
            )
            if sg.get("VpcId"):
                yield self._edge(
                    EdgeType.CONTAINS,
                    CIRef(type=CIType.vpc, external_id=sg["VpcId"]),
                    CIRef(type=CIType.security_group, external_id=sg_id),
                    "aws:ec2:describe_security_groups",
                )
            yield from self._connects_to_edges_for_sg(sg)

        for reservation in ec2.describe_instances().get("Reservations", []):
            for inst in reservation.get("Instances", []):
                inst_id = inst["InstanceId"]
                yield DiscoveredCI(
                    type=CIType.ec2_instance,
                    external_id=inst_id,
                    name=_tag_name(inst.get("Tags")),
                    attributes={
                        "instance_type": inst.get("InstanceType"),
                        "state": inst.get("State", {}).get("Name"),
                        "subnet": inst.get("SubnetId"),
                        "vpc": inst.get("VpcId"),
                        "private_ip": inst.get("PrivateIpAddress"),
                    },
                )
                if inst.get("SubnetId"):
                    yield self._edge(
                        EdgeType.CONTAINS,
                        CIRef(type=CIType.subnet, external_id=inst["SubnetId"]),
                        CIRef(type=CIType.ec2_instance, external_id=inst_id),
                        "aws:ec2:describe_instances",
                    )
                for sg in inst.get("SecurityGroups", []):
                    if sg.get("GroupId"):
                        yield self._edge(
                            EdgeType.MEMBER_OF,
                            CIRef(type=CIType.ec2_instance, external_id=inst_id),
                            CIRef(type=CIType.security_group, external_id=sg["GroupId"]),
                            "aws:ec2:describe_instances",
                        )

        yield from self._discover_elbs(region)
        yield from self._discover_rds(region)
        yield from self._discover_eks(region)

    def _connects_to_edges_for_sg(self, sg: dict) -> Iterator[DiscoveredEdge]:
        """Given one security group dict from describe_security_groups, yield CONNECTS_TO
        DiscoveredEdges for its ingress IpPermissions (internet-sourced and SG-sourced).

        Internet edges: one edge per target SG, evidence collapsed across all rules that
        reference a public CIDR for that SG.
        SG-to-SG edges: one edge per (src_group_id, sg_id) pair, evidence collapsed across
        all rules referencing that source group for that SG.
        """
        sg_id: str = sg["GroupId"]

        # Maps for collapsing: internet -> list of evidence details; sg-pair -> list of details.
        internet_details: list[str] = []
        # (src_group_id, port_range_label) -> list of evidence detail strings
        sg_details: dict[tuple[str, str], list[str]] = {}

        for permission in sg.get("IpPermissions", []):
            label = _port_range_label(permission)

            for cidr in _public_cidrs_in_permission(permission):
                internet_details.append(f"sg {sg_id} allows {label} from {cidr}")

            for src_group_id in _source_group_ids_in_permission(permission):
                detail = f"sg {sg_id} allows {label} from group {src_group_id}"
                sg_details.setdefault((src_group_id, label), []).append(detail)

        # Emit internet -> sg edge (at most one per SG).
        if internet_details:
            if not self._internet_ci_emitted:
                self._internet_ci_emitted = True
                yield DiscoveredCI(
                    type=CIType.internet,
                    external_id=INTERNET_EXTERNAL_ID,
                    name=INTERNET_NAME,
                )
            # De-duplicate and sort evidence.
            seen: set[str] = set()
            evidence: list[Evidence] = []
            for detail in sorted(set(internet_details)):
                if detail not in seen:
                    seen.add(detail)
                    evidence.append(Evidence(source="aws", detail=detail))
            yield DiscoveredEdge(
                type=EdgeType.CONNECTS_TO,
                from_ref=CIRef(type=CIType.internet, external_id=INTERNET_EXTERNAL_ID),
                to_ref=CIRef(type=CIType.security_group, external_id=sg_id),
                source=EdgeSource.declared,
                confidence=1.0,
                evidence=evidence,
            )

        # Emit one SG-to-SG edge per (src_group_id, port_range_label) pair.
        for (src_group_id, rule_label) in sorted(sg_details):
            seen_sg: set[str] = set()
            sg_evidence: list[Evidence] = []
            for detail in sorted(set(sg_details[(src_group_id, rule_label)])):
                if detail not in seen_sg:
                    seen_sg.add(detail)
                    sg_evidence.append(Evidence(source="aws", detail=detail))
            yield DiscoveredEdge(
                type=EdgeType.CONNECTS_TO,
                from_ref=CIRef(type=CIType.security_group, external_id=src_group_id),
                to_ref=CIRef(type=CIType.security_group, external_id=sg_id),
                source=EdgeSource.declared,
                confidence=1.0,
                evidence=sg_evidence,
                edge_key=rule_label,
            )

    def _discover_elbs(self, region: str) -> Iterator[DiscoveryEvent]:
        elb = self._session.client("elbv2", region_name=region)
        for lb in elb.describe_load_balancers().get("LoadBalancers", []):
            arn = lb["LoadBalancerArn"]
            elb_ref = CIRef(type=CIType.elb, external_id=arn)
            yield DiscoveredCI(
                type=CIType.elb,
                external_id=arn,
                name=lb.get("LoadBalancerName"),
                attributes={
                    "type": lb.get("Type"),
                    "scheme": lb.get("Scheme"),
                    "dns_name": lb.get("DNSName"),
                    "vpc": lb.get("VpcId"),
                },
            )
            if lb.get("VpcId"):
                yield self._edge(
                    EdgeType.CONTAINS,
                    CIRef(type=CIType.vpc, external_id=lb["VpcId"]),
                    elb_ref,
                    "aws:elbv2:describe_load_balancers",
                )
            dns = lb.get("DNSName")
            if dns:
                yield DiscoveredCI(
                    type=CIType.dns_name,
                    external_id=dns,
                    name=dns,
                    attributes={},
                )
                yield self._edge(
                    EdgeType.RESOLVES_TO,
                    CIRef(type=CIType.dns_name, external_id=dns),
                    elb_ref,
                    "aws:elbv2:describe_load_balancers",
                )
            for tg in elb.describe_target_groups(LoadBalancerArn=arn).get(
                "TargetGroups", []
            ):
                health = elb.describe_target_health(
                    TargetGroupArn=tg["TargetGroupArn"]
                ).get("TargetHealthDescriptions", [])
                for desc in health:
                    target_id = desc.get("Target", {}).get("Id", "")
                    if target_id.startswith("i-"):
                        instance_ref = CIRef(
                            type=CIType.ec2_instance, external_id=target_id
                        )
                        yield self._edge(
                            EdgeType.ROUTES_TO,
                            elb_ref,
                            instance_ref,
                            "aws:elbv2:describe_target_health",
                        )
                        yield self._edge(
                            EdgeType.EXPOSES,
                            elb_ref,
                            instance_ref,
                            "aws:elbv2:describe_target_health",
                        )

    def _discover_rds(self, region: str) -> Iterator[DiscoveryEvent]:
        rds = self._session.client("rds", region_name=region)
        for db in rds.describe_db_instances().get("DBInstances", []):
            arn = db["DBInstanceArn"]
            vpc_id = db.get("DBSubnetGroup", {}).get("VpcId")
            yield DiscoveredCI(
                type=CIType.rds,
                external_id=arn,
                name=db.get("DBInstanceIdentifier"),
                attributes={
                    "engine": db.get("Engine"),
                    "instance_class": db.get("DBInstanceClass"),
                    "status": db.get("DBInstanceStatus"),
                    "vpc": vpc_id,
                },
            )
            if vpc_id:
                yield self._edge(
                    EdgeType.CONTAINS,
                    CIRef(type=CIType.vpc, external_id=vpc_id),
                    CIRef(type=CIType.rds, external_id=arn),
                    "aws:rds:describe_db_instances",
                )

    def _discover_eks(self, region: str) -> Iterator[DiscoveryEvent]:
        eks = self._session.client("eks", region_name=region)
        for name in eks.list_clusters().get("clusters", []):
            cluster = eks.describe_cluster(name=name).get("cluster", {})
            arn = cluster.get("arn") or name
            vpc_id = cluster.get("resourcesVpcConfig", {}).get("vpcId")
            yield DiscoveredCI(
                type=CIType.eks_cluster,
                external_id=arn,
                name=cluster.get("name", name),
                attributes={
                    "status": cluster.get("status"),
                    "version": cluster.get("version"),
                    "vpc": vpc_id,
                },
            )
            if vpc_id:
                yield self._edge(
                    EdgeType.CONTAINS,
                    CIRef(type=CIType.vpc, external_id=vpc_id),
                    CIRef(type=CIType.eks_cluster, external_id=arn),
                    "aws:eks:describe_cluster",
                )
