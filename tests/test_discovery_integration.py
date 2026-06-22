"""End-to-end: moto AWS -> connector -> reconcile -> relational + AGE graph."""

from __future__ import annotations

import boto3
from moto import mock_aws

from infra_twin.collectors.aws import AwsConnector
from infra_twin.core_model import CIType
from infra_twin.db.graph import cypher
from infra_twin.db.repositories import CIRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import discover_and_reconcile

REGION = "us-east-1"


def test_discover_and_reconcile_populates_graph(pool, make_tenant):
    tenant = make_tenant()
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")
        account = boto3.client("sts", region_name=REGION).get_caller_identity()[
            "Account"
        ]
        connector = AwsConnector(
            boto3.Session(region_name=REGION), account_id=account, regions=[REGION]
        )
        result = discover_and_reconcile(pool, tenant, connector)

    assert result.cis_created > 0
    assert result.edges_written > 0

    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        # moto seeds a default VPC, so discovery finds the default plus the one we created.
        assert len(repo.get_current(type=CIType.vpc)) >= 1

        # The graph projection carries the tenant and the hierarchy edge.
        vpc_rows = cypher(
            conn, f"MATCH (n:vpc) WHERE n.tenant_id = '{tenant}' RETURN n"
        )
        assert len(vpc_rows) >= 1
        edge_rows = cypher(
            conn,
            f"MATCH (:vpc)-[r:CONTAINS]->(:subnet) WHERE r.tenant_id = '{tenant}' RETURN r",
        )
        assert len(edge_rows) >= 1
