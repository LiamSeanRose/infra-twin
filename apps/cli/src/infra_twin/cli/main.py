"""``infra-twin`` CLI.

The ``discover`` command runs read-only AWS discovery and reconciles the result into the
graph. It builds a boto3 session (optionally via a read-only assume-role) and hands a real
``AwsConnector`` to the same ``discover_and_reconcile`` orchestration covered by tests.

The ``discover-k8s`` command runs read-only Kubernetes discovery and reconciles the result
into the graph. It builds a real K8sClient adapter (lazily importing the ``kubernetes``
library) and hands a ``KubernetesConnector`` to the same orchestration.

The ``discover-azure`` command runs read-only Azure discovery and reconciles the result
into the graph. It builds a real AzureClient adapter (lazily importing the Azure SDK) and
hands an ``AzureConnector`` to the same orchestration.

The ``discover-gcp`` command runs read-only GCP discovery and reconciles the result into
the graph. It builds a real GcpClient adapter (lazily importing the Google Cloud SDK) and
hands a ``GcpConnector`` to the same orchestration.

The ``discover-db`` command runs read-only PostgreSQL DB-introspection discovery and
reconciles the result into the graph. It builds a real DbIntrospectionClient adapter
(lazily importing ``psycopg``) and hands a ``DbIntrospectionConnector`` to the same
orchestration.

The ``discover-saas`` command runs read-only SaaS API discovery and reconciles the result
into the graph. It builds a real SaasDiscoveryClient adapter (lazily importing the SaaS
HTTP/SDK layer) and hands a ``SaasDiscoveryConnector`` to the same orchestration.

The ``age-inferred-edges`` command runs the inferred-edge aging sweep for a tenant,
decaying stale inferred edges and closing those past their TTL.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from uuid import UUID

import boto3

from infra_twin.collectors.aws import AwsConnector
from infra_twin.collectors.azure import AzureClient, AzureConnector
from infra_twin.collectors.db import DbIntrospectionClient, DbIntrospectionConnector
from infra_twin.collectors.gcp import GcpClient, GcpConnector
from infra_twin.collectors.k8s import K8sClient, KubernetesConnector
from infra_twin.collectors.saas import SaasDiscoveryClient, SaasDiscoveryConnector
from infra_twin.db.pool import make_pool
from infra_twin.reconciliation import age_inferred_edges, discover_and_reconcile


def _build_session(
    region: str, role_arn: str | None, external_id: str | None
) -> boto3.Session:
    if not role_arn:
        return boto3.Session(region_name=region)
    sts = boto3.client("sts")
    params = {"RoleArn": role_arn, "RoleSessionName": "infra-twin-discovery"}
    if external_id:
        params["ExternalId"] = external_id
    creds = sts.assume_role(**params)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def _discover(args: argparse.Namespace) -> int:
    session = _build_session(args.regions[0], args.role_arn, args.external_id)
    account_id = session.client("sts").get_caller_identity()["Account"]
    connector = AwsConnector(session, account_id=account_id, regions=args.regions)

    pool = make_pool()
    try:
        result = discover_and_reconcile(pool, UUID(args.tenant), connector)
    finally:
        pool.close()

    print(
        f"account={account_id} regions={','.join(args.regions)}\n"
        f"  CIs:   +{result.cis_created} ~{result.cis_updated} "
        f"={result.cis_unchanged} -{result.cis_closed}\n"
        f"  edges: {result.edges_written} written, {result.edges_closed} closed"
    )
    return 0


def _build_k8s_client(kubeconfig: str | None, context: str | None) -> K8sClient:
    """Build a real K8sClient adapter using the ``kubernetes`` library.

    The ``kubernetes`` import is intentionally lazy so that importing this module and
    running the AWS path never requires the ``kubernetes`` package to be installed.
    """
    import kubernetes  # noqa: PLC0415 — lazy import by design

    config_kwargs: dict = {}
    if kubeconfig:
        config_kwargs["config_file"] = kubeconfig
    if context:
        config_kwargs["context"] = context
    kubernetes.config.load_kube_config(**config_kwargs)

    core_v1 = kubernetes.client.CoreV1Api()
    apps_v1 = kubernetes.client.AppsV1Api()

    def _obj_to_dict(obj: object) -> dict:
        return kubernetes.client.ApiClient().sanitize_for_serialization(obj)

    class _RealK8sClient:
        def list_namespaces(self) -> list[dict]:
            return [_obj_to_dict(ns) for ns in core_v1.list_namespace().items]

        def list_nodes(self) -> list[dict]:
            return [_obj_to_dict(n) for n in core_v1.list_node().items]

        def list_deployments(self) -> list[dict]:
            return [
                _obj_to_dict(d)
                for d in apps_v1.list_deployment_for_all_namespaces().items
            ]

        def list_services(self) -> list[dict]:
            return [_obj_to_dict(s) for s in core_v1.list_service_for_all_namespaces().items]

        def list_pods(self) -> list[dict]:
            return [_obj_to_dict(p) for p in core_v1.list_pod_for_all_namespaces().items]

    return _RealK8sClient()


def _discover_k8s(args: argparse.Namespace) -> int:
    client = _build_k8s_client(
        kubeconfig=getattr(args, "kubeconfig", None),
        context=getattr(args, "context", None),
    )
    cluster_name = args.cluster_name or args.cluster_id
    connector = KubernetesConnector(client, cluster_id=args.cluster_id, cluster_name=cluster_name)

    pool = make_pool()
    try:
        result = discover_and_reconcile(pool, UUID(args.tenant), connector)
    finally:
        pool.close()

    print(
        f"cluster={args.cluster_id}\n"
        f"  CIs:   +{result.cis_created} ~{result.cis_updated} "
        f"={result.cis_unchanged} -{result.cis_closed}\n"
        f"  edges: {result.edges_written} written, {result.edges_closed} closed"
    )
    return 0


def _build_azure_client(
    subscription_id: str,
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
) -> AzureClient:
    """Build a real AzureClient adapter using the Azure SDK.

    The Azure SDK imports are intentionally lazy so that importing this module and running
    the AWS or K8s paths never requires the Azure SDK packages to be installed.
    """
    import azure.identity  # noqa: PLC0415 — lazy import by design
    import azure.mgmt.network  # noqa: PLC0415 — lazy import by design
    import azure.mgmt.compute  # noqa: PLC0415 — lazy import by design
    import azure.mgmt.resource  # noqa: PLC0415 — lazy import by design

    if tenant_id and client_id and client_secret:
        credential = azure.identity.ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    else:
        credential = azure.identity.DefaultAzureCredential()

    resource_client = azure.mgmt.resource.ResourceManagementClient(credential, subscription_id)
    network_client = azure.mgmt.network.NetworkManagementClient(credential, subscription_id)
    compute_client = azure.mgmt.compute.ComputeManagementClient(credential, subscription_id)

    class _RealAzureClient:
        def list_resource_groups(self) -> list[dict]:
            return [rg.as_dict() for rg in resource_client.resource_groups.list()]

        def list_virtual_networks(self) -> list[dict]:
            return [vnet.as_dict() for vnet in network_client.virtual_networks.list_all()]

        def list_network_security_groups(self) -> list[dict]:
            return [nsg.as_dict() for nsg in network_client.network_security_groups.list_all()]

        def list_virtual_machines(self) -> list[dict]:
            return [vm.as_dict() for vm in compute_client.virtual_machines.list_all()]

    return _RealAzureClient()


def _discover_azure(args: argparse.Namespace) -> int:
    client = _build_azure_client(
        subscription_id=args.subscription_id,
        tenant_id=getattr(args, "azure_tenant_id", None),
        client_id=getattr(args, "azure_client_id", None),
        client_secret=getattr(args, "azure_client_secret", None),
    )
    connector = AzureConnector(
        client,
        subscription_id=args.subscription_id,
        subscription_name=getattr(args, "subscription_name", None),
    )

    pool = make_pool()
    try:
        result = discover_and_reconcile(pool, UUID(args.tenant), connector)
    finally:
        pool.close()

    print(
        f"subscription={args.subscription_id}\n"
        f"  CIs:   +{result.cis_created} ~{result.cis_updated} "
        f"={result.cis_unchanged} -{result.cis_closed}\n"
        f"  edges: {result.edges_written} written, {result.edges_closed} closed"
    )
    return 0


def _build_db_client(dsn: str, instance_name: str | None) -> DbIntrospectionClient:
    """Build a real DbIntrospectionClient adapter using a read-only psycopg connection.

    The ``psycopg`` import is intentionally lazy so that importing this module and running
    the AWS, K8s, Azure, or GCP paths never requires ``psycopg`` to be installed.

    Opens the connection in autocommit mode and sets the session read-only so that the
    adapter can only ever issue catalog SELECTs — never DDL or DML.
    """
    import psycopg  # noqa: PLC0415 — lazy import by design

    conn = psycopg.connect(dsn, autocommit=True)
    conn.execute("SET default_transaction_read_only = on")

    class _RealDbClient:
        def list_databases(self) -> list[dict]:
            rows = conn.execute(
                "SELECT datname AS name, pg_catalog.pg_get_userbyid(datdba) AS owner,"
                " pg_catalog.pg_encoding_to_char(encoding) AS encoding"
                " FROM pg_catalog.pg_database"
                " WHERE datistemplate = false"
                " ORDER BY datname"
            ).fetchall()
            cols = ["name", "owner", "encoding"]
            return [dict(zip(cols, row)) for row in rows]

        def list_schemas(self) -> list[dict]:
            rows = conn.execute(
                "SELECT catalog_name AS database, schema_name AS name,"
                " schema_owner AS owner"
                " FROM information_schema.schemata"
                " ORDER BY catalog_name, schema_name"
            ).fetchall()
            cols = ["database", "name", "owner"]
            return [dict(zip(cols, row)) for row in rows]

        def list_tables(self) -> list[dict]:
            rows = conn.execute(
                "SELECT t.table_catalog AS database, t.table_schema AS schema,"
                " t.table_name AS name,"
                " CASE t.table_type"
                "   WHEN 'VIEW' THEN 'view'"
                "   ELSE 'table'"
                " END AS kind,"
                " c.reltuples::bigint AS estimated_rows"
                " FROM information_schema.tables t"
                " LEFT JOIN pg_catalog.pg_class c"
                "   ON c.relname = t.table_name"
                "   AND c.relnamespace = (SELECT oid FROM pg_catalog.pg_namespace"
                "                          WHERE nspname = t.table_schema)"
                " WHERE t.table_schema NOT IN ('pg_catalog', 'information_schema')"
                " ORDER BY t.table_catalog, t.table_schema, t.table_name"
            ).fetchall()
            cols = ["database", "schema", "name", "kind", "estimated_rows"]
            return [dict(zip(cols, row)) for row in rows]

        def list_foreign_keys(self) -> list[dict]:
            rows = conn.execute(
                "SELECT tc.constraint_name,"
                " tc.table_catalog AS database,"
                " tc.table_schema AS from_schema,"
                " tc.table_name AS from_table,"
                " array_agg(kcu.column_name ORDER BY kcu.ordinal_position) AS from_columns,"
                " ccu.table_schema AS to_schema,"
                " ccu.table_name AS to_table,"
                " array_agg(ccu.column_name ORDER BY kcu.ordinal_position) AS to_columns"
                " FROM information_schema.table_constraints tc"
                " JOIN information_schema.key_column_usage kcu"
                "   ON tc.constraint_name = kcu.constraint_name"
                "   AND tc.table_schema = kcu.table_schema"
                "   AND tc.table_catalog = kcu.table_catalog"
                " JOIN information_schema.constraint_column_usage ccu"
                "   ON tc.constraint_name = ccu.constraint_name"
                "   AND tc.table_catalog = ccu.table_catalog"
                " WHERE tc.constraint_type = 'FOREIGN KEY'"
                " GROUP BY tc.constraint_name, tc.table_catalog, tc.table_schema,"
                "          tc.table_name, ccu.table_schema, ccu.table_name"
                " ORDER BY tc.constraint_name"
            ).fetchall()
            cols = ["constraint_name", "database", "from_schema", "from_table",
                    "from_columns", "to_schema", "to_table", "to_columns"]
            result = []
            for row in rows:
                d = dict(zip(cols, row))
                # psycopg returns arrays as Python lists; ensure list[str].
                d["from_columns"] = list(d["from_columns"]) if d["from_columns"] else []
                d["to_columns"] = list(d["to_columns"]) if d["to_columns"] else []
                result.append(d)
            return result

    return _RealDbClient()


def _discover_db(args: argparse.Namespace) -> int:
    client = _build_db_client(dsn=args.dsn, instance_name=args.instance_name)
    connector = DbIntrospectionConnector(
        client,
        host=args.host,
        port=args.port,
        instance_name=args.instance_name,
    )

    pool = make_pool()
    try:
        result = discover_and_reconcile(pool, UUID(args.tenant), connector)
    finally:
        pool.close()

    print(
        f"host={args.host} port={args.port}\n"
        f"  CIs:   +{result.cis_created} ~{result.cis_updated} "
        f"={result.cis_unchanged} -{result.cis_closed}\n"
        f"  edges: {result.edges_written} written, {result.edges_closed} closed"
    )
    return 0


def _build_gcp_client(
    project_id: str,
    credentials_path: str | None = None,
) -> GcpClient:
    """Build a real GcpClient adapter using the Google Cloud SDK.

    The Google Cloud SDK imports are intentionally lazy so that importing this module and
    running the AWS, K8s, or Azure paths never requires the Google Cloud packages to be
    installed.
    """
    from google.cloud import compute_v1  # noqa: PLC0415 — lazy import by design

    if credentials_path:
        from google.oauth2 import service_account  # noqa: PLC0415 — lazy import by design

        credentials = service_account.Credentials.from_service_account_file(
            credentials_path,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
    else:
        credentials = None

    networks_client = compute_v1.NetworksClient(credentials=credentials)
    subnetworks_client = compute_v1.SubnetworksClient(credentials=credentials)
    firewalls_client = compute_v1.FirewallsClient(credentials=credentials)
    instances_client = compute_v1.AggregatedInstancesClient(credentials=credentials)

    class _RealGcpClient:
        def list_networks(self) -> list[dict]:
            return [
                type(net).to_dict(net)
                for net in networks_client.list(project=project_id)
            ]

        def list_subnetworks(self) -> list[dict]:
            result: list[dict] = []
            for _region, scoped in subnetworks_client.aggregated_list(project=project_id):
                for sn in scoped.subnetworks or []:
                    result.append(type(sn).to_dict(sn))
            return result

        def list_firewalls(self) -> list[dict]:
            return [
                type(fw).to_dict(fw)
                for fw in firewalls_client.list(project=project_id)
            ]

        def list_instances(self) -> list[dict]:
            result: list[dict] = []
            for _zone, scoped in instances_client.list(project=project_id):
                for inst in scoped.instances or []:
                    result.append(type(inst).to_dict(inst))
            return result

    return _RealGcpClient()


def _discover_gcp(args: argparse.Namespace) -> int:
    client = _build_gcp_client(
        project_id=args.project_id,
        credentials_path=getattr(args, "credentials_path", None),
    )
    connector = GcpConnector(
        client,
        project_id=args.project_id,
        project_name=getattr(args, "project_name", None),
    )

    pool = make_pool()
    try:
        result = discover_and_reconcile(pool, UUID(args.tenant), connector)
    finally:
        pool.close()

    print(
        f"project={args.project_id}\n"
        f"  CIs:   +{result.cis_created} ~{result.cis_updated} "
        f"={result.cis_unchanged} -{result.cis_closed}\n"
        f"  edges: {result.edges_written} written, {result.edges_closed} closed"
    )
    return 0


def _build_saas_client(
    api_base: str | None = None,
    api_token: str | None = None,
) -> SaasDiscoveryClient:
    """Build a real SaasDiscoveryClient adapter using an HTTP/SDK layer.

    The SaaS HTTP/SDK import is intentionally lazy so that importing this module and
    running the AWS, K8s, Azure, GCP, or DB paths never requires the SaaS SDK to be
    installed.
    """
    import urllib.request  # noqa: PLC0415 — lazy import by design
    import json  # noqa: PLC0415 — lazy import by design

    headers: dict[str, str] = {}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"

    def _get(path: str) -> list[dict]:
        if not api_base:
            return []
        url = f"{api_base.rstrip('/')}/{path.lstrip('/')}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())

    class _RealSaasClient:
        def list_apps(self) -> list[dict]:
            return _get("/apps")

        def list_accounts(self) -> list[dict]:
            return _get("/accounts")

        def list_resources(self) -> list[dict]:
            return _get("/resources")

        def list_access_grants(self) -> list[dict]:
            return _get("/access-grants")

    return _RealSaasClient()


def _discover_saas(args: argparse.Namespace) -> int:
    client = _build_saas_client(
        api_base=getattr(args, "api_base", None),
        api_token=getattr(args, "api_token", None),
    )
    connector = SaasDiscoveryConnector(
        client,
        account_id=args.account_id,
        account_name=getattr(args, "account_name", None),
    )

    pool = make_pool()
    try:
        result = discover_and_reconcile(pool, UUID(args.tenant), connector)
    finally:
        pool.close()

    print(
        f"account={args.account_id}\n"
        f"  CIs:   +{result.cis_created} ~{result.cis_updated} "
        f"={result.cis_unchanged} -{result.cis_closed}\n"
        f"  edges: {result.edges_written} written, {result.edges_closed} closed"
    )
    return 0


def _age_inferred_edges(args: argparse.Namespace) -> int:
    pool = make_pool()
    try:
        result = age_inferred_edges(
            pool, UUID(args.tenant), now=datetime.now(timezone.utc)
        )
    finally:
        pool.close()

    print(
        f"decayed={result.decayed} closed={result.closed} "
        f"untouched={result.untouched} run={result.connector_run_id}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="infra-twin")
    sub = parser.add_subparsers(dest="command", required=True)

    discover = sub.add_parser("discover", help="Run AWS discovery and reconcile it.")
    discover.add_argument("--tenant", required=True, help="Tenant UUID.")
    discover.add_argument(
        "--regions", required=True, nargs="+", help="AWS regions to scan."
    )
    discover.add_argument("--role-arn", help="Read-only role to assume in the target account.")
    discover.add_argument("--external-id", help="External ID for the assume-role.")
    discover.set_defaults(func=_discover)

    age_cmd = sub.add_parser(
        "age-inferred-edges",
        help="Decay or TTL-close stale inferred edges for a tenant.",
    )
    age_cmd.add_argument("--tenant", required=True, help="Tenant UUID.")
    age_cmd.set_defaults(func=_age_inferred_edges)

    daz = sub.add_parser("discover-azure", help="Run Azure discovery and reconcile it.")
    daz.add_argument("--tenant", required=True, help="Tenant UUID.")
    daz.add_argument("--subscription-id", required=True, help="Azure subscription id.")
    daz.add_argument("--subscription-name", default=None, help="Display name for the subscription CI.")
    daz.add_argument("--azure-tenant-id", default=None, help="Azure AD tenant id (for service principal auth).")
    daz.add_argument("--azure-client-id", default=None, help="Azure service principal client id.")
    daz.add_argument("--azure-client-secret", default=None, help="Azure service principal client secret.")
    daz.set_defaults(func=_discover_azure)

    dgcp = sub.add_parser("discover-gcp", help="Run GCP discovery and reconcile it.")
    dgcp.add_argument("--tenant", required=True, help="Tenant UUID.")
    dgcp.add_argument("--project-id", required=True, help="GCP project id.")
    dgcp.add_argument("--project-name", default=None, help="Display name for the project CI.")
    dgcp.add_argument("--credentials-path", default=None, help="Path to a service-account JSON key.")
    dgcp.set_defaults(func=_discover_gcp)

    ddb = sub.add_parser("discover-db", help="Run PostgreSQL DB-introspection discovery and reconcile it.")
    ddb.add_argument("--tenant", required=True, help="Tenant UUID.")
    ddb.add_argument("--dsn", required=True, help="Read-only DSN of the customer database to introspect.")
    ddb.add_argument("--host", required=True, help="Hostname used for the instance external_id.")
    ddb.add_argument("--port", required=True, type=int, help="Port used for the instance external_id.")
    ddb.add_argument("--instance-name", default=None, help="Display name for the db_instance CI.")
    ddb.set_defaults(func=_discover_db)

    dsaas = sub.add_parser("discover-saas", help="Run SaaS API discovery and reconcile it.")
    dsaas.add_argument("--tenant", required=True, help="Tenant UUID.")
    dsaas.add_argument("--account-id", required=True, help="Provider-native SaaS account scope id.")
    dsaas.add_argument("--account-name", default=None, help="Display label for the SaaS account scope.")
    dsaas.add_argument("--api-base", default=None, help="Base URL of the SaaS API.")
    dsaas.add_argument("--api-token", default=None, help="Bearer token for the SaaS API.")
    dsaas.set_defaults(func=_discover_saas)

    dk8s = sub.add_parser("discover-k8s", help="Run Kubernetes discovery and reconcile it.")
    dk8s.add_argument("--tenant", required=True, help="Tenant UUID.")
    dk8s.add_argument("--cluster-id", required=True, help="Stable external_id for the cluster CI.")
    dk8s.add_argument("--cluster-name", default=None, help="Display name for the cluster CI.")
    dk8s.add_argument(
        "--kubeconfig",
        default=None,
        help="Path to kubeconfig file; defaults to standard resolution.",
    )
    dk8s.add_argument(
        "--context",
        default=None,
        help="Kubeconfig context to select.",
    )
    dk8s.set_defaults(func=_discover_k8s)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
