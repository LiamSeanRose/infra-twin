"""Read-only PostgreSQL database-introspection discovery connector.

Discovers a PostgreSQL instance hierarchy (instance -> database -> schema -> table) and
declared foreign-key DEPENDS_ON edges via an injected DbIntrospectionClient and emits
canonical discovery events.

The connector holds no internal ids, never mutates the introspected database, and never
raises on missing optional keys — all accesses use .get() chains.

A ``DbIntrospectionClient`` is injected so the same code runs against a real read-only
database connection (in the CLI) and against an in-memory fake in tests.
"""

from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable

from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge, DiscoveryEvent
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence


@runtime_checkable
class DbIntrospectionClient(Protocol):
    """Minimal read-only catalog surface required by DbIntrospectionConnector.

    Production wraps a read-only connection to the CUSTOMER database and issues only
    catalog SELECTs against information_schema / pg_catalog. Test fakes return in-memory
    fixtures. Each method returns a list of plain dicts.
    """

    def list_databases(self) -> list[dict]: ...        # logical databases on the server
    def list_schemas(self) -> list[dict]: ...          # schemas (namespaces)
    def list_tables(self) -> list[dict]: ...           # tables/relations
    def list_foreign_keys(self) -> list[dict]: ...     # declared FK constraints


_CI_TYPES: frozenset[CIType] = frozenset(
    {
        CIType.db_instance,
        CIType.db_database,
        CIType.db_schema,
        CIType.db_table,
    }
)

_EDGE_TYPES: frozenset[EdgeType] = frozenset(
    {
        EdgeType.CONTAINS,
        EdgeType.DEPENDS_ON,
    }
)


class DbIntrospectionConnector:
    """Discovers a PostgreSQL instance hierarchy from a single server."""

    source: str = "db"
    ci_types: frozenset[CIType] = _CI_TYPES
    edge_types: frozenset[EdgeType] = _EDGE_TYPES

    def __init__(
        self,
        client: DbIntrospectionClient,
        host: str,
        port: int,
        instance_name: str | None = None,
    ) -> None:
        self._client = client
        self._host = host
        self._port = port
        self._instance_name = instance_name

    # -- helpers -----------------------------------------------------------------

    def _evidence(self, detail: str) -> list[Evidence]:
        return [Evidence(source="db", detail=detail)]

    def _edge(
        self,
        etype: EdgeType,
        from_ref: CIRef,
        to_ref: CIRef,
        detail: str,
        edge_key: str = "",
    ) -> DiscoveredEdge:
        return DiscoveredEdge(
            type=etype,
            from_ref=from_ref,
            to_ref=to_ref,
            source=EdgeSource.declared,
            confidence=1.0,
            evidence=self._evidence(detail),
            edge_key=edge_key,
        )

    # -- discovery ---------------------------------------------------------------

    def discover(self) -> Iterator[DiscoveryEvent]:
        host = self._host
        port = self._port
        instance_prefix = f"{host}:{port}"
        instance_name = self._instance_name or instance_prefix

        instance_ref = CIRef(type=CIType.db_instance, external_id=instance_prefix)

        # 1. db_instance CI — always emitted exactly once.
        yield DiscoveredCI(
            type=CIType.db_instance,
            external_id=instance_prefix,
            name=instance_name,
            attributes={
                "host": host,
                "port": port,
                "engine": "postgresql",
                "version": None,
            },
        )

        # 2. Databases — emit CIs, CONTAINS instance->database, track discovered set.
        discovered_databases: dict[str, str] = {}  # database name -> external_id
        for db in self._client.list_databases():
            db_name: str | None = db.get("name")
            if not db_name:
                continue
            db_external_id = f"{instance_prefix}/{db_name}"
            yield DiscoveredCI(
                type=CIType.db_database,
                external_id=db_external_id,
                name=db_name,
                attributes={
                    "database": db_name,
                    "owner": db.get("owner"),
                    "encoding": db.get("encoding"),
                },
            )
            yield self._edge(
                EdgeType.CONTAINS,
                instance_ref,
                CIRef(type=CIType.db_database, external_id=db_external_id),
                "db:instance:database",
            )
            discovered_databases[db_name] = db_external_id

        # 3. Schemas — emit CIs, CONTAINS database->schema when parent resolves.
        discovered_schemas: dict[tuple[str, str], str] = {}  # (database, schema) -> external_id
        for schema in self._client.list_schemas():
            schema_name: str | None = schema.get("name")
            if not schema_name:
                continue
            db_name_for_schema: str | None = schema.get("database")
            schema_external_id = f"{instance_prefix}/{db_name_for_schema}/{schema_name}"
            yield DiscoveredCI(
                type=CIType.db_schema,
                external_id=schema_external_id,
                name=schema_name,
                attributes={
                    "database": db_name_for_schema,
                    "schema": schema_name,
                    "owner": schema.get("owner"),
                },
            )
            if db_name_for_schema and db_name_for_schema in discovered_databases:
                parent_db_external_id = discovered_databases[db_name_for_schema]
                yield self._edge(
                    EdgeType.CONTAINS,
                    CIRef(type=CIType.db_database, external_id=parent_db_external_id),
                    CIRef(type=CIType.db_schema, external_id=schema_external_id),
                    "db:database:schema",
                )
            discovered_schemas[(db_name_for_schema or "", schema_name)] = schema_external_id

        # 4. Tables — emit CIs, CONTAINS schema->table when parent resolves.
        discovered_tables: dict[tuple[str, str, str], str] = {}  # (database, schema, table) -> external_id
        for table in self._client.list_tables():
            table_name: str | None = table.get("name")
            if not table_name:
                continue
            db_name_for_table: str | None = table.get("database")
            schema_name_for_table: str | None = table.get("schema")
            table_external_id = f"{instance_prefix}/{db_name_for_table}/{schema_name_for_table}/{table_name}"

            # Normalize kind from relkind or kind field.
            kind: str | None = table.get("kind") or table.get("relkind")

            # estimated_rows may be int or None.
            estimated_rows_raw = table.get("estimated_rows")
            estimated_rows: int | None = (
                int(estimated_rows_raw)
                if estimated_rows_raw is not None
                else None
            )

            yield DiscoveredCI(
                type=CIType.db_table,
                external_id=table_external_id,
                name=table_name,
                attributes={
                    "database": db_name_for_table,
                    "schema": schema_name_for_table,
                    "table": table_name,
                    "kind": kind,
                    "estimated_rows": estimated_rows,
                },
            )
            schema_key = (db_name_for_table or "", schema_name_for_table or "")
            if schema_name_for_table and schema_key in discovered_schemas:
                parent_schema_external_id = discovered_schemas[schema_key]
                yield self._edge(
                    EdgeType.CONTAINS,
                    CIRef(type=CIType.db_schema, external_id=parent_schema_external_id),
                    CIRef(type=CIType.db_table, external_id=table_external_id),
                    "db:schema:table",
                )
            discovered_tables[(db_name_for_table or "", schema_name_for_table or "", table_name)] = table_external_id

        # 5. Foreign keys — emit DEPENDS_ON edges when both endpoints are discovered.
        for fk in self._client.list_foreign_keys():
            fk_database: str | None = fk.get("database")
            from_schema: str | None = fk.get("from_schema")
            from_table: str | None = fk.get("from_table")
            to_schema: str | None = fk.get("to_schema")
            to_table: str | None = fk.get("to_table")

            if not from_table or not to_table:
                continue

            from_key = (fk_database or "", from_schema or "", from_table)
            to_key = (fk_database or "", to_schema or "", to_table)

            if from_key not in discovered_tables or to_key not in discovered_tables:
                continue

            from_external_id = discovered_tables[from_key]
            to_external_id = discovered_tables[to_key]

            constraint_name: str = fk.get("constraint_name") or "<unnamed>"
            from_columns: list[str] = fk.get("from_columns") or []
            to_columns: list[str] = fk.get("to_columns") or []
            from_cols = ",".join(from_columns)
            to_cols = ",".join(to_columns)

            detail = (
                f"db:fk:{constraint_name} "
                f"({from_schema}.{from_table}({from_cols}) -> "
                f"{to_schema}.{to_table}({to_cols}))"
            )

            yield self._edge(
                EdgeType.DEPENDS_ON,
                CIRef(type=CIType.db_table, external_id=from_external_id),
                CIRef(type=CIType.db_table, external_id=to_external_id),
                detail,
                edge_key=constraint_name,
            )
