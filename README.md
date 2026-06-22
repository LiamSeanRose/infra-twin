# infra-twin

Agentless, read-only infrastructure discovery and graph platform.

infra-twin connects to a cloud account (or Kubernetes cluster, database, or SaaS app)
through read-only credentials, discovers the resources running there, reconciles them into
a canonical **Configuration Item (CI)** and **relationship (edge)** model, and stores the
result in a single PostgreSQL database with the Apache AGE graph extension. On top of that
graph it answers four questions:

- **What do I have?** — normalized inventory across providers.
- **What depends on what?** — a queryable topology graph.
- **What breaks if this changes?** — blast-radius traversal from any resource.
- **What changed recently?** — a rolling 7-day change feed.

It also supports natural-language querying that is always compiled to a **validated,
templated** graph query through tool-use — never executed as free-form input.

## Key properties

- **Agentless and read-only.** Discovery runs entirely against provider APIs via read-only
  credentials. There is no write/mutate path against a connected account.
- **Bitemporal, never hard-delete.** Every CI and edge carries a `valid_from` / `valid_to`
  validity window; facts are closed and re-opened, never physically deleted.
- **Multi-tenant at the storage layer.** Every row is tenant-scoped, with isolation enforced
  by PostgreSQL Row-Level Security — not left to callers.
- **Edge provenance always present.** Every edge records its `source` (`declared` |
  `inferred`), a `confidence` score, and the `evidence` it was derived from.
- **Multi-source.** Connectors for AWS, Azure, GCP, Kubernetes, PostgreSQL, and SaaS APIs.
- **Telemetry-based inference.** Declared edges can be augmented with dependency edges
  inferred from observed traffic (e.g. VPC flow logs), with confidence and evidence.

## Repository layout

```
apps/        end-user-facing applications (API surface, web UI, CLI)
services/    deployable services (discovery, reconciliation, query)
packages/    shared libraries (data model, db access, connector SDK)
infra/       infrastructure-as-code and onboarding templates
migrations/  forward-only, idempotent SQL migrations
```

## Tech stack

- **Language:** Python 3.12+ (typed, Pydantic v2), managed as a `uv` workspace.
- **Datastore:** PostgreSQL + Apache AGE (single database), accessed via `psycopg` 3.
- **API:** FastAPI (REST + GraphQL read surface).
- **NL → query:** Claude via the Anthropic API, compiled to whitelisted, validated query
  templates through tool-use.
- **Frontend:** React + TypeScript + Vite, graph visualization via Cytoscape.js.
- **Local stack:** Docker Compose runs `apache/age` (PostgreSQL + AGE).

## Prerequisites

- Docker and Docker Compose
- [`uv`](https://docs.astral.sh/uv/)
- Node.js + npm (for the web UI)

## Quickstart

```bash
make build      # uv sync — install the workspace + dev deps
make run        # docker compose up -d — start PostgreSQL + AGE
make migrate    # apply database migrations (forward-only, idempotent)
make serve      # run the FastAPI surface on http://127.0.0.1:8000
```

Web UI (in a second terminal):

```bash
make web-install   # once
make web           # Vite dev server on http://localhost:5173
```

Run the test suite (against the local stack):

```bash
make test
```

`make stop` tears the local database down.

## Configuration

Copy `.env.example` and fill in values. The main settings:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Application DSN (RLS-enforced app role). |
| `ADMIN_DATABASE_URL` | Superuser DSN, used only by the migration runner. |
| `INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN` | Shared secret authorizing tenant creation. |
| `ANTHROPIC_API_KEY` | API key for the natural-language query surface (`POST /ask`). Server-side only. |
| `INFRA_TWIN_NL_MODEL` | Optional model override for NL → query (defaults to `claude-sonnet-4-6`). |

## Usage

1. **Create a tenant and issue an API key** (uses the bootstrap admin token):

   ```bash
   curl -s -X POST http://127.0.0.1:8000/tenants \
     -H "Authorization: Bearer $INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN" \
     -H "content-type: application/json" \
     -d '{"name":"demo","role":"editor"}'
   ```

   The response includes a `tenant_id` and an `api_key`.

2. **Discover resources** with the CLI (one subcommand per source):

   ```bash
   # AWS (read-only assume-role)
   uv run infra-twin discover --tenant <TENANT_ID> --regions us-east-1 --role-arn <ROLE_ARN>

   # A PostgreSQL database (read-only introspection)
   uv run infra-twin discover-db --tenant <TENANT_ID> \
     --dsn "postgresql://user:pass@host:5432/db" --host host --port 5432

   # Others: discover-azure, discover-gcp, discover-k8s, discover-saas
   ```

3. **Explore** at http://localhost:5173 — paste the `api_key`, load the graph, inspect
   blast radius and recent changes, and ask natural-language questions.

## Data model

Everything in the graph is a **CI node** or an **edge**, both persisted in PostgreSQL and
projected into Apache AGE.

- **CI node:** `id`, `tenant_id`, `type`, `external_id`, normalized `attributes`,
  `valid_from` / `valid_to`.
- **Edge:** `id`, `tenant_id`, `type`, `from_id` / `to_id`, `source`, `confidence`,
  `evidence`, `valid_from` / `valid_to`.

## API surface

Selected endpoints (all tenant-scoped and authenticated, except `/health`):

| Endpoint | Description |
|---|---|
| `GET /health` | Liveness check. |
| `POST /tenants` | Create a tenant and issue an API key (bootstrap-admin only). |
| `GET /graph` | The CI + edge graph for the tenant. |
| `POST /ask` | Natural-language question → templated graph query. |
| `GET /changes` | Rolling change feed (default 7 days). |
| `GET /cis/{id}/blast-radius` | Downstream impact traversal from a CI. |
| `POST /rca` | Root-cause analysis over change events and topology. |
| `GET /findings`, `POST /findings/evaluate` | Risk findings. |
| `POST /graphql` | Read-only GraphQL surface over the same data. |

See `infra-digital-twin-plan.md` for the full architecture and design rationale.
