# Infrastructure Digital Twin Platform — Strategy, Architecture & Roadmap

*A founder's working document. Opinionated on purpose. Read the "Brutal Truths" section first if you read nothing else.*

---

## 0. Brutal Truths (read this first)

Before the 17 sections you asked for, here is the framing that should govern every decision below.

1. **The graph is not the moat.** A property graph of cloud resources is now table stakes. JupiterOne built a unicorn on "the graph is a security primitive." Wiz built its entire CNAPP on a real-time security graph and just sold to Google for $32B (announced March 2025, closed March 2026). Lyft open-sourced Cartography (Neo4j-based infra graph) years ago. The graph is a *commodity capability*. Your moat has to be **data correctness + freshness + the reasoning layer on top**, not the existence of a graph.

2. **"Digital twin" is dangerous marketing.** A true digital twin implies you can *simulate* — "what will happen if I make this change." That requires a behavioral model of the system, not just a topology map. Almost nobody in IT infrastructure has achieved high-fidelity predictive simulation, and the ones who claim to are mostly doing topology-based blast-radius analysis (which is valuable but is *not* simulation). Treat predictive "what-if" as the **last** capability you build, not the pitch you lead with. If you promise simulation in your seed deck you will spend 18 months failing to deliver it.

3. **Discovery is a grind, not a breakthrough.** The hard, unglamorous, never-finished work is: building connectors, keeping them working as vendor APIs change, and **reconciling the same real-world thing seen by five different sources into one node**. This "connector treadmill" + entity resolution is where most companies in this space quietly die. Budget for it as a permanent cost center, not a phase.

4. **Stale data kills trust, and distrust kills the product.** The CMDB graveyard is full of accurate-on-day-one, garbage-by-month-three databases. The instant an SRE catches your graph being wrong during an incident, they stop using it forever. Freshness and correctness are existential, not features.

5. **You have no buyer yet.** "Infrastructure visibility" is not a budget line. Security teams buy CAASM/CSPM. SREs buy observability. IT ops buys ITSM/CMDB. FinOps buys cost tools. Each is a *different product with a different champion*. Pick one wedge for the MVP. Trying to serve all of them at once is the #1 way startups here fail.

6. **You are entering a market with deep-pocketed incumbents and a giant who just spent $32B.** Do not fight ServiceNow, Datadog, Dynatrace, or Google/Wiz head-on. Win a niche they serve badly, then expand.

Everything below is written with these truths in mind.

---

## 1. Product Vision

**One-liner:** A continuously-updated, queryable model of an organization's entire infrastructure that lets any engineer ask plain-English questions about what they have, how it connects, and what breaks when something changes — and trust the answer.

**The layered vision (and the order you earn the right to build each layer):**

| Layer | Capability | The question it answers | Difficulty |
|---|---|---|---|
| 1. **Inventory** | Discover & catalog assets | "What do I have?" | Medium |
| 2. **Topology** | Map relationships | "How is it connected?" | Hard |
| 3. **Dependency** | Infer what relies on what | "What depends on what?" | Very hard |
| 4. **Impact** | Topology-based blast radius | "What breaks if this fails?" | Hard |
| 5. **History** | Temporal change tracking | "What changed recently?" | Hard |
| 6. **Reasoning** | Root-cause & risk analysis | "Why did this break? What's risky?" | Very hard |
| 7. **Simulation** | Predictive what-if | "What happens if I change this?" | Brutal |

Layers 1–2 are your MVP. Layers 3–5 are your Series A story. Layers 6–7 are the long-term vision and the fundraising narrative — **but you do not need them to have a real business.** A trustworthy, fresh inventory + dependency + blast-radius product is already worth money to the right buyer.

**What "AI-powered" actually means here** (be honest with yourself):
- *Near-term, real:* natural-language → graph query translation; relationship inference from telemetry; natural-language explanations of blast radius and change history; anomaly/drift detection.
- *Medium-term, hard:* automated root-cause analysis (correlating change events + topology + telemetry).
- *Long-term, aspirational:* genuine predictive simulation.

Lead the product with #1 (it works today and demos beautifully). Treat the rest as roadmap.

---

## 2. Market Analysis

**The space is real and large, but fragmented across several adjacent markets** — you are not in one clean market:

- **Digital twin (broad):** ~$36B in 2025, projected ~$49B in 2026, ~35% CAGR (Mordor Intelligence). *Caveat:* this number is dominated by manufacturing/IoT/industrial twins, **not** IT infrastructure. Don't quote it as your TAM without disaggregating — investors will catch it.
- **AIOps platforms:** ~$11–17B in 2025 depending on the analyst, ~21–24% CAGR toward $55–78B by the early 2030s (Coherent, SkyQuest). This is closer to your actual market.
- **Adjacent budgets you'll actually pull from:** CMDB/ITSM, observability, CAASM/CSPM (cyber asset & cloud security), application dependency mapping (ADM), and FinOps.

**Tailwinds (why now):**
- Hybrid/multi-cloud is the default; nobody knows what they actually have anymore.
- AI/agent sprawl is creating a brand-new visibility gap (JupiterOne literally just launched "AI Attack Surface Management" in May 2026 to chase exactly this).
- Zero Trust and regulatory pressure (DORA, SOC 2, etc.) demand accurate asset & dependency inventories.
- LLMs finally make natural-language querying of a complex graph genuinely usable — this is the new capability that didn't exist 3 years ago and is your best wedge.

**Headwinds (be honest):**
- Buyers are fatigued by "single pane of glass" promises.
- Deploying these tools is notoriously painful (integration with legacy + disparate monitoring tools is the #1 complaint in AIOps adoption surveys).
- The cyber-physical security and "shortage of modeling talent" constraints cited in twin reports apply to you too.

**Realistic TAM framing for a deck:** Don't claim the digital-twin TAM. Frame it as: *"We sit at the intersection of AIOps + CAASM + ADM, a combined serviceable market in the tens of billions, growing 20%+, and we win the slice that incumbents serve with stale, siloed data."*

---

## 3. Competitor Analysis

Group them by what they actually are. Your positioning depends on knowing which fight you're picking.

**A. Graph-native asset/security platforms (your closest analogs):**
- **JupiterOne** — CAASM, graph-native, 200+ integrations, ~$119M raised, ~$1B valuation, agentless API collection, query language (J1QL) over the graph. *This is the company most similar to your vision.* Note their pivot toward AI risk (May 2026). They proved the model; they're also proof the security wedge works.
- **Wiz** (now Google Cloud) — agentless cloud security graph, real-time, attack-path analysis, >$1B ARR, sold for $32B. The gold standard for "scan the cloud, build a graph, surface what matters." Now backed by Google's wallet. **Do not try to be a better Wiz.**
- **Cartography** (open source, Lyft) — Neo4j-based infra/asset graph. Free. Your "build vs. buy" competitor and a recruiting/credibility reference. Anyone technical will ask "why not just run Cartography?"
- **Steampipe / Resoto/Fix** (open source) — SQL/graph over cloud APIs. Same "why not free?" pressure.

**B. CMDB / Discovery / ITSM incumbents:**
- **ServiceNow** (CMDB + Discovery + Service Mapping) — the 800-lb gorilla. Enterprise system of record, deep ITOM, doubling down on agentic AI in 2026. Expensive, heavy, but owns the enterprise relationship.
- **Device42** (now Freshworks) — strong agentless discovery + ADM + IPAM/DCIM, "mini CMDB," reasonable pricing. Mid-market favorite.
- **BMC Helix, OpenText (uCMDB)** — legacy enterprise.

**C. Application Dependency Mapping specialists:**
- **Faddom** — agentless, credential-less, real-time maps in ~1 hour, free community tier, ServiceNow partnership. Migration/M&A/Zero-Trust use cases. Low-friction; a direct threat to a naive MVP.
- **Virima** — ADM + CMDB + ITSM overlays.

**D. Observability players with topology:**
- **Dynatrace** (Smartscape topology + Davis AI causal RCA) — arguably the closest to "automated root cause via topology" in production today.
- **Datadog** (service maps, dependency mapping, watchdog) — huge install base.
- **New Relic, Splunk** (now Cisco).

**Honest competitive read:** Every major capability in your vision exists *somewhere* today. Nobody combines **(a) cross-domain discovery (cloud + on-prem + SaaS + DB + app), (b) a trustworthy continuously-reconciled graph, and (c) a genuinely good natural-language reasoning layer aimed at a non-security generalist engineering audience.** That intersection — especially the NL reasoning layer over a *trusted* cross-domain graph — is the only defensible gap. Even there, your defensibility is execution + data quality, not technology.

**Your wedge recommendation:** Start where the incumbents are *weakest and the data is easiest to get cleanly* — agentless, read-only **cloud + SaaS dependency & blast-radius for mid-market engineering teams who can't afford ServiceNow and find Datadog's topology shallow**, with NL querying as the hook. Pick security OR SRE as the initial champion (lean SRE/platform-eng; it's less crowded than CAASM where JupiterOne/Wiz dominate).

---

## 4. Technical Architecture

High-level, event-driven, with a graph at the core and a clear separation between *collection*, *the model*, and *reasoning*.

```
            ┌─────────────────────────────────────────────────────────┐
            │                     Clients / API                         │
            │   Web UI · NL query box · REST/GraphQL · Webhooks         │
            └───────────────┬─────────────────────────┬────────────────┘
                            │                         │
                  ┌─────────▼─────────┐     ┌──────────▼──────────┐
                  │  Query / Reasoning │     │   Auth / Tenancy    │
                  │  - NL→graph query  │     │   - OIDC/SSO        │
                  │  - blast radius    │     │   - RBAC, tenant id │
                  │  - RCA / risk      │     └─────────────────────┘
                  │  - LLM orchestration│
                  └─────────┬──────────┘
                            │ reads
            ┌───────────────▼───────────────────────────────────────────┐
            │                  CORE GRAPH MODEL                          │
            │   Property graph (nodes=CIs, edges=relationships)          │
            │   + bitemporal history  + relational store for raw facts   │
            └───────────────▲───────────────────────────────────────────┘
                            │ writes (upserts via reconciliation)
                  ┌─────────┴──────────┐
                  │  Ingestion /        │
                  │  Reconciliation     │ ← THE HARD PART
                  │  - entity resolution│
                  │  - relationship     │
                  │    inference        │
                  │  - temporal diffing │
                  └─────────▲──────────┘
                            │ normalized events
            ┌───────────────┴───────────────────────────────────────────┐
            │                COLLECTORS / CONNECTORS                      │
            │  AWS · Azure · GCP · K8s · SaaS APIs · DB introspection ·   │
            │  netflow/traces (later) · agents (much later)               │
            └────────────────────────────────────────────────────────────┘
```

**Core principles:**
- **Collectors are dumb; the brain is reconciliation.** Connectors just fetch and normalize to a canonical event schema. All intelligence (dedup, merge, infer) lives in one place.
- **Append-only fact store + derived graph.** Keep raw observations immutably (you'll need them for debugging "why is the graph wrong" and for time-travel). Derive the current graph from facts.
- **Bitemporal from day one.** Track both *valid time* (when the fact was true in the world) and *transaction/observed time* (when you learned it). This is the only way to answer "what changed" and "what did it look like last Tuesday" correctly. Retrofitting this later is agony — bake it in.
- **Everything is tenant-scoped at the lowest layer.** (See §14.)

---

## 5. Recommended Tech Stack

Pragmatic, hireable, and chosen to maximize a solo dev's velocity in Phase 1.

| Concern | MVP choice | Why | Scale-up path |
|---|---|---|---|
| **Language (backend)** | Python (FastAPI) | Best ecosystem for cloud SDKs + LLM tooling; fast to build | Add Go for hot-path collectors/services later |
| **Graph store** | **PostgreSQL + Apache AGE** *or* **Neo4j** | AGE = one database to operate (graph + relational + JSONB facts in Postgres). Neo4j = faster graph DX but another system + licensing/scale caveats | Neo4j/Memgraph cluster, or a purpose-built store, only when scale forces it |
| **Raw fact / time-series** | PostgreSQL (JSONB + partitioned tables) | Don't add Kafka/ClickHouse on day one | Kafka + ClickHouse/Timescale when ingest volume demands |
| **Async / jobs** | Celery or Arq + Redis | Scheduled discovery runs | Temporal for durable workflows (great fit for long discovery jobs) |
| **LLM / reasoning** | Claude API (via the Anthropic API) | NL→query, explanations, RCA narratives; tool-use for structured graph queries | Add retrieval/eval harness, fine-tuned routing |
| **Frontend** | React + TypeScript; graph viz via Cytoscape.js or Sigma.js | Mature graph rendering | WebGL (regraph/ogma) for big graphs |
| **API** | REST + GraphQL (GraphQL fits graph data well) | | gRPC between internal services |
| **Auth** | Auth0/WorkOS (SSO/SCIM) or Keycloak | Don't build auth | — |
| **Infra** | Single cloud (AWS), containers on ECS/Fargate or a small EKS | | EKS + full IaC |
| **IaC** | Terraform from day one | | Terraform + Helm + GitOps (Argo CD) |
| **Observability of *your* product** | OpenTelemetry + Grafana/Datadog free tier | Dogfood it | — |

**Opinion on the graph store debate:** For a solo-dev MVP, **PostgreSQL + Apache AGE** is the lower-operational-risk choice — one system to run, transactional consistency with your raw facts, JSONB for flexible properties, and you can still do graph traversals. Neo4j has nicer graph ergonomics (Cypher, visualization, traversal performance) and is the obvious choice if graph queries are your core loop and you value DX over ops simplicity. **Do not start with a distributed graph DB** (JanusGraph/TigerGraph/Neptune) — premature, and the operational tax will sink a solo founder.

---

## 6. Data Model Design

**Canonical Configuration Item (CI) — the universal node shape:**

```jsonc
{
  "ci_id":        "uuid",            // YOUR stable internal id (survives across scans)
  "tenant_id":    "uuid",            // isolation key, on every row
  "type":         "Host | VM | Container | Pod | Cluster | VPC | Subnet |
                    LoadBalancer | Database | Bucket | IAMRole | User |
                    Application | Service | SaaSApp | NetworkInterface |
                    SecurityGroup | CloudAccount | Region ...",
  "name":         "human label",
  "properties":   { /* type-specific, JSONB */ },
  "source_keys":  [                  // every external identity that maps to this CI
    {"source": "aws", "native_id": "i-0abc...", "arn": "..."},
    {"source": "datadog", "native_id": "host:web-1"},
    {"source": "k8s", "native_id": "pod/uid"}
  ],
  "first_seen":   "ts",
  "last_seen":    "ts",
  "valid_from":   "ts",              // bitemporal
  "valid_to":     "ts | null",
  "confidence":   0.0-1.0            // how sure are we this CI is real/correct
}
```

**Relationship (edge) shape:**

```jsonc
{
  "edge_id":    "uuid",
  "tenant_id":  "uuid",
  "from_ci":    "ci_id",
  "to_ci":      "ci_id",
  "type":       "CONTAINS | RUNS_ON | CONNECTS_TO | DEPENDS_ON | ROUTES_TO |
                 HAS_ACCESS_TO | OWNS | EXPOSES | MEMBER_OF | RESOLVES_TO",
  "directed":   true,
  "source":     "declared | inferred",      // declared (from config) vs inferred (from telemetry)
  "confidence": 0.0-1.0,                     // critical for inferred edges
  "evidence":   [ {"source":"netflow","observed_at":"ts","detail":"..."} ],
  "valid_from": "ts", "valid_to": "ts|null"
}
```

**Three modeling decisions that matter:**
1. **`source_keys` array is the heart of entity resolution.** A CI is the *merge* of everything that resolves to the same real-world thing. (See hardest problem #1.)
2. **`source: declared vs inferred` + `confidence` on every edge.** Inferred dependencies are guesses; never present them as fact. Let users filter by confidence.
3. **Bitemporal columns on everything.** "Closing" a CI/edge = setting `valid_to`, never deleting. History is a first-class citizen.

---

## 7. Graph Database Design

**Node labels** = CI types (above). **Edge types** = relationship types (above).

**Core query patterns to design for:**
- *Inventory:* filter nodes by type/tenant/property.
- *Topology:* 1–2 hop neighborhood of a node.
- *Dependency / blast radius:* transitive closure along `DEPENDS_ON`/`RUNS_ON`/`ROUTES_TO` (bounded-depth traversal, both directions).
- *Path / attack-path:* shortest/all paths between two nodes (e.g., "can the internet reach this database?").
- *Temporal:* "graph as of timestamp T" → filter edges/nodes where `valid_from <= T < valid_to`.

**The supernode problem (plan for it now):** Shared resources — a default VPC, a wildcard IAM role, a central load balancer, a shared DB — accumulate tens of thousands of edges. Naive blast-radius traversal explodes. Mitigations:
- Cap traversal depth and fan-out; return "and N more" rather than expanding fully.
- Weight/rank edges so traversal prioritizes high-confidence, high-relevance paths.
- Detect supernodes (degree > threshold) and treat them specially in UI and queries.

**Time-travel implementation:** Don't store N full snapshots. Store the bitemporal edge/node validity intervals and reconstruct any point in time by filtering. Materialize daily snapshots only if query latency demands it.

**Cypher example (blast radius, conceptual):**
```cypher
MATCH (failed:CI {ci_id: $id, tenant_id: $t})
MATCH path = (failed)<-[:DEPENDS_ON|RUNS_ON|ROUTES_TO*1..4]-(impacted:CI)
WHERE ALL(r IN relationships(path) WHERE r.valid_to IS NULL AND r.confidence > 0.6)
RETURN impacted, length(path) AS distance
ORDER BY distance
```

---

## 8. Infrastructure Discovery Architecture

**Tiered by intrusiveness — start at the least intrusive, which is also the easiest sale:**

| Tier | Method | Gets you | Friction |
|---|---|---|---|
| 0 | **Agentless API discovery** (cloud control planes, SaaS APIs, K8s API, DB introspection) | The bulk of cloud/SaaS/container inventory + declared relationships | Low — read-only creds. *Start here.* |
| 1 | **Telemetry-based inference** (VPC flow logs, CloudTrail, traces, DNS) | Inferred *runtime* dependencies (who talks to whom) | Medium — data access + inference accuracy |
| 2 | **Active probing** (port scans, traceroute) | Network reachability | Medium — security teams nervous |
| 3 | **Agents** (on-host) | Deep host detail, process-level deps | High — deployment, trust, maintenance. *Avoid until enterprise demand forces it.* |

**Connector architecture:**
- A **connector SDK/contract**: each connector implements `discover() -> stream of canonical CI/edge events`. Keep auth, pagination, rate-limit handling inside the connector; emit normalized events only.
- **Incremental + full sync:** support both periodic full reconciliation and event-driven deltas (CloudTrail/EventBridge, K8s watch, webhooks) so freshness doesn't require constant full scans.
- **Rate-limit & cost awareness:** cloud APIs throttle and cost money; backoff, cache, and schedule are first-class concerns.
- **Connector health is a product surface:** show users which sources are stale/erroring. A silently broken connector = silently wrong graph = lost trust.

**Reconciliation pipeline (the real engine):** normalize → match to existing CI via `source_keys` and fuzzy heuristics → merge or create → diff against current graph → emit temporal updates (open/close validity) → recompute affected inferred edges.

---

## 9. Cloud Integration Architecture

- **Read-only, least-privilege, cross-account roles.** AWS: customer deploys an IAM role with a ReadOnly-ish managed policy + external ID; you assume it. Azure: app registration + reader role. GCP: service account with viewer. **Never ask for write access in early product** — it's a much harder security review and you don't need it.
- **Per-account, per-region fan-out** with concurrency control and throttling.
- **Event-driven freshness:** subscribe to CloudTrail/EventBridge (AWS), Activity Log (Azure), Cloud Asset Inventory feeds (GCP), K8s watch API — so changes flow in near-real-time without full re-scans.
- **Normalize to your canonical model** at the connector edge, not downstream. Each cloud's resource taxonomy is different; map them all to your CI types.
- **Credential handling is a Tier-1 security concern** (see §10). Customers are handing you keys to their kingdom's *map*; treat it accordingly.
- **Cost guardrails:** discovery itself incurs API + egress + (if you read flow logs) significant data cost. Make scan frequency configurable and surface its cost.

---

## 10. Security Architecture

For a product that holds a *map of the customer's entire attack surface*, security is the product, not a checkbox. A breach here is company-ending.

- **Tenant isolation is the #1 risk.** A bug that leaks one tenant's graph to another is catastrophic and exactly the kind of thing that ends a security-adjacent startup. Enforce `tenant_id` at the data layer (row-level security in Postgres, or separate graph namespaces), and *test it adversarially* in CI.
- **Least privilege everywhere:** read-only customer creds; scoped service identities internally.
- **Secrets:** never store long-lived customer cloud keys in plaintext; prefer assume-role/OIDC federation over stored keys. Use a vault (AWS Secrets Manager / HashiCorp Vault).
- **Encryption:** TLS in transit; encryption at rest; consider per-tenant encryption keys for the highest-paranoia enterprise buyers.
- **Data residency & retention:** enterprise/EU buyers will require regional data residency and configurable retention. Architect for it (don't hardcode one region).
- **Audit logging:** every query and data access logged immutably — this is also a sellable feature.
- **Compliance roadmap:** SOC 2 Type II is effectively required to sell to anyone serious; start collecting evidence early. ISO 27001 and (for EU) GDPR/DORA alignment follow.
- **The "never act on data, only model it" boundary:** if you later add remediation/write actions, that's a categorically higher trust bar — keep read-only and write-action capabilities strictly separated.

---

## 11. AI Architecture

Be precise about what AI does, because vague "AI-powered" claims here are both a credibility risk and a reliability risk.

**Near-term, high-value, achievable:**
1. **NL → graph query.** User asks "what databases are reachable from the internet?" → LLM (Claude) with tool-use translates to a parameterized graph query against a *constrained* schema, executes it, and explains the result. **Critical:** the LLM generates *structured, validated, parameterized* queries against a known schema — never free-form unvalidated query strings (injection + hallucination risk). Whitelist query templates / use a query-builder DSL the LLM fills in.
2. **Natural-language explanations** of blast radius, change diffs, and risk findings — turning graph output into readable narratives.
3. **Relationship inference** from telemetry (this is ML/heuristics more than LLM): classify whether observed traffic represents a real dependency.
4. **Drift / anomaly detection:** flag unusual changes ("a public IP was just attached to a database").

**Medium-term, hard:**
5. **Root-cause analysis:** correlate recent change events + topology + telemetry to rank likely causes of an incident. Dynatrace's Davis is the bar; this is genuinely hard and easy to get embarrassingly wrong.

**Long-term, aspirational (don't promise early):**
6. **Predictive what-if simulation.** Requires behavioral modeling. Honest framing: until you have it, "what happens if I change X" is answered as *topology-based impact estimation*, not true simulation.

**Reliability discipline:** ground every LLM answer in actual graph query results (retrieval, not recall). Show the underlying data/evidence for every AI claim. Build an eval harness early — hallucinated infrastructure facts during an incident will destroy trust faster than anything.

---

## 12. Monitoring Architecture

Two distinct things — don't conflate them:

**A. Monitoring *your customers'* infrastructure** (to keep the graph fresh & detect change):
- Event-driven change feeds (CloudTrail/EventBridge, K8s watch, webhooks) → near-real-time graph updates.
- Scheduled reconciliation scans to catch drift the event feeds miss.
- **You are not building an APM/metrics platform.** Don't ingest high-cardinality metrics in early phases — integrate with the customer's existing observability (Datadog/Prometheus/CloudWatch) and *link* to it from the graph instead. Competing with Datadog on metrics ingestion is suicide.

**B. Monitoring *your own* platform** (reliability):
- OpenTelemetry tracing, structured logs, RED/USE metrics, SLOs on query latency and discovery freshness.
- **Freshness SLO is your most important internal metric:** "p95 time from real-world change → reflected in graph." Track it religiously; it's your trust proxy.

---

## 13. API Architecture

- **GraphQL for the read/query surface** — it maps naturally to graph data and lets clients fetch exactly the subgraph they need.
- **REST for actions/admin** (connector config, tenant management, exports).
- **NL query endpoint** wrapping the AI layer.
- **Webhooks / event subscriptions** so customers get notified of changes/risks (and so you fit into their workflows — Slack, Jira, PagerDuty).
- **API-first from day one:** your own UI consumes the same public API. This is also how you'll integrate with the tools customers already use (the integration story matters as much as the standalone UI).
- **Versioning + rate limiting + per-tenant quotas** from the start.

---

## 14. Multi-Tenant SaaS Architecture

**Tenancy model — recommended progression:**
- **Phase 1–2 (pooled, row-level isolation):** shared database, `tenant_id` on every row, enforced via Postgres Row-Level Security. Cheapest, simplest. The risk is isolation bugs — mitigate with RLS + adversarial tests.
- **Phase 3 (pooled + isolated tiers):** offer dedicated DB/namespace for enterprise tenants who require it; keep SMB pooled.
- **Phase 4 (cell-based / per-region):** shard tenants across "cells" for blast-radius containment, noisy-neighbor isolation, and data residency.

**Hard tenancy issues specific to a graph product:**
- **Graph isolation:** if using Neo4j, separate databases per tenant (Neo4j 4+) or strict label/property scoping; if Postgres+AGE, RLS + per-tenant graph names.
- **Noisy neighbor:** a tenant with 2M nodes can starve others. Need per-tenant resource quotas on discovery + query.
- **Per-tenant connector scheduling & cost attribution.**

---

## 15. Scalability Considerations

**Where it actually gets hard, in order of when you'll hit it:**
1. **Ingest volume** before graph size — flow logs and event feeds are firehoses. ClickHouse/Kafka for raw, derive graph asynchronously.
2. **Graph size:** a large enterprise = 10⁷–10⁹ nodes/edges across history. Single-instance graph DBs strain here. Mitigations: drop/aggregate low-value history, partition by tenant/cell, materialize hot subgraphs.
3. **Traversal cost:** bounded-depth, supernode handling (§7), pre-computed blast-radius for critical CIs.
4. **Reconciliation throughput:** entity resolution is O(messy); make it incremental and parallelizable per tenant.
5. **Query concurrency:** read replicas; cache common queries; rate limit.

**Principle:** scale the *raw fact ingestion* path horizontally and keep the *graph* as small and fresh as correctness allows. History is the thing that secretly blows up your storage and traversal cost — have a retention/aggregation strategy.

---

## 16. Cost Estimates

Rough, order-of-magnitude, for planning (not a budget):

**Phase 1 (solo, 3 months):**
- Cloud infra (small): **$150–400/mo** (one Postgres, a couple of containers, Redis).
- LLM API usage (dev + light demo): **$100–500/mo** depending on query volume.
- Auth (Auth0/WorkOS free→starter): **$0–150/mo**.
- Domain, misc SaaS, monitoring free tiers: **~$100/mo**.
- **Total infra: ~$500–1,000/mo.** Dominant cost is *your time/salary*, not infra.

**Phase 2 (beta, first customers):**
- Infra scales with data: **$1–5K/mo** (more compute, flow-log/event processing, ClickHouse).
- LLM: **$500–3K/mo**.
- SOC 2 prep (auditor + tooling like Vanta/Drata): **$15–40K one-time + annual**.
- Small team (2–4): the real cost.

**Phase 3 (production SaaS):**
- Infra: **$10–50K/mo+**, highly dependent on data volume per customer (flow logs are the cost bomb — meter and pass through).
- **Watch the unit economics:** discovery + LLM cost per tenant must be well below their subscription price. Per-tenant cost attribution (§14) is how you avoid waking up to a margin disaster.

**Phase 4 (enterprise):** dedicated/cell infra, dominated by data residency + scale; price enterprise deals to cover dedicated capacity.

**The cost trap:** LLM calls and flow-log ingestion are variable costs that scale with usage. If you price flat-rate and a customer hammers NL queries or has huge traffic, you lose money per query. Architect cost metering and quotas *before* you have the problem.

---

## 17. Development Phases

### Phase 1 — Smallest Possible MVP (1 dev, 3 months)

**Goal:** Prove that a fresh, trustworthy graph of *one cloud* + a natural-language query box delivers a "wow" in a live demo and a real engineer says "I'd use this."

**Scope discipline — what's IN:**
- **One cloud: AWS.** Agentless, read-only, assume-role discovery of a focused resource set (EC2, VPC/subnet/SG, ELB, RDS, S3, IAM roles/users, EKS basics).
- Canonical CI + edge model with **bitemporal columns** (don't skip this).
- Postgres + Apache AGE (single DB) — or Neo4j if you prefer graph DX.
- Reconciliation v1 (within-AWS dedup; declared relationships only).
- **NL → graph query** via Claude with validated/templated queries.
- Blast-radius (impact) traversal for a CI.
- "What changed in the last 7 days" from temporal diffs.
- Minimal React UI: graph viz (Cytoscape) + NL query box + change feed.
- Single-tenant (or trivially scoped) — real multi-tenancy is Phase 2.

**What's explicitly OUT (resist these):** multi-cloud, agents, flow-log/trace-based inference, RCA, simulation, real-time metrics, full multi-tenant SaaS, billing, on-prem.

**Technologies:** Python/FastAPI, Postgres+AGE (or Neo4j), Celery+Redis, React+TS+Cytoscape, Claude API, Terraform, single AWS account.

**Deliverables:** deployed demo; AWS read-only onboarding flow; the four core questions answered (have / connected / depends-on / blast-radius) + change history; NL query working on real data.

**Risks:**
- *Scope creep* (the killer — you will be tempted to add a second cloud). 
- NL→query reliability (mitigate with templates + evals).
- Reconciliation harder than expected even within one cloud.
- Building infra before talking to a design partner.

**Effort:** ~3 months solo *if* scope holds. The single biggest determinant of success is saying no to features. Line up **one design partner before you write code.**

---

### Phase 2 — Beta Platform / First Customers

**Goal:** 3–10 paying or committed design-partner customers; prove freshness and trust at small scale; find the wedge that converts.

**Features:** real **multi-tenancy** (RLS, tenant onboarding, SSO); **second cloud** (Azure or GCP) *only if customers demand it*; **telemetry-based dependency inference** (VPC flow logs / traces) with confidence scoring; connector health dashboard; event-driven freshness (CloudTrail/EventBridge); risk findings v1 (e.g., internet-reachable databases, overly-permissive roles); Slack/Jira notifications; basic RBAC; usage metering.

**Technologies:** add Temporal (durable discovery workflows), ClickHouse/Kafka if flow-log volume requires, WorkOS/Auth0 for SSO/SCIM, Vanta/Drata to start SOC 2.

**Deliverables:** multi-tenant beta; 2-cloud discovery; inferred dependencies with confidence; first risk findings; SOC 2 in progress; design-partner case studies.

**Risks:** connector treadmill begins in earnest; inference false positives erode trust; the "no clear buyer" problem becomes real — *use beta to pick the wedge decisively*; isolation bugs.

**Effort:** ~6–9 months, team of 2–4.

---

### Phase 3 — Production SaaS

**Goal:** Repeatable self-serve-ish sales motion; reliable at scale; SOC 2 Type II done; positive unit economics.

**Features:** full connector catalog for the chosen wedge (cloud + key SaaS + K8s + DBs); robust reconciliation & entity resolution; RCA v1; mature NL reasoning + eval harness; per-tenant cost attribution & quotas; data residency options; SLA/SLOs; admin/audit; billing.

**Technologies:** EKS + GitOps (Argo CD), Helm, full Terraform IaC, read replicas/caching, observability stack, cell/region readiness.

**Deliverables:** GA product; SOC 2 Type II; documented SLAs; pricing with healthy margins; reference customers.

**Risks:** scaling graph + history; LLM/flow-log cost blowout; incumbents shipping "good enough" versions of your wedge; support burden from connector breakage.

**Effort:** ~9–18 months, team of ~8–20.

---

### Phase 4 — Enterprise Platform

**Goal:** Land large enterprises; cross-domain coverage; the "digital twin" reasoning/simulation narrative starts delivering.

**Features:** on-prem/agent discovery (only now), hybrid/multi-cloud at scale, advanced RCA, predictive what-if (topology → behavioral), full compliance (ISO 27001, FedRAMP path if relevant), SSO/SCIM/SAML, data residency per region, private/cell deployments, professional services.

**Technologies:** cell-based architecture, dedicated tenant infra, advanced graph scaling, possibly per-tenant encryption keys.

**Deliverables:** enterprise contracts; cross-domain twin; simulation capability (honestly scoped); full compliance posture.

**Risks:** enterprise sales cycle & services drag; simulation over-promised; competing with ServiceNow/Google-Wiz on their turf; complexity collapse.

**Effort:** multi-year, 20+ team.

---

## 18. Database Schemas (relational core)

```sql
-- Tenancy
CREATE TABLE tenants (
  tenant_id    UUID PRIMARY KEY,
  name         TEXT NOT NULL,
  created_at   TIMESTAMPTZ DEFAULT now()
);

-- Configuration Items (current + historical via valid_to)
CREATE TABLE cis (
  ci_id        UUID DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants,
  type         TEXT NOT NULL,
  name         TEXT,
  properties   JSONB NOT NULL DEFAULT '{}',
  confidence   REAL DEFAULT 1.0,
  first_seen   TIMESTAMPTZ NOT NULL,
  last_seen    TIMESTAMPTZ NOT NULL,
  valid_from   TIMESTAMPTZ NOT NULL,
  valid_to     TIMESTAMPTZ,                 -- NULL = current
  PRIMARY KEY (ci_id, valid_from)
);
CREATE INDEX ON cis (tenant_id, type) WHERE valid_to IS NULL;
CREATE INDEX ON cis USING GIN (properties);

-- Mapping of external source identities -> internal CI (entity resolution)
CREATE TABLE source_keys (
  tenant_id   UUID NOT NULL,
  source      TEXT NOT NULL,               -- aws, azure, k8s, datadog...
  native_id   TEXT NOT NULL,               -- arn / resource id / host key
  ci_id       UUID NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, source, native_id)
);

-- Relationships
CREATE TABLE edges (
  edge_id     UUID DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL,
  from_ci     UUID NOT NULL,
  to_ci       UUID NOT NULL,
  type        TEXT NOT NULL,
  source      TEXT NOT NULL,               -- 'declared' | 'inferred'
  confidence  REAL DEFAULT 1.0,
  evidence    JSONB DEFAULT '[]',
  valid_from  TIMESTAMPTZ NOT NULL,
  valid_to    TIMESTAMPTZ,
  PRIMARY KEY (edge_id, valid_from)
);
CREATE INDEX ON edges (tenant_id, from_ci) WHERE valid_to IS NULL;
CREATE INDEX ON edges (tenant_id, to_ci)   WHERE valid_to IS NULL;

-- Immutable raw observations (audit + debugging + replay)
CREATE TABLE raw_facts (
  fact_id     BIGSERIAL PRIMARY KEY,
  tenant_id   UUID NOT NULL,
  source      TEXT NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL,
  payload     JSONB NOT NULL
) PARTITION BY RANGE (observed_at);

-- Connector run health
CREATE TABLE connector_runs (
  run_id      UUID PRIMARY KEY,
  tenant_id   UUID NOT NULL,
  source      TEXT NOT NULL,
  status      TEXT NOT NULL,               -- ok | error | partial
  started_at  TIMESTAMPTZ, finished_at TIMESTAMPTZ,
  error       TEXT
);

-- Row-level security (tenant isolation)
ALTER TABLE cis        ENABLE ROW LEVEL SECURITY;
ALTER TABLE edges      ENABLE ROW LEVEL SECURITY;
-- ... + policies keying on current_setting('app.tenant_id')
```

---

## 19. Graph Schemas

**Node labels (with key properties):**
- `CloudAccount`, `Region`, `VPC`, `Subnet`, `SecurityGroup`
- `Host`, `VM`, `Container`, `Pod`, `Cluster`, `NetworkInterface`
- `LoadBalancer`, `Database`, `Bucket`, `IAMRole`, `User`, `Group`
- `Application`, `Service`, `SaaSApp`

**Edge types (directionality matters):**
- `CONTAINS` (Account→VPC→Subnet→Host)
- `RUNS_ON` (Container→Pod→Host)
- `CONNECTS_TO` / `ROUTES_TO` (network reachability/flow)
- `DEPENDS_ON` (service→database) — often *inferred*
- `HAS_ACCESS_TO` (IAMRole→Bucket) — for attack-path queries
- `EXPOSES` (LoadBalancer→Service), `RESOLVES_TO` (DNS→IP), `MEMBER_OF`, `OWNS`

**Every edge carries:** `source` (declared/inferred), `confidence`, `valid_from/valid_to`, `evidence`.

**Indexing/constraints:** unique on `(tenant_id, ci_id)`; index labels + tenant; for Neo4j use composite indexes on `(tenant_id, type)`; for AGE rely on the relational indexes above.

---

## 20. Service Boundaries & Microservice Recommendations

**Start as a modular monolith, not microservices.** A solo dev building microservices in Phase 1 is a self-inflicted wound. Define *internal module boundaries* now so you can split later:

| Module / (future) service | Responsibility |
|---|---|
| `collectors` | Per-source discovery; emit canonical events. *First to extract into separate services* (different scaling, different failure modes). |
| `reconciliation` | Entity resolution, merge, temporal diffing. The brain. |
| `graph` | Graph storage + traversal API. |
| `query` | GraphQL/REST + blast-radius/path algorithms. |
| `reasoning` | LLM orchestration, NL→query, explanations, RCA. |
| `tenancy/auth` | Tenants, RBAC, SSO, quotas. |
| `notifications` | Webhooks, Slack/Jira/PagerDuty. |
| `web` | Frontend BFF. |

**Extraction order when you scale:** collectors → reasoning (LLM cost/latency isolation) → reconciliation → the rest. Don't split before pain demands it.

---

## 21. Repository Structure / Monorepo Layout

**Recommendation: monorepo** (Turborepo or Nx for JS + a Python workspace, or just a well-structured polyglot monorepo). For a small team it maximizes refactor velocity and shared types.

```
infra-twin/
├── apps/
│   ├── api/                 # FastAPI app (query, auth, BFF)
│   └── web/                 # React + TS frontend
├── services/
│   ├── collectors/          # per-source connectors (aws/, azure/, k8s/...)
│   ├── reconciliation/      # entity resolution + temporal diffing
│   └── reasoning/           # LLM orchestration
├── packages/
│   ├── core-model/          # canonical CI/edge schemas (single source of truth)
│   ├── graph-client/        # graph store access layer
│   ├── connector-sdk/       # the connector contract
│   └── shared-types/        # generated TS/Python types from core-model
├── infra/
│   ├── terraform/           # IaC
│   └── helm/                # k8s charts (Phase 3+)
├── migrations/              # DB migrations
├── docs/
└── .github/workflows/       # CI/CD
```

**Key discipline:** `core-model` is the canonical schema; generate language-specific types from it so the connector SDK, API, and frontend never drift.

---

## 22. CI/CD Design

- **CI on every PR:** lint, type-check, unit tests, **tenant-isolation tests** (adversarial — prove tenant A can't read tenant B), connector contract tests (against recorded API fixtures), schema-migration check, LLM eval suite (NL→query accuracy gate).
- **Build:** containerize each app/service; tag by git SHA.
- **CD:** trunk-based, deploy-on-merge to staging; manual promote to prod (Phase 1–2) → progressive/canary (Phase 3+).
- **Migrations:** expand-contract pattern (never break the running schema); migrations gated in CI.
- **Secrets:** never in repo; OIDC from CI to cloud (no long-lived keys in CI).
- **Tooling:** GitHub Actions early; Argo CD / GitOps once on Kubernetes.

---

## 23. Infrastructure-as-Code Design

- **Terraform for all cloud infra**, in `infra/terraform`, split by environment (state per env, remote backend, locking).
- **Two distinct IaC concerns — keep them separate:**
  1. *Your platform's* infra (your VPC, DB, compute).
  2. *Customer onboarding* infra — the read-only IAM role/policy a customer deploys to grant you access. Ship this as a **one-click CloudFormation StackSet / Terraform module** customers run in their account. This onboarding artifact is a real product surface; make it trivial and auditable.
- **Helm** for app deployment (Phase 3+); **GitOps** (Argo CD) so the deployed state = git state.
- **Policy as code** (OPA/Conftest) to enforce least-privilege and tagging on your own infra.

---

## 24. The Hardest Technical Problems (and how to attack them)

Ranked by how likely they are to sink you.

**1. Entity resolution / reconciliation (THE one).**
*Problem:* the same real host appears as an EC2 instance (AWS), a host in Datadog, a node in K8s, a row in the CMDB — with different IDs. Merging them correctly, and *not* over-merging distinct things, is the core data problem. Wrong merges = a wrong graph = lost trust.
*Approach:* deterministic matching first (cloud ARNs, instance IDs, MAC, private IP+time, hostnames) via the `source_keys` table; probabilistic/fuzzy matching with **confidence scores** for the ambiguous tail; keep merges *reversible* (store provenance so you can un-merge); surface low-confidence merges for human review in early phases; never silently over-merge. This is a permanent investment, not a one-time build.

**2. Data freshness vs. cost.**
*Problem:* polling everything constantly is expensive and rate-limited; polling rarely makes the graph stale and untrusted.
*Approach:* hybrid — event-driven deltas (CloudTrail/EventBridge, K8s watch, webhooks) for near-real-time, plus periodic full reconciliation to catch what events miss. Track and publish a **freshness SLO** per source. Make scan frequency (and its cost) configurable.

**3. Dependency inference accuracy.**
*Problem:* real dependencies aren't declared; you infer them from flow logs/traces/DNS, which is noisy. False positives clutter; false negatives miss the thing that breaks.
*Approach:* never present inferred edges as fact — always with `confidence` and `evidence`; let users filter by confidence; combine multiple signals (flow + DNS + config) before asserting; let users confirm/reject to improve the model. Start with declared relationships (high trust) and layer inference on carefully.

**4. The supernode problem.**
*Problem:* shared resources with huge fan-out blow up traversals and visualizations.
*Approach:* degree thresholds, bounded-depth + bounded-fan-out traversal, edge ranking, "and N more" summarization, special UI treatment. (Detailed in §7.)

**5. Bitemporal modeling at scale.**
*Problem:* "what changed" and "what did it look like at time T" require keeping history without exploding storage/traversal cost.
*Approach:* validity intervals on nodes/edges (not full snapshots); reconstruct points in time by filtering; aggregate/expire old low-value history; materialize daily snapshots only if latency forces it.

**6. Predictive "what-if" simulation.**
*Problem:* genuine simulation needs a behavioral model, not just topology — the holy grail and the most over-promised capability in this space.
*Approach:* be honest. Ship *topology-based impact estimation* ("these N services depend on X with this confidence") and call it that, not "simulation." Pursue true behavioral simulation only with real telemetry and only at Phase 4, scoped narrowly (e.g., capacity/blast-radius for a specific change class), never as a blanket promise.

**7. Multi-tenant graph isolation.**
*Problem:* a single isolation bug leaking one customer's infra map to another is company-ending for a security-adjacent product.
*Approach:* `tenant_id` enforced at the storage layer (RLS / separate graph DBs); adversarial isolation tests in CI; per-tenant resource quotas; consider cell-based isolation for enterprise. Treat this as a security-critical invariant, not a feature.

**8. NL→query reliability (LLM hallucination).**
*Problem:* an LLM inventing infrastructure facts during an incident destroys trust instantly.
*Approach:* constrained/templated/validated query generation (no free-form query strings); ground every answer in actual query results; show the evidence; an eval harness gating accuracy in CI; confidence/uncertainty surfaced to the user.

**9. The connector treadmill (organizational, not algorithmic — but it kills companies).**
*Problem:* every connector breaks when a vendor changes their API; coverage is never "done"; maintenance grows linearly with integrations.
*Approach:* a strict connector SDK/contract; recorded-fixture contract tests that catch breakage; connector health as a user-facing surface; ruthless prioritization of which integrations to build (follow the wedge, not the long tail); treat connector maintenance as permanent staffed work.

---

## 25. Where Startups in This Space Actually Fail (assumptions challenged)

- **They build the platform before the wedge.** "Discover everything for everyone" has no buyer. The graveyard is full of horizontal infra-visibility startups with beautiful graphs and no champion. *Pick one buyer, one wedge, one demo that makes them say "shut up and take my money."*
- **They underestimate the connector treadmill** and entity resolution, treating discovery as a solved 3-month problem. It's a permanent cost center.
- **They let the graph go stale** and lose trust on the first wrong answer during an incident. Freshness/correctness is existential.
- **They over-invest in AI/simulation early** to chase the vision deck, while the boring discovery+reconciliation foundation is shaky. The foundation *is* the product; AI is the interface.
- **They compete head-on with incumbents.** Trying to out-CMDB ServiceNow, out-observe Datadog, or out-graph Wiz/Google is a losing fight. Win where they're weak (cross-domain, low-friction, NL-native, mid-market).
- **They confuse "single source of truth" ambition with product.** Boiling the ocean = never shipping value. Truth in *one domain*, trusted, beats a half-accurate map of everything.
- **They mispr­ice variable costs** (LLM + flow logs) under flat plans and bleed margin per power user.
- **They treat "AI-powered" as positioning rather than reliability engineering**, and the first hallucinated infra fact ends the customer relationship.

**The single most important thing:** get one design partner *before* writing code, build the smallest thing that answers their real question with data they trust, and resist every temptation to broaden until that loop is tight.

---

*End of document. The roadmap is deliberately conservative on the "digital twin / simulation" promise and aggressive on data trust, because that's the order reality rewards in this space.*
---

## Changelog

- 2026-06-22: Split the §22/§23 "Platform CI/CD + IaC" scope item into two sequenced slices
  without removing any capability: (31a) the GitHub Actions CI pipeline that runs the plan's
  §22 gates (lint/type where configured, the full pytest invariant suite — adversarial
  tenant-isolation, connector contract, NL→query eval accuracy, migration check — against a
  real Postgres+AGE service container on every PR), and (31b) platform-deploy IaC +
  containerization (Dockerfiles per app/service tagged by git SHA, Terraform for the platform's
  own infra). Rationale: both halves were lumped together but have different shapes; CI is a
  thin, fully-testable vertical slice and a prerequisite for trustworthy CD, so it ships first.
  Customer-onboarding IaC (§23 concern #2) was already shipped earlier and is unaffected. No
  core capability removed — only added detail and re-sequenced for dependency order.
