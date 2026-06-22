"""NL→query: templated/validated compilation and execution (offline, no API calls)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from infra_twin.api import create_app
from infra_twin.api.nlquery import answer_question
from infra_twin.api.nlquery.planner import ClaudePlanner, QueryPlan
from infra_twin.api.nlquery.templates import REGISTRY, ReachabilityParams
from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import reconcile

CI_SCOPE = frozenset({CIType.vpc, CIType.subnet})
EDGE_SCOPE = frozenset({EdgeType.CONTAINS})

# Scope for reachability-specific seeding
_REACH_CI_SCOPE = frozenset({
    CIType.internet,
    CIType.security_group,
    CIType.ec2_instance,
})
_REACH_EDGE_SCOPE = frozenset({
    EdgeType.CONNECTS_TO,
    EdgeType.EXPOSES,
})


class FakePlanner:
    """Returns a preset plan — stands in for the LLM so tests stay offline."""

    def __init__(self, plan: QueryPlan | None):
        self._plan = plan

    def plan(self, question: str) -> QueryPlan | None:
        return self._plan


def _seed(pool, tenant):
    events = [
        DiscoveredCI(type=CIType.vpc, external_id="vpc-1", name="net"),
        DiscoveredCI(type=CIType.subnet, external_id="sub-1", name="a"),
        DiscoveredEdge(
            type=EdgeType.CONTAINS,
            from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
            to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
            evidence=[Evidence(source="test")],
        ),
    ]
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant, events, source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE
        )


def _ask(pool, tenant, plan):
    with tenant_session(pool, tenant) as conn:
        return answer_question(conn, tenant, "q", FakePlanner(plan))


def test_inventory_template(pool, make_tenant):
    tenant = make_tenant()
    _seed(pool, tenant)
    answer = _ask(pool, tenant, QueryPlan("inventory", {"type": "vpc"}))
    assert answer.answered and answer.template == "inventory"
    assert [c["external_id"] for c in answer.data["cis"]] == ["vpc-1"]
    assert answer.summary == "Found 1 configuration item of type vpc."


def test_count_by_type_template(pool, make_tenant):
    tenant = make_tenant()
    _seed(pool, tenant)
    answer = _ask(pool, tenant, QueryPlan("count_by_type", {}))
    assert answer.data["counts"] == {"vpc": 1, "subnet": 1}


def test_blast_radius_template(pool, make_tenant):
    tenant = make_tenant()
    _seed(pool, tenant)
    answer = _ask(pool, tenant, QueryPlan("blast_radius", {"external_id": "vpc-1"}))
    assert answer.answered
    assert any(i["type"] == "subnet" for i in answer.data["impacted"])


def test_blast_radius_unknown_resource(pool, make_tenant):
    tenant = make_tenant()
    answer = _ask(pool, tenant, QueryPlan("blast_radius", {"external_id": "nope"}))
    assert answer.answered and answer.data["found"] is False


def test_recent_changes_template(pool, make_tenant):
    tenant = make_tenant()
    _seed(pool, tenant)
    answer = _ask(pool, tenant, QueryPlan("recent_changes", {"days": 7}))
    assert answer.answered and len(answer.data["events"]) >= 1


def test_unsupported_plan_declines(pool, make_tenant):
    tenant = make_tenant()
    answer = _ask(pool, tenant, QueryPlan("unsupported", {}))
    assert answer.answered is False
    assert answer.summary == "I can't answer that with the available queries."


def test_no_plan_declines(pool, make_tenant):
    tenant = make_tenant()
    answer = _ask(pool, tenant, None)
    assert answer.answered is False


def test_invalid_args_decline(pool, make_tenant):
    tenant = make_tenant()
    # blast_radius requires external_id; omitting it must not execute anything.
    answer = _ask(pool, tenant, QueryPlan("blast_radius", {}))
    assert answer.answered is False and answer.template == "blast_radius"


def test_nlquery_is_tenant_scoped(pool, make_tenant):
    a, b = make_tenant("A"), make_tenant("B")
    _seed(pool, a)
    answer = _ask(pool, b, QueryPlan("inventory", {}))
    assert answer.data["cis"] == []


# -- ClaudePlanner parsing (mocked Anthropic client, no network) ------------------

def _fake_client(blocks):
    messages = SimpleNamespace(calls=[])

    def create(**kwargs):
        messages.calls.append(kwargs)
        return SimpleNamespace(content=blocks)

    messages.create = create
    return SimpleNamespace(messages=messages)


def test_claude_planner_parses_tool_use():
    block = SimpleNamespace(type="tool_use", name="inventory", input={"type": "ec2_instance"})
    client = _fake_client([block])
    planner = ClaudePlanner(client=client, model="claude-sonnet-4-6")

    plan = planner.plan("what ec2 instances do I have?")
    assert plan == QueryPlan("inventory", {"type": "ec2_instance"})

    kwargs = client.messages.calls[0]
    assert kwargs["tool_choice"] == {"type": "any"}  # forced templated selection
    names = {t["name"] for t in kwargs["tools"]}
    assert {"inventory", "blast_radius", "unsupported"} <= names


def test_claude_planner_returns_none_without_tool_use():
    block = SimpleNamespace(type="text", text="hello")
    planner = ClaudePlanner(client=_fake_client([block]))
    assert planner.plan("hi") is None


# -- /ask endpoint ----------------------------------------------------------------

def test_ask_endpoint_with_injected_planner(pool, make_tenant_with_key):
    tenant, api_key = make_tenant_with_key()
    _seed(pool, tenant)
    planner = FakePlanner(QueryPlan("inventory", {"type": "vpc"}))
    client = TestClient(create_app(pool=pool, planner=planner))

    resp = client.post(
        "/ask", json={"question": "list vpcs"}, headers={"Authorization": f"Bearer {api_key}"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["answered"] is True
    assert body["template"] == "inventory"
    assert [c["external_id"] for c in body["data"]["cis"]] == ["vpc-1"]


def test_ask_endpoint_503_without_api_key(pool, make_tenant_with_key, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _, api_key = make_tenant_with_key()
    client = TestClient(create_app(pool=pool))  # no planner injected, no key
    resp = client.post(
        "/ask", json={"question": "list vpcs"}, headers={"Authorization": f"Bearer {api_key}"}
    )
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Reachability NL template: registration / validation (AC 11, 12, 20)
# ---------------------------------------------------------------------------

def test_reachability_template_registered_in_registry():
    """AC 12: REGISTRY contains key 'reachability'."""
    assert "reachability" in REGISTRY


def test_reachability_template_params_model():
    """AC 12: REGISTRY['reachability'].params_model is ReachabilityParams."""
    assert REGISTRY["reachability"].params_model is ReachabilityParams


def test_reachability_template_has_handler_and_summarize():
    """AC 12: template has handler and summarize callables."""
    tmpl = REGISTRY["reachability"]
    assert callable(tmpl.handler)
    assert callable(tmpl.summarize)


def test_reachability_params_model_valid_input():
    """AC 11: ReachabilityParams validates good input."""
    params = ReachabilityParams(external_id="i-12345", max_depth=4, internet_only=True)
    assert params.external_id == "i-12345"
    assert params.max_depth == 4
    assert params.internet_only is True


def test_reachability_params_model_defaults():
    """AC 11: ReachabilityParams has correct defaults: max_depth=6, internet_only=False."""
    params = ReachabilityParams(external_id="sg-abc")
    assert params.max_depth == 6
    assert params.internet_only is False


def test_reachability_params_missing_external_id_raises():
    """AC 11 / AC 20a: missing external_id raises ValidationError."""
    with pytest.raises(ValidationError):
        ReachabilityParams()


def test_reachability_params_max_depth_below_minimum_raises():
    """AC 11 / AC 20a: max_depth < 1 raises ValidationError (ge=1)."""
    with pytest.raises(ValidationError):
        ReachabilityParams(external_id="i-1", max_depth=0)


def test_reachability_params_max_depth_above_maximum_raises():
    """AC 11 / AC 20a: max_depth > 10 raises ValidationError (le=10)."""
    with pytest.raises(ValidationError):
        ReachabilityParams(external_id="i-1", max_depth=11)


def test_reachability_params_max_depth_boundaries_valid():
    """AC 11: max_depth=1 and max_depth=10 are both valid (boundary values)."""
    p1 = ReachabilityParams(external_id="i-1", max_depth=1)
    p10 = ReachabilityParams(external_id="i-1", max_depth=10)
    assert p1.max_depth == 1
    assert p10.max_depth == 10


def test_claude_planner_tools_include_reachability():
    """AC 20b: ClaudePlanner._tools() tool-name set includes 'reachability'."""
    planner = ClaudePlanner(client=_fake_client([]), model="claude-sonnet-4-6")
    names = {t["name"] for t in planner._tools()}
    assert "reachability" in names


def test_reachability_invalid_args_decline(pool, make_tenant):
    """AC 20a: QueryPlan('reachability', {}) (missing external_id) yields answered=False, template='reachability'."""
    tenant = make_tenant()
    answer = _ask(pool, tenant, QueryPlan("reachability", {}))
    assert answer.answered is False
    assert answer.template == "reachability"


# ---------------------------------------------------------------------------
# Reachability NL template: happy path (AC 19)
# ---------------------------------------------------------------------------

def _seed_reachability(pool, tenant):
    """Seed internet -CONNECTS_TO-> sg-1 -EXPOSES-> i-target for reachability NL tests."""
    events = [
        DiscoveredCI(type=CIType.internet, external_id="internet", name="Internet (0.0.0.0/0, ::/0)"),
        DiscoveredCI(type=CIType.security_group, external_id="sg-reach-1", name="sg-reach-1"),
        DiscoveredCI(type=CIType.ec2_instance, external_id="i-reach-target", name="i-reach-target"),
        DiscoveredEdge(
            type=EdgeType.CONNECTS_TO,
            from_ref=CIRef(type=CIType.internet, external_id="internet"),
            to_ref=CIRef(type=CIType.security_group, external_id="sg-reach-1"),
            evidence=[Evidence(source="aws", detail="sg sg-reach-1 allows tcp/443 from 0.0.0.0/0")],
        ),
        DiscoveredEdge(
            type=EdgeType.EXPOSES,
            from_ref=CIRef(type=CIType.security_group, external_id="sg-reach-1"),
            to_ref=CIRef(type=CIType.ec2_instance, external_id="i-reach-target"),
            evidence=[Evidence(source="aws", detail="sg-reach-1 exposes i-reach-target")],
        ),
    ]
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant, events,
            source="test",
            ci_types=_REACH_CI_SCOPE,
            edge_types=_REACH_EDGE_SCOPE,
        )


def test_reachability_template_happy_path(pool, make_tenant):
    """AC 19: reachability template with internet-exposed target returns answered=True, reached_by_internet=True."""
    tenant = make_tenant()
    _seed_reachability(pool, tenant)
    answer = _ask(
        pool, tenant,
        QueryPlan("reachability", {"external_id": "i-reach-target"}),
    )
    assert answer.answered is True
    assert answer.template == "reachability"
    assert answer.data["found"] is True
    assert answer.data["reached_by_internet"] is True
    internet_sources = [s for s in answer.data["sources"] if s["is_internet"]]
    assert len(internet_sources) >= 1, "at least one internet source expected"


def test_reachability_template_path_hop_types(pool, make_tenant):
    """AC 19: internet source path contains CONNECTS_TO and EXPOSES hop edge types."""
    tenant = make_tenant()
    _seed_reachability(pool, tenant)
    answer = _ask(
        pool, tenant,
        QueryPlan("reachability", {"external_id": "i-reach-target"}),
    )
    assert answer.answered is True
    internet_src = next(s for s in answer.data["sources"] if s["is_internet"])
    hop_types = {h["edge_type"] for h in internet_src["path"]}
    assert "CONNECTS_TO" in hop_types
    assert "EXPOSES" in hop_types


def test_reachability_template_unknown_resource(pool, make_tenant):
    """AC 13: _reachability returns found=False when external_id resolves to no current CI."""
    tenant = make_tenant()
    answer = _ask(
        pool, tenant,
        QueryPlan("reachability", {"external_id": "i-does-not-exist"}),
    )
    assert answer.answered is True
    assert answer.data["found"] is False
    assert answer.data["reached_by_internet"] is False
    assert answer.data["sources"] == []


def test_reachability_template_summary_found(pool, make_tenant):
    """§4 NL handler: summary for found resource counts sources."""
    tenant = make_tenant()
    _seed_reachability(pool, tenant)
    answer = _ask(
        pool, tenant,
        QueryPlan("reachability", {"external_id": "i-reach-target"}),
    )
    assert answer.answered is True
    n = len(answer.data["sources"])
    assert f"{n} source" in answer.summary


def test_reachability_template_summary_not_found(pool, make_tenant):
    """§4 NL handler: summary for not-found resource."""
    tenant = make_tenant()
    answer = _ask(
        pool, tenant,
        QueryPlan("reachability", {"external_id": "no-such-resource"}),
    )
    assert "no-such-resource" in answer.summary.lower() or "no configuration item" in answer.summary.lower()


def test_reachability_template_internet_only_filter(pool, make_tenant):
    """§4 NL handler: internet_only=True filters sources to only internet ones."""
    tenant = make_tenant()
    _seed_reachability(pool, tenant)
    answer = _ask(
        pool, tenant,
        QueryPlan("reachability", {"external_id": "i-reach-target", "internet_only": True}),
    )
    assert answer.answered is True
    assert answer.data["internet_only"] is True
    # Only internet sources in response (or empty if no internet path)
    for src in answer.data["sources"]:
        assert src["is_internet"] is True


def test_reachability_template_internet_only_summary_can_reach(pool, make_tenant):
    """§4 NL handler: internet_only=True + reached_by_internet=True -> 'can reach' summary."""
    tenant = make_tenant()
    _seed_reachability(pool, tenant)
    answer = _ask(
        pool, tenant,
        QueryPlan("reachability", {"external_id": "i-reach-target", "internet_only": True}),
    )
    assert answer.answered is True
    assert answer.data["reached_by_internet"] is True
    assert "can reach" in answer.summary


def test_reachability_template_internet_only_summary_cannot_reach(pool, make_tenant):
    """§4 NL handler: internet_only=True + no internet path -> 'cannot reach' summary."""
    tenant = make_tenant()
    # Seed: sg reaches instance but no internet CI
    events = [
        DiscoveredCI(type=CIType.security_group, external_id="sg-nointernet", name="sg-nointernet"),
        DiscoveredCI(type=CIType.ec2_instance, external_id="i-nointernet", name="i-nointernet"),
        DiscoveredEdge(
            type=EdgeType.CONNECTS_TO,
            from_ref=CIRef(type=CIType.security_group, external_id="sg-nointernet"),
            to_ref=CIRef(type=CIType.ec2_instance, external_id="i-nointernet"),
            evidence=[Evidence(source="aws", detail="internal rule")],
        ),
    ]
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant, events,
            source="test",
            ci_types=_REACH_CI_SCOPE,
            edge_types=_REACH_EDGE_SCOPE,
        )
    answer = _ask(
        pool, tenant,
        QueryPlan("reachability", {"external_id": "i-nointernet", "internet_only": True}),
    )
    assert answer.answered is True
    assert answer.data["reached_by_internet"] is False
    assert "cannot reach" in answer.summary


def test_reachability_template_tenant_scoped(pool, make_tenant):
    """NL reachability template: tenant B cannot see tenant A's internet-exposed resource."""
    tenant_a = make_tenant("A")
    tenant_b = make_tenant("B")
    _seed_reachability(pool, tenant_a)

    # Tenant B queries for a resource that exists in tenant A only
    answer = _ask(
        pool, tenant_b,
        QueryPlan("reachability", {"external_id": "i-reach-target"}),
    )
    # Either not found (correct scoping) or found=True with no internet sources
    if answer.data.get("found"):
        assert answer.data["reached_by_internet"] is False
        assert not any(s["is_internet"] for s in answer.data.get("sources", []))
    else:
        assert answer.data["found"] is False


def test_ask_endpoint_reachability_via_injected_planner(pool, make_tenant_with_key):
    """AC 19: /ask endpoint can invoke the reachability template successfully."""
    tenant, api_key = make_tenant_with_key()
    _seed_reachability(pool, tenant)
    planner = FakePlanner(QueryPlan("reachability", {"external_id": "i-reach-target"}))
    client = TestClient(create_app(pool=pool, planner=planner))

    resp = client.post(
        "/ask",
        json={"question": "can the internet reach i-reach-target?"},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["answered"] is True
    assert body["template"] == "reachability"
    assert body["data"]["reached_by_internet"] is True
