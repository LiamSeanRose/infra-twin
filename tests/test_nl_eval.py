"""NL Reasoning Eval Harness – pure offline unit tests.

No DB fixtures (pool / make_tenant / make_tenant_with_key), no live Anthropic
calls, no network.  Runs anywhere with: uv run pytest tests/test_nl_eval.py
"""

from __future__ import annotations

import importlib
import sys
from typing import Dict, Optional

import pytest

from infra_twin.api.nlquery.eval import CaseResult, EvalReport, evaluate_planner
from infra_twin.api.nlquery.eval_dataset import (
    GOLDEN_DATASET,
    UNSUPPORTED_EXPECTED,
    GoldenCase,
)
from infra_twin.api.nlquery.planner import UNSUPPORTED, QueryPlan
from infra_twin.api.nlquery.templates import REGISTRY

# ---------------------------------------------------------------------------
# Gate thresholds (committed regression baseline against RecordedPlanner)
# ---------------------------------------------------------------------------
MIN_OVERALL_ACCURACY: float = 1.0
MIN_UNSUPPORTED_ROUTING_ACCURACY: float = 1.0


# ---------------------------------------------------------------------------
# RecordedPlanner: deterministic test stand-in for the Planner Protocol
# ---------------------------------------------------------------------------

class RecordedPlanner:
    """Planner backed by a pre-recorded mapping of question -> QueryPlan | None.

    Implements the Planner Protocol.  For questions not in the mapping returns
    None (documented default – treated by the scorer as "no template chosen").
    Performs no network or DB work.
    """

    def __init__(self, mapping: Dict[str, Optional[QueryPlan]]) -> None:
        self._mapping = mapping

    def plan(self, question: str) -> QueryPlan | None:
        return self._mapping.get(question, None)


# ---------------------------------------------------------------------------
# Helper: build an all-correct RecordedPlanner from GOLDEN_DATASET
# ---------------------------------------------------------------------------

def _make_perfect_planner() -> RecordedPlanner:
    """Return a RecordedPlanner that gives the perfect answer for every golden case."""
    mapping: Dict[str, Optional[QueryPlan]] = {}
    for case in GOLDEN_DATASET:
        if case.expected_template == UNSUPPORTED_EXPECTED:
            # Any "unsupported" answer is correct; use the explicit sentinel name.
            mapping[case.question] = QueryPlan(UNSUPPORTED, {})
        else:
            # Use the dataset's expected_args if provided, else empty dict.
            args = case.expected_args if case.expected_args is not None else {}
            mapping[case.question] = QueryPlan(case.expected_template, args)
    return RecordedPlanner(mapping)


# ===========================================================================
# 1.  Dataset integrity (pre-flight checks, no scorer needed)
# ===========================================================================

class TestGoldenDatasetIntegrity:
    """All expected_template values must be in REGISTRY or == UNSUPPORTED."""

    def test_every_expected_template_is_valid(self):
        valid_templates = set(REGISTRY.keys()) | {UNSUPPORTED_EXPECTED}
        for case in GOLDEN_DATASET:
            assert case.expected_template in valid_templates, (
                f"Invalid expected_template {case.expected_template!r} for question "
                f"{case.question!r}"
            )

    def test_all_registry_keys_covered(self):
        covered = {c.expected_template for c in GOLDEN_DATASET}
        for key in REGISTRY:
            assert key in covered, f"REGISTRY key {key!r} has no golden cases"

    def test_min_two_phrasings_per_real_template(self):
        from collections import Counter
        counts = Counter(
            c.expected_template
            for c in GOLDEN_DATASET
            if c.expected_template != UNSUPPORTED_EXPECTED
        )
        for key in REGISTRY:
            assert counts[key] >= 2, (
                f"Template {key!r} needs >=2 phrasings; found {counts[key]}"
            )

    def test_at_least_four_unsupported_cases(self):
        count = sum(1 for c in GOLDEN_DATASET if c.expected_template == UNSUPPORTED_EXPECTED)
        assert count >= 4, f"Expected >=4 UNSUPPORTED cases; found {count}"

    def test_at_least_one_args_graded_case_per_parametrized_template(self):
        """Every real template that has parameters must have at least one args-graded case."""
        # CountByTypeParams has no required fields; we still expect at least one args case.
        from collections import defaultdict
        args_graded: dict[str, bool] = defaultdict(bool)
        for case in GOLDEN_DATASET:
            if case.expected_template in REGISTRY and case.expected_args is not None:
                args_graded[case.expected_template] = True
        for key in REGISTRY:
            assert args_graded[key], (
                f"Template {key!r} has no args-graded golden case"
            )

    def test_golden_dataset_is_non_empty(self):
        assert len(GOLDEN_DATASET) > 0

    def test_golden_dataset_is_tuple(self):
        assert isinstance(GOLDEN_DATASET, tuple)

    def test_goldencase_is_frozen(self):
        case = GOLDEN_DATASET[0]
        with pytest.raises((AttributeError, TypeError)):
            case.question = "mutated"  # type: ignore[misc]


# ===========================================================================
# 2.  Harness correctness: all-correct planner
# ===========================================================================

class TestPerfectPlannerReport:
    """All-correct RecordedPlanner over the full golden dataset must score 1.0 everywhere."""

    def _report(self) -> EvalReport:
        return evaluate_planner(_make_perfect_planner(), GOLDEN_DATASET)

    def test_overall_accuracy_is_1(self):
        assert self._report().overall_accuracy == 1.0

    def test_template_accuracy_is_1(self):
        assert self._report().template_accuracy == 1.0

    def test_args_accuracy_is_1(self):
        assert self._report().args_accuracy == 1.0

    def test_unsupported_routing_accuracy_is_1(self):
        assert self._report().unsupported_routing_accuracy == 1.0

    def test_total_matches_dataset_length(self):
        report = self._report()
        assert report.total == len(GOLDEN_DATASET)

    def test_results_length_matches_total(self):
        report = self._report()
        assert len(report.results) == report.total

    def test_all_cases_passed(self):
        report = self._report()
        assert all(r.passed for r in report.results)

    def test_all_template_matches(self):
        report = self._report()
        assert all(r.template_match for r in report.results)

    def test_results_is_tuple(self):
        assert isinstance(self._report().results, tuple)

    def test_report_is_frozen(self):
        report = self._report()
        with pytest.raises((AttributeError, TypeError)):
            report.total = 0  # type: ignore[misc]


# ===========================================================================
# 3.  Harness correctness: wrong / misrouted planner cases
# ===========================================================================

class TestMisroutedPlannerReport:
    """Scorer must reflect failures exactly when the planner gives wrong answers."""

    # ---- 3a. Template misroute (wrong template, not UNSUPPORTED) ---------------

    def test_wrong_template_scores_fail(self):
        """A question expecting 'inventory' returned as 'blast_radius' -> template_match=False."""
        case = GoldenCase(
            question="what EC2 instances do I have",
            expected_template="inventory",
            expected_args={"type": "ec2_instance"},
        )
        planner = RecordedPlanner({
            "what EC2 instances do I have": QueryPlan("blast_radius", {"external_id": "x"})
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is False
        assert r.passed is False
        assert report.overall_accuracy < 1.0

    def test_wrong_template_does_not_pollute_args_denominator(self):
        """When template_match=False, the case must not enter the args_accuracy denominator."""
        case = GoldenCase(
            question="what EC2 instances do I have",
            expected_template="inventory",
            expected_args={"type": "ec2_instance"},
        )
        planner = RecordedPlanner({
            "what EC2 instances do I have": QueryPlan("blast_radius", {"external_id": "x"})
        })
        report = evaluate_planner(planner, [case])
        # No args-checked case should be counted (args_accuracy is vacuously 1.0)
        r = report.results[0]
        # args_checked=True from the dataset side, but since template_match=False,
        # args are not compared (vacuous pass per spec §4 rule 4).
        assert r.args_match is True  # vacuous
        # args_accuracy must be 1.0 because no args were actually compared
        assert report.args_accuracy == 1.0

    # ---- 3b. UNSUPPORTED question routed to a real template --------------------

    def test_unsupported_expected_routed_to_real_template_is_fail(self):
        """An unanswerable question routed to a real template -> template_match=False."""
        case = GoldenCase(
            question="what's the weather in San Francisco",
            expected_template=UNSUPPORTED_EXPECTED,
            expected_args=None,
        )
        planner = RecordedPlanner({
            "what's the weather in San Francisco": QueryPlan("inventory", {"type": "ec2_instance"})
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is False
        assert r.passed is False
        assert report.unsupported_routing_accuracy < 1.0

    def test_unsupported_expected_routed_to_real_template_drops_routing_accuracy(self):
        """unsupported_routing_accuracy falls below 1.0 on the dangerous misroute."""
        n_unsup = 4
        cases = [
            GoldenCase(
                question=f"unsupported question {i}",
                expected_template=UNSUPPORTED_EXPECTED,
                expected_args=None,
            )
            for i in range(n_unsup)
        ]
        # First case misrouted; rest are correctly marked UNSUPPORTED.
        mapping: Dict[str, Optional[QueryPlan]] = {
            "unsupported question 0": QueryPlan("recent_changes", {"days": 7}),
        }
        for i in range(1, n_unsup):
            mapping[f"unsupported question {i}"] = QueryPlan(UNSUPPORTED, {})

        report = evaluate_planner(RecordedPlanner(mapping), cases)
        assert report.unsupported_routing_accuracy == pytest.approx(3 / 4)

    # ---- 3c. Answerable question routed to UNSUPPORTED -------------------------

    def test_answerable_routed_to_unsupported_plan_is_fail(self):
        """Real-template question returned as QueryPlan('unsupported', {}) -> passed=False."""
        case = GoldenCase(
            question="what breaks if vpc-123 goes down",
            expected_template="blast_radius",
            expected_args={"external_id": "vpc-123"},
        )
        planner = RecordedPlanner({
            "what breaks if vpc-123 goes down": QueryPlan(UNSUPPORTED, {})
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is False
        assert r.passed is False

    def test_answerable_routed_to_none_is_fail(self):
        """Real-template question where planner returns None -> passed=False."""
        case = GoldenCase(
            question="what breaks if vpc-123 goes down",
            expected_template="blast_radius",
            expected_args={"external_id": "vpc-123"},
        )
        planner = RecordedPlanner({})  # returns None for all
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.predicted_template is None
        assert r.template_match is False
        assert r.passed is False

    # ---- 3d. Specific aggregate counts -----------------------------------------

    def test_overall_accuracy_exact_fraction(self):
        """3 cases, 1 fails -> overall_accuracy == 2/3."""
        cases = [
            GoldenCase("q1", "inventory", {"type": "ec2_instance"}),
            GoldenCase("q2", "inventory", {"type": "vpc"}),
            GoldenCase("q3", UNSUPPORTED_EXPECTED, None),
        ]
        mapping: Dict[str, Optional[QueryPlan]] = {
            "q1": QueryPlan("inventory", {"type": "ec2_instance"}),  # correct
            "q2": QueryPlan("blast_radius", {"external_id": "x"}),  # wrong template
            "q3": QueryPlan(UNSUPPORTED, {}),                         # correct
        }
        report = evaluate_planner(RecordedPlanner(mapping), cases)
        assert report.total == 3
        assert report.overall_accuracy == pytest.approx(2 / 3)
        assert report.template_accuracy == pytest.approx(2 / 3)

    def test_unsupported_routing_accuracy_exact_fraction(self):
        """2 UNSUPPORTED cases, 1 misrouted -> unsupported_routing_accuracy == 0.5."""
        cases = [
            GoldenCase("unsup1", UNSUPPORTED_EXPECTED, None),
            GoldenCase("unsup2", UNSUPPORTED_EXPECTED, None),
        ]
        mapping: Dict[str, Optional[QueryPlan]] = {
            "unsup1": QueryPlan(UNSUPPORTED, {}),             # correct
            "unsup2": QueryPlan("inventory", {}),             # dangerous misroute
        }
        report = evaluate_planner(RecordedPlanner(mapping), cases)
        assert report.unsupported_routing_accuracy == pytest.approx(0.5)


# ===========================================================================
# 4.  Template-match vs args-match are scored independently
# ===========================================================================

class TestIndependentTemplateAndArgsScoring:
    """Correct template + wrong-but-valid args -> template_match=True, args_match=False."""

    def test_correct_template_wrong_valid_args(self):
        """days=14 vs expected days=7 -> template_match=True, args_match=False, passed=False."""
        case = GoldenCase(
            question="what changed this week",
            expected_template="recent_changes",
            expected_args={"days": 7},
        )
        planner = RecordedPlanner({
            "what changed this week": QueryPlan("recent_changes", {"days": 14})
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is True
        assert r.args_match is False
        assert r.args_valid is True
        assert r.passed is False

    def test_template_accuracy_does_not_count_args_failures(self):
        """template_accuracy reflects template correctness regardless of args."""
        case = GoldenCase(
            question="what changed this week",
            expected_template="recent_changes",
            expected_args={"days": 7},
        )
        planner = RecordedPlanner({
            "what changed this week": QueryPlan("recent_changes", {"days": 14})
        })
        report = evaluate_planner(planner, [case])
        assert report.template_accuracy == 1.0
        assert report.args_accuracy == 0.0
        assert report.overall_accuracy == 0.0

    def test_no_expected_args_passes_on_template_match_alone(self):
        """expected_args=None means args_checked=False; template match alone -> passed=True."""
        case = GoldenCase(
            question="what infrastructure resources are currently running?",
            expected_template="inventory",
            expected_args=None,
        )
        planner = RecordedPlanner({
            "what infrastructure resources are currently running?": QueryPlan(
                "inventory", {"type": "s3_bucket"}
            )
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.args_checked is False
        assert r.args_match is True
        assert r.template_match is True
        assert r.passed is True


# ===========================================================================
# 5.  Args validation robustness (bad planner output must not crash scorer)
# ===========================================================================

class TestArgsValidationRobustness:
    """evaluate_planner must never raise on bad planner output."""

    def test_missing_required_arg_blast_radius(self):
        """blast_radius without external_id -> args_valid=False, no exception raised."""
        case = GoldenCase(
            question="what breaks if vpc-123 goes down",
            expected_template="blast_radius",
            expected_args={"external_id": "vpc-123"},
        )
        planner = RecordedPlanner({
            "what breaks if vpc-123 goes down": QueryPlan("blast_radius", {})
        })
        report = evaluate_planner(planner, [case])  # must NOT raise
        r = report.results[0]
        assert r.args_valid is False
        assert r.args_match is False
        assert r.passed is False

    def test_out_of_range_arg_recent_changes(self):
        """recent_changes with days=999 (le=30 violated) -> args_valid=False, no exception."""
        case = GoldenCase(
            question="what changed this week",
            expected_template="recent_changes",
            expected_args={"days": 7},
        )
        planner = RecordedPlanner({
            "what changed this week": QueryPlan("recent_changes", {"days": 999})
        })
        report = evaluate_planner(planner, [case])  # must NOT raise
        r = report.results[0]
        assert r.args_valid is False
        assert r.args_match is False
        assert r.passed is False

    def test_planner_raising_exception_is_scored_as_fail(self):
        """If planner.plan() itself raises, the scorer maps it to plan=None -> FAIL."""
        class BrokenPlanner:
            def plan(self, question: str) -> QueryPlan | None:
                raise RuntimeError("network unavailable")

        case = GoldenCase(
            question="what EC2 instances do I have",
            expected_template="inventory",
            expected_args={"type": "ec2_instance"},
        )
        report = evaluate_planner(BrokenPlanner(), [case])  # must NOT raise
        r = report.results[0]
        assert r.predicted_template is None
        assert r.passed is False

    def test_hallucinated_template_name_does_not_raise(self):
        """Planner returns a name not in REGISTRY; scorer must not raise."""
        case_real = GoldenCase(
            question="list my VPCs",
            expected_template="inventory",
            expected_args={"type": "vpc"},
        )
        case_unsup = GoldenCase(
            question="delete my VPC",
            expected_template=UNSUPPORTED_EXPECTED,
            expected_args=None,
        )
        planner = RecordedPlanner({
            "list my VPCs": QueryPlan("delete_vpc", {}),     # hallucinated, not in REGISTRY
            "delete my VPC": QueryPlan("delete_vpc", {}),    # hallucinated; still safe route
        })
        report = evaluate_planner(planner, [case_real, case_unsup])  # must NOT raise
        results = {r.question: r for r in report.results}

        # Real-template case: hallucinated name != "inventory" -> fail
        assert results["list my VPCs"].template_match is False
        assert results["list my VPCs"].passed is False

        # UNSUPPORTED case: hallucinated name not in REGISTRY -> correct routing per spec §4.3
        assert results["delete my VPC"].template_match is True
        assert results["delete my VPC"].passed is True


# ===========================================================================
# 6.  UNSUPPORTED routing edge cases (spec §6)
# ===========================================================================

class TestUnsupportedRouting:
    """Both directions of UNSUPPORTED misroute must be caught as failures."""

    def test_plan_none_for_unsupported_expected_is_correct(self):
        """Edge case 1: planner returns None for UNSUPPORTED-expected -> CORRECT."""
        case = GoldenCase(
            question="what's the weather in San Francisco",
            expected_template=UNSUPPORTED_EXPECTED,
            expected_args=None,
        )
        planner = RecordedPlanner({})  # returns None for all
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is True
        assert r.passed is True

    def test_plan_none_for_real_template_expected_is_fail(self):
        """Edge case 2: planner returns None for real-template question -> FAIL."""
        case = GoldenCase(
            question="what EC2 instances do I have",
            expected_template="inventory",
            expected_args={"type": "ec2_instance"},
        )
        planner = RecordedPlanner({})
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is False
        assert r.passed is False

    def test_queryplan_unsupported_for_unsupported_expected_is_correct(self):
        """Edge case 3: QueryPlan('unsupported', {}) for UNSUPPORTED case -> CORRECT."""
        case = GoldenCase(
            question="write me a poem about clouds",
            expected_template=UNSUPPORTED_EXPECTED,
            expected_args=None,
        )
        planner = RecordedPlanner({"write me a poem about clouds": QueryPlan(UNSUPPORTED, {})})
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is True
        assert r.passed is True

    def test_queryplan_unsupported_for_real_template_expected_is_fail(self):
        """Edge case 4: QueryPlan('unsupported', {}) for real-template question -> FAIL."""
        case = GoldenCase(
            question="what changes this week",
            expected_template="recent_changes",
            expected_args={"days": 7},
        )
        planner = RecordedPlanner({"what changes this week": QueryPlan(UNSUPPORTED, {})})
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is False
        assert r.passed is False

    def test_hallucinated_name_for_unsupported_expected_is_correct(self):
        """Edge case 5a: hallucinated name not in REGISTRY for UNSUPPORTED case -> CORRECT."""
        case = GoldenCase(
            question="delete my VPC",
            expected_template=UNSUPPORTED_EXPECTED,
            expected_args=None,
        )
        planner = RecordedPlanner({"delete my VPC": QueryPlan("delete_vpc", {})})
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is True
        assert r.passed is True

    def test_hallucinated_name_for_real_template_expected_is_fail(self):
        """Edge case 5b: hallucinated name not in REGISTRY for real-template question -> FAIL."""
        case = GoldenCase(
            question="list my VPCs",
            expected_template="inventory",
            expected_args=None,
        )
        planner = RecordedPlanner({"list my VPCs": QueryPlan("list_vpcs_magic", {})})
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is False
        assert r.passed is False


# ===========================================================================
# 7.  Args edge cases from spec §6
# ===========================================================================

class TestArgsEdgeCases:
    """Pydantic defaults, extras, count_by_type, etc."""

    def test_pydantic_defaults_applied_for_reachability(self):
        """Edge case 9: planner returns minimal args; Pydantic fills defaults -> args_match=True."""
        case = GoldenCase(
            question="can the internet reach i-1",
            expected_template="reachability",
            expected_args={"external_id": "i-1", "max_depth": 6, "internet_only": False},
        )
        planner = RecordedPlanner({
            "can the internet reach i-1": QueryPlan("reachability", {"external_id": "i-1"})
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.args_match is True
        assert r.passed is True

    def test_pydantic_defaults_applied_for_blast_radius(self):
        """Default max_depth=4 on blast_radius applied; match with explicit expected max_depth=4."""
        case = GoldenCase(
            question="what breaks if vpc-123 goes down",
            expected_template="blast_radius",
            expected_args={"external_id": "vpc-123", "max_depth": 4},
        )
        planner = RecordedPlanner({
            "what breaks if vpc-123 goes down": QueryPlan(
                "blast_radius", {"external_id": "vpc-123"}
            )
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.args_match is True
        assert r.passed is True

    def test_count_by_type_empty_args_match(self):
        """Edge case 14: count_by_type with {} expected and {} predicted -> args_match=True."""
        case = GoldenCase(
            question="how many of each resource do I have",
            expected_template="count_by_type",
            expected_args={},
        )
        planner = RecordedPlanner({
            "how many of each resource do I have": QueryPlan("count_by_type", {})
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.args_checked is True
        assert r.args_match is True
        assert r.passed is True

    def test_correct_template_valid_unequal_args(self):
        """Edge case 7: correct template, args valid but not equal -> args_match=False, passed=False."""
        case = GoldenCase(
            question="show changes in the last 14 days",
            expected_template="recent_changes",
            expected_args={"days": 14},
        )
        planner = RecordedPlanner({
            "show changes in the last 14 days": QueryPlan("recent_changes", {"days": 7})
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is True
        assert r.args_match is False
        assert r.passed is False

    def test_extra_unknown_keys_validated_via_model(self):
        """Edge case 10: extra unknown keys -> Pydantic by default ignores them; match on dump."""
        # RecentChangesParams has no extra='forbid'; extra keys are silently ignored.
        case = GoldenCase(
            question="what changed this week",
            expected_template="recent_changes",
            expected_args={"days": 7},
        )
        planner = RecordedPlanner({
            "what changed this week": QueryPlan(
                "recent_changes", {"days": 7, "unknown_extra_key": "baz"}
            )
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        # Pydantic will either ignore or error; in either case scorer must not raise
        # and the result should be deterministic.
        assert isinstance(r.args_match, bool)

    def test_args_mismatch_max_depth_not_default(self):
        """Planner returns max_depth=2, expected default (4) -> args_match=False."""
        case = GoldenCase(
            question="what depends on i-0abc",
            expected_template="blast_radius",
            expected_args={"external_id": "i-0abc"},  # max_depth omitted -> default 4
        )
        planner = RecordedPlanner({
            "what depends on i-0abc": QueryPlan(
                "blast_radius", {"external_id": "i-0abc", "max_depth": 2}
            )
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        # expected resolves to max_depth=4, predicted resolves to max_depth=2 -> mismatch
        assert r.template_match is True
        assert r.args_match is False
        assert r.passed is False


# ===========================================================================
# 8.  Edge cases: empty and zero-denominator datasets (spec §6 cases 11-13)
# ===========================================================================

class TestZeroDenominatorEdgeCases:
    """No ZeroDivisionError on empty / degenerate datasets."""

    def test_empty_dataset_all_accuracies_1(self):
        """Edge case 11: empty dataset -> total=0, all four accuracies==1.0."""
        planner = RecordedPlanner({})
        report = evaluate_planner(planner, ())
        assert report.total == 0
        assert report.results == ()
        assert report.overall_accuracy == 1.0
        assert report.template_accuracy == 1.0
        assert report.args_accuracy == 1.0
        assert report.unsupported_routing_accuracy == 1.0

    def test_zero_unsupported_cases_routing_accuracy_is_1(self):
        """Edge case 12: no UNSUPPORTED cases -> unsupported_routing_accuracy==1.0."""
        cases = [
            GoldenCase("q1", "inventory", {"type": "ec2_instance"}),
        ]
        planner = RecordedPlanner({"q1": QueryPlan("inventory", {"type": "ec2_instance"})})
        report = evaluate_planner(planner, cases)
        assert report.unsupported_routing_accuracy == 1.0

    def test_zero_args_checked_cases_args_accuracy_is_1(self):
        """Edge case 13: no args-graded cases -> args_accuracy==1.0."""
        cases = [
            GoldenCase("delete my VPC", UNSUPPORTED_EXPECTED, None),
        ]
        planner = RecordedPlanner({"delete my VPC": QueryPlan(UNSUPPORTED, {})})
        report = evaluate_planner(planner, cases)
        assert report.args_accuracy == 1.0

    def test_only_unsupported_cases_no_args_denom(self):
        """Dataset with only UNSUPPORTED cases -> args_accuracy==1.0 (no args to check)."""
        cases = [
            GoldenCase(f"unsup {i}", UNSUPPORTED_EXPECTED, None)
            for i in range(4)
        ]
        planner = RecordedPlanner({
            f"unsup {i}": QueryPlan(UNSUPPORTED, {})
            for i in range(4)
        })
        report = evaluate_planner(planner, cases)
        assert report.args_accuracy == 1.0
        assert report.unsupported_routing_accuracy == 1.0

    def test_single_case_dataset_no_crash(self):
        """Single-element dataset doesn't divide by zero or crash."""
        case = GoldenCase("what EC2 instances do I have", "inventory", {"type": "ec2_instance"})
        planner = RecordedPlanner({
            "what EC2 instances do I have": QueryPlan("inventory", {"type": "ec2_instance"})
        })
        report = evaluate_planner(planner, [case])
        assert report.total == 1
        assert report.overall_accuracy == 1.0


# ===========================================================================
# 9.  Determinism: same inputs -> identical EvalReport
# ===========================================================================

class TestDeterminism:
    """Edge case 16: same planner + same dataset must yield identical results."""

    def test_reports_are_identical_on_repeated_runs(self):
        planner = _make_perfect_planner()
        report1 = evaluate_planner(planner, GOLDEN_DATASET)
        report2 = evaluate_planner(planner, GOLDEN_DATASET)
        assert report1 == report2

    def test_results_order_matches_dataset_order(self):
        """Results must be in the same order as the dataset (no reordering)."""
        planner = _make_perfect_planner()
        report = evaluate_planner(planner, GOLDEN_DATASET)
        for i, (case, result) in enumerate(zip(GOLDEN_DATASET, report.results)):
            assert result.question == case.question, (
                f"Result at index {i} out of order: expected {case.question!r}, "
                f"got {result.question!r}"
            )


# ===========================================================================
# 10.  Module-level import safety (spec §6 edge case 17)
# ===========================================================================

class TestModuleImportSafety:
    """Importing eval.py must not construct an Anthropic client or touch network."""

    def test_eval_module_importable_without_anthropic_key(self, monkeypatch):
        """Importing eval does NOT instantiate ClaudePlanner or contact Anthropic."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        # Force a re-import to ensure module-level code runs again.
        mod_name = "infra_twin.api.nlquery.eval"
        saved = sys.modules.pop(mod_name, None)
        try:
            import importlib
            m = importlib.import_module(mod_name)
            # evaluate_planner must exist and be callable
            assert callable(m.evaluate_planner)
        finally:
            if saved is not None:
                sys.modules[mod_name] = saved
            else:
                sys.modules.pop(mod_name, None)

    def test_eval_dataset_importable_without_anthropic_key(self, monkeypatch):
        """eval_dataset.py imports only stdlib + nlquery; no Anthropic dependency."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        mod_name = "infra_twin.api.nlquery.eval_dataset"
        saved = sys.modules.pop(mod_name, None)
        try:
            import importlib
            m = importlib.import_module(mod_name)
            assert hasattr(m, "GOLDEN_DATASET")
            assert hasattr(m, "GoldenCase")
        finally:
            if saved is not None:
                sys.modules[mod_name] = saved
            else:
                sys.modules.pop(mod_name, None)

    def test_claude_planner_not_in_eval_module_level(self):
        """ClaudePlanner must NOT be importable from eval at module level."""
        import infra_twin.api.nlquery.eval as eval_mod
        assert not hasattr(eval_mod, "ClaudePlanner"), (
            "ClaudePlanner leaked to eval module scope; must be inside __main__ guard"
        )


# ===========================================================================
# 11.  Acceptance criteria specific tests
# ===========================================================================

class TestAcceptanceCriteria:
    """One test per AC from spec §7 that isn't covered above."""

    def test_ac4_every_expected_template_is_registry_key_or_unsupported(self):
        """AC 4: mechanically check every case in GOLDEN_DATASET."""
        valid = set(REGISTRY.keys()) | {UNSUPPORTED_EXPECTED}
        violations = [
            c for c in GOLDEN_DATASET if c.expected_template not in valid
        ]
        assert violations == [], f"Invalid expected_template values: {violations}"

    def test_ac5_eval_report_has_required_fields(self):
        """AC 5: EvalReport frozen dataclass has all required fields."""
        import dataclasses
        fields = {f.name for f in dataclasses.fields(EvalReport)}
        required = {
            "results", "total", "template_accuracy", "args_accuracy",
            "unsupported_routing_accuracy", "overall_accuracy",
        }
        assert required <= fields

    def test_ac5_case_result_has_required_fields(self):
        """AC 5: CaseResult frozen dataclass has all required fields."""
        import dataclasses
        fields = {f.name for f in dataclasses.fields(CaseResult)}
        required = {
            "question", "expected_template", "predicted_template",
            "template_match", "args_checked", "args_match", "args_valid", "passed",
        }
        assert required <= fields

    def test_ac7_eval_module_imports_only_allowed_symbols(self):
        """AC 7: eval.py must not import DB, services, or psycopg at module level."""
        import ast, pathlib
        src = pathlib.Path(
            "/home/labadmin/projects/infra-twin/apps/api/src/infra_twin/api/nlquery/eval.py"
        ).read_text()
        tree = ast.parse(src)
        forbidden_prefixes = ("psycopg", "infra_twin.db", "services")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                # Check only top-level imports (not inside if __name__ == "__main__")
                if isinstance(node, ast.ImportFrom) and node.module:
                    for prefix in forbidden_prefixes:
                        assert not node.module.startswith(prefix), (
                            f"eval.py imports forbidden module {node.module!r}"
                        )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        for prefix in forbidden_prefixes:
                            assert not alias.name.startswith(prefix), (
                                f"eval.py imports forbidden module {alias.name!r}"
                            )

    def test_ac8_claude_planner_not_at_module_level_in_eval(self):
        """AC 8: ClaudePlanner instantiation must be inside __main__ guard only."""
        import ast, pathlib
        src = pathlib.Path(
            "/home/labadmin/projects/infra-twin/apps/api/src/infra_twin/api/nlquery/eval.py"
        ).read_text()
        tree = ast.parse(src)

        # Find the __main__ guard body lines
        main_guard_linenos: set[int] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"
            ):
                for child in ast.walk(node):
                    if hasattr(child, "lineno"):
                        main_guard_linenos.add(child.lineno)

        # Find all "ClaudePlanner" references
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "ClaudePlanner":
                assert node.lineno in main_guard_linenos, (
                    f"ClaudePlanner referenced at line {node.lineno} outside __main__ guard"
                )

    def test_ac11_perfect_planner_all_accuracies_1(self):
        """AC 11: all-correct RecordedPlanner over GOLDEN_DATASET -> all accuracies == 1.0."""
        report = evaluate_planner(_make_perfect_planner(), GOLDEN_DATASET)
        assert report.overall_accuracy == 1.0
        assert report.template_accuracy == 1.0
        assert report.args_accuracy == 1.0
        assert report.unsupported_routing_accuracy == 1.0

    def test_ac12_misrouting_planner(self):
        """AC 12: misrouted case has passed=False, template_match=False; overall < 1.0."""
        case = GoldenCase(
            question="what EC2 instances do I have",
            expected_template="inventory",
            expected_args={"type": "ec2_instance"},
        )
        planner = RecordedPlanner({
            "what EC2 instances do I have": QueryPlan("blast_radius", {"external_id": "x"})
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.passed is False
        assert r.template_match is False
        assert report.overall_accuracy < 1.0

    def test_ac13_unsupported_expected_routed_to_real_template(self):
        """AC 13: unanswerable -> real template -> template_match=False, passed=False, routing < 1.0."""
        case = GoldenCase(
            question="what's the weather in San Francisco",
            expected_template=UNSUPPORTED_EXPECTED,
            expected_args=None,
        )
        planner = RecordedPlanner({
            "what's the weather in San Francisco": QueryPlan("inventory", {"type": "ec2_instance"})
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is False
        assert r.passed is False
        assert report.unsupported_routing_accuracy < 1.0

    def test_ac14_answerable_routed_to_unsupported(self):
        """AC 14: answerable question routed to unsupported -> passed=False."""
        case = GoldenCase(
            question="what EC2 instances do I have",
            expected_template="inventory",
            expected_args={"type": "ec2_instance"},
        )
        planner = RecordedPlanner({
            "what EC2 instances do I have": QueryPlan(UNSUPPORTED, {})
        })
        report = evaluate_planner(planner, [case])
        assert report.results[0].passed is False

    def test_ac15_invalid_args_no_exception(self):
        """AC 15: correct template + invalid args -> args_valid=False, args_match=False, no raise."""
        case = GoldenCase(
            question="what breaks if vpc-123 goes down",
            expected_template="blast_radius",
            expected_args={"external_id": "vpc-123"},
        )
        planner = RecordedPlanner({
            "what breaks if vpc-123 goes down": QueryPlan("blast_radius", {})
        })
        report = evaluate_planner(planner, [case])  # must NOT raise
        r = report.results[0]
        assert r.args_valid is False
        assert r.args_match is False
        assert r.passed is False

    def test_ac16_template_match_and_args_match_independent(self):
        """AC 16: correct template, wrong-but-valid args -> template_match=True, args_match=False."""
        case = GoldenCase(
            question="what changed this week",
            expected_template="recent_changes",
            expected_args={"days": 7},
        )
        planner = RecordedPlanner({
            "what changed this week": QueryPlan("recent_changes", {"days": 14})
        })
        report = evaluate_planner(planner, [case])
        r = report.results[0]
        assert r.template_match is True
        assert r.args_match is False

    def test_ac18_empty_dataset(self):
        """AC 18: evaluate_planner(planner, ()) -> total==0, all accuracies 1.0."""
        report = evaluate_planner(RecordedPlanner({}), ())
        assert report.total == 0
        assert report.overall_accuracy == 1.0
        assert report.template_accuracy == 1.0
        assert report.args_accuracy == 1.0
        assert report.unsupported_routing_accuracy == 1.0


# ===========================================================================
# 12.  THE GATE: committed regression baseline (spec §7 AC 17)
# ===========================================================================

class TestRegressionGate:
    """Gate: all-correct RecordedPlanner over the full GOLDEN_DATASET.

    Swapping in ClaudePlanner is an out-of-band operator run (python -m
    infra_twin.api.nlquery.eval) and is NOT a CI dependency.  This test only
    verifies the harness itself is correct against the deterministic baseline.
    """

    MIN_OVERALL_ACCURACY = 1.0
    MIN_UNSUPPORTED_ROUTING_ACCURACY = 1.0

    def test_gate_overall_accuracy(self):
        """Gate: overall_accuracy must meet MIN_OVERALL_ACCURACY == 1.0."""
        report = evaluate_planner(_make_perfect_planner(), GOLDEN_DATASET)
        assert report.overall_accuracy >= self.MIN_OVERALL_ACCURACY, (
            f"overall_accuracy {report.overall_accuracy:.4f} < "
            f"threshold {self.MIN_OVERALL_ACCURACY}"
        )

    def test_gate_unsupported_routing_accuracy(self):
        """Gate: unsupported_routing_accuracy must meet MIN_UNSUPPORTED_ROUTING_ACCURACY == 1.0."""
        report = evaluate_planner(_make_perfect_planner(), GOLDEN_DATASET)
        assert report.unsupported_routing_accuracy >= self.MIN_UNSUPPORTED_ROUTING_ACCURACY, (
            f"unsupported_routing_accuracy {report.unsupported_routing_accuracy:.4f} < "
            f"threshold {self.MIN_UNSUPPORTED_ROUTING_ACCURACY}"
        )

    def test_gate_full_report_sane(self):
        """Gate: full report sanity check across all four metrics simultaneously."""
        report = evaluate_planner(_make_perfect_planner(), GOLDEN_DATASET)
        assert report.total == len(GOLDEN_DATASET)
        assert report.overall_accuracy >= self.MIN_OVERALL_ACCURACY
        assert report.template_accuracy >= self.MIN_OVERALL_ACCURACY
        assert report.args_accuracy >= self.MIN_OVERALL_ACCURACY
        assert report.unsupported_routing_accuracy >= self.MIN_UNSUPPORTED_ROUTING_ACCURACY

    def test_gate_committed_total(self):
        """Gate: GOLDEN_DATASET must have exactly 21 committed cases (per changes.md)."""
        assert len(GOLDEN_DATASET) == 21, (
            f"GOLDEN_DATASET changed size: expected 21, got {len(GOLDEN_DATASET)}. "
            "Update this constant if the dataset is intentionally extended."
        )
