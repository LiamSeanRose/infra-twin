"""Deterministic accuracy scorer for the NL→query planner.

Scores a Planner against the committed golden dataset: correct whitelisted template,
correct args (validated through params_model the same way engine.py does), and correct
routing of unanswerable questions to UNSUPPORTED.

The scorer is pure: no I/O, no DB, no network, no Anthropic. The injected planner
provides all planner behaviour. ClaudePlanner is constructed only inside the
``__main__`` guard at the bottom of this file.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from pydantic import ValidationError

from infra_twin.api.nlquery.eval_dataset import GOLDEN_DATASET, GoldenCase, UNSUPPORTED_EXPECTED
from infra_twin.api.nlquery.planner import Planner, QueryPlan, UNSUPPORTED
from infra_twin.api.nlquery.templates import REGISTRY


@dataclass(frozen=True)
class CaseResult:
    question: str
    expected_template: str
    predicted_template: str | None  # None if planner returned None
    template_match: bool
    args_checked: bool              # True only when the case supplied expected_args on a real template
    args_match: bool                # True when args_checked is False (vacuously) OR validated args equal
    args_valid: bool                # False when correct template chosen but its args fail params_model
    passed: bool                    # template_match AND (not args_checked OR args_match)


@dataclass(frozen=True)
class EvalReport:
    results: tuple[CaseResult, ...]
    total: int
    template_accuracy: float           # fraction with template_match over all cases
    args_accuracy: float               # fraction with args_match over cases where args_checked is True; 1.0 if none
    unsupported_routing_accuracy: float  # fraction correct over UNSUPPORTED-expected cases; 1.0 if none
    overall_accuracy: float            # fraction with passed over all cases


def _score_case(plan: QueryPlan | None, case: GoldenCase) -> CaseResult:
    """Score a single case given the planner's returned plan (or None)."""
    predicted_template: str | None = None if plan is None else plan.name

    # 1. Template match
    if case.expected_template == UNSUPPORTED:
        # Any outcome that doesn't pick a real REGISTRY template is a correct routing.
        template_match = (
            plan is None
            or plan.name == UNSUPPORTED
            or plan.name not in REGISTRY
        )
    else:
        template_match = (predicted_template == case.expected_template)

    # 2. Args validation and match
    args_checked = (
        case.expected_args is not None
        and case.expected_template in REGISTRY
    )

    if not args_checked:
        # Vacuously correct: no args to grade.
        args_valid = True
        args_match = True
    elif not template_match:
        # Wrong template; don't attempt args comparison (vacuous pass so this case
        # does not pollute the args denominator).
        args_valid = True
        args_match = True
    else:
        # Both sides must validate; then compare model_dump() output.
        try:
            predicted_params = REGISTRY[plan.name].params_model(**plan.args)  # type: ignore[union-attr]
            args_valid = True
        except (ValidationError, Exception):
            args_valid = False
            predicted_params = None  # type: ignore[assignment]

        try:
            expected_params = REGISTRY[case.expected_template].params_model(**case.expected_args)  # type: ignore[arg-type]
        except (ValidationError, Exception):
            # Expected args themselves fail — treat as args mismatch.
            args_match = False
            return CaseResult(
                question=case.question,
                expected_template=case.expected_template,
                predicted_template=predicted_template,
                template_match=template_match,
                args_checked=args_checked,
                args_match=False,
                args_valid=args_valid,
                passed=False,
            )

        if args_valid:
            args_match = predicted_params.model_dump() == expected_params.model_dump()
        else:
            args_match = False

    passed = template_match and (not args_checked or args_match)

    return CaseResult(
        question=case.question,
        expected_template=case.expected_template,
        predicted_template=predicted_template,
        template_match=template_match,
        args_checked=args_checked,
        args_match=args_match,
        args_valid=args_valid,
        passed=passed,
    )


def evaluate_planner(
    planner: Planner, dataset: Sequence[GoldenCase]
) -> EvalReport:
    """Score ``planner`` against ``dataset``; return a fully typed EvalReport.

    Pure and deterministic: the only side-effecting call is ``planner.plan``, and the
    scorer never raises — bad planner output becomes a scoring failure, not a crash.
    """
    results: list[CaseResult] = []

    for case in dataset:
        try:
            plan = planner.plan(case.question)
        except Exception:
            plan = None

        result = _score_case(plan, case)
        results.append(result)

    total = len(results)

    if total == 0:
        return EvalReport(
            results=(),
            total=0,
            template_accuracy=1.0,
            args_accuracy=1.0,
            unsupported_routing_accuracy=1.0,
            overall_accuracy=1.0,
        )

    template_matches = sum(1 for r in results if r.template_match)
    template_accuracy = template_matches / total

    args_checked_results = [r for r in results if r.args_checked]
    if args_checked_results:
        args_accuracy = sum(1 for r in args_checked_results if r.args_match) / len(args_checked_results)
    else:
        args_accuracy = 1.0

    unsupported_results = [r for r in results if r.expected_template == UNSUPPORTED_EXPECTED]
    if unsupported_results:
        unsupported_routing_accuracy = (
            sum(1 for r in unsupported_results if r.template_match) / len(unsupported_results)
        )
    else:
        unsupported_routing_accuracy = 1.0

    passed_count = sum(1 for r in results if r.passed)
    overall_accuracy = passed_count / total

    return EvalReport(
        results=tuple(results),
        total=total,
        template_accuracy=template_accuracy,
        args_accuracy=args_accuracy,
        unsupported_routing_accuracy=unsupported_routing_accuracy,
        overall_accuracy=overall_accuracy,
    )


def _print_report(report: EvalReport) -> None:
    print(f"Total cases    : {report.total}")
    print(f"Overall        : {report.overall_accuracy:.2%}")
    print(f"Template acc.  : {report.template_accuracy:.2%}")
    print(f"Args acc.      : {report.args_accuracy:.2%}")
    print(f"Unsupported rt.: {report.unsupported_routing_accuracy:.2%}")
    print()
    for r in report.results:
        status = "PASS" if r.passed else "FAIL"
        pred = r.predicted_template if r.predicted_template is not None else "<none>"
        print(
            f"[{status}] {r.question!r}\n"
            f"       expected={r.expected_template!r}  predicted={pred!r}"
            f"  tmpl={'Y' if r.template_match else 'N'}"
            f"  args_checked={'Y' if r.args_checked else 'N'}"
            f"  args_match={'Y' if r.args_match else 'N'}"
            f"  args_valid={'Y' if r.args_valid else 'N'}"
        )


if __name__ == "__main__":
    # Operator out-of-band run against the real Anthropic API.
    # This block is NOT executed in CI and is never imported by tests.
    from infra_twin.api.nlquery.planner import ClaudePlanner

    live_planner = ClaudePlanner()
    report = evaluate_planner(live_planner, GOLDEN_DATASET)
    _print_report(report)
