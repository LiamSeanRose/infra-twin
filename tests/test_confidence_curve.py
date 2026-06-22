"""Unit tests for the pure confidence_for_observations helper.

Covers every acceptance criterion and edge case from specs.md §7 that
pertains to the confidence curve: AC 1-8, edge cases 1-5 (pure math).

No I/O, no DB, no fixtures required.
"""

from __future__ import annotations

import pytest

from infra_twin.core_model import (
    INFERRED_BASELINE_CONFIDENCE,
    INFERRED_CONFIDENCE_DECAY,
    confidence_for_observations,
)
from infra_twin.collectors.aws import DEFAULT_FLOW_CONFIDENCE


# ---------------------------------------------------------------------------
# AC 1: module and constants exist
# ---------------------------------------------------------------------------


def test_inferred_baseline_confidence_is_06():
    """AC 1: INFERRED_BASELINE_CONFIDENCE == 0.6 exactly."""
    assert INFERRED_BASELINE_CONFIDENCE == 0.6


def test_inferred_confidence_decay_in_open_unit_interval():
    """AC 1: INFERRED_CONFIDENCE_DECAY in (0, 1)."""
    assert 0 < INFERRED_CONFIDENCE_DECAY < 1


def test_inferred_confidence_decay_is_05():
    """AC 1: INFERRED_CONFIDENCE_DECAY == 0.5 (the spec-pinned value)."""
    assert INFERRED_CONFIDENCE_DECAY == 0.5


# ---------------------------------------------------------------------------
# AC 2: N=1 -> 0.6 exactly
# ---------------------------------------------------------------------------


def test_confidence_n1_is_baseline():
    """AC 2: confidence_for_observations(1) == 0.6 exactly."""
    assert confidence_for_observations(1) == pytest.approx(0.6, abs=1e-9)


def test_confidence_n1_equals_baseline_constant():
    """AC 2: confidence_for_observations(1) == INFERRED_BASELINE_CONFIDENCE."""
    assert confidence_for_observations(1) == pytest.approx(
        INFERRED_BASELINE_CONFIDENCE, abs=1e-9
    )


# ---------------------------------------------------------------------------
# AC 3, 4: pinned curve values
# ---------------------------------------------------------------------------


def test_confidence_n2_is_08():
    """AC 3: confidence_for_observations(2) == 0.8."""
    assert confidence_for_observations(2) == pytest.approx(0.8, abs=1e-9)


def test_confidence_n3_is_09():
    """AC 4: confidence_for_observations(3) == 0.9."""
    assert confidence_for_observations(3) == pytest.approx(0.9, abs=1e-9)


def test_confidence_n2_n3_values():
    """AC 3, 4: combined check for N=2 and N=3 pinned curve values."""
    assert confidence_for_observations(2) == pytest.approx(0.8, abs=1e-9)
    assert confidence_for_observations(3) == pytest.approx(0.9, abs=1e-9)


def test_confidence_n4_is_095():
    """Pinned curve value: confidence_for_observations(4) == 0.95."""
    assert confidence_for_observations(4) == pytest.approx(0.95, abs=1e-9)


def test_confidence_n5_is_0975():
    """Pinned curve value: confidence_for_observations(5) == 0.975."""
    assert confidence_for_observations(5) == pytest.approx(0.975, abs=1e-9)


# ---------------------------------------------------------------------------
# AC 5: strictly increasing, always < 1.0, always > 0.0
# ---------------------------------------------------------------------------


def test_confidence_strictly_increasing():
    """AC 5: confidence_for_observations is strictly increasing over N=1..50."""
    values = [confidence_for_observations(n) for n in range(1, 51)]
    for i in range(len(values) - 1):
        assert values[i] < values[i + 1], (
            f"not strictly increasing at N={i + 1}: "
            f"{values[i]} >= {values[i + 1]}"
        )


def test_confidence_always_below_one():
    """AC 5: confidence_for_observations is always strictly < 1.0 for N=1..200."""
    for n in range(1, 201):
        v = confidence_for_observations(n)
        assert v < 1.0, f"confidence_for_observations({n}) >= 1.0: got {v}"


def test_confidence_always_above_zero():
    """AC 5: confidence_for_observations is always strictly > 0.0 for N=1..200."""
    for n in range(1, 201):
        v = confidence_for_observations(n)
        assert v > 0.0, f"confidence_for_observations({n}) <= 0.0: got {v}"


# ---------------------------------------------------------------------------
# AC 6: raises ValueError for invalid count
# ---------------------------------------------------------------------------


def test_confidence_rejects_zero():
    """AC 6: confidence_for_observations(0) raises ValueError."""
    with pytest.raises(ValueError):
        confidence_for_observations(0)


def test_confidence_rejects_negative_one():
    """AC 6: confidence_for_observations(-1) raises ValueError."""
    with pytest.raises(ValueError):
        confidence_for_observations(-1)


def test_confidence_rejects_large_negative():
    """AC 6: confidence_for_observations(-100) raises ValueError."""
    with pytest.raises(ValueError):
        confidence_for_observations(-100)


# ---------------------------------------------------------------------------
# AC 7: deterministic (same input -> same output)
# ---------------------------------------------------------------------------


def test_confidence_deterministic():
    """AC 7: confidence_for_observations produces identical output on two calls."""
    for n in (1, 2, 3, 10, 50):
        assert confidence_for_observations(n) == confidence_for_observations(n), (
            f"non-deterministic at N={n}"
        )


# ---------------------------------------------------------------------------
# AC 8: DEFAULT_FLOW_CONFIDENCE == 0.6 AND == INFERRED_BASELINE_CONFIDENCE
# ---------------------------------------------------------------------------


def test_default_flow_confidence_is_06():
    """AC 8: DEFAULT_FLOW_CONFIDENCE == 0.6."""
    assert DEFAULT_FLOW_CONFIDENCE == 0.6


def test_default_flow_confidence_equals_baseline():
    """AC 8: DEFAULT_FLOW_CONFIDENCE == INFERRED_BASELINE_CONFIDENCE."""
    assert DEFAULT_FLOW_CONFIDENCE == INFERRED_BASELINE_CONFIDENCE
