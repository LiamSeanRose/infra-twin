"""Pure confidence helpers for inferred edges.

No I/O, no global mutable state.

Two helpers live here:
- ``confidence_for_observations``: maps an observation count to a bounded,
  strictly-increasing confidence value that never reaches 1.0.
- ``decayed_confidence``: maps (current_confidence, staleness age) to a decayed
  confidence, used by the aging sweep to weaken unobserved inferred edges.
"""

from __future__ import annotations

from datetime import timedelta

INFERRED_BASELINE_CONFIDENCE: float = 0.6
"""Confidence for a single observation (N == 1)."""

INFERRED_CONFIDENCE_DECAY: float = 0.5
"""Geometric decay base in (0, 1). Each additional observation halves the remaining
gap between the current confidence and 1.0, giving a fast-but-saturating ramp."""

STALE_FLOOR_CONFIDENCE: float = 0.2
"""Lower bound a decaying inferred edge's confidence can never drop below."""

INFERRED_FRESHNESS_WINDOW: timedelta = timedelta(days=7)
"""Age (since last_observed_at) at or below which NO decay is applied."""

INFERRED_EDGE_TTL: timedelta = timedelta(days=30)
"""Age (since last_observed_at) beyond which a still-unobserved inferred edge is closed."""

INFERRED_DECAY_PER_DAY: float = 0.05
"""Linear confidence loss per day of staleness past the freshness window."""


def confidence_for_observations(count: int) -> float:
    """Map an observation count N (>= 1) to a bounded, strictly-increasing confidence.

    Curve:  1 - (1 - INFERRED_BASELINE_CONFIDENCE) * INFERRED_CONFIDENCE_DECAY ** (count - 1)

    Simplified: 1 - 0.4 * 0.5 ** (count - 1)

    Properties:
      - count == 1            -> exactly INFERRED_BASELINE_CONFIDENCE (0.6)
      - strictly increasing in count (each step halves the gap to 1.0)
      - always < 1.0 for all finite count (the positive term never reaches 0)
      - always > 0.0
      - deterministic / pure (no I/O, no global state, same input -> same output)

    Raises ValueError if count < 1.
    """
    if count < 1:
        raise ValueError(f"count must be >= 1; got {count!r}")
    raw = 1.0 - (1.0 - INFERRED_BASELINE_CONFIDENCE) * (INFERRED_CONFIDENCE_DECAY ** (count - 1))
    # For very large N, float64 arithmetic rounds the result to exactly 1.0.  Clamp to
    # preserve the mathematical invariant "always strictly < 1.0" across all finite N.
    return min(raw, 1.0 - 1e-15)


def decayed_confidence(current_confidence: float, age: timedelta) -> float:
    """Map (current_confidence, staleness age) -> a decayed confidence.

    Properties (pinned by unit tests):
      - age <= INFERRED_FRESHNESS_WINDOW            -> returns current_confidence unchanged
      - age >  INFERRED_FRESHNESS_WINDOW            -> strictly lower than current_confidence
                                                       (until it reaches the floor)
      - monotonically NON-increasing in age
      - never returns a value > current_confidence  (never raises confidence)
      - never returns a value < STALE_FLOOR_CONFIDENCE
      - deterministic / pure (no I/O, no global state)
      - raises ValueError if age < timedelta(0)

    Curve (linear, past window):
      days_stale = (age - INFERRED_FRESHNESS_WINDOW).total_seconds() / 86400.0
      raw        = current_confidence - INFERRED_DECAY_PER_DAY * days_stale
      result     = max(STALE_FLOOR_CONFIDENCE, min(current_confidence, raw))

    When current_confidence is already <= STALE_FLOOR_CONFIDENCE the function
    returns current_confidence unchanged for age <= window, and STALE_FLOOR_CONFIDENCE
    for age > window (never raises).
    """
    if age < timedelta(0):
        raise ValueError(f"age must be >= timedelta(0); got {age!r}")

    if age <= INFERRED_FRESHNESS_WINDOW:
        return current_confidence

    days_stale = (age - INFERRED_FRESHNESS_WINDOW).total_seconds() / 86400.0
    raw = current_confidence - INFERRED_DECAY_PER_DAY * days_stale
    # Clamp: never raise above the input, never drop below the floor.
    return max(STALE_FLOOR_CONFIDENCE, min(current_confidence, raw))
