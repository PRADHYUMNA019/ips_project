#!/usr/bin/env python3
"""
tests/test_prop_drift_guard.py — Property-based tests for PoisoningAwareDriftGuard (Prompt 10 §1.3).

Verifies across random multi-window update sequences:
  1. Bounded-step invariant: on every window, tau_new is within [tau_old / gamma, tau_old * gamma].
  2. Rollback invariant: check_post_update_health restores exact prev_threshold when benign alert rate > rollback_alert_rate_max.
"""

from __future__ import annotations

import numpy as np
from hypothesis import given, settings
from hypothesis import strategies as st

from ips.drift.guard import GuardConfig, PoisoningAwareDriftGuard


@given(
    gamma=st.floats(min_value=1.05, max_value=2.0, allow_nan=False, allow_infinity=False),
    win_means=st.lists(
        st.floats(min_value=0.05, max_value=0.80, allow_nan=False, allow_infinity=False),
        min_size=3,
        max_size=12,
    ),
)
@settings(max_examples=60, deadline=None)
def test_prop_drift_guard_bounded_step_and_exact_rollback(gamma, win_means):
    """Threshold change per window never exceeds factor gamma, and rollback restores exact previous threshold."""
    rng = np.random.default_rng(123)
    anchor_benign = rng.normal(0.10, 0.015, size=200).clip(0.02, 0.20)
    canary_attacks = rng.normal(0.65, 0.04, size=100).clip(0.50, 0.90)

    cfg = GuardConfig(
        target_fpr=0.01,
        min_persistence_windows=2,
        consistency_rho=0.60,
        max_step_gamma=gamma,
        rollback_alert_rate_max=0.30,
        enable_bounded_step=True,
    )
    devices = ["sensor-01", "sensor-02", "sensor-03", "sensor-04"]
    guard = PoisoningAwareDriftGuard(
        device_class="sensor",
        class_devices=devices,
        initial_threshold=0.16,
        anchor_benign_scores=anchor_benign,
        canary_dev_attack_scores=canary_attacks,
        config=cfg,
    )

    for w_mean in win_means:
        tau_before = guard.threshold
        events = []
        for d in devices:
            for _ in range(10):
                events.append(
                    {
                        "device_id": d,
                        "score": float(max(0.01, rng.normal(w_mean, 0.01))),
                        "iat_ms": float(rng.gamma(3.0, 250.0)),
                        "is_attack": False,
                    }
                )
        res = guard.evaluate_window(events, mode="guarded")
        tau_after = guard.threshold

        # Invariant 1: Bounded step per window
        assert (tau_before / gamma) - 1e-9 <= tau_after <= (tau_before * gamma) + 1e-9, (
            f"Bounded step violated: {tau_before} -> {tau_after} with gamma={gamma}"
        )

        # Invariant 2: Exact rollback restoration when post-update benign alert rate spikes
        if res["adapted"]:
            spike_scores = np.full(50, tau_after + 0.50, dtype=np.float64)
            rb = guard.check_post_update_health(spike_scores)
            assert rb["rolled_back"] is True
            assert guard.threshold == tau_before, f"Rollback failed to restore {tau_before}, got {guard.threshold}"
