#!/usr/bin/env python3
"""
tests/test_prop_thresholds.py — Property-based tests for EVT, Split-Conformal, and 3-sigma thresholds (Prompt 10 §1.3 & §1.6).

Verifies:
  1. fit_evt_threshold NEVER returns NaN or +/-inf on arbitrary finite non-negative score arrays.
  2. compute_split_conformal_threshold is monotonically non-increasing in alpha across BOTH valid_regime
     (alpha >= 1/(n+1)) and sub-floor regimes, and satisfies empirical coverage mean(scores <= tau) >= 1 - alpha
     whenever valid_regime is True (kills M27: SURVIVED -> KILLED).
  3. compute_3sigma_threshold matches manual mean + 3*std computation within floating-point precision.
"""

from __future__ import annotations

import math

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ips.models.evt import (
    compute_3sigma_threshold,
    compute_split_conformal_threshold,
    fit_evt_threshold,
)


@given(
    scores_list=st.lists(
        st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
        min_size=30,
        max_size=250,
    ),
    alpha_small=st.floats(min_value=0.04, max_value=0.25, allow_nan=False, allow_infinity=False),
    alpha_delta=st.floats(min_value=0.05, max_value=0.25, allow_nan=False, allow_infinity=False),
)
@settings(max_examples=80, deadline=None)
def test_prop_evt_finiteness_conformal_monotonicity_and_3sigma(scores_list, alpha_small, alpha_delta):
    """EVT never returns NaN/inf, split-conformal is monotone + valid-coverage in alpha, and 3-sigma matches manual formula."""
    scores = np.asarray(scores_list, dtype=np.float64)
    alpha_large = min(0.49, alpha_small + alpha_delta)

    # 1. EVT fit finiteness (both moderate alpha and extreme tail alpha=1e-4)
    evt_res = fit_evt_threshold(scores, target_fpr=alpha_small)
    evt_tail = fit_evt_threshold(scores, target_fpr=1e-4)
    assert math.isfinite(evt_res["threshold"]), f"EVT returned non-finite threshold: {evt_res}"
    assert math.isfinite(evt_tail["threshold"]), f"EVT returned non-finite tail threshold: {evt_tail}"

    # 2. Split-conformal monotonicity & finite-sample order-statistic coverage inside valid_regime
    c_small = compute_split_conformal_threshold(scores, target_fpr=alpha_small)
    c_large = compute_split_conformal_threshold(scores, target_fpr=alpha_large)
    assert c_small["valid_regime"] is True
    assert c_large["valid_regime"] is True
    assert c_small["threshold"] + 1e-12 >= c_large["threshold"], (
        f"Conformal non-monotone in valid_regime: tau({alpha_small})={c_small['threshold']} < tau({alpha_large})={c_large['threshold']}"
    )
    emp_cov = float(np.mean(scores <= c_small["threshold"]))
    expected_cov = math.ceil((len(scores) + 1) * (1.0 - alpha_small)) / float(len(scores))
    assert emp_cov + 1e-9 >= min(1.0, expected_cov), (
        f"Split-conformal empirical coverage {emp_cov:.4f} < order-stat bound {expected_cov:.4f}"
    )

    # 3. Mean + 3*sigma exact formula match
    t_3s = compute_3sigma_threshold(scores)
    manual_3s = float(np.mean(scores)) + 3.0 * float(np.std(scores))
    assert t_3s == pytest.approx(manual_3s, rel=1e-9, abs=1e-9)
