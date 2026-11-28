#!/usr/bin/env python3
"""
tests/test_prop_features.py — Property-based Hypothesis fuzz tests for feature extraction (Prompt 10 §1.3).

Invariants verified across random packet sequences (sizes 0..65535, dirs {0,1},
timestamps including equal, non-monotonic, negative deltas, and huge 10-hour gaps):
  1. Output length equals 3*N + 8 for all valid N.
  2. Every entry is finite (no NaN, no +/-inf).
  3. Every entry lies within the documented [0.0, 1.5] range.
  4. Progressive checkpoint invariance: recompute_early_matrix_for_k(df, k) and
     prefix slicing build_early_vector(sizes[:k], dirs[:k], iats[:k-1], early_n=k)
     produce identical checkpoint-k vectors regardless of packets arriving after k.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from hypothesis import given, settings
from hypothesis import strategies as st

from ips.features import (
    FEATURE_CLIP_MAX,
    build_early_vector,
    build_valid_mask_matrix,
    recompute_early_matrix_for_k,
)


@given(
    early_n=st.sampled_from([4, 8, 12, 16, 24]),
    packets=st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=65535),
            st.integers(min_value=0, max_value=1),
            st.floats(min_value=-1e6, max_value=3.6e7, allow_nan=False, allow_infinity=False),
        ),
        min_size=0,
        max_size=32,
    ),
)
@settings(max_examples=120, deadline=None)
def test_prop_feature_vector_bounds_finiteness_and_mask(early_n, packets):
    """Random packet sequences (incl. non-monotonic/negative timestamp deltas & huge gaps) stay finite in [0, 1.5]."""
    sizes = [p[0] for p in packets]
    dirs = [p[1] for p in packets]
    # Simulate non-monotonic timestamp differences as raw deltas passed to build_early_vector
    raw_ts = [p[2] for p in packets]
    iats_ms = [raw_ts[i] - raw_ts[i - 1] for i in range(1, len(raw_ts))]

    vec = build_early_vector(sizes, dirs, iats_ms, early_n=early_n)
    assert vec.shape == (3 * early_n + 8,)
    assert vec.dtype == np.float32
    assert np.all(np.isfinite(vec)), f"Non-finite feature produced: {vec}"
    assert float(np.min(vec)) >= 0.0, f"Negative feature produced: min={np.min(vec)}"
    assert float(np.max(vec)) <= FEATURE_CLIP_MAX + 1e-6, f"Feature exceeded {FEATURE_CLIP_MAX}: max={np.max(vec)}"

    mask = build_valid_mask_matrix(vec, expected_early_n=early_n)
    assert mask.shape == vec.shape
    vlen = min(len(sizes), early_n)
    assert int(np.sum(mask[:early_n])) == vlen
    assert int(np.sum(mask[early_n : 2 * early_n])) == vlen
    assert int(np.sum(mask[2 * early_n : 3 * early_n - 1])) == max(0, vlen - 1)


@given(
    packets=st.lists(
        st.tuples(
            st.integers(min_value=1, max_value=1500),
            st.integers(min_value=0, max_value=1),
            st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False),
        ),
        min_size=1,
        max_size=24,
    ),
)
@settings(max_examples=80, deadline=None)
def test_prop_progressive_checkpoint_prefix_invariance(packets):
    """Checkpoint-k features computed from a full stream equal features from the first k packets alone."""
    sizes = [p[0] for p in packets]
    dirs = [p[1] for p in packets]
    iats_ms = [p[2] for p in packets[1:]]

    for k in (4, 8, 16):
        vec_prefix = build_early_vector(sizes[:k], dirs[:k], iats_ms[: max(0, k - 1)], early_n=k)
        vec_full_truncated = build_early_vector(sizes, dirs, iats_ms, early_n=k)
        assert np.allclose(vec_prefix, vec_full_truncated, atol=1e-7), f"Checkpoint-{k} vector depended on packets beyond index {k - 1}"

    # Also verify DataFrame raw-column recomputation matches direct prefix construction
    raw_row = {"raw_valid_len": len(sizes)}
    for i, (sz, dr) in enumerate(zip(sizes, dirs)):
        raw_row[f"size_{i}"] = sz
        raw_row[f"dir_{i}"] = dr
    for i, dt in enumerate(iats_ms):
        raw_row[f"iat_{i}"] = dt
    df = pd.DataFrame([raw_row])

    for k in (4, 8, 16):
        mat_k = recompute_early_matrix_for_k(df, k)
        direct_k = build_early_vector(sizes[:k], dirs[:k], iats_ms[: max(0, k - 1)], early_n=k)
        assert np.allclose(mat_k[0], direct_k, atol=1e-6)
