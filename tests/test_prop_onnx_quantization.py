#!/usr/bin/env python3
"""
tests/test_prop_onnx_quantization.py — Property-based ONNX INT8 vs FP32 rank-correlation test (Prompt 10 §1.3).

Exports a trained EarlyFlowAutoencoder to FP32 and dynamic-INT8 ONNX once per module, then feeds
randomized valid `3N+8` early-flow batches via Hypothesis and asserts that the Spearman rank
correlation between FP32 and INT8 masked reconstruction error rankings is >= 0.90 (documented floor).
"""

from __future__ import annotations

import os
import tempfile

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from scipy.stats import spearmanr

from ips.models.quantize import export_to_onnx, quantize_to_int8, score_masked_onnx
from ips.models.train import train_autoencoder


@pytest.fixture(scope="module")
def exported_onnx_pair():
    rng = np.random.default_rng(42)
    early_n = 8
    dim = 3 * early_n + 8  # 32
    x_tr = rng.uniform(0.05, 0.35, size=(160, dim)).astype(np.float32)
    x_tr[:, -1] = 1.0
    x_va = rng.uniform(0.05, 0.35, size=(40, dim)).astype(np.float32)
    x_va[:, -1] = 1.0

    ae, _ = train_autoencoder(x_tr, x_va, input_dim=dim, epochs=25, seed=42)
    tmp_dir = tempfile.mkdtemp(prefix="prop_onnx_")
    fp32_p = os.path.join(tmp_dir, "ae_fp32.onnx")
    int8_p = os.path.join(tmp_dir, "ae_int8.onnx")
    export_to_onnx(ae, dim, fp32_p)
    quantize_to_int8(fp32_p, int8_p)
    return fp32_p, int8_p, dim


@given(seed=st.integers(min_value=1, max_value=100_000))
@settings(max_examples=25, deadline=None)
def test_prop_onnx_int8_vs_fp32_spearman_rank_correlation(exported_onnx_pair, seed):
    """On random mixed-scale early-flow inputs, INT8 vs FP32 reconstruction error Spearman rho >= 0.90."""
    fp32_p, int8_p, dim = exported_onnx_pair
    rng = np.random.default_rng(seed)

    # Generate 40 flows spanning tight benign-like values up to large anomaly values so scores have spread
    scales = np.linspace(0.05, 1.40, 40, dtype=np.float32)[:, None]
    x_batch = np.clip(rng.normal(loc=scales, scale=0.05, size=(40, dim)), 0.0, 1.5).astype(np.float32)
    vlen_choices = rng.choice(np.array([0.25, 0.5, 0.75, 1.0], dtype=np.float32), size=40)
    x_batch[:, -1] = vlen_choices

    s_fp32 = score_masked_onnx(fp32_p, x_batch)
    s_int8 = score_masked_onnx(int8_p, x_batch)
    assert np.all(np.isfinite(s_fp32)) and np.all(np.isfinite(s_int8))

    rho, _ = spearmanr(s_fp32, s_int8)
    assert float(rho) >= 0.90, f"INT8 vs FP32 Spearman rank correlation dropped to {rho:.4f} (< 0.90)"
