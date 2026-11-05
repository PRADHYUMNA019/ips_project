#!/usr/bin/env python3
"""
tests/test_models.py — Unit tests for ML models, EVT thresholding, and quantization.
"""
import os
import json
import tempfile
import pytest
import numpy as np

from ips.models.evt import (
    fit_evt_threshold,
    compute_3sigma_threshold,
    compute_empirical_threshold,
    clopper_pearson_ci,
)
from ips.models.autoencoder import (
    EarlyFlowAutoencoder,
    KitsuneStyleEnsemble,
    explain_anomaly,
)
from ips.features import get_feature_names


def test_clopper_pearson_rule_of_three():
    """Verify that for 0 false positives in 3000 samples, CP upper bound <= 0.0015 (Rule of Three ~ 3/N)."""
    low, high = clopper_pearson_ci(k=0, n=3000, alpha=0.05)
    assert low == 0.0
    # Rule of three approximation: ~ 3/3000 = 0.001 (exact Clopper-Pearson ~ 0.00123)
    assert 0.0009 <= high <= 0.0015


def test_evt_gpd_fitting_and_threshold():
    """Verify Peaks-Over-Threshold GPD fitting on simulated heavy-tailed scores."""
    np.random.seed(42)
    # Generate 500 benign scores with positive skew (exponential tail)
    base = np.random.exponential(scale=0.05, size=500)

    res = fit_evt_threshold(base, target_fpr=0.001, high_quantile=0.90)
    assert "threshold" in res
    assert res["threshold"] > res["u"]
    assert res["N"] == 500
    assert res["N_u"] > 0
    assert np.isfinite(res["threshold"])
    assert "three_sigma" in res
    assert "empirical_q" in res


def test_evt_small_sample_fallback():
    """Verify that samples < 50 trigger graceful empirical quantile fallback."""
    tiny_scores = np.array([0.01, 0.02, 0.03, 0.05, 0.10])
    res = fit_evt_threshold(tiny_scores, target_fpr=0.01)
    assert "fallback" in res["method"]
    assert np.isfinite(res["threshold"])


def test_autoencoder_forward_and_explainability():
    """Verify PyTorch Autoencoder forward pass, reconstruction error, and top-3 explanations."""
    try:
        import torch
    except ImportError:
        pytest.skip("PyTorch not installed")

    input_dim = 44  # 3*12 + 8
    model = EarlyFlowAutoencoder(input_dim=input_dim)
    model.eval()

    dummy_x = np.random.uniform(0.0, 1.0, size=(5, input_dim)).astype(np.float32)
    mse, sq_err = model.get_reconstruction_error(dummy_x)

    assert mse.shape == (5,)
    assert sq_err.shape == (5, input_dim)
    assert np.all(mse >= 0.0)

    # Test explainability on first sample
    feat_names = get_feature_names(early_n=12)
    explanations = explain_anomaly(sq_err[0], feat_names, top_k=3)

    assert len(explanations) == 3
    assert "feature" in explanations[0]
    assert "squared_error" in explanations[0]
    assert explanations[0]["squared_error"] >= explanations[1]["squared_error"]
    assert explanations[1]["squared_error"] >= explanations[2]["squared_error"]


def test_kitsune_style_ensemble():
    """Verify Kitsune-style sub-network grouping and scoring."""
    try:
        import torch
    except ImportError:
        pytest.skip("PyTorch not installed")

    ensemble = KitsuneStyleEnsemble(early_n=12)
    dummy_x = np.random.uniform(0.0, 1.0, size=(4, 44)).astype(np.float32)
    scores = ensemble.score(dummy_x)
    assert scores.shape == (4,)
    assert np.all(scores >= 0.0)


def test_onnx_export_and_int8_quantization():
    """Verify ONNX export, dynamic INT8 quantization, and latency benchmark."""
    try:
        import torch
        import onnx
        import onnxruntime as ort
    except ImportError:
        pytest.skip("torch, onnx, or onnxruntime missing")

    from ips.models.quantize import export_to_onnx, quantize_to_int8, benchmark_onnx_latency, compare_fp32_int8

    input_dim = 44
    model = EarlyFlowAutoencoder(input_dim=input_dim)

    with tempfile.TemporaryDirectory() as tmp_dir:
        fp32_path = os.path.join(tmp_dir, "model_fp32.onnx")
        int8_path = os.path.join(tmp_dir, "model_int8.onnx")

        export_to_onnx(model, input_dim=input_dim, onnx_path=fp32_path)
        assert os.path.exists(fp32_path)

        quantize_to_int8(fp32_path, int8_path)
        assert os.path.exists(int8_path)

        lat = benchmark_onnx_latency(int8_path, input_dim=input_dim, n_warmup=5, n_iter=20)
        assert "p50_us" in lat
        assert lat["p50_us"] > 0

        dummy_batch = np.random.uniform(0.0, 1.0, size=(20, input_dim)).astype(np.float32)
        comp = compare_fp32_int8(fp32_path, int8_path, input_dim, dummy_batch)
        assert comp["fp32_size_kb"] > 0
        assert comp["int8_size_kb"] > 0
        assert comp["max_abs_diff"] < 0.2  # INT8 fidelity check


def test_train_and_eval_pipeline_smoke():
    """Verify end-to-end train_pipeline and run_offline_evaluation on smoke data."""
    from ips.smoke.synth import generate_smoke_dataset
    from ips.models.train import train_pipeline
    from ips.models.eval_offline import run_offline_evaluation

    with tempfile.TemporaryDirectory() as tmp_dir:
        smoke_csv = os.path.join(tmp_dir, "smoke_test_data.csv")
        model_dir = os.path.join(tmp_dir, "models")
        out_dir = os.path.join(tmp_dir, "smoke_out")

        generate_smoke_dataset(
            n_benign=200, n_attack=50, early_n=12,
            session_id="test_smoke", out_csv=smoke_csv
        )
        card = train_pipeline(
            data_path=smoke_csv, early_n=12, epochs=4, seed=42, model_dir=model_dir
        )
        assert card["data_source"] == "synthetic-smoke"
        assert os.path.exists(card["onnx_int8_path"])

        card_path = os.path.join(model_dir, "model_card.json")
        metrics = run_offline_evaluation(
            test_data_path=smoke_csv,
            model_card_path=card_path,
            out_dir=out_dir,
            run_n_sweep=False,
        )
        assert metrics["source"] == "synthetic-smoke"
        assert os.path.exists(os.path.join(out_dir, "eval_models.csv"))
        assert os.path.exists(os.path.join(out_dir, "calibration_curve.csv"))
        assert os.path.exists(os.path.join(out_dir, "quantization_table.csv"))

