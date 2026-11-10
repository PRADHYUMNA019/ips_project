#!/usr/bin/env python3
"""
tests/test_models.py — Unit tests for ML models, EVT thresholding, and quantization.
"""
import os
import math
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
    # B6 / M7: Assert method is evt_gpd_pot and verify POT formula kills sign-flip mutant M7
    assert res["method"] == "evt_gpd_pot"
    ratio = (0.001 * float(res["N"])) / float(res["N_u"])
    term = math.pow(ratio, -res["xi"]) - 1.0
    expected_t = res["u"] + (res["sigma"] / res["xi"]) * term
    assert pytest.approx(res["threshold"], 1e-6) == expected_t


def test_evt_small_sample_fallback():
    """Verify that samples < 50 trigger graceful empirical quantile fallback."""
    tiny_scores = np.array([0.01, 0.02, 0.03, 0.05, 0.10])
    res = fit_evt_threshold(tiny_scores, target_fpr=0.01)
    assert "fallback" in res["method"]
    assert np.isfinite(res["threshold"])


def test_evt_known_answer_exponential_tail_b6():
    """B6: Known-answer test fitting EVT GPD on Exponential(1) samples with analytical quantile -ln(q)."""
    np.random.seed(42)
    # Samples drawn from Exponential(1) where true survival is P(X > x) = exp(-x)
    samples = np.random.exponential(scale=1.0, size=2000)
    target_q = 1e-3
    res = fit_evt_threshold(samples, target_fpr=target_q, high_quantile=0.90)

    fitted_threshold = res["threshold"]
    analytical_quantile = -np.log(target_q)  # -ln(1e-3) = 6.907755...

    rel_error = abs(fitted_threshold - analytical_quantile) / analytical_quantile
    assert rel_error < 0.15, (
        f"EVT fitted threshold {fitted_threshold:.4f} deviated by {rel_error:.2%} "
        f"from analytical quantile {analytical_quantile:.4f} (> 15% tolerance)"
    )
    assert fitted_threshold == pytest.approx(analytical_quantile, rel=0.15)



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


def test_train_and_eval_pipeline_runs_only():
    """Verify end-to-end train_pipeline and run_offline_evaluation runs without crashing on smoke data (B5)."""
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
        assert os.path.exists(os.path.join(out_dir, "progressive_pareto.csv"))


def test_autoencoder_separates_synthetic_clusters():
    """B5: Non-tautological test asserting autoencoder achieves AUROC >= 0.90 on separable synthetic clusters."""
    try:
        import torch
    except ImportError:
        pytest.skip("PyTorch not installed")
    from scipy.stats import mannwhitneyu
    from ips.models.autoencoder import EarlyFlowAutoencoder

    torch.manual_seed(42)
    np.random.seed(42)
    d = 16

    # Benign cluster around 0.1, anomaly cluster around 2.0
    x_train_benign = np.random.normal(0.1, 0.05, size=(200, d)).astype(np.float32)
    x_test_benign = np.random.normal(0.1, 0.05, size=(50, d)).astype(np.float32)
    x_test_attack = np.random.normal(2.0, 0.2, size=(50, d)).astype(np.float32)

    ae = EarlyFlowAutoencoder(input_dim=d)
    opt = torch.optim.Adam(ae.parameters(), lr=0.01)
    x_t = torch.from_numpy(x_train_benign)

    for _ in range(30):
        opt.zero_grad()
        loss = torch.mean((ae(x_t) - x_t) ** 2)
        loss.backward()
        opt.step()

    mse_ben, _ = ae.get_reconstruction_error(x_test_benign)
    mse_atk, _ = ae.get_reconstruction_error(x_test_attack)

    u_stat = mannwhitneyu(mse_atk, mse_ben).statistic
    auroc = float(u_stat / (len(mse_atk) * len(mse_ben)))
    assert auroc >= 0.90, f"Autoencoder failed to separate clusters: AUROC={auroc:.4f}"


def test_split_conformal_regime_and_alpha_budget():
    """C9 & C1: Verify split-conformal regime boundary alpha >= 1/(n+1) and checkpoint alpha spending."""
    from ips.models.evt import compute_split_conformal_threshold, allocate_checkpoint_alpha_budget

    scores = np.linspace(0.01, 1.0, 99)  # n=99 -> min_supported_alpha = 1/(99+1) = 0.01
    res_valid = compute_split_conformal_threshold(scores, target_fpr=0.05)
    assert res_valid["valid_regime"] is True
    assert pytest.approx(res_valid["min_supported_alpha"], 1e-6) == 0.01

    # B4 (DEF-07 / M8): Exact finite-sample order statistic test
    # 99 scores evenly spaced from 0.01 to 0.99, alpha=0.1
    # k = ceil((99 + 1) * (1.0 - 0.1)) = 90 -> score[89] == 0.90
    scores_99 = np.linspace(0.01, 0.99, 99)
    res_b4 = compute_split_conformal_threshold(scores_99, target_fpr=0.1)
    assert res_b4["valid_regime"] is True
    assert res_b4["order_stat_idx"] == 90
    assert res_b4["threshold"] == pytest.approx(0.90, abs=1e-5)

    res_invalid = compute_split_conformal_threshold(scores, target_fpr=0.001)  # < 0.01
    assert res_invalid["valid_regime"] is False

    eq = allocate_checkpoint_alpha_budget(0.003, [4, 8, 16], scheme="equal")
    assert pytest.approx(sum(eq.values()), 1e-9) == 0.003
    assert pytest.approx(eq[4], 1e-9) == 0.001

    fl = allocate_checkpoint_alpha_budget(0.007, [4, 8, 16], scheme="front_loaded")
    assert pytest.approx(sum(fl.values()), 1e-9) == 0.007
    assert fl[4] > fl[8] > fl[16]


def test_contamination_study_and_trimmed_loss(tmp_path):
    """C12: Verify training-set contamination study and trimmed-loss mitigation."""
    from ips.smoke.synth import generate_smoke_dataset
    from ips.eval.contamination import run_contamination_study

    df_tr = generate_smoke_dataset(
        n_benign=120, n_attack=40, early_n=8, session_id="smoke_c12_tr",
        out_csv=str(tmp_path / "tr.csv"), seed=301
    )
    df_cal = generate_smoke_dataset(
        n_benign=80, n_attack=0, early_n=8, session_id="smoke_c12_cal",
        out_csv=str(tmp_path / "cal.csv"), seed=302
    )
    df_te = generate_smoke_dataset(
        n_benign=80, n_attack=40, early_n=8, session_id="smoke_c12_te",
        out_csv=str(tmp_path / "te.csv"), seed=303
    )

    res_df = run_contamination_study(
        df_tr, df_cal, df_te,
        early_n=8,
        contamination_rates=(0.0, 0.02, 0.05),
        trim_pct=0.05,
        epochs=4,
        seed=42,
        out_dir=str(tmp_path),
    )
    assert len(res_df) == 6  # 3 rates * 2 methods (standard_mse, trimmed_5pct)
    assert set(res_df["training_method"].unique()) == {"standard_mse", "trimmed_5pct"}
    assert (tmp_path / "contamination_study.csv").exists()


def test_short_flow_masked_padding_invariance_c1():
    """
    C1 (Prompt 6 §7): Verify that for a short flow (valid_len = 4 < early_n = 12),
    reconstruction loss and anomaly score are computed strictly over positions < valid_len,
    and changing padded positions (>= valid_len) does NOT change the anomaly score.
    """
    try:
        import torch
    except ImportError:
        pytest.skip("PyTorch not installed")
    from ips.features import build_early_vector
    from ips.models.autoencoder import EarlyFlowAutoencoder

    early_n = 12
    input_dim = 3 * early_n + 8  # 44
    torch.manual_seed(42)
    ae = EarlyFlowAutoencoder(input_dim=input_dim)

    # Short flow with valid_len = 4 (packets 0..3 only; positions 4..11 are padding)
    vec_zero_padded = build_early_vector(
        sizes=[200, 150, 300, 120],
        dirs=[0, 1, 0, 1],
        iat_ms_list=[10.0, 15.0, 20.0],
        early_n=early_n,
    )
    # Create a copy where all padded slots (size_4..11, dir_4..11, log_iat_3..10) are perturbed
    vec_perturbed_pad = vec_zero_padded.copy()
    vec_perturbed_pad[4:early_n] = 0.99                  # perturb padded sizes
    vec_perturbed_pad[early_n + 4 : 2 * early_n] = 1.0   # perturb padded dirs
    vec_perturbed_pad[2 * early_n + 3 : 3 * early_n - 1] = 6.5  # perturb padded log_iats

    x_batch = np.stack([vec_zero_padded, vec_perturbed_pad], axis=0)
    scores, sq_err = ae.get_reconstruction_error(x_batch)

    # 1. Anomaly score must be invariant to padding values
    assert scores[0] == pytest.approx(scores[1], abs=1e-7), (
        f"Short-flow score changed when padding values changed: {scores[0]:.6f} vs {scores[1]:.6f}"
    )
    # 2. Squared error on padded positions (>= valid_len) must be strictly zero
    assert np.all(sq_err[:, 4:early_n] == 0.0), "Padded size slots must have zero masked squared error"
    assert np.all(sq_err[:, early_n + 4 : 2 * early_n] == 0.0), "Padded dir slots must have zero masked squared error"
    assert np.all(sq_err[:, 2 * early_n + 3 : 3 * early_n - 1] == 0.0), "Padded log_iat slots must have zero masked squared error"



