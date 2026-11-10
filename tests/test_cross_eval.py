#!/usr/bin/env python3
"""
tests/test_cross_eval.py — Cross-domain evaluation leakage guards for IoT-23 Benign and TQH-C2 (B7).
"""
import numpy as np
import pytest
import ips.eval.cross_domain as cd
from ips.eval.cross_domain import evaluate_cross_domain_pair


def test_iot23_tqh_c2_cross_domain_train_eval_isolation(monkeypatch):
    """
    B7: Import the real cross-domain entry point from ips/eval/cross_domain.py,
    provide a source training/calibration set and a target set (synthetic stand-in
    for IoT-23 Benign / TQH-C2) with a sentinel wrapper that raises if any target
    row reaches model fit, scaler fit, threshold calibration, or hyperparameter
    selection, and assert that scaler statistics equal those computed on TRAIN alone.
    """
    rng = np.random.default_rng(101)
    early_n = 8
    dim = 3 * early_n + 8  # 32 features

    # Source domain (Own Testbed Benign): centered around 0.20
    x_source_train = rng.normal(0.20, 0.04, size=(120, dim)).astype(np.float32)
    x_source_cal = rng.normal(0.20, 0.04, size=(80, dim)).astype(np.float32)
    x_source_test = rng.normal(0.20, 0.04, size=(60, dim)).astype(np.float32)

    # Target domain (IoT-23 Benign / TQH-C2 stand-in): distinct distribution centered around 0.75
    x_target_iot23 = rng.normal(0.75, 0.05, size=(60, dim)).astype(np.float32)
    # Tag target rows with exact byte fingerprints so any row reaching fit/calib/scaler is caught
    target_row_hashes = {row.tobytes() for row in x_target_iot23}

    stages_checked = []

    def sentinel_check_matrix(stage_name: str, arr: np.ndarray):
        stages_checked.append(stage_name)
        arr_f32 = np.asarray(arr, dtype=np.float32)
        if arr_f32.ndim == 2:
            for r in arr_f32:
                if r.tobytes() in target_row_hashes:
                    raise RuntimeError(
                        f"TARGET DOMAIN LEAKAGE (IoT-23 / TQH-C2): target row reached '{stage_name}'!"
                    )

    # Wrap train_autoencoder and fit_evt_threshold in ips.eval.cross_domain with sentinel checks
    orig_train_ae = cd.train_autoencoder
    orig_fit_evt = cd.fit_evt_threshold

    def guarded_train_ae(x_train, x_val, *args, **kwargs):
        sentinel_check_matrix("model_fit", x_train)
        sentinel_check_matrix("hyperparam_selection_val", x_val)
        return orig_train_ae(x_train, x_val, *args, **kwargs)

    cal_scores_expected_len = len(x_source_cal)

    def guarded_fit_evt(scores, *args, **kwargs):
        stages_checked.append("threshold_calibration")
        if len(scores) != cal_scores_expected_len:
            raise RuntimeError(
                f"TARGET DOMAIN LEAKAGE: calibration score count {len(scores)} != source cal {cal_scores_expected_len}"
            )
        return orig_fit_evt(scores, *args, **kwargs)

    monkeypatch.setattr(cd, "train_autoencoder", guarded_train_ae)
    monkeypatch.setattr(cd, "fit_evt_threshold", guarded_fit_evt)

    res = evaluate_cross_domain_pair(
        x_source_train=x_source_train,
        x_source_cal=x_source_cal,
        x_source_test=x_source_test,
        x_target_benign=x_target_iot23,
        early_n=early_n,
        target_fpr=0.05,
        direction_name="testbed_to_iot23_tqh_c2",
        epochs=3,
        seed=42,
        fit_hook=sentinel_check_matrix,
    )

    # Assert all 4 fitting/calibration stages were verified by the sentinel
    assert "scaler_fit" in stages_checked
    assert "model_fit" in stages_checked
    assert "hyperparam_selection_val" in stages_checked
    assert "threshold_calibration" in stages_checked

    # Assert scaler statistics equal those computed on x_source_train ALONE
    expected_mean = np.mean(x_source_train, axis=0)
    expected_std = np.std(x_source_train, axis=0)
    assert "scaler_mean" in res and "scaler_std" in res
    np.testing.assert_allclose(res["scaler_mean"], expected_mean, rtol=1e-6, atol=1e-6)
    np.testing.assert_allclose(res["scaler_std"], expected_std, rtol=1e-6, atol=1e-6)

    # Verify that if a target row from IoT-23/TQH-C2 leaks into train or cal, the guard raises
    x_contaminated_train = x_source_train.copy()
    x_contaminated_train[0] = x_target_iot23[0]
    with pytest.raises((RuntimeError, ValueError), match="LEAKAGE"):
        evaluate_cross_domain_pair(
            x_source_train=x_contaminated_train,
            x_source_cal=x_source_cal,
            x_source_test=x_source_test,
            x_target_benign=x_target_iot23,
            early_n=early_n,
            epochs=2,
            fit_hook=sentinel_check_matrix,
        )
