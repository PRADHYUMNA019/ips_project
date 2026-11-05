#!/usr/bin/env python3
"""
tests/test_drift_guard.py — V1 unit tests for WP8 (periodicity.py, guard.py, scenarios.py).
"""
import os
import numpy as np
import pytest

from ips.drift.periodicity import analyze_periodicity, SlowC2Tracker
from ips.drift.guard import PoisoningAwareDriftGuard, GuardConfig
from ips.drift.scenarios import (
    _make_anchor_and_canary,
    run_method_on_scenario,
    run_all_drift_scenarios,
)


def test_periodicity_and_slow_c2_tracker():
    """Verify periodicity analyzer and SlowC2Tracker distinguish periodic C2 from Poisson traffic (N4)."""
    rng = np.random.default_rng(42)

    # Periodic 60s beacon with 10% jitter
    beacon_iats = rng.uniform(54.0, 66.0, size=15).tolist()
    res_per = analyze_periodicity(beacon_iats)
    assert res_per["is_periodic"] is True
    assert res_per["cv"] < 0.20

    # Exponential (Poisson) inter-arrivals -> CV ~ 1.0 -> aperiodic
    exp_iats = rng.exponential(scale=60.0, size=30).tolist()
    res_aper = analyze_periodicity(exp_iats)
    assert res_aper["is_periodic"] is False

    # SlowC2Tracker host-pair tracking
    tracker = SlowC2Tracker(min_connections=8, cv_threshold=0.35)
    t_c2 = 1000.0
    last_out = None
    for _ in range(10):
        t_c2 += float(rng.uniform(28.0, 32.0))
        last_out = tracker.record_connection("10.0.1.4", "198.51.100.9", 443, t_c2)
    assert last_out is not None
    assert last_out["is_c2_beacon"] is True


def test_g2_small_class_limitation_and_rollback():
    """Verify G2 rejects small classes (<3 devices, e.g. 2 cameras) and rollback restores prev_threshold."""
    anchor, canary, init_t = _make_anchor_and_canary(42)
    # Camera class has only 2 devices -> G2 must report REJECTED_G2_UNAVAILABLE_SMALL_CLASS
    guard_cam = PoisoningAwareDriftGuard(
        device_class="camera",
        class_devices=["cam-01", "cam-02"],
        initial_threshold=init_t,
        anchor_benign_scores=anchor,
        canary_dev_attack_scores=canary,
        config=GuardConfig(min_persistence_windows=1),
    )
    win = [
        {"device_id": "cam-01", "score": 0.22, "iat_ms": 400.0, "is_attack": False},
        {"device_id": "cam-02", "score": 0.22, "iat_ms": 650.0, "is_attack": False},
    ] * 10
    res = guard_cam.evaluate_window(win, mode="guarded")
    assert res["status"] == "REJECTED_G2_UNAVAILABLE_SMALL_CLASS"
    assert res["adapted"] is False

    # Verify post-update rollback when alert rate spikes
    guard_cam.prev_threshold = 0.165
    guard_cam.threshold = 0.120
    rb = guard_cam.check_post_update_health(np.array([0.14, 0.15, 0.15, 0.16, 0.11]))
    assert rb["rolled_back"] is True
    assert guard_cam.threshold == pytest.approx(0.165)


def test_s1_benign_drift_and_s3_boiling_frog_and_s4_coordinated(tmp_path):
    """Verify S1 benign adaptation, S3 single-device poisoning rejection, and S4 coordinated G2 bypass + G4 defense."""
    df = run_all_drift_scenarios(str(tmp_path), is_smoke=True)
    assert os.path.exists(str(tmp_path / "drift_metrics.csv"))
    assert os.path.exists(str(tmp_path / "figures" / "s1_benign_drift.png"))
    assert os.path.exists(str(tmp_path / "figures" / "s3_boiling_frog.png"))
    assert os.path.exists(str(tmp_path / "figures" / "s4_coordinated_poisoning.png"))

    # S1: Guarded adapts to benign firmware shift and achieves much lower FPR than static
    s1_static = df[(df["scenario"] == "S1_benign_firmware_step") & (df["method"] == "static")].iloc[0]
    s1_guarded = df[(df["scenario"] == "S1_benign_firmware_step") & (df["method"] == "guarded")].iloc[0]
    assert s1_guarded["post_drift_benign_fpr"] < s1_static["post_drift_benign_fpr"]
    assert s1_guarded["post_drift_attack_tpr"] >= 0.95

    # S3: Plain ADWIN gets poisoned (attack TPR drops), while Guarded rejects poisoning and keeps TPR >= 0.95
    s3_plain = df[(df["scenario"] == "S3_single_device_boiling_frog") & (df["method"] == "plain_adwin_retrain")].iloc[0]
    s3_guarded = df[(df["scenario"] == "S3_single_device_boiling_frog") & (df["method"] == "guarded")].iloc[0]
    assert s3_guarded["post_drift_attack_tpr"] >= 0.95
    assert s3_plain["post_drift_attack_tpr"] < 0.25
    assert s3_guarded["guard_rejections"] > 0

    # S4: Coordinated compromise of 3/4 sensors defeats G1+G2+G3 (so no_G4 gets poisoned),
    # while full Guarded (with G4 canary validation + bounded step) preserves higher attack TPR!
    s4_no_g4 = df[(df["scenario"] == "S4_coordinated_multi_device_poisoning") & (df["method"] == "no_G4")].iloc[0]
    s4_guarded = df[(df["scenario"] == "S4_coordinated_multi_device_poisoning") & (df["method"] == "guarded")].iloc[0]
    assert s4_guarded["post_drift_attack_tpr"] > s4_no_g4["post_drift_attack_tpr"]

    # C3 & B5: Verify evasion_cost_curve.csv and cesnet_natural_drift.csv were generated
    assert (tmp_path / "evasion_cost_curve.csv").exists()
    assert (tmp_path / "figures" / "evasion_cost_curve.png").exists()
    assert (tmp_path / "cesnet_natural_drift.csv").exists()


def test_cost_of_evasion_and_cesnet_drift_c3_b5(tmp_path):
    """C3 & B5: Verify adaptive-attacker cost-of-evasion curve and CESNET natural drift (no G2)."""
    from ips.drift.evasion_cost import (
        run_cost_of_evasion_experiment,
        generate_adaptive_boiling_frog_sequence,
    )
    from ips.drift.scenarios import evaluate_cesnet_natural_drift

    ev_df = run_cost_of_evasion_experiment(out_dir=str(tmp_path), budget_q=40, is_smoke=True)
    assert len(ev_df) == 12
    # Full defense (Progressive + Tier-2 + Guard) must achieve >= detection rate of Single-Window N=12
    assert (ev_df["det_progressive_plus_tier2_guard"] >= ev_df["det_single_n12"]).all()

    bf_seq = generate_adaptive_boiling_frog_sequence(n_steps=6)
    assert len(bf_seq) == 6
    assert bf_seq[-1]["target_goodput_kbps"] > bf_seq[0]["target_goodput_kbps"]

    ces_df = evaluate_cesnet_natural_drift(out_dir=str(tmp_path), is_smoke=True)
    assert len(ces_df) == 24  # 8 weeks * 3 methods
    assert (ces_df["g2_applicable"] == False).all()


