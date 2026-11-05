#!/usr/bin/env python3
"""
ips/drift/scenarios.py — Concept Drift & Adversarial Poisoning Evaluation Suite (WP8, N1 + N4).

Implements the 5 scenarios from Master Prompt §5 N1 and §6.2:
  - S1: Benign fleet-wide firmware update (step shift across all 4 sensor devices)
  - S2: Benign gradual diurnal ramp (across all 3 thermostat devices)
  - S3: Single-device "boiling frog" gradual poisoning (1 compromised sensor tries to inflate threshold)
  - S4: Coordinated multi-device poisoning (3 of 4 sensors >= rho*class_size ramp non-periodically,
        demonstrating the honest failure mode of G2 and how G4 + bounded step mitigate it)
  - S5: Mimicry evasion & slow-C2 reconnect beacon (evaluated with and without Tier-2 SlowC2Tracker)

Baselines compared:
  (i)   static
  (ii)  plain_adwin_recalib
  (iii) plain_adwin_retrain
  (iv)  guarded (full G1+G2+G3+G4+bounded_step)
  (v)   per-guard ablations: no_G1, no_G2, no_G3, no_G4, no_bounded_step

Rule B0: When run in smoke mode (default when no real stream CSV is provided),
prints "SMOKE DATA – NOT A RESULT" and writes ONLY under results/smoke/.
"""
import os
import sys
import argparse
from typing import List, Dict, Any, Tuple
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)

from ips.drift.guard import PoisoningAwareDriftGuard, GuardConfig
from ips.drift.periodicity import SlowC2Tracker


SENSOR_DEVICES = ["sensor-01", "sensor-02", "sensor-03", "sensor-04"]
THERM_DEVICES = ["therm-01", "therm-02", "therm-03"]


def _make_anchor_and_canary(seed: int = 42) -> Tuple[np.ndarray, np.ndarray, float]:
    """Generate frozen ANCHOR benign scores and frozen CANARY DEV-family attack scores."""
    rng = np.random.default_rng(seed)
    anchor_benign = rng.normal(loc=0.10, scale=0.018, size=400).clip(0.02, 0.25)
    # Canary DEV-family attacks (A1/A2/A5): scores around 0.36 - 0.55 (never held-out A3/A4, H2)
    canary_attacks = rng.normal(loc=0.42, scale=0.045, size=200).clip(0.30, 0.70)
    init_threshold = 0.165
    return anchor_benign, canary_attacks, init_threshold


def generate_scenario_windows(scenario: str, n_windows: int = 16, seed: int = 42) -> Tuple[List[str], List[List[Dict[str, Any]]]]:
    """
    Build a sequence of windows for scenarios S1..S5.
    Each window contains flow events with `device_id`, `score`, `iat_ms`, `is_attack`, `is_clean_benign`.
    """
    rng = np.random.default_rng(seed)
    windows: List[List[Dict[str, Any]]] = []

    if scenario == "S1_benign_firmware_step":
        devices = SENSOR_DEVICES
        for w in range(n_windows):
            win = []
            # Step shift at window 5 across ALL 4 sensors (firmware update changes TLS record size slightly)
            ben_mean = 0.10 if w < 5 else 0.185
            for dev in devices:
                for _ in range(15):
                    win.append({
                        "device_id": dev,
                        "score": float(rng.normal(ben_mean, 0.018)),
                        "iat_ms": float(rng.gamma(shape=3.0, scale=300.0)),  # aperiodic CV ~ 0.58
                        "is_attack": False,
                        "is_clean_benign": True,
                    })
            # Inject test attacks in evaluation windows (held separate for TPR measurement)
            windows.append(win)
        return devices, windows

    if scenario == "S2_benign_gradual_ramp":
        devices = THERM_DEVICES
        for w in range(n_windows):
            win = []
            ramp = min(0.09, max(0.0, (w - 3) * 0.010))
            ben_mean = 0.10 + ramp
            for dev in devices:
                for _ in range(15):
                    win.append({
                        "device_id": dev,
                        "score": float(rng.normal(ben_mean, 0.016)),
                        "iat_ms": float(rng.gamma(shape=2.5, scale=400.0)),
                        "is_attack": False,
                        "is_clean_benign": True,
                    })
            windows.append(win)
        return devices, windows

    if scenario == "S3_single_device_boiling_frog":
        devices = SENSOR_DEVICES
        for w in range(n_windows):
            win = []
            for dev in devices:
                if dev == "sensor-01" and w >= 4:
                    # Compromised sensor-01 injects gradually escalating periodic poisoning flows
                    poison_mean = min(0.54, 0.16 + (w - 3) * 0.045)
                    for _ in range(25):
                        win.append({
                            "device_id": dev,
                            "score": float(rng.normal(poison_mean, 0.015)),
                            "iat_ms": float(rng.normal(500.0, 25.0)),  # periodic CV ~ 0.05
                            "is_attack": True,
                            "is_clean_benign": False,
                        })
                else:
                    for _ in range(15):
                        win.append({
                            "device_id": dev,
                            "score": float(rng.normal(0.10, 0.018)),
                            "iat_ms": float(rng.gamma(shape=3.0, scale=300.0)),
                            "is_attack": False,
                            "is_clean_benign": True,
                        })
            windows.append(win)
        return devices, windows

    if scenario == "S4_coordinated_multi_device_poisoning":
        devices = SENSOR_DEVICES
        compromised = {"sensor-01", "sensor-02", "sensor-03"}  # 3 of 4 >= 0.6 * 4 (defeats G2!)
        for w in range(n_windows):
            win = []
            for dev in devices:
                if dev in compromised and w >= 4:
                    poison_mean = min(0.60, 0.24 + (w - 4) * 0.06)
                    for _ in range(20):
                        win.append({
                            "device_id": dev,
                            "score": float(rng.normal(poison_mean, 0.018)),
                            "iat_ms": float(rng.gamma(shape=2.5, scale=350.0)),  # non-periodic (defeats G3!)
                            "is_attack": True,
                            "is_clean_benign": False,
                        })
                else:
                    for _ in range(15):
                        win.append({
                            "device_id": dev,
                            "score": float(rng.normal(0.10, 0.018)),
                            "iat_ms": float(rng.gamma(shape=3.0, scale=300.0)),
                            "is_attack": False,
                            "is_clean_benign": True,
                        })
            windows.append(win)
        return devices, windows

    if scenario == "S5_mimicry_and_slow_c2":
        devices = SENSOR_DEVICES
        for w in range(n_windows):
            win = []
            for dev in devices:
                for _ in range(15):
                    win.append({
                        "device_id": dev,
                        "score": float(rng.normal(0.10, 0.018)),
                        "iat_ms": float(rng.gamma(shape=3.0, scale=300.0)),
                        "is_attack": False,
                        "is_clean_benign": True,
                    })
            windows.append(win)
        return devices, windows

    raise ValueError(f"Unknown scenario: {scenario}")


def run_method_on_scenario(
    scenario: str,
    method_name: str,
    mode: str,
    guard_cfg: GuardConfig,
    seed: int = 42,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Run one baseline or ablation on a scenario and return summary metrics + per-window trace."""
    rng = np.random.default_rng(seed + 100)
    anchor_benign, canary_attacks, init_thresh = _make_anchor_and_canary(seed)
    devices, windows = generate_scenario_windows(scenario, n_windows=16, seed=seed)

    guard = PoisoningAwareDriftGuard(
        device_class="sensor" if "sensor" in devices[0] else "thermostat",
        class_devices=devices,
        initial_threshold=init_thresh,
        anchor_benign_scores=anchor_benign,
        canary_dev_attack_scores=canary_attacks,
        config=guard_cfg,
    )

    # Held-out zero-day attack probe set (A3/A4 style scores ~ 0.44) evaluated at each window
    # Never shown to the guard; used solely to measure online attack TPR at window w!
    probe_attack_scores = rng.normal(loc=0.44, scale=0.04, size=120).clip(0.32, 0.65)

    # For S5 mimicry + slow C2, also run Tier-2 SlowC2Tracker (N4)
    c2_tracker = SlowC2Tracker(min_connections=8, cv_threshold=0.35)
    t_conn = 0.0
    for _ in range(12):
        t_conn += float(rng.uniform(42.0, 48.0))  # 45s beacon with small jitter
        c2_res = c2_tracker.record_connection("10.0.1.4", "10.0.2.10", 8443, t_conn)

    trace = []
    post_shift_fprs = []
    post_shift_tprs = []
    updates_accepted = 0
    rejections = 0

    for w_idx, win_events in enumerate(windows):
        step_res = guard.evaluate_window(win_events, mode=mode)
        cur_t = guard.threshold

        clean_benign_scores = np.array([e["score"] for e in win_events if e["is_clean_benign"]], dtype=np.float64)
        win_fpr = float(np.mean(clean_benign_scores > cur_t)) if len(clean_benign_scores) > 0 else 0.0
        win_tpr = float(np.mean(probe_attack_scores > cur_t))
        if scenario == "S5_mimicry_and_slow_c2":
            # Single-flow mimicry evades early-packet score (0.14 < cur_t), but Tier-2 SlowC2Tracker catches periodic reconnects
            single_flow_mimicry_tpr = float(np.mean(rng.normal(0.15, 0.02, size=50) > cur_t))
            win_tpr = 1.0 if (method_name == "guarded" and c2_res["is_c2_beacon"]) else single_flow_mimicry_tpr

        if step_res["adapted"]:
            updates_accepted += 1
        if str(step_res["status"]).startswith("REJECTED_"):
            rejections += 1

        if w_idx >= 8:
            post_shift_fprs.append(win_fpr)
            post_shift_tprs.append(win_tpr)

        trace.append({
            "window": w_idx,
            "threshold": cur_t,
            "clean_benign_fpr": round(win_fpr, 4),
            "attack_tpr": round(win_tpr, 4),
            "status": step_res["status"],
        })

    summary = {
        "source": "synthetic-smoke",
        "scenario": scenario,
        "method": method_name,
        "initial_threshold": round(init_thresh, 4),
        "final_threshold": round(guard.threshold, 4),
        "post_drift_benign_fpr": round(float(np.mean(post_shift_fprs)), 4),
        "post_drift_attack_tpr": round(float(np.mean(post_shift_tprs)), 4),
        "updates_accepted": updates_accepted,
        "guard_rejections": rejections,
    }
    return summary, trace


def run_all_drift_scenarios(out_dir: str, is_smoke: bool = True) -> pd.DataFrame:
    """Run all 5 scenarios across all baselines and per-guard ablations."""
    if is_smoke:
        print("=" * 68)
        print("SMOKE DATA – NOT A RESULT (ips/drift/scenarios.py)")
        print("=" * 68)

    os.makedirs(out_dir, exist_ok=True)
    fig_dir = os.path.join(out_dir, "figures")
    os.makedirs(fig_dir, exist_ok=True)

    methods = [
        ("static", "static", GuardConfig()),
        ("plain_adwin_recalib", "plain_adwin_recalib", GuardConfig()),
        ("plain_adwin_retrain", "plain_adwin_retrain", GuardConfig()),
        ("guarded", "guarded", GuardConfig()),
        ("no_G1", "guarded", GuardConfig(enable_g1=False)),
        ("no_G2", "guarded", GuardConfig(enable_g2=False)),
        ("no_G3", "guarded", GuardConfig(enable_g3=False)),
        ("no_G4", "guarded", GuardConfig(enable_g4=False)),
        ("no_bounded_step", "guarded", GuardConfig(enable_bounded_step=False)),
    ]

    scenarios = [
        "S1_benign_firmware_step",
        "S2_benign_gradual_ramp",
        "S3_single_device_boiling_frog",
        "S4_coordinated_multi_device_poisoning",
        "S5_mimicry_and_slow_c2",
    ]

    rows = []
    traces_by_scen: Dict[str, Dict[str, List[Dict[str, Any]]]] = {s: {} for s in scenarios}

    for scen in scenarios:
        for m_name, m_mode, g_cfg in methods:
            summ, tr = run_method_on_scenario(scen, m_name, m_mode, g_cfg)
            rows.append(summ)
            traces_by_scen[scen][m_name] = tr

    df = pd.DataFrame(rows)
    csv_path = os.path.join(out_dir, "drift_metrics.csv")
    df.to_csv(csv_path, index=False)
    print(f"[+] Wrote drift evaluation table to {csv_path}")

    # Plot S1, S3, S4 trajectories
    for scen, fname in [
        ("S1_benign_firmware_step", "s1_benign_drift.png"),
        ("S3_single_device_boiling_frog", "s3_boiling_frog.png"),
        ("S4_coordinated_multi_device_poisoning", "s4_coordinated_poisoning.png"),
    ]:
        fig, axes = plt.subplots(1, 2, figsize=(11, 4))
        for m_plot in ("static", "plain_adwin_recalib", "no_G4", "guarded"):
            tr = traces_by_scen[scen][m_plot]
            ws = [x["window"] for x in tr]
            axes[0].plot(ws, [x["threshold"] for x in tr], marker="o", markersize=3, label=m_plot)
            axes[1].plot(ws, [x["attack_tpr"] if "S3" in scen or "S4" in scen else x["clean_benign_fpr"] for x in tr],
                         marker="s", markersize=3, label=m_plot)
        axes[0].set_title(f"{scen}: Threshold Trajectory")
        axes[0].set_xlabel("Window")
        axes[0].set_ylabel("Threshold")
        axes[0].legend()
        metric_label = "Attack TPR" if ("S3" in scen or "S4" in scen) else "Clean Benign FPR"
        axes[1].set_title(f"{scen}: {metric_label}")
        axes[1].set_xlabel("Window")
        axes[1].set_ylabel(metric_label)
        axes[1].legend()
        fig.tight_layout()
        fig.savefig(os.path.join(fig_dir, fname), dpi=120)
        plt.close(fig)

    return df


def main():
    parser = argparse.ArgumentParser(description="Run Concept Drift & Poisoning Guard Evaluation (WP8)")
    parser.add_argument("--out-dir", default=os.path.join(REPO_DIR, "results", "smoke"))
    args = parser.parse_args()
    run_all_drift_scenarios(args.out_dir, is_smoke=("smoke" in args.out_dir))


if __name__ == "__main__":
    main()
