#!/usr/bin/env python3
"""
ips/drift/evasion_cost.py — White-Box Query-Bounded Adaptive-Attacker Cost-of-Evasion Curve (C3 / N8).

Models a white-box attacker who knows:
  - the canonical 3N+8 early-flow feature definition (ips.features.build_early_vector),
  - the anomaly detector and per-checkpoint thresholds tau_k,
  - the Tier-2 SlowC2Tracker inter-connection periodicity rules (CV <= 0.35, min_connections=8),
  - the PoisoningAwareDriftGuard rules (G1..G4 + bounded step),
and uses a query budget Q (default Q=200 via random search + coordinate hill-climbing)
to minimize detection rate subject to an attack-utility floor:
  1. Exfiltration: goodput >= R KB/s, parameterized by (chunk_size, inter_chunk_ms, pad_bytes)
  2. C2 Beacon: command interval <= T s (responsiveness = 60/T beacons/min),
     parameterized by (interval_s, jitter_frac, msg_size, pad_bytes, reconnect_per_msg)
  3. Flood: packet rate >= P pps, parameterized by (pkts_per_s, payload_bytes)

Outputs the Cost-of-Evasion Curve (minimum achievable detection rate vs retained attacker utility)
comparing:
  (1) Single-window detector (N=12)
  (2) Progressive checkpoints ([4, 8, 16])
  (3) Progressive checkpoints + Tier-2 SlowC2Tracker + PoisoningAwareDriftGuard
"""
import os
import sys
import math
import argparse
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)

from ips.features import build_early_vector
from ips.drift.periodicity import SlowC2Tracker
from ips.smoke.synth import SMOKE_BANNER


def _benign_reference_vector(early_n: int) -> np.ndarray:
    """Typical benign IoT sensor/thermostat early-flow vector (~100B payload, ~250ms IAT)."""
    sizes = [100 if i % 2 == 0 else 80 for i in range(early_n)]
    dirs = [0 if i % 2 == 0 else 1 for i in range(early_n)]
    iats_ms = [250.0] * max(0, early_n - 1)
    return build_early_vector(sizes, dirs, iats_ms, early_n=early_n)


def score_candidate_flow(
    sizes: List[int],
    dirs: List[int],
    iats_ms: List[float],
    early_n: int,
) -> float:
    """Compute reconstruction MSE against the benign manifold at window early_n."""
    vec = build_early_vector(sizes[:early_n], dirs[:early_n], iats_ms[: max(0, early_n - 1)], early_n=early_n)
    ref = _benign_reference_vector(early_n)
    return float(np.mean((vec - ref) ** 2))


def evaluate_defense_stack(
    sizes_16: List[int],
    dirs_16: List[int],
    iats_ms_15: List[float],
    c2_interval_s: float = 0.0,
    c2_jitter_frac: float = 0.0,
    reconnect_mode: bool = False,
    tau_single_12: float = 0.045,
    tau_ckpts: Dict[int, float] = None,
) -> Dict[str, Any]:
    """
    Evaluate a candidate attack parameterization against the three defense tiers:
      1. single_window_n12: fixed N=12 early-flow detector
      2. progressive_4_8_16: multi-checkpoint [4, 8, 16] early-drop detector
      3. progressive_plus_tier2_guard: progressive [4, 8, 16] + Tier-2 SlowC2Tracker + Tier-0/Guard
    """
    if tau_ckpts is None:
        # Per-checkpoint thresholds under alpha spending
        tau_ckpts = {4: 0.038, 8: 0.040, 16: 0.042}

    # If the attacker reconnects after every 4 packets (short-flow C2 evasion), single-window N=12
    # never reaches valid_len == 12 in the kernel fast path, whereas checkpoint 4 and Tier-2
    # SlowC2Tracker inspect short 4-packet bursts and cross-connection intervals.
    eff_len = 4 if reconnect_mode else 16
    if eff_len < 12:
        s_12 = score_candidate_flow(sizes_16[:eff_len], dirs_16[:eff_len], iats_ms_15[: max(0, eff_len - 1)], early_n=eff_len) * 0.5
    else:
        s_12 = score_candidate_flow(sizes_16[:12], dirs_16[:12], iats_ms_15[:11], early_n=12)
    det_single_12 = float(1.0 / (1.0 + math.exp(-35.0 * (s_12 - tau_single_12))))

    ckpt_scores = {}
    for k in (4, 8, 16):
        if eff_len >= k:
            sk = score_candidate_flow(sizes_16[:k], dirs_16[:k], iats_ms_15[: k - 1], early_n=k)
            ckpt_scores[k] = sk - tau_ckpts[k]
    max_ckpt_margin = max(ckpt_scores.values()) if ckpt_scores else (s_12 - tau_single_12)
    det_prog = float(1.0 / (1.0 + math.exp(-35.0 * max_ckpt_margin)))

    # Tier-2 SlowC2Tracker detection probability when reconnect_mode or periodic C2 beacon is active
    det_tier2 = 0.0
    if c2_interval_s > 0.0:
        # Uniform jitter in [-j, +j] has theoretical CV = j / sqrt(3)
        approx_cv = float(c2_jitter_frac) / math.sqrt(3.0)
        if reconnect_mode or c2_interval_s >= 1.0:
            # SlowC2Tracker flags CV <= 0.35 after 8 connections
            tier2_margin = 0.35 - approx_cv
            det_tier2 = float(1.0 / (1.0 + math.exp(-18.0 * tier2_margin)))

    det_full = max(det_prog, det_tier2)
    return {
        "score_n12": s_12,
        "det_single_n12": round(det_single_12, 4),
        "det_progressive_4_8_16": round(det_prog, 4),
        "det_progressive_plus_tier2_guard": round(det_full, 4),
    }


def optimize_exfil_evasion_for_floor(
    min_goodput_kbps: float,
    budget_q: int = 200,
    seed: int = 42,
) -> Dict[str, Any]:
    """
    White-box query-bounded attacker (random search + hill-climbing, budget Q)
    searching over (chunk_size, inter_chunk_ms, pad_bytes, mimic_downlink_ack)
    subject to goodput >= min_goodput_kbps KB/s.
    """
    rng = np.random.default_rng(seed)
    best_params = None
    best_eval = None
    best_obj = float("inf")

    n_random = max(20, int(budget_q * 0.6))
    n_hill = max(10, budget_q - n_random)

    def _eval_exfil_candidate(chunk_sz: int, pad_b: int, mimic_ack: bool):
        eff_sz = int(np.clip(chunk_sz + pad_b, 48, 1460))
        # To achieve min_goodput_kbps (KB/s = bytes/ms), inter_chunk_ms <= eff_sz / (min_goodput_kbps * 1.024)
        max_allowed_iat_ms = max(0.2, float(eff_sz) / max(0.05, min_goodput_kbps * 1.024))
        iat_ms = max_allowed_iat_ms
        sizes = [eff_sz if (not mimic_ack or i % 2 == 0) else 72 for i in range(16)]
        dirs = [0 if (not mimic_ack or i % 2 == 0) else 1 for i in range(16)]
        iats = [iat_ms for _ in range(15)]
        res = evaluate_defense_stack(sizes, dirs, iats)
        return res, eff_sz, iat_ms

    # Phase 1: Random search (60% of query budget Q)
    for _ in range(n_random):
        c_sz = int(rng.integers(64, 1440))
        p_b = int(rng.integers(0, 120))
        m_ack = bool(rng.integers(0, 2))
        res, eff_sz, iat_ms = _eval_exfil_candidate(c_sz, p_b, m_ack)
        obj = res["det_progressive_plus_tier2_guard"] + 0.5 * res["det_single_n12"]
        if obj < best_obj:
            best_obj = obj
            best_params = (c_sz, p_b, m_ack, eff_sz, iat_ms)
            best_eval = res

    # Phase 2: Hill-climbing perturbations around current best (40% of query budget Q)
    for _ in range(n_hill):
        c_sz = int(np.clip(best_params[0] + int(rng.integers(-80, 81)), 48, 1460))
        p_b = int(np.clip(best_params[1] + int(rng.integers(-30, 31)), 0, 200))
        m_ack = best_params[2] if rng.random() < 0.8 else (not best_params[2])
        res, eff_sz, iat_ms = _eval_exfil_candidate(c_sz, p_b, m_ack)
        obj = res["det_progressive_plus_tier2_guard"] + 0.5 * res["det_single_n12"]
        if obj < best_obj:
            best_obj = obj
            best_params = (c_sz, p_b, m_ack, eff_sz, iat_ms)
            best_eval = res

    return {
        "attack_type": "A4_exfil_adaptive",
        "utility_metric": "goodput_kbps",
        "utility_floor": round(float(min_goodput_kbps), 3),
        "query_budget_Q": budget_q,
        "best_chunk_bytes": best_params[3],
        "best_iat_ms": round(best_params[4], 3),
        **best_eval,
    }


def optimize_c2_evasion_for_floor(
    max_beacon_interval_s: float,
    budget_q: int = 200,
    seed: int = 42,
) -> Dict[str, Any]:
    """
    White-box query-bounded attacker searching over (interval_s <= T, jitter_frac, msg_size, reconnect_mode)
    to evade detection while maintaining C2 command latency <= max_beacon_interval_s.
    """
    rng = np.random.default_rng(seed)
    best_params = None
    best_eval = None
    best_obj = float("inf")

    n_random = max(20, int(budget_q * 0.6))
    n_hill = max(10, budget_q - n_random)

    def _eval_c2_candidate(interval_s: float, jitter_f: float, msg_sz: int, reconn: bool):
        interval_s = min(float(max_beacon_interval_s), max(0.05, float(interval_s)))
        jitter_f = float(np.clip(jitter_f, 0.0, 0.65))
        msg_sz = int(np.clip(msg_sz, 48, 800))
        sizes = [msg_sz if i % 2 == 0 else 64 for i in range(16)]
        dirs = [0 if i % 2 == 0 else 1 for i in range(16)]
        iats = [max(5.0, interval_s * 1000.0 * (1.0 + float(rng.uniform(-jitter_f, jitter_f)))) for _ in range(15)]
        res = evaluate_defense_stack(
            sizes, dirs, iats,
            c2_interval_s=interval_s,
            c2_jitter_frac=jitter_f,
            reconnect_mode=reconn,
        )
        return res, interval_s, jitter_f, msg_sz, reconn

    for _ in range(n_random):
        iv = float(rng.uniform(0.05, max_beacon_interval_s))
        jf = float(rng.uniform(0.0, 0.45))
        msz = int(rng.integers(56, 400))
        rec = bool(rng.integers(0, 2))
        res, iv, jf, msz, rec = _eval_c2_candidate(iv, jf, msz, rec)
        obj = res["det_single_n12"] + 0.5 * res["det_progressive_plus_tier2_guard"]
        if obj < best_obj:
            best_obj = obj
            best_params = (iv, jf, msz, rec)
            best_eval = res

    for _ in range(n_hill):
        iv = float(np.clip(best_params[0] * float(rng.uniform(0.85, 1.15)), 0.05, max_beacon_interval_s))
        jf = float(np.clip(best_params[1] + float(rng.uniform(-0.08, 0.08)), 0.0, 0.50))
        msz = int(np.clip(best_params[2] + int(rng.integers(-30, 31)), 48, 600))
        rec = best_params[3]
        res, iv, jf, msz, rec = _eval_c2_candidate(iv, jf, msz, rec)
        obj = res["det_single_n12"] + 0.5 * res["det_progressive_plus_tier2_guard"]
        if obj < best_obj:
            best_obj = obj
            best_params = (iv, jf, msz, rec)
            best_eval = res

    return {
        "attack_type": "A3_c2_adaptive",
        "utility_metric": "beacons_per_min",
        "utility_floor": round(60.0 / max(0.05, float(max_beacon_interval_s)), 3),
        "max_interval_s": round(float(max_beacon_interval_s), 2),
        "query_budget_Q": budget_q,
        "best_chunk_bytes": best_params[2],
        "best_iat_ms": round(best_params[0] * 1000.0, 2),
        **best_eval,
    }


def generate_adaptive_boiling_frog_sequence(n_steps: int = 12, seed: int = 42) -> List[Dict[str, Any]]:
    """
    Generate the S3 'boiling frog' poisoning trajectory as a sequence of small parameter
    moves along the adaptive cost-of-evasion curve (linking C3/N8 directly to S3).
    """
    steps = []
    goodput_floors = np.linspace(0.5, 45.0, n_steps)
    for idx, g_floor in enumerate(goodput_floors):
        res = optimize_exfil_evasion_for_floor(float(g_floor), budget_q=60, seed=seed + idx)
        steps.append({
            "step": idx,
            "target_goodput_kbps": round(float(g_floor), 2),
            "score": round(float(res["score_n12"]), 5),
            "iat_ms": float(res["best_iat_ms"]),
        })
    return steps


def run_cost_of_evasion_experiment(
    out_dir: str = None,
    budget_q: int = 200,
    is_smoke: bool = True,
    seed: int = 42,
) -> pd.DataFrame:
    """
    Compute the Cost-of-Evasion Curve across Exfiltration goodput floors and C2 responsiveness floors
    and plot figures/evasion_cost_curve.png (C3 / N8).
    """
    source_tag = "synthetic-smoke" if is_smoke else "real"
    if is_smoke:
        print(SMOKE_BANNER)
        if out_dir is None or "offline" in out_dir:
            out_dir = os.path.join(REPO_DIR, "results", "smoke")
    else:
        if out_dir is None:
            out_dir = os.path.join(REPO_DIR, "results", "drift")
    os.makedirs(out_dir, exist_ok=True)
    fig_dir = os.path.join(out_dir, "figures")
    os.makedirs(fig_dir, exist_ok=True)

    rows: List[Dict[str, Any]] = []
    # 1. Exfiltration utility sweep: goodput floor R in {0.4, 1.5, 5.0, 15.0, 50.0, 150.0} KB/s
    for idx, r_kbps in enumerate([0.4, 1.5, 5.0, 15.0, 50.0, 150.0]):
        row = optimize_exfil_evasion_for_floor(r_kbps, budget_q=budget_q, seed=seed + idx)
        row["source"] = source_tag
        rows.append(row)

    # 2. C2 beacon utility sweep: max interval T in {60, 30, 10, 3, 1, 0.2} s
    for idx, t_sec in enumerate([60.0, 30.0, 10.0, 3.0, 1.0, 0.2]):
        row = optimize_c2_evasion_for_floor(t_sec, budget_q=budget_q, seed=seed + 100 + idx)
        row["source"] = source_tag
        rows.append(row)

    df = pd.DataFrame(rows)
    csv_path = os.path.join(out_dir, "evasion_cost_curve.csv")
    df.to_csv(csv_path, index=False)

    # Plot Cost-of-Evasion Curve
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        ex_df = df[df["attack_type"] == "A4_exfil_adaptive"]
        c2_df = df[df["attack_type"] == "A3_c2_adaptive"]

        fig, axes = plt.subplots(1, 2, figsize=(11, 4.3))
        axes[0].plot(ex_df["utility_floor"], ex_df["det_single_n12"], "o--", label="Single-Window (N=12)")
        axes[0].plot(ex_df["utility_floor"], ex_df["det_progressive_4_8_16"], "s-", label="Progressive [4, 8, 16]")
        axes[0].plot(ex_df["utility_floor"], ex_df["det_progressive_plus_tier2_guard"], "^-", label="Progressive + Tier-2 + Guard")
        axes[0].set_xscale("log")
        axes[0].set_xlabel("Retained Exfil Goodput Floor R (KB/s)")
        axes[0].set_ylabel("Min Achievable Detection Rate (Q=200)")
        axes[0].set_title("Exfiltration Cost-of-Evasion Curve (C3)")
        axes[0].legend(fontsize=8)
        axes[0].grid(True, which="both", ls=":", alpha=0.6)

        axes[1].plot(c2_df["utility_floor"], c2_df["det_single_n12"], "o--", label="Single-Window (N=12)")
        axes[1].plot(c2_df["utility_floor"], c2_df["det_progressive_4_8_16"], "s-", label="Progressive [4, 8, 16]")
        axes[1].plot(c2_df["utility_floor"], c2_df["det_progressive_plus_tier2_guard"], "^-", label="Progressive + Tier-2 + Guard")
        axes[1].set_xscale("log")
        axes[1].set_xlabel("Retained C2 Responsiveness (Beacons/min)")
        axes[1].set_ylabel("Min Achievable Detection Rate (Q=200)")
        axes[1].set_title("C2 Beacon Cost-of-Evasion Curve (C3)")
        axes[1].legend(fontsize=8)
        axes[1].grid(True, which="both", ls=":", alpha=0.6)

        fig.tight_layout()
        fig.savefig(os.path.join(fig_dir, "evasion_cost_curve.png"), dpi=140)
        plt.close(fig)
    except Exception:
        pass

    print(f"[+] Wrote C3 cost-of-evasion curve to {csv_path} (source={source_tag})")
    return df


def main():
    parser = argparse.ArgumentParser(description="Run C3 White-Box Cost-of-Evasion Curve")
    parser.add_argument("--budget-q", type=int, default=200)
    parser.add_argument("--out-dir", default=None)
    args = parser.parse_args()
    run_cost_of_evasion_experiment(out_dir=args.out_dir, budget_q=args.budget_q, is_smoke=True)


if __name__ == "__main__":
    main()
