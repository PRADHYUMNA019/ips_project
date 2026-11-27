#!/usr/bin/env python3
"""
demo/run_smoke_pipeline.py — End-to-End Synthetic Smoke Pipeline & Watermarked Figure Generator (Prompt 8, Phase 2).

Evidence Type: SYNTHETIC SMOKE (pipeline demonstration only — NOT A RESULT).
Every generated figure carries the visible watermark: "SYNTHETIC SMOKE DATA — NOT A RESULT".

Executes the full chain on deterministic synthetic smoke data:
  1. Generate smoke flows (separate train, calibration, validation/test sessions)
  2. Build splits & verify split-integrity leakage assertions (ips.data.build_splits)
  3. Extract canonical 3N+8 features (ips.features)
  4. Train per-checkpoint models k in {4, 8, 16} + INT8 quantization (ips.models.train)
  5. Calibrate thresholds: EVT (POT GPD), split-conformal, mean+3sigma (ips.models.evt)
  6. Offline evaluation + progressive checkpoint Pareto (ips.models.eval_offline)
  7. Closed loop with MockBPFBackend (engine decisions, sticky DROP, watchdog load shedding)
  8. Drift guard scenarios S1-S5 (static vs guarded traces) (ips.drift.scenarios)
  9. Cost-of-evasion curve Q=200 (ips.drift.evasion_cost)
 10. Generate 5 colour-blind-safe watermarked figures + caption files under demo/figures/smoke/
 11. Determinism check (--check-determinism): run twice into separate dirs and diff all outputs.
"""
import os
import sys
import json
import time
import shutil
import random
import hashlib
import argparse
import tempfile
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, precision_recall_curve, auc

# Enforce R6 CPU thread cap before importing torch
os.environ["OMP_NUM_THREADS"] = "4"
os.environ["MKL_NUM_THREADS"] = "4"

import torch
torch.set_num_threads(4)

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_DIR)

from ips.smoke.synth import generate_smoke_dataset, SMOKE_BANNER
from ips.data.build_splits import verify_split_integrity
from ips.features import get_feature_names, assert_no_forbidden_features, build_early_vector
from ips.models.train import train_pipeline, extract_matrix_from_df
from ips.models.eval_offline import (
    run_offline_evaluation,
    score_onnx_model,
    evaluate_progressive_checkpoints,
)
from ips.models.evt import compute_calibration_curve
from ips.engine.engine import MockBPFBackend, IPSEngine
from ips.engine.schema import make_flow_key, VERDICT_DROP, VERDICT_BYPASS
from ips.drift.scenarios import run_method_on_scenario, run_all_drift_scenarios
from ips.drift.guard import GuardConfig
from ips.drift.evasion_cost import run_cost_of_evasion_experiment

WATERMARK_TEXT = "SYNTHETIC SMOKE DATA — NOT A RESULT"

# Colour-blind-safe Okabe-Ito palette
PALETTE = {
    "blue": "#0072B2",
    "vermillion": "#D55E00",
    "green": "#009E73",
    "purple": "#CC79A7",
    "orange": "#E69F00",
    "sky": "#56B4E9",
    "black": "#000000",
}


def add_smoke_watermark(fig):
    """Stamp prominent diagonal + header watermark per Prompt 8 Rule R1."""
    fig.text(
        0.5, 0.5, WATERMARK_TEXT,
        fontsize=20, color="#B00020", alpha=0.18,
        ha="center", va="center", rotation=24, fontweight="bold",
        transform=fig.transFigure, zorder=100,
    )
    fig.text(
        0.5, 0.99, WATERMARK_TEXT,
        fontsize=9, color="#B00020", alpha=0.95,
        ha="center", va="top", fontweight="bold",
        transform=fig.transFigure, zorder=101,
    )


def run_mock_closed_loop_demo(card_path: str, early_n: int = 16, seed: int = 42) -> Dict[str, Any]:
    """Exercise MockBPFBackend + IPSEngine: progressive verdicts, sticky DROP, watchdog load shedding."""
    random.seed(seed)
    np.random.seed(seed)

    cfg = {
        "system": {
            "early_n": early_n,
            "checkpoints": [4, 8, 16],
            "flow_idle_s": 120,
            "verdict_ttl_s": 60,
            "bypass_ttl_s": 60,
            "drop_ttl_s": 60,
        },
        "engine": {
            "mode": "enforce",
            "model_card": card_path,
            "bypass_enabled": True,
            "alpha_spending": "equal",
            "target_fpr_key": "001",
            "watchdog": {"shed_cpu_pct": 85.0, "shed_ringbuf_pct": 75.0, "cooldown_s": 5.0},
        },
    }
    backend = MockBPFBackend(early_n=early_n, checkpoints=[4, 8, 16])
    engine = IPSEngine(config=cfg, backend=backend, mode_override="enforce", bypass_override=True)

    t0 = 10_000_000_000
    decisions = []

    # 1. Attack flow (high-rate large payload -> triggers DROP at checkpoint 4, remains sticky)
    for pkt_i in range(1, 20):
        act, ev = backend.simulate_packet(
            "10.0.1.4", 44444, "10.0.2.10", 8443, "TCP", 1450, 0, t0 + pkt_i * 1_000_000
        )
        if ev is not None:
            d = engine.handle_early_flow_event(ev, now_ns=t0 + pkt_i * 1_000_000)
            decisions.append({"flow": "attack_exfil_1", "pkt": pkt_i, "verdict": d["verdict_written"], "score": round(float(d["score"]), 6)})
    # Test sticky DROP invariant explicitly: feed a low-score later checkpoint event on same 5-tuple
    fake_benign_late_ev = {
        "ip_a": "10.0.1.4", "port_a": 44444, "ip_b": "10.0.2.10", "port_b": 8443, "proto": "TCP",
        "sizes": [64] * 16, "dirs": [i % 2 for i in range(16)], "iat_ns": [10_000_000_000] * 15,
        "valid_len": 16, "checkpoint_idx": 2, "first_ts_ns": t0, "last_ts_ns": t0 + 20_000_000,
    }
    sticky_d = engine.handle_early_flow_event(fake_benign_late_ev, now_ns=t0 + 25_000_000)

    # 2. Benign flow (small periodic MQTT sensor at 10s interval, client-first (pkt_i-1)%2 -> continues at k=4,8, BYPASS at k=16)
    for pkt_i in range(1, 20):
        act, ev = backend.simulate_packet(
            "10.0.1.11", 51001, "10.0.2.10", 8883, "TCP", 56 if (pkt_i - 1) % 2 == 1 else 64, (pkt_i - 1) % 2, t0 + pkt_i * 10_000_000_000
        )
        if ev is not None:
            d = engine.handle_early_flow_event(ev, now_ns=t0 + pkt_i * 10_000_000_000)
            decisions.append({"flow": "benign_sensor_1", "pkt": pkt_i, "verdict": d["verdict_written"], "score": round(float(d["score"]), 6)})

    # 3. Watchdog load-shedding activation & cooldown recovery
    engine.last_watchdog_s = 99.0
    engine.last_lag_ms = float(engine.max_engine_lag_ms) + 100.0  # strictly exceeds max_engine_lag_ms
    w1 = engine.step_watchdog(now_s=100.0)
    shed_after_spike = bool(engine.shed_active)
    engine.last_lag_ms = 1.0
    w2 = engine.step_watchdog(now_s=100.0 + engine.cooldown_s + 2.0)
    shed_after_cooldown = bool(engine.shed_active)

    return {
        "source": "synthetic-smoke",
        "decisions": decisions,
        "sticky_drop_verdict": sticky_d["verdict_written"],
        "pkts_dropped_verdict": int(backend.stats["pkts_dropped_verdict"]),
        "pkts_bypassed": int(backend.stats["pkts_bypassed"]),
        "events_emitted": int(backend.stats["events_emitted"]),
        "watchdog_shed_triggered": shed_after_spike,
        "watchdog_action_spike": w1["action"],
        "watchdog_recovered_after_cooldown": (not shed_after_cooldown),
        "watchdog_action_recover": w2["action"],
    }


def generate_smoke_figures(
    test_df: pd.DataFrame,
    card: Dict[str, Any],
    calib_df: pd.DataFrame,
    pareto_df: pd.DataFrame,
    evasion_df: pd.DataFrame,
    drift_traces: Dict[str, Dict[str, List[Dict[str, Any]]]],
    fig_dir: str,
):
    """Produce all 5 watermarked colour-blind-safe smoke figures + caption files."""
    os.makedirs(fig_dir, exist_ok=True)
    plt.rcParams.update({"font.size": 10, "axes.titlesize": 11, "axes.labelsize": 10})

    y_true = test_df["is_attack"].to_numpy(dtype=int)
    ckpt_cfg = card.get("checkpoint_models", {})
    ckpts = [int(k) for k in sorted(ckpt_cfg.keys(), key=lambda x: int(x))]

    # (a) ROC / PR per checkpoint
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.6))
    colors = [PALETTE["blue"], PALETTE["orange"], PALETTE["green"]]
    ckpt_metrics_summary = {}
    for idx, k in enumerate(ckpts):
        cinfo = ckpt_cfg[str(k)]
        sub_k = test_df[test_df["raw_valid_len"] >= k] if "raw_valid_len" in test_df.columns else test_df
        y_k = sub_k["is_attack"].to_numpy(dtype=int)
        X_k, _, _ = extract_matrix_from_df(sub_k, early_n=k)
        onnx_p = cinfo.get("onnx_int8_path", cinfo.get("onnx_fp32_path"))
        scores_k_reach = score_onnx_model(onnx_p, X_k)
        X_all_k, _, _ = extract_matrix_from_df(test_df, early_n=k)
        scores_k_all = score_onnx_model(onnx_p, X_all_k)
        fpr, tpr, _ = roc_curve(y_k, scores_k_reach)
        prec, rec, _ = precision_recall_curve(y_k, scores_k_reach)
        roc_auc = auc(fpr, tpr)
        pr_auc = auc(rec, prec)
        ckpt_metrics_summary[k] = (scores_k_all, roc_auc, pr_auc)
        col = colors[idx % len(colors)]
        ax1.plot(fpr, tpr, color=col, lw=2.0, label=f"k={k} pkts (n={len(sub_k)}, AUROC={roc_auc:.3f})")
        ax2.plot(rec, prec, color=col, lw=2.0, label=f"k={k} pkts (n={len(sub_k)}, AUPRC={pr_auc:.3f})")

    ax1.plot([0, 1], [0, 1], "--", color="gray", lw=1)
    ax1.set_xlabel("False Positive Rate")
    ax1.set_ylabel("True Positive Rate")
    ax1.set_title("ROC Curve per Checkpoint (k=4, 8, 16)")
    ax1.legend(loc="lower right", fontsize=8)
    ax1.grid(True, ls=":", alpha=0.6)

    ax2.set_xlabel("Recall (TPR)")
    ax2.set_ylabel("Precision")
    ax2.set_title("Precision-Recall Curve per Checkpoint")
    ax2.legend(loc="lower left", fontsize=8)
    ax2.grid(True, ls=":", alpha=0.6)

    add_smoke_watermark(fig)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    p_a = os.path.join(fig_dir, "fig_a_roc_pr_per_checkpoint.png")
    fig.savefig(p_a, dpi=150)
    plt.close(fig)
    with open(p_a.replace(".png", ".caption.txt"), "w", encoding="utf-8") as f:
        f.write(
            f"{WATERMARK_TEXT}\n"
            "Figure (a): ROC and Precision-Recall curves per progressive checkpoint (k=4, 8, 16 payload packets) "
            "computed on synthetic smoke flows (pipeline demonstration only; not a research result).\n"
        )

    # (b) Detection vs packets leaked (progressive vs single checkpoint)
    fig, ax = plt.subplots(figsize=(7.2, 4.8))
    single_pts = []
    raw_vlens = test_df["raw_valid_len"].to_numpy(dtype=int) if "raw_valid_len" in test_df.columns else np.full(len(test_df), 16)
    tot_pkts = test_df["total_pkts"].to_numpy(dtype=int) if "total_pkts" in test_df.columns else raw_vlens
    atk_mask = (y_true == 1)
    for k in ckpts:
        scores_k = ckpt_metrics_summary[k][0]
        tau_k = float(ckpt_cfg[str(k)].get("tau_equal_01", ckpt_cfg[str(k)].get("tau_equal_001", 0.05)))
        dropped = (scores_k >= tau_k) & (raw_vlens >= k)
        tpr_k = float(np.mean(dropped[atk_mask])) if np.any(atk_mask) else 0.0
        leaked = np.where(dropped[atk_mask], k, tot_pkts[atk_mask])
        mean_leaked = float(np.mean(leaked)) if len(leaked) > 0 else float(k)
        single_pts.append((k, mean_leaked, tpr_k))

    sx = [p[1] for p in single_pts]
    sy = [p[2] for p in single_pts]
    ax.plot(sx, sy, "o--", color=PALETTE["blue"], lw=2, markersize=8, label="Single Checkpoint (fixed k)")
    for k, xl, yl in single_pts:
        ax.annotate(f"Single k={k}", (xl, yl), textcoords="offset points", xytext=(6, -12), fontsize=8)

    if len(pareto_df) > 0:
        prog_sub = pareto_df[pareto_df["target_flow_fpr"] == 0.01] if "target_flow_fpr" in pareto_df.columns else pareto_df
        if len(prog_sub) == 0:
            prog_sub = pareto_df
        px = prog_sub["mean_attack_packets_leaked"].to_numpy(dtype=float)
        py = prog_sub["tpr"].to_numpy(dtype=float)
        ax.scatter(px, py, marker="D", s=90, color=PALETTE["vermillion"], zorder=5, label="Progressive [4, 8, 16] (Early DROP)")
        for _, r in prog_sub.iterrows():
            ax.annotate(
                f"Prog ({r['alpha_spending']})",
                (float(r["mean_attack_packets_leaked"]), float(r["tpr"])),
                textcoords="offset points", xytext=(6, 6), fontsize=8, color=PALETTE["vermillion"],
            )

    ax.set_xlabel("Mean Attack Payload Packets Leaked Before Verdict (lower is better)")
    ax.set_ylabel("Attack Detection Rate (TPR, higher is better)")
    ax.set_title("Detection vs. Attack Packets Leaked: Progressive vs. Single Checkpoint")
    ax.set_ylim(-0.05, 1.08)
    ax.legend(loc="lower right", fontsize=8)
    ax.grid(True, ls=":", alpha=0.6)
    add_smoke_watermark(fig)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    p_b = os.path.join(fig_dir, "fig_b_detection_vs_packets_leaked.png")
    fig.savefig(p_b, dpi=150)
    plt.close(fig)
    with open(p_b.replace(".png", ".caption.txt"), "w", encoding="utf-8") as f:
        f.write(
            f"{WATERMARK_TEXT}\n"
            "Figure (b): Attack detection rate (TPR) versus mean attack payload packets leaked before verdict, "
            "comparing single fixed checkpoints (k=4, 8, 16) against progressive [4, 8, 16] early-drop on synthetic smoke data.\n"
        )

    # (c) Calibration: target vs achieved FPR for EVT / conformal / 3-sigma
    fig, ax = plt.subplots(figsize=(7.0, 4.8))
    tx = calib_df["target_fpr"].to_numpy(dtype=float)
    eps = 1e-5
    y_evt = np.maximum(eps, calib_df["evt_achieved_fpr"].to_numpy(dtype=float))
    y_conf = np.maximum(eps, calib_df["conformal_achieved_fpr"].to_numpy(dtype=float))
    y_3s = np.maximum(eps, calib_df["three_sigma_achieved_fpr"].to_numpy(dtype=float))
    ax.plot(tx, tx, "--", color=PALETTE["black"], lw=1.5, label="Ideal (Target = Achieved)")
    ax.plot(tx, y_evt, "o-", color=PALETTE["blue"], lw=2, label="EVT (POT GPD)")
    ax.plot(tx, y_conf, "s-", color=PALETTE["green"], lw=2, label="Split-Conformal")
    ax.plot(tx, y_3s, "^-", color=PALETTE["vermillion"], lw=2, label="Mean + 3σ")
    if "conformal_min_supported_alpha" in calib_df.columns and len(calib_df) > 0:
        min_a = float(calib_df["conformal_min_supported_alpha"].iloc[0])
        ax.axvline(min_a, color=PALETTE["purple"], ls=":", lw=1.8, label=f"Conformal floor 1/(n+1)={min_a:.4f}")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Target False Positive Rate (α)")
    ax.set_ylabel("Achieved Benign FPR (floored at 1e-5 for log scale)")
    ax.set_title("Threshold Calibration: EVT vs. Split-Conformal vs. Mean+3σ")
    ax.legend(loc="lower right", fontsize=8)
    ax.grid(True, which="both", ls=":", alpha=0.6)
    add_smoke_watermark(fig)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    p_c = os.path.join(fig_dir, "fig_c_calibration_target_vs_achieved_fpr.png")
    fig.savefig(p_c, dpi=150)
    plt.close(fig)
    with open(p_c.replace(".png", ".caption.txt"), "w", encoding="utf-8") as f:
        f.write(
            f"{WATERMARK_TEXT}\n"
            "Figure (c): Target FPR vs. achieved benign FPR across EVT (POT GPD), split-conformal, and fixed mean+3sigma "
            "thresholds on synthetic smoke data (0 achieved FPR floored at 1e-5 for log plotting).\n"
        )

    # (d) Drift scenarios S1-S5: S1/S2 show Clean Benign FPR; S3/S4/S5 show Attack Detection TPR (Prompt 9 Item 5a)
    scen_specs = [
        ("S1_benign_firmware_step", "S1: Benign Step\n(Clean Benign FPR ↓)", "clean_benign_fpr", "Clean Benign FPR"),
        ("S2_benign_gradual_ramp", "S2: Benign Ramp\n(Clean Benign FPR ↓)", "clean_benign_fpr", "Clean Benign FPR"),
        ("S3_single_device_boiling_frog", "S3: Boiling Frog\n(Attack TPR ↑)", "attack_tpr", "Held-Out Attack TPR"),
        ("S4_coordinated_multi_device_poisoning", "S4: Coord. Poison\n(Attack TPR ↑)", "attack_tpr", "Held-Out Attack TPR"),
        ("S5_mimicry_and_slow_c2", "S5: Mimicry + Slow C2\n(Concurrent C2 TPR ↑)", "attack_tpr", "Concurrent Attack TPR"),
    ]
    fig, axes = plt.subplots(1, 5, figsize=(16.5, 4.1), sharey=False)
    for idx, (ax, (skey, stitle, mkey, ylabel)) in enumerate(zip(axes, scen_specs)):
        tr_st = drift_traces[skey]["static"]
        tr_ad = drift_traces[skey]["plain_adwin_retrain"]
        tr_gd = drift_traces[skey]["guarded"]
        ws = [r["window"] for r in tr_st]
        v_st = [r[mkey] for r in tr_st]
        v_ad = [r[mkey] for r in tr_ad]
        v_gd = [r[mkey] for r in tr_gd]
        ax.plot(ws, v_st, "s--", color=PALETTE["vermillion"], lw=1.7, markersize=3.8, label="Static (Tier-1)")
        if skey != "S5_mimicry_and_slow_c2":
            ax.plot(ws, v_ad, "^:", color=PALETTE["orange"], lw=1.8, markersize=3.8, label="Unguarded ADWIN")
        ax.plot(ws, v_gd, "o-", color=PALETTE["blue"], lw=2.1, markersize=4.0, label="Guarded (G1–G4 + Tier-2)")
        ax.set_title(stitle, fontsize=9)
        ax.set_xlabel("Window")
        ax.set_ylabel(ylabel, fontsize=8.5)
        ax.grid(True, ls=":", alpha=0.6)
        ax.set_ylim(-0.05, 1.08)
        if idx in (0, 2):
            ax.legend(loc="best", fontsize=7)
    add_smoke_watermark(fig)
    fig.tight_layout(rect=[0, 0, 1, 0.92])
    p_d = os.path.join(fig_dir, "fig_d_drift_s1_s5_fpr_over_time.png")
    fig.savefig(p_d, dpi=150)
    plt.close(fig)
    with open(p_d.replace(".png", ".caption.txt"), "w", encoding="utf-8") as f:
        f.write(
            f"{WATERMARK_TEXT}\n"
            "Figure (d): Drift & poisoning scenarios S1-S5 across windows 0..15 on synthetic smoke streams. "
            "Panels S1 & S2 plot Clean Benign FPR (Static spikes after benign shift while Guarded adapts); "
            "Panels S3 & S4 plot Held-Out Attack TPR (Unguarded ADWIN accepts poisoned updates and loses detection, "
            "whereas Guarded G1-G4 rejects S3 and bounds S4); Panel S5 plots Concurrent Mimicry/Slow-C2 Detection Rate "
            "(Tier-2 SlowC2Tracker fires once >=8 periodic connections accumulate at window 7).\n"
        )

    # (e) Cost-of-evasion curve
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.6))
    exf = evasion_df[evasion_df["attack_type"] == "A4_exfil_adaptive"].sort_values("utility_floor")
    c2 = evasion_df[evasion_df["attack_type"] == "A3_c2_adaptive"].sort_values("utility_floor")

    for ax, sub, xlabel, title in [
        (ax1, exf, "Minimum Exfiltration Goodput Floor (KB/s)", "A4 Exfiltration: White-Box Evasion Cost (Q=200)"),
        (ax2, c2, "Maximum C2 Beacon Interval Ceiling (s)", "A3 Slow-C2: White-Box Evasion Cost (Q=200)"),
    ]:
        if len(sub) > 0:
            xv = sub["utility_floor"].to_numpy(dtype=float)
            ax.plot(xv, sub["det_single_n12"], "s--", color=PALETTE["orange"], lw=2, label="Single Window (N=12)")
            ax.plot(xv, sub["det_progressive_4_8_16"], "^-.", color=PALETTE["blue"], lw=2, label="Progressive [4, 8, 16]")
            ax.plot(xv, sub["det_progressive_plus_tier2_guard"], "o-", color=PALETTE["green"], lw=2.2, label="Progressive + Tier-2 SlowC2")
        ax.set_xlabel(xlabel)
        ax.set_ylabel("Min. Achievable Detection Prob.")
        ax.set_title(title)
        ax.set_ylim(-0.05, 1.08)
        ax.legend(loc="lower right", fontsize=8)
        ax.grid(True, ls=":", alpha=0.6)
    add_smoke_watermark(fig)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    p_e = os.path.join(fig_dir, "fig_e_cost_of_evasion_curve.png")
    fig.savefig(p_e, dpi=150)
    plt.close(fig)
    with open(p_e.replace(".png", ".caption.txt"), "w", encoding="utf-8") as f:
        f.write(
            f"{WATERMARK_TEXT}\n"
            "Figure (e): Query-bounded (Q=200) white-box adaptive-attacker cost-of-evasion curve showing minimum achievable "
            "detection probability across utility floors for single-window, progressive [4,8,16], and full Tier-2 stack (synthetic smoke).\n"
        )


def run_once(work_dir: str, fig_dir: str = None, epochs: int = 50, seed: int = 42) -> Dict[str, Any]:
    """Run the entire synthetic smoke pipeline deterministically into work_dir."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.set_num_threads(4)

    os.makedirs(work_dir, exist_ok=True)
    model_dir = os.path.join(work_dir, "models")
    eval_dir = os.path.join(work_dir, "eval")
    drift_dir = os.path.join(work_dir, "drift")
    os.makedirs(model_dir, exist_ok=True)
    os.makedirs(eval_dir, exist_ok=True)
    os.makedirs(drift_dir, exist_ok=True)

    # 1. Generate separate synthetic smoke sessions (train, calibration, validation, test)
    train_csv = os.path.join(work_dir, "smoke_train.csv")
    calib_csv = os.path.join(work_dir, "smoke_calib.csv")
    val_csv = os.path.join(work_dir, "smoke_val.csv")
    test_csv = os.path.join(work_dir, "smoke_test.csv")

    df_tr = generate_smoke_dataset(n_benign=240, n_attack=0, early_n=16, session_id="smoke_s1_tr", out_csv=train_csv, seed=seed)
    df_ca = generate_smoke_dataset(n_benign=180, n_attack=0, early_n=16, session_id="smoke_s2_ca", out_csv=calib_csv, seed=seed + 1)
    df_va = generate_smoke_dataset(n_benign=100, n_attack=60, early_n=16, session_id="smoke_s3_va", out_csv=val_csv, seed=seed + 2)
    # Keep DEV families only in validation so B2(b) zero-day assertion passes
    df_va = df_va[(df_va["is_attack"] == 0) | (~df_va["label_family"].isin(["A3_c2", "A4_exfil"]))].reset_index(drop=True)
    df_va.to_csv(val_csv, index=False)
    df_te = generate_smoke_dataset(n_benign=150, n_attack=100, early_n=16, session_id="smoke_s4_te", out_csv=test_csv, seed=seed + 3)

    # 2. Verify split integrity & leakage assertions
    split_check = verify_split_integrity(
        {"train": df_tr, "calibration": df_ca, "validation": df_va, "test": df_te},
        min_calibration_flows=100,
    )
    assert split_check["passed"] is True

    # 3. Verify feature schema & shortcut guard
    feat_names = get_feature_names(16)
    assert_no_forbidden_features(feat_names)

    # 4 & 5. Train per-checkpoint models [4, 8, 16] + EVT/conformal/3sigma calibration + INT8 export
    card = train_pipeline(
        data_path=train_csv,
        calib_path=calib_csv,
        early_n=16,
        checkpoints=[4, 8, 16],
        epochs=epochs,
        seed=seed,
        model_dir=model_dir,
    )
    card_path = os.path.join(model_dir, "model_card.json")

    # 6. Offline evaluation
    offline_summary = run_offline_evaluation(
        test_data_path=test_csv,
        model_card_path=card_path,
        out_dir=eval_dir,
        run_n_sweep=False,
    )

    # 7. Closed loop with MockBPFBackend
    mock_res = run_mock_closed_loop_demo(card_path, early_n=16, seed=seed)
    with open(os.path.join(work_dir, "mock_closed_loop.json"), "w", encoding="utf-8") as f:
        json.dump(mock_res, f, indent=2, sort_keys=True)

    # 8. Drift guard scenarios S1-S5 (static vs guarded traces + full summary)
    drift_df = run_all_drift_scenarios(drift_dir, is_smoke=True)
    drift_traces: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for scen in [
        "S1_benign_firmware_step",
        "S2_benign_gradual_ramp",
        "S3_single_device_boiling_frog",
        "S4_coordinated_multi_device_poisoning",
        "S5_mimicry_and_slow_c2",
    ]:
        _, tr_st = run_method_on_scenario(scen, "static", "static", GuardConfig(), seed=seed)
        _, tr_ad = run_method_on_scenario(scen, "plain_adwin_retrain", "plain_adwin_retrain", GuardConfig(), seed=seed)
        _, tr_gd = run_method_on_scenario(scen, "guarded", "guarded", GuardConfig(), seed=seed)
        drift_traces[scen] = {"static": tr_st, "plain_adwin_retrain": tr_ad, "guarded": tr_gd}
    with open(os.path.join(drift_dir, "drift_traces_static_vs_guarded.json"), "w", encoding="utf-8") as f:
        json.dump(drift_traces, f, indent=2, sort_keys=True)

    # 9. Cost-of-evasion curve (Q=200)
    evasion_df = run_cost_of_evasion_experiment(out_dir=drift_dir, budget_q=200, seed=seed)

    # 10. Generate 5 watermarked figures if fig_dir requested
    calib_df = pd.read_csv(os.path.join(eval_dir, "calibration_curve.csv"))
    pareto_df = pd.read_csv(os.path.join(eval_dir, "progressive_pareto.csv"))
    if fig_dir:
        generate_smoke_figures(df_te, card, calib_df, pareto_df, evasion_df, drift_traces, fig_dir)

    # Build deterministic digest over all non-timing outputs for reproducibility diff
    deterministic_artefacts = [
        ("smoke_train.csv", train_csv),
        ("smoke_calib.csv", calib_csv),
        ("smoke_test.csv", test_csv),
        ("eval_models.csv", os.path.join(eval_dir, "eval_models.csv")),
        ("calibration_curve.csv", os.path.join(eval_dir, "calibration_curve.csv")),
        ("progressive_pareto.csv", os.path.join(eval_dir, "progressive_pareto.csv")),
        ("mock_closed_loop.json", os.path.join(work_dir, "mock_closed_loop.json")),
        ("drift_metrics.csv", os.path.join(drift_dir, "drift_metrics.csv")),
        ("drift_traces_static_vs_guarded.json", os.path.join(drift_dir, "drift_traces_static_vs_guarded.json")),
        ("evasion_cost_curve.csv", os.path.join(drift_dir, "evasion_cost_curve.csv")),
    ]
    hashes = {}
    for label, path in deterministic_artefacts:
        with open(path, "rb") as f:
            hashes[label] = hashlib.sha256(f.read()).hexdigest()

    return {
        "source": "synthetic-smoke",
        "split_check_passed": split_check["passed"],
        "offline_int8_auroc": offline_summary.get("auroc"),
        "offline_int8_auprc": offline_summary.get("auprc"),
        "mock_closed_loop": mock_res,
        "drift_rows": len(drift_df),
        "evasion_rows": len(evasion_df),
        "hashes": hashes,
    }


def main():
    parser = argparse.ArgumentParser(description="Run end-to-end synthetic smoke pipeline (Prompt 8 Phase 2)")
    parser.add_argument("--fast", action="store_true", help="Single pass (used by demo/run_demo.ps1)")
    parser.add_argument("--check-determinism", action="store_true", help="Run twice and diff all deterministic artefacts")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    out_root = os.path.join(REPO_DIR, "results", "smoke", "p8_run1")
    fig_dir = os.path.join(REPO_DIR, "demo", "figures", "smoke")
    ev_dir = os.path.join(REPO_DIR, "demo", "evidence", "smoke")
    os.makedirs(ev_dir, exist_ok=True)

    t0 = time.perf_counter()
    res1 = run_once(out_root, fig_dir=fig_dir, epochs=args.epochs, seed=args.seed)
    elapsed1 = round(time.perf_counter() - t0, 2)

    report = {
        "evidence_type": "SYNTHETIC SMOKE (pipeline demonstration only — NOT A RESULT)",
        "utc_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "seed": args.seed,
        "epochs": args.epochs,
        "run1_elapsed_s": elapsed1,
        "run1_summary": res1,
    }

    if args.check_determinism and not args.fast:
        out_root2 = os.path.join(REPO_DIR, "results", "smoke", "p8_run2")
        res2 = run_once(out_root2, fig_dir=None, epochs=args.epochs, seed=args.seed)
        diffs = {}
        for k, h1 in res1["hashes"].items():
            h2 = res2["hashes"].get(k)
            diffs[k] = ("IDENTICAL" if h1 == h2 else f"DIFF ({h1[:12]} vs {h2[:12]})")
        n_identical = sum(1 for v in diffs.values() if v == "IDENTICAL")
        report["determinism_check"] = {
            "total_files": len(diffs),
            "identical_files": n_identical,
            "all_identical": (n_identical == len(diffs)),
            "per_file": diffs,
        }
        print(f"\n[DETERMINISM CHECK] {n_identical}/{len(diffs)} deterministic artefacts byte-for-byte IDENTICAL.")
        for k, v in diffs.items():
            print(f"  - {k}: {v}")

    summary_path = os.path.join(ev_dir, "smoke_pipeline_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Wrote smoke pipeline summary to {summary_path} ({elapsed1}s)")


if __name__ == "__main__":
    main()
