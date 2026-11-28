#!/usr/bin/env python3
"""
demo/run_exploratory_p8.py — Exploratory Real Cross-Device Benign Transfer on Aposemat IoT-23 (Prompt 8, Phase 4).

Evidence Type: REAL PUBLIC DATA — EXPLORATORY ONLY (NOT PART OF PRE-REGISTERED STUDY).
Plan pre-stated in docs/EXPLORATORY_P8.md BEFORE execution.
TQH-C2 D per-packet scoring is explicitly SKIPPED per §4.3 because TQH-C2_features_D.zip lacks per-packet sequences.

Runs seeds {42, 43, 44} with torch.set_num_threads(4) on real IoT-23 benign pcaps:
  - Config A: Train on Echo (5-1) -> Calibrate on Somfy (7-1) -> Test ONCE on Hue (4-1)
  - Config B: Train on Echo (5-1) -> Calibrate on Hue (4-1) -> Test ONCE on Somfy (7-1)
across checkpoints k in {4, 8, 16}. Reports mean & spread of held-out benign FPR, KS statistic,
and top-3 shifting features.
"""

import os
import sys
import glob
import random
import argparse
import numpy as np
import pandas as pd
from scipy import stats

os.environ["OMP_NUM_THREADS"] = "4"
os.environ["MKL_NUM_THREADS"] = "4"

import torch

torch.set_num_threads(4)

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_DIR)

from datasets.adapters.iot23_adapter import adapt_iot23_pcap
from ips.features import get_feature_names, recompute_early_matrix_for_k
from ips.models.train import train_autoencoder
from ips.models.evt import fit_evt_threshold


def load_capture_df(data_dir: str, cap_name: str, early_n: int = 16) -> pd.DataFrame:
    pcaps = sorted(glob.glob(os.path.join(data_dir, cap_name, "*.pcap")))
    if not pcaps:
        raise FileNotFoundError(f"No pcaps found for {cap_name} under {data_dir}")
    dfs = [adapt_iot23_pcap(p, capture_name=cap_name, early_n=early_n, is_attack=0) for p in pcaps]
    return pd.concat(dfs, ignore_index=True)


def run_config_once(
    df_train: pd.DataFrame,
    df_cal: pd.DataFrame,
    df_test: pd.DataFrame,
    config_name: str,
    k: int,
    seed: int,
    epochs: int = 15,
) -> dict:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)

    X_tr = recompute_early_matrix_for_k(df_train, k)
    X_ca = recompute_early_matrix_for_k(df_cal, k)
    X_te = recompute_early_matrix_for_k(df_test, k)

    # Split training capture 85/15 for early-stopping validation (strictly within train capture)
    n_tr = max(10, int(0.85 * len(X_tr)))
    perm = np.random.default_rng(seed).permutation(len(X_tr))
    X_tr_fit = X_tr[perm[:n_tr]]
    X_tr_val = X_tr[perm[n_tr:]] if n_tr < len(X_tr) else X_tr_fit

    model, _ = train_autoencoder(X_tr_fit, X_tr_val, input_dim=X_tr.shape[1], epochs=epochs, batch_size=32, seed=seed)

    cal_scores, cal_sq = model.get_reconstruction_error(X_ca)
    test_scores, test_sq = model.get_reconstruction_error(X_te)

    evt_05 = fit_evt_threshold(cal_scores, target_fpr=0.05)
    evt_01 = fit_evt_threshold(cal_scores, target_fpr=0.01)

    fpr_evt_05 = float(np.mean(test_scores > float(evt_05["threshold"])))
    fpr_evt_01 = float(np.mean(test_scores > float(evt_01["threshold"])))
    fpr_conf_05 = float(np.mean(test_scores > float(evt_05["conformal_q"])))
    fpr_3sig = float(np.mean(test_scores > float(evt_05["three_sigma"])))

    ks_stat, ks_pval = stats.ks_2samp(cal_scores, test_scores)
    feat_names = get_feature_names(k)
    err_diff = np.mean(test_sq, axis=0) - np.mean(cal_sq, axis=0)
    top3_idx = np.argsort(np.abs(err_diff))[::-1][:3]
    top3_str = "; ".join(f"{feat_names[i]} ({err_diff[i]:+.4f})" for i in top3_idx)

    return {
        "source": "REAL PUBLIC DATA — EXPLORATORY (Aposemat IoT-23 Benign)",
        "config": config_name,
        "checkpoint_k": k,
        "seed": seed,
        "n_train": len(X_tr),
        "n_calib": len(X_ca),
        "n_test": len(X_te),
        "fpr_evt_target05": round(fpr_evt_05, 4),
        "fpr_evt_target01": round(fpr_evt_01, 4),
        "fpr_conformal_target05": round(fpr_conf_05, 4),
        "fpr_three_sigma": round(fpr_3sig, 4),
        "ks_stat_cal_vs_test": round(float(ks_stat), 4),
        "ks_pvalue": float(ks_pval),
        "top_3_shifting_features": top3_str,
    }


def main():
    parser = argparse.ArgumentParser(description="Run Prompt 8 Phase 4 Exploratory Real IoT-23 Experiment")
    parser.add_argument("--data-dir", default=os.path.join(os.environ.get("IPS_DATA_ROOT", r"D:\ips_data"), "iot23"))
    parser.add_argument("--out-csv", default=os.path.join(REPO_DIR, "demo", "evidence", "real", "exploratory_results.csv"))
    args = parser.parse_args()

    print("[*] Loading real IoT-23 benign captures (4-1 Hue, 5-1 Echo, 7-1 Somfy)...", flush=True)
    df_hue = load_capture_df(args.data_dir, "CTU-Honeypot-Capture-4-1", early_n=16)
    df_echo = load_capture_df(args.data_dir, "CTU-Honeypot-Capture-5-1", early_n=16)
    df_somfy = load_capture_df(args.data_dir, "CTU-Honeypot-Capture-7-1", early_n=16)
    print(f"    Loaded: Hue={len(df_hue)}, Echo={len(df_echo)}, Somfy={len(df_somfy)} flows", flush=True)

    configs = [
        ("Echo(5-1)_train -> Somfy(7-1)_calib -> Hue(4-1)_test", df_echo, df_somfy, df_hue),
        ("Echo(5-1)_train -> Hue(4-1)_calib -> Somfy(7-1)_test", df_echo, df_hue, df_somfy),
    ]

    rows = []
    for cname, d_tr, d_ca, d_te in configs:
        for k in (4, 8, 16):
            for seed in (42, 43, 44):
                r = run_config_once(d_tr, d_ca, d_te, cname, k=k, seed=seed, epochs=15)
                rows.append(r)

    df_res = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(os.path.abspath(args.out_csv)), exist_ok=True)
    df_res.to_csv(args.out_csv, index=False)

    print("\n=== EXPLORATORY REAL IOT-23 CROSS-DEVICE BENIGN RESULTS (Mean +/- Std over seeds 42,43,44) ===")
    agg = (
        df_res.groupby(["config", "checkpoint_k"])
        .agg(
            fpr_evt05_mean=("fpr_evt_target05", "mean"),
            fpr_evt05_std=("fpr_evt_target05", "std"),
            fpr_evt01_mean=("fpr_evt_target01", "mean"),
            fpr_conf05_mean=("fpr_conformal_target05", "mean"),
            fpr_3sig_mean=("fpr_three_sigma", "mean"),
            ks_mean=("ks_stat_cal_vs_test", "mean"),
            top_features=("top_3_shifting_features", "first"),
        )
        .reset_index()
    )
    print(agg.to_string(index=False))
    print(f"\n[+] Wrote {args.out_csv}")


if __name__ == "__main__":
    main()
