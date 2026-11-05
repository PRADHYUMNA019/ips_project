#!/usr/bin/env python3
"""
ips/eval/impairment.py — Network-Impairment Robustness & Feature Ablation Study (C11 / N11).

Evaluates early-flow anomaly detection across a grid of WAN/Wi-Fi impairments:
  - delay_ms in [0, 5, 15, 30, 50]
  - jitter_ms in [0, 2, 10, 20, 20]
  - loss_pct in [0.0, 0.5, 1.0, 1.5, 2.0]%
  - reorder_pct in [0.0, 0.5, 2.0, 3.5, 5.0]%

Repeats evaluation across three feature-set ablations:
  1. 'full_features': all 3N+8 early-flow features
  2. 'no_iat_features': drops log_iat_0..N-2, mean_log_iat, std_log_iat
  3. 'no_size_features': drops size_0..N-1, bytes_up, bytes_down, first_payload_size
to test the hypothesis that IAT features degrade under jitter while packet-size features remain stable.
"""
import os
import sys
import argparse
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)

from ips.features import build_early_vector, get_feature_names, recompute_early_matrix_for_k
from ips.models.evt import fit_evt_threshold, clopper_pearson_ci
from ips.models.train import is_smoke_dataframe, train_autoencoder
from ips.smoke.synth import SMOKE_BANNER, generate_smoke_dataset

IMPAIRMENT_PROFILES = [
    {"profile": "clean", "delay_ms": 0.0, "jitter_ms": 0.0, "loss_pct": 0.0, "reorder_pct": 0.0},
    {"profile": "mild_wifi", "delay_ms": 5.0, "jitter_ms": 2.0, "loss_pct": 0.5, "reorder_pct": 0.5},
    {"profile": "mod_jitter", "delay_ms": 15.0, "jitter_ms": 10.0, "loss_pct": 1.0, "reorder_pct": 2.0},
    {"profile": "high_jitter", "delay_ms": 30.0, "jitter_ms": 20.0, "loss_pct": 1.5, "reorder_pct": 3.5},
    {"profile": "severe_wan", "delay_ms": 50.0, "jitter_ms": 20.0, "loss_pct": 2.0, "reorder_pct": 5.0},
]


def get_ablation_feature_mask(early_n: int, ablation_mode: str) -> np.ndarray:
    """Return boolean mask of active features for ('full_features' | 'no_iat_features' | 'no_size_features')."""
    names = get_feature_names(early_n)
    mask = np.ones(len(names), dtype=bool)
    if ablation_mode == "full_features":
        return mask
    elif ablation_mode == "no_iat_features":
        for i, col in enumerate(names):
            if "iat" in col:
                mask[i] = False
        return mask
    elif ablation_mode == "no_size_features":
        for i, col in enumerate(names):
            if col.startswith("size_") or col in ("bytes_up", "bytes_down", "first_payload_size"):
                mask[i] = False
        return mask
    else:
        raise ValueError(f"Unknown ablation_mode '{ablation_mode}'")


def apply_netem_impairment_to_matrix(
    df: pd.DataFrame,
    early_n: int,
    delay_ms: float,
    jitter_ms: float,
    loss_pct: float,
    reorder_pct: float,
    seed: int = 42,
) -> np.ndarray:
    """
    Simulate tc-netem delay, jitter, loss (retransmission penalty), and packet reordering
    on early-flow packets and rebuild the [M, 3*N+8] canonical feature matrix.
    """
    if delay_ms == 0.0 and jitter_ms == 0.0 and loss_pct == 0.0 and reorder_pct == 0.0:
        return recompute_early_matrix_for_k(df, early_n)

    rng = np.random.default_rng(seed)
    has_log_iat = "log_iat_0" in df.columns
    rows = []

    for _, row in df.iterrows():
        raw_vlen = int(row.get("raw_valid_len", early_n)) if "raw_valid_len" in row and not np.isnan(row["raw_valid_len"]) else early_n
        vlen = min(raw_vlen, early_n)
        if has_log_iat:
            sizes = [int(round(float(row.get(f"size_{i}", 0.0)) * 1500.0)) for i in range(vlen)]
            dirs = [int(round(float(row.get(f"dir_{i}", 0.0)))) for i in range(vlen)]
            iats_ms = [
                max(0.0, (10.0 ** float(row.get(f"log_iat_{i}", 0.0)) - 1.0) / 1000.0)
                for i in range(max(0, vlen - 1))
            ]
        else:
            sizes = [int(row[f"size_{i}"]) for i in range(vlen) if f"size_{i}" in row]
            dirs = [int(row.get(f"dir_{i}", 0)) for i in range(len(sizes))]
            iats_ms = [float(row.get(f"iat_{i}", 0.0)) for i in range(max(0, len(sizes) - 1))]

        # 1. Packet reordering with probability reorder_pct / 100
        if reorder_pct > 0.0 and len(sizes) >= 2:
            for i in range(len(sizes) - 1):
                if rng.random() < (reorder_pct / 100.0):
                    sizes[i], sizes[i + 1] = sizes[i + 1], sizes[i]
                    dirs[i], dirs[i + 1] = dirs[i + 1], dirs[i]

        # 2. Delay jitter & packet-loss retransmission spikes on IATs
        impaired_iats = []
        for dt in iats_ms:
            jitter_delta = float(rng.normal(0.0, jitter_ms)) if jitter_ms > 0.0 else 0.0
            loss_rto = (200.0 + delay_ms * 2.0) if (loss_pct > 0.0 and rng.random() < (loss_pct / 100.0)) else 0.0
            new_dt = max(0.01, dt + jitter_delta + loss_rto)
            impaired_iats.append(new_dt)

        rows.append(build_early_vector(sizes, dirs, impaired_iats, early_n=early_n))

    return np.array(rows, dtype=np.float32) if rows else np.zeros((0, 3 * early_n + 8), dtype=np.float32)


def run_impairment_study(
    train_df: pd.DataFrame,
    calib_df: pd.DataFrame,
    test_df: pd.DataFrame,
    early_n: int = 12,
    epochs: int = 12,
    seed: int = 42,
    out_dir: str = None,
) -> pd.DataFrame:
    """
    Train clean models under each feature ablation ('full_features', 'no_iat_features', 'no_size_features')
    and evaluate robustness across all netem impairment profiles (C11 / N11).
    """
    is_smoke = (
        is_smoke_dataframe(train_df)
        or is_smoke_dataframe(calib_df)
        or is_smoke_dataframe(test_df)
    )
    source_tag = "synthetic-smoke" if is_smoke else "real"
    if is_smoke:
        print(SMOKE_BANNER)
        if out_dir is None or "offline" in out_dir:
            out_dir = os.path.join(REPO_DIR, "results", "smoke")
    else:
        if out_dir is None:
            out_dir = os.path.join(REPO_DIR, "results", "offline")
    os.makedirs(out_dir, exist_ok=True)

    benign_tr_df = train_df[train_df["is_attack"] == 0] if "is_attack" in train_df.columns else train_df
    benign_cal_df = calib_df[calib_df["is_attack"] == 0] if "is_attack" in calib_df.columns else calib_df

    X_tr_clean_full = recompute_early_matrix_for_k(benign_tr_df, early_n)
    X_cal_clean_full = recompute_early_matrix_for_k(benign_cal_df, early_n)
    y_test = test_df["is_attack"].to_numpy(dtype=int)
    ben_test_mask = (y_test == 0)
    atk_test_mask = (y_test == 1)

    n_tr = max(20, int(len(X_tr_clean_full) * 0.8))
    rows: List[Dict[str, Any]] = []

    for abl_mode in ("full_features", "no_iat_features", "no_size_features"):
        fmask = get_ablation_feature_mask(early_n, abl_mode)
        X_tr_abl = X_tr_clean_full[:n_tr, fmask]
        X_val_abl = X_tr_clean_full[n_tr:, fmask]
        X_cal_abl = X_cal_clean_full[:, fmask]

        model, _ = train_autoencoder(
            X_tr_abl, X_val_abl, input_dim=X_tr_abl.shape[1], epochs=epochs, seed=seed
        )
        cal_scores, _ = model.get_reconstruction_error(X_cal_abl)
        evt_01 = fit_evt_threshold(cal_scores, target_fpr=0.01)
        evt_001 = fit_evt_threshold(cal_scores, target_fpr=0.001)
        tau_01 = evt_01["threshold"]
        tau_001 = evt_001["threshold"]

        clean_fpr_01 = None
        for p_idx, prof in enumerate(IMPAIRMENT_PROFILES):
            X_test_imp_full = apply_netem_impairment_to_matrix(
                test_df,
                early_n=early_n,
                delay_ms=prof["delay_ms"],
                jitter_ms=prof["jitter_ms"],
                loss_pct=prof["loss_pct"],
                reorder_pct=prof["reorder_pct"],
                seed=seed + p_idx,
            )
            X_test_abl = X_test_imp_full[:, fmask]
            scores, _ = model.get_reconstruction_error(X_test_abl)

            auroc = float(roc_auc_score(y_test, scores)) if len(np.unique(y_test)) > 1 else 0.5
            tpr_01 = float(np.mean(scores[atk_test_mask] >= tau_01)) if np.any(atk_test_mask) else 0.0
            tpr_001 = float(np.mean(scores[atk_test_mask] >= tau_001)) if np.any(atk_test_mask) else 0.0

            fp_01 = int(np.sum(scores[ben_test_mask] >= tau_01))
            n_ben = int(np.sum(ben_test_mask))
            fpr_01 = fp_01 / n_ben if n_ben > 0 else 0.0
            ci_01 = clopper_pearson_ci(fp_01, n_ben)

            if prof["profile"] == "clean":
                clean_fpr_01 = fpr_01

            rows.append({
                "ablation_mode": abl_mode,
                "active_features": int(np.sum(fmask)),
                "profile": prof["profile"],
                "delay_ms": prof["delay_ms"],
                "jitter_ms": prof["jitter_ms"],
                "loss_pct": prof["loss_pct"],
                "reorder_pct": prof["reorder_pct"],
                "auroc": round(auroc, 4),
                "tpr_at_fpr01": round(tpr_01, 4),
                "tpr_at_fpr001": round(tpr_001, 4),
                "achieved_fpr_01": round(fpr_01, 4),
                "fpr_ci95_low": round(ci_01[0], 5),
                "fpr_ci95_high": round(ci_01[1], 5),
                "fpr_drift_from_clean": round(fpr_01 - (clean_fpr_01 or 0.0), 4),
                "source": source_tag,
            })

    res_df = pd.DataFrame(rows)
    out_csv = os.path.join(out_dir, "netem_impairment.csv")
    res_df.to_csv(out_csv, index=False)
    print(f"[+] Saved C11 netem impairment & feature ablation study to {out_csv} (source={source_tag})")
    return res_df


def main():
    parser = argparse.ArgumentParser(description="Run C11 network-impairment robustness study")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--early-n", type=int, default=12)
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df_tr = generate_smoke_dataset(n_benign=400, n_attack=0, early_n=args.early_n, session_id="smoke_c11_tr", seed=401)
    df_cal = generate_smoke_dataset(n_benign=250, n_attack=0, early_n=args.early_n, session_id="smoke_c11_cal", seed=402)
    df_te = generate_smoke_dataset(n_benign=250, n_attack=120, early_n=args.early_n, session_id="smoke_c11_te", seed=403)
    run_impairment_study(df_tr, df_cal, df_te, early_n=args.early_n, epochs=args.epochs, seed=args.seed)


if __name__ == "__main__":
    main()
