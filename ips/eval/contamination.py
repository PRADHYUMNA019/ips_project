#!/usr/bin/env python3
"""
ips/eval/contamination.py — Training-Set Contamination & Trimmed-Loss Mitigation Study (C12 / N12).

Evaluates sensitivity of benign-only autoencoder training when the "benign" training capture
is contaminated with c in {0%, 0.5%, 1%, 2%, 5%} stealthy attack flows from DEV families
(never from held-out families A3_c2, A4_exfil).

Compares:
  1. Standard MSE training (unmitigated)
  2. Trimmed-loss training (drops the highest-loss t% of samples in each training step)
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

from ips.features import recompute_early_matrix_for_k
from ips.models.autoencoder import EarlyFlowAutoencoder
from ips.models.evt import fit_evt_threshold, clopper_pearson_ci
from ips.models.train import is_smoke_dataframe, train_autoencoder
from ips.smoke.synth import SMOKE_BANNER, generate_smoke_dataset

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import TensorDataset, DataLoader
except ImportError:
    torch = None

HELD_OUT_FAMILIES = {"A3_c2", "A4_exfil"}
DEV_FAMILIES = {"A1_flood", "A2_slowloris", "A5_bruteforce"}


def train_autoencoder_trimmed(
    X_train: np.ndarray,
    X_val: np.ndarray,
    input_dim: int,
    trim_pct: float = 0.05,
    epochs: int = 20,
    batch_size: int = 64,
    lr: float = 0.002,
    seed: int = 42,
):
    """
    Train PyTorch Autoencoder with Trimmed MSE Loss (C12 / N12):
    In each mini-batch, drops the top `trim_pct` fraction of samples with the highest
    reconstruction MSE before backpropagating gradients.
    """
    if torch is None:
        raise RuntimeError("torch is required for train_autoencoder_trimmed")
    torch.manual_seed(seed)
    np.random.seed(seed)

    model = EarlyFlowAutoencoder(input_dim=input_dim)
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)

    dataset = TensorDataset(torch.from_numpy(X_train.astype(np.float32)))
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    val_t = torch.from_numpy(X_val.astype(np.float32))

    best_loss = float("inf")
    best_weights = None

    model.train()
    for _ in range(epochs):
        for (batch_x,) in loader:
            optimizer.zero_grad()
            out = model(batch_x)
            per_sample_mse = torch.mean((out - batch_x) ** 2, dim=1)
            n_b = len(per_sample_mse)
            n_keep = max(1, int(round(n_b * (1.0 - trim_pct))))
            if n_keep < n_b:
                vals, _ = torch.topk(per_sample_mse, k=n_keep, largest=False)
                loss = torch.mean(vals)
            else:
                loss = torch.mean(per_sample_mse)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            val_out = model(val_t)
            val_per_sample = torch.mean((val_out - val_t) ** 2, dim=1)
            n_v_keep = max(1, int(round(len(val_per_sample) * (1.0 - trim_pct))))
            val_keep, _ = torch.topk(val_per_sample, k=n_v_keep, largest=False)
            val_loss = float(torch.mean(val_keep).item())

        if val_loss < best_loss:
            best_loss = val_loss
            best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        model.train()

    if best_weights:
        model.load_state_dict(best_weights)
    model.eval()
    return model, best_loss


def run_contamination_study(
    train_df: pd.DataFrame,
    calib_df: pd.DataFrame,
    test_df: pd.DataFrame,
    early_n: int = 12,
    contamination_rates: Tuple[float, ...] = (0.0, 0.005, 0.01, 0.02, 0.05),
    trim_pct: float = 0.05,
    epochs: int = 15,
    seed: int = 42,
    out_dir: str = None,
) -> pd.DataFrame:
    """
    Execute the C12 training-set contamination sweep and trimmed-loss mitigation study.
    Strictly enforces that contaminating flows come ONLY from DEV attack families.
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

    # Extract clean benign training pool and DEV-family attack pool
    benign_train_df = train_df[train_df["is_attack"] == 0].copy()
    fam_col = "attack_family" if "attack_family" in train_df.columns else "label_family"
    dev_attack_pool_df = train_df[
        (train_df["is_attack"] == 1) & (~train_df[fam_col].isin(HELD_OUT_FAMILIES))
    ].copy()
    if len(dev_attack_pool_df) == 0 and fam_col in test_df.columns:
        # If train_df was strictly benign, draw DEV-family contaminating pool from non-held-out attacks
        dev_attack_pool_df = test_df[
            (test_df["is_attack"] == 1) & (~test_df[fam_col].isin(HELD_OUT_FAMILIES))
        ].copy()

    # Assert zero held-out family contamination
    if fam_col in dev_attack_pool_df.columns:
        leaked = set(dev_attack_pool_df[fam_col].unique()).intersection(HELD_OUT_FAMILIES)
        if leaked:
            raise ValueError(f"C12 VIOLATION: Held-out families found in contamination pool: {leaked}")

    X_benign_all = recompute_early_matrix_for_k(benign_train_df, early_n)
    X_dev_atk_pool = recompute_early_matrix_for_k(dev_attack_pool_df, early_n)
    input_dim = X_benign_all.shape[1]

    n_tr = max(20, int(len(X_benign_all) * 0.8))
    X_benign_tr = X_benign_all[:n_tr]
    X_benign_val = X_benign_all[n_tr:]

    calib_benign_df = calib_df[calib_df["is_attack"] == 0] if "is_attack" in calib_df.columns else calib_df
    X_calib = recompute_early_matrix_for_k(calib_benign_df, early_n)

    X_test = recompute_early_matrix_for_k(test_df, early_n)
    y_test = test_df["is_attack"].to_numpy(dtype=int)
    test_fam = test_df[fam_col].astype(str).to_numpy() if fam_col in test_df.columns else np.where(y_test == 1, "A3_c2", "benign")

    held_out_mask = np.isin(test_fam, list(HELD_OUT_FAMILIES)) | (y_test == 0)
    benign_test_mask = (y_test == 0)
    held_out_atk_mask = np.isin(test_fam, list(HELD_OUT_FAMILIES))

    rng = np.random.default_rng(seed)
    rows: List[Dict[str, Any]] = []
    baseline_clean_tpr = None

    for c_rate in contamination_rates:
        if c_rate <= 0.0 or len(X_dev_atk_pool) == 0:
            X_tr_mixed = X_benign_tr.copy()
            n_injected = 0
        else:
            n_injected = max(1, int(round(len(X_benign_tr) * c_rate / max(1e-6, 1.0 - c_rate))))
            idx = rng.choice(len(X_dev_atk_pool), size=n_injected, replace=(n_injected > len(X_dev_atk_pool)))
            X_tr_mixed = np.vstack([X_benign_tr, X_dev_atk_pool[idx]])

        for method_name, is_trimmed in [("standard_mse", False), (f"trimmed_{int(trim_pct*100)}pct", True)]:
            if is_trimmed:
                model, _ = train_autoencoder_trimmed(
                    X_tr_mixed, X_benign_val, input_dim=input_dim,
                    trim_pct=trim_pct, epochs=epochs, seed=seed
                )
            else:
                model, _ = train_autoencoder(
                    X_tr_mixed, X_benign_val, input_dim=input_dim,
                    epochs=epochs, seed=seed
                )

            calib_scores, _ = model.get_reconstruction_error(X_calib)
            evt_01 = fit_evt_threshold(calib_scores, target_fpr=0.01)
            evt_001 = fit_evt_threshold(calib_scores, target_fpr=0.001)
            tau_01 = evt_01["threshold"]
            tau_001 = evt_001["threshold"]

            test_scores, _ = model.get_reconstruction_error(X_test)
            auroc_all = float(roc_auc_score(y_test, test_scores)) if len(np.unique(y_test)) > 1 else 0.5
            auroc_ho = (
                float(roc_auc_score(y_test[held_out_mask], test_scores[held_out_mask]))
                if np.any(held_out_atk_mask) and np.any(benign_test_mask)
                else auroc_all
            )

            ho_scores = test_scores[held_out_atk_mask] if np.any(held_out_atk_mask) else test_scores[y_test == 1]
            ben_scores = test_scores[benign_test_mask]

            tpr_ho_01 = float(np.mean(ho_scores >= tau_01)) if len(ho_scores) > 0 else 0.0
            tpr_ho_001 = float(np.mean(ho_scores >= tau_001)) if len(ho_scores) > 0 else 0.0
            fpr_ben_01 = float(np.mean(ben_scores >= tau_01)) if len(ben_scores) > 0 else 0.0
            fpr_ben_001 = float(np.mean(ben_scores >= tau_001)) if len(ben_scores) > 0 else 0.0
            ci_01 = clopper_pearson_ci(int(np.sum(ben_scores >= tau_01)), len(ben_scores))

            if c_rate == 0.0 and not is_trimmed:
                baseline_clean_tpr = tpr_ho_01

            rows.append({
                "contamination_rate": c_rate,
                "contamination_pct": round(c_rate * 100.0, 2),
                "n_benign_train": len(X_benign_tr),
                "n_injected_dev_attacks": n_injected,
                "training_method": method_name,
                "trim_pct": trim_pct if is_trimmed else 0.0,
                "held_out_auroc": round(auroc_ho, 4),
                "all_attack_auroc": round(auroc_all, 4),
                "held_out_tpr_at_fpr01": round(tpr_ho_01, 4),
                "held_out_tpr_at_fpr001": round(tpr_ho_001, 4),
                "benign_fpr_at_01": round(fpr_ben_01, 4),
                "benign_fpr_ci95_low": round(ci_01[0], 5),
                "benign_fpr_ci95_high": round(ci_01[1], 5),
                "benign_fpr_at_001": round(fpr_ben_001, 4),
                "baseline_clean_tpr_01": round(baseline_clean_tpr or tpr_ho_01, 4),
                "source": source_tag,
            })

    res_df = pd.DataFrame(rows)
    out_csv = os.path.join(out_dir, "contamination_study.csv")
    res_df.to_csv(out_csv, index=False)
    print(f"[+] Saved C12 contamination study to {out_csv} (source={source_tag})")
    return res_df


def main():
    parser = argparse.ArgumentParser(description="Run C12 training-set contamination study")
    parser.add_argument("--early-n", type=int, default=12)
    parser.add_argument("--epochs", type=int, default=15)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df_tr = generate_smoke_dataset(n_benign=500, n_attack=100, early_n=args.early_n, session_id="smoke_c12_train", seed=201)
    df_cal = generate_smoke_dataset(n_benign=300, n_attack=0, early_n=args.early_n, session_id="smoke_c12_cal", seed=202)
    df_te = generate_smoke_dataset(n_benign=300, n_attack=150, early_n=args.early_n, session_id="smoke_c12_test", seed=203)
    run_contamination_study(df_tr, df_cal, df_te, early_n=args.early_n, epochs=args.epochs, seed=args.seed)


if __name__ == "__main__":
    main()
