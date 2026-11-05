#!/usr/bin/env python3
"""
ips/eval/cross_domain.py — Cross-Domain Benign Generalization Experiment (WP2b, B6).

Evaluates domain shift between Own Testbed benign traffic and Aposemat IoT-23
benign hardware captures (CTU-Honeypot-Capture-4-1 Philips Hue,
CTU-Honeypot-Capture-5-1 Amazon Echo, CTU-Honeypot-Capture-7-1 Somfy Door Lock):
  1. Forward direction: Train Autoencoder on Testbed Benign Session 1, calibrate
     EVT threshold on Testbed Benign Session 2, and evaluate WITHOUT retuning on:
       - In-domain Testbed Benign Session 3
       - Out-of-domain IoT-23 Benign captures (Hue, Echo, Somfy)
  2. Reverse direction: Train & calibrate on IoT-23 Benign, evaluate on Testbed Benign.
  3. Metrics reported:
       - Achieved FPR + Clopper-Pearson 95% CI
       - Two-sample Kolmogorov-Smirnov (KS) statistic & p-value on anomaly scores
       - Domain-separation AUROC (how distinguishable out-of-domain benign scores are from in-domain benign)
       - Top-3 features driving the domain shift (by mean per-feature squared error increase)

Rule B0: When run without real IoT-23 pcap extracts (--smoke), writes ONLY to results/smoke/
and prints "SMOKE DATA – NOT A RESULT".
"""
import os
import sys
import argparse
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd
from scipy import stats
from sklearn.metrics import roc_auc_score

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)

from ips.features import get_feature_names, recompute_early_matrix_for_k
from ips.models.evt import fit_evt_threshold, clopper_pearson_ci
from ips.models.train import train_autoencoder
from datasets.adapters.iot23_adapter import adapt_iot23_record
from ips.smoke.synth import generate_smoke_dataset, SMOKE_BANNER


def evaluate_cross_domain_pair(
    x_source_train: np.ndarray,
    x_source_cal: np.ndarray,
    x_source_test: np.ndarray,
    x_target_benign: np.ndarray,
    early_n: int = 12,
    target_fpr: float = 0.01,
    direction_name: str = "testbed_to_iot23",
    source_tag: str = "synthetic-smoke",
    epochs: int = 15,
    seed: int = 42,
) -> Dict[str, Any]:
    """Train & calibrate strictly on source domain benign, then measure shift on target domain benign."""
    input_dim = x_source_train.shape[1]
    feat_names = get_feature_names(early_n)

    model, _ = train_autoencoder(
        x_source_train,
        x_source_cal,
        input_dim=input_dim,
        epochs=epochs,
        seed=seed,
    )

    cal_scores, _ = model.get_reconstruction_error(x_source_cal)
    in_test_scores, in_sq_err = model.get_reconstruction_error(x_source_test)
    out_test_scores, out_sq_err = model.get_reconstruction_error(x_target_benign)

    evt_res = fit_evt_threshold(cal_scores, target_fpr=target_fpr)
    tau = float(evt_res["threshold"])

    # In-domain FPR
    fp_in = int(np.sum(in_test_scores > tau))
    n_in = len(in_test_scores)
    fpr_in = fp_in / max(1, n_in)
    ci_in_lo, ci_in_hi = clopper_pearson_ci(fp_in, max(1, n_in))

    # Out-of-domain FPR (without any retuning!)
    fp_out = int(np.sum(out_test_scores > tau))
    n_out = len(out_test_scores)
    fpr_out = fp_out / max(1, n_out)
    ci_out_lo, ci_out_hi = clopper_pearson_ci(fp_out, max(1, n_out))

    # Score distribution shift: KS test and domain AUROC
    ks_stat, ks_pval = stats.ks_2samp(in_test_scores, out_test_scores)
    y_dom = np.concatenate([np.zeros(n_in, dtype=int), np.ones(n_out, dtype=int)])
    s_dom = np.concatenate([in_test_scores, out_test_scores])
    dom_auroc = float(roc_auc_score(y_dom, s_dom)) if (n_in > 0 and n_out > 0) else 0.5

    # Per-feature shift attribution
    mean_err_diff = np.mean(out_sq_err, axis=0) - np.mean(in_sq_err, axis=0)
    top_idx = np.argsort(mean_err_diff)[::-1][:3]
    top_shift_features = [f"{feat_names[i]} (+{mean_err_diff[i]:.4f})" for i in top_idx]

    return {
        "source": source_tag,
        "direction": direction_name,
        "target_fpr": target_fpr,
        "threshold": round(tau, 6),
        "in_domain_fpr": round(fpr_in, 4),
        "in_domain_fpr_ci": f"[{ci_in_lo:.4f}, {ci_in_hi:.4f}]",
        "cross_domain_fpr": round(fpr_out, 4),
        "cross_domain_fpr_ci": f"[{ci_out_lo:.4f}, {ci_out_hi:.4f}]",
        "ks_statistic": round(float(ks_stat), 4),
        "ks_pvalue": float(ks_pval),
        "domain_shift_auroc": round(dom_auroc, 4),
        "top_3_shift_features": "; ".join(top_shift_features),
    }


def _build_smoke_iot23_benign(early_n: int = 12, n_per_device: int = 80, seed: int = 99) -> pd.DataFrame:
    """Build smoke IoT-23 benign fixture for Hue (4-1), Echo (5-1), and Somfy (7-1) (V1 code verification)."""
    rng = np.random.default_rng(seed)
    rows = []
    specs = [
        ("CTU-Honeypot-Capture-4-1", 115, 220.0),  # Philips Hue
        ("CTU-Honeypot-Capture-5-1", 260, 85.0),   # Amazon Echo
        ("CTU-Honeypot-Capture-7-1", 75, 450.0),   # Somfy Door Lock
    ]
    for cap_name, sz_mean, iat_mean in specs:
        for _ in range(n_per_device):
            raw = {}
            for i in range(early_n):
                raw[f"size_{i}"] = max(20, int(rng.normal(sz_mean, 25)))
                raw[f"dir_{i}"] = 0 if (i % 2 == 0) else 1
                if i < early_n - 1:
                    raw[f"iat_{i}"] = max(5.0, float(rng.normal(iat_mean, iat_mean * 0.25)))
            rows.append(adapt_iot23_record(raw, early_n=early_n, capture_name=cap_name, is_attack=0))
    return pd.DataFrame(rows)


def run_cross_domain_experiment(out_dir: str, early_n: int = 12, is_smoke: bool = True) -> pd.DataFrame:
    if is_smoke:
        print(SMOKE_BANNER)
    os.makedirs(out_dir, exist_ok=True)

    tb_s1 = generate_smoke_dataset(n_benign=300, n_attack=0, early_n=early_n, session_id="tb_s1", seed=41)
    tb_s2 = generate_smoke_dataset(n_benign=200, n_attack=0, early_n=early_n, session_id="tb_s2", seed=42)
    tb_s3 = generate_smoke_dataset(n_benign=200, n_attack=0, early_n=early_n, session_id="tb_s3", seed=43)
    iot23_df = _build_smoke_iot23_benign(early_n=early_n, n_per_device=80, seed=99)

    x_tb_train = recompute_early_matrix_for_k(tb_s1, early_n)
    x_tb_cal = recompute_early_matrix_for_k(tb_s2, early_n)
    x_tb_test = recompute_early_matrix_for_k(tb_s3, early_n)
    x_iot_all = recompute_early_matrix_for_k(iot23_df, early_n)

    rows = []
    # 1. Forward: Train on Testbed -> Evaluate on IoT-23 (overall and per device)
    rows.append(
        evaluate_cross_domain_pair(
            x_tb_train, x_tb_cal, x_tb_test, x_iot_all,
            early_n=early_n, direction_name="Testbed -> IoT-23 (All 3 Benign Devices)",
        )
    )
    for cap in ("CTU-Honeypot-Capture-4-1", "CTU-Honeypot-Capture-5-1", "CTU-Honeypot-Capture-7-1"):
        sub_df = iot23_df[iot23_df["session_id"] == cap]
        x_sub = recompute_early_matrix_for_k(sub_df, early_n)
        rows.append(
            evaluate_cross_domain_pair(
                x_tb_train, x_tb_cal, x_tb_test, x_sub,
                early_n=early_n, direction_name=f"Testbed -> IoT-23 ({cap})",
            )
        )

    # 2. Reverse: Train on IoT-23 -> Evaluate on Testbed
    n_iot = len(x_iot_all)
    idx = np.random.default_rng(42).permutation(n_iot)
    x_iot_tr = x_iot_all[idx[: int(0.5 * n_iot)]]
    x_iot_ca = x_iot_all[idx[int(0.5 * n_iot) : int(0.75 * n_iot)]]
    x_iot_te = x_iot_all[idx[int(0.75 * n_iot) :]]
    rows.append(
        evaluate_cross_domain_pair(
            x_iot_tr, x_iot_ca, x_iot_te, x_tb_test,
            early_n=early_n, direction_name="IoT-23 -> Testbed (Reverse)",
        )
    )

    df_out = pd.DataFrame(rows)
    out_csv = os.path.join(out_dir, "cross_domain_eval.csv")
    df_out.to_csv(out_csv, index=False)
    print(f"[+] Wrote cross-domain evaluation table to {out_csv}")
    return df_out


def main():
    parser = argparse.ArgumentParser(description="Run Cross-Domain Benign Generalization Experiment (B6)")
    parser.add_argument("--out-dir", default=os.path.join(REPO_DIR, "results", "smoke"))
    parser.add_argument("--early-n", type=int, default=12)
    args = parser.parse_args()
    run_cross_domain_experiment(args.out_dir, early_n=args.early_n, is_smoke=("smoke" in args.out_dir))


if __name__ == "__main__":
    main()
