#!/usr/bin/env python3
"""
ips/models/eval_offline.py — Comprehensive offline evaluation, N-sweep, EVT curve, and quantization tables.

Produces:
  1. Model comparison table (IF vs AE-FP32 vs AE-INT8 vs Kitsune-style vs Per-Class AE)
  2. Per-family & Leave-One-Family-Out (LOFO) zero-day evaluation table
  3. Early-window N sweep (N in {4, 6, 8, 12, 16, 24}) with Time-to-Verdict (B1)
  4. EVT Target-vs-Achieved FPR Calibration Curve CSV + Matplotlib Figure (N3)
  5. FP32 vs INT8 Quantization comparison table

Rule B0: When run on synthetic smoke data, all outputs are written strictly under
results/smoke/ and stamped with source="synthetic-smoke".
"""
import os
import sys
import json
import pickle
import argparse
from typing import Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)

from ips.models.train import extract_matrix_from_df, is_smoke_dataframe, train_autoencoder
from ips.models.evt import clopper_pearson_ci, compute_calibration_curve, fit_evt_threshold
from ips.smoke.synth import SMOKE_BANNER

try:
    import onnxruntime as ort
except ImportError:
    ort = None


def evaluate_scores(y_true: np.ndarray, scores: np.ndarray, thresholds_dict: Dict[str, float]) -> Dict[str, Any]:
    """Calculate AUROC, AUPRC, and TPR/FPR with Clopper-Pearson 95% CIs at each threshold."""
    if len(np.unique(y_true)) < 2:
        return {"auroc": 0.5, "auprc": 0.0}

    auroc = float(roc_auc_score(y_true, scores))
    prec, rec, _ = precision_recall_curve(y_true, scores)
    auprc = float(auc(rec, prec))

    metrics: Dict[str, Any] = {
        "auroc": round(auroc, 4),
        "auprc": round(auprc, 4),
    }

    n_benign = int(np.sum(y_true == 0))
    n_attack = int(np.sum(y_true == 1))

    for name, t_val in thresholds_dict.items():
        y_pred = (scores >= t_val).astype(int)
        tp = int(np.sum((y_pred == 1) & (y_true == 1)))
        fp = int(np.sum((y_pred == 1) & (y_true == 0)))

        tpr = tp / n_attack if n_attack > 0 else 0.0
        fpr = fp / n_benign if n_benign > 0 else 0.0
        ci_low, ci_high = clopper_pearson_ci(fp, n_benign)

        metrics[f"tpr_{name}"] = round(tpr, 4)
        metrics[f"fpr_{name}"] = round(fpr, 4)
        metrics[f"fpr_ci95_{name}"] = f"[{ci_low:.5f}, {ci_high:.5f}]"

    return metrics


def score_onnx_model(onnx_path: str, X: np.ndarray) -> np.ndarray:
    """Compute per-sample reconstruction MSE using an ONNX model."""
    sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    inp_name = sess.get_inputs()[0].name
    out = sess.run(None, {inp_name: X.astype(np.float32)})[0]
    return np.mean(np.square(X - out), axis=1)


def compute_time_to_verdict_ms(df: pd.DataFrame, early_n: int) -> np.ndarray:
    """Compute elapsed time (ms) to reach the N-th payload packet per flow (Requirement B1)."""
    ttv = []
    for _, row in df.iterrows():
        raw_vlen = int(row.get("raw_valid_len", early_n)) if "raw_valid_len" in row and pd.notna(row["raw_valid_len"]) else early_n
        target_pkts = min(raw_vlen, early_n)
        s = 0.0
        for i in range(max(0, target_pkts - 1)):
            col_raw = f"iat_{i}"
            col_log = f"log_iat_{i}"
            if col_raw in row and pd.notna(row[col_raw]):
                s += float(row[col_raw])
            elif col_log in row and pd.notna(row[col_log]):
                val = float(row[col_log])
                if val > 0.0:
                    s += max(0.0, (10.0 ** val - 1.0) / 1000.0)
        if s == 0.0 and "duration_ms" in row and pd.notna(row["duration_ms"]):
            s = float(row["duration_ms"]) * (float(target_pkts) / float(max(1, raw_vlen)))
        ttv.append(s)
    return np.array(ttv, dtype=np.float64)


def evaluate_progressive_checkpoints(
    df: pd.DataFrame,
    card: Dict[str, Any],
    scheme: str = "equal",
    target_fpr_key: str = "001",
    source_tag: str = "synthetic-smoke",
) -> Dict[str, Any]:
    """
    Evaluate progressive multi-checkpoint inference (C1 / N7):
      - Early DROP at the first checkpoint k where score_k >= tau_k(alpha_k).
      - Late BYPASS at the final checkpoint K if no checkpoint fired.
      - Short flows ending before packet k are only evaluated at checkpoints <= raw_valid_len.
    Reports empirical flow-level FPR (measuring union-bound conservativeness) and attack-packet leakage.
    """
    ckpt_cfg = card.get("checkpoint_models", {})
    checkpoints = [int(k) for k in sorted(ckpt_cfg.keys(), key=lambda x: int(x))]
    if not checkpoints:
        return {}

    y = df["is_attack"].to_numpy(dtype=int) if "is_attack" in df.columns else np.zeros(len(df), dtype=int)
    raw_vlens = (
        df["raw_valid_len"].to_numpy(dtype=int)
        if "raw_valid_len" in df.columns
        else np.full(len(df), max(checkpoints), dtype=int)
    )
    total_pkts = (
        df["total_pkts"].to_numpy(dtype=int)
        if "total_pkts" in df.columns
        else raw_vlens.copy()
    )

    # Pre-compute score matrices and TTV arrays at each checkpoint k
    scores_by_k: Dict[int, np.ndarray] = {}
    tau_by_k: Dict[int, float] = {}
    ttv_by_k: Dict[int, np.ndarray] = {}

    tau_field = f"tau_{scheme}_{target_fpr_key}"
    for k in checkpoints:
        cinfo = ckpt_cfg[str(k)]
        X_k, _, _ = extract_matrix_from_df(df, early_n=k)
        onnx_p = cinfo.get("onnx_int8_path", cinfo.get("onnx_fp32_path"))
        scores_by_k[k] = score_onnx_model(onnx_p, X_k)
        tau_by_k[k] = float(cinfo.get(tau_field, cinfo.get("tau_equal_001", 0.05)))
        ttv_by_k[k] = compute_time_to_verdict_ms(df, early_n=k)

    n_flows = len(df)
    flow_dropped = np.zeros(n_flows, dtype=int)
    verdict_pkt = np.zeros(n_flows, dtype=int)
    verdict_time_ms = np.zeros(n_flows, dtype=np.float64)
    packets_leaked = np.zeros(n_flows, dtype=int)
    max_norm_score = np.zeros(n_flows, dtype=np.float64)

    last_k = checkpoints[-1]
    for i in range(n_flows):
        vlen = int(raw_vlens[i])
        tot_p = max(vlen, int(total_pkts[i]))
        decided = False
        for k in checkpoints:
            if vlen >= k:
                sk = float(scores_by_k[k][i])
                tk = tau_by_k[k]
                norm_s = sk / max(1e-9, tk)
                if norm_s > max_norm_score[i]:
                    max_norm_score[i] = norm_s
                if sk >= tk:
                    flow_dropped[i] = 1
                    verdict_pkt[i] = k
                    verdict_time_ms[i] = float(ttv_by_k[k][i])
                    packets_leaked[i] = k  # stopped at packet k
                    decided = True
                    break
        if not decided:
            # Never triggered DROP; either reached last_k (late BYPASS) or finished early
            verdict_pkt[i] = min(vlen, last_k)
            reach_k = max([k for k in checkpoints if vlen >= k], default=checkpoints[0])
            verdict_time_ms[i] = float(ttv_by_k[reach_k][i])
            packets_leaked[i] = tot_p

    ben_mask = (y == 0)
    atk_mask = (y == 1)
    n_ben = int(np.sum(ben_mask))
    n_atk = int(np.sum(atk_mask))

    fp = int(np.sum(flow_dropped[ben_mask] == 1))
    tp = int(np.sum(flow_dropped[atk_mask] == 1))
    achieved_fpr = fp / n_ben if n_ben > 0 else 0.0
    achieved_tpr = tp / n_atk if n_atk > 0 else 0.0
    ci_low, ci_high = clopper_pearson_ci(fp, n_ben)
    auroc = float(roc_auc_score(y, max_norm_score)) if len(np.unique(y)) > 1 else 0.5

    target_alpha = 0.001 if target_fpr_key == "001" else 0.01
    return {
        "scheme": f"progressive_{checkpoints}_{scheme}_fpr{target_fpr_key}",
        "checkpoints": str(checkpoints),
        "alpha_spending": scheme,
        "target_flow_fpr": target_alpha,
        "achieved_flow_fpr": round(achieved_fpr, 5),
        "fpr_ci95_low": round(ci_low, 5),
        "fpr_ci95_high": round(ci_high, 5),
        "union_bound_ratio": round(achieved_fpr / max(1e-9, target_alpha), 3),
        "tpr": round(achieved_tpr, 4),
        "auroc": round(auroc, 4),
        "mean_verdict_pkt_attack": round(float(np.mean(verdict_pkt[atk_mask])), 2) if n_atk > 0 else 0.0,
        "mean_attack_packets_leaked": round(float(np.mean(packets_leaked[atk_mask])), 2) if n_atk > 0 else 0.0,
        "mean_time_to_verdict_atk_ms": round(float(np.mean(verdict_time_ms[atk_mask])), 2) if n_atk > 0 else 0.0,
        "p95_time_to_verdict_atk_ms": round(float(np.percentile(verdict_time_ms[atk_mask], 95)), 2) if n_atk > 0 else 0.0,
        "source": source_tag,
    }


def plot_calibration_curve(calib_rows: List[Dict[str, Any]], fig_path: str, is_smoke: bool):
    """Plot Target FPR vs Achieved FPR with Clopper-Pearson CIs and Split-Conformal regime boundary (C9/N9)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        df_c = pd.DataFrame(calib_rows)
        fig, ax = plt.subplots(figsize=(6.5, 4.8))
        x = df_c["target_fpr"].values
        y_evt = df_c["evt_achieved_fpr"].values
        y_conf = df_c["conformal_achieved_fpr"].values if "conformal_achieved_fpr" in df_c.columns else df_c["emp_achieved_fpr"].values
        y_3s = df_c["three_sigma_achieved_fpr"].values

        ax.plot(x, x, "k--", label="Ideal (Target = Achieved)")
        ax.plot(x, y_evt, "o-", label="EVT (POT GPD)")
        ax.plot(x, y_conf, "s-", label="Split-Conformal")
        ax.plot(x, y_3s, "^-", label="Fixed Mean + 3σ")

        if "conformal_min_supported_alpha" in df_c.columns and len(df_c) > 0:
            min_alpha = float(df_c["conformal_min_supported_alpha"].iloc[0])
            ax.axvline(min_alpha, color="red", linestyle=":", label=f"Conformal floor 1/(n+1)={min_alpha:.4f}")

        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("Target FPR (α)")
        ax.set_ylabel("Achieved FPR on Held-Out Benign Test")
        title = "EVT vs Split-Conformal Target-FPR Calibration (C9)"
        if is_smoke:
            title += " [SMOKE DATA - NOT A RESULT]"
        ax.set_title(title)
        ax.legend(fontsize=8)
        ax.grid(True, which="both", ls=":", alpha=0.6)
        os.makedirs(os.path.dirname(os.path.abspath(fig_path)), exist_ok=True)
        fig.tight_layout()
        fig.savefig(fig_path, dpi=150)
        plt.close(fig)
    except Exception:
        pass


def run_offline_evaluation(test_data_path: str, model_card_path: str = "models/model_card.json",
                           out_dir: str = None, run_n_sweep: bool = True) -> Dict[str, Any]:
    """Run full WP5 offline evaluation suite."""
    with open(model_card_path, "r", encoding="utf-8") as f:
        card = json.load(f)

    df = pd.read_csv(test_data_path) if test_data_path.endswith(".csv") else pd.read_parquet(test_data_path)
    is_smoke = is_smoke_dataframe(df, test_data_path) or (card.get("data_source") == "synthetic-smoke")
    source_tag = "synthetic-smoke" if is_smoke else "real"

    # Enforce B0 rule: smoke results never leave results/smoke/
    if is_smoke:
        print(SMOKE_BANNER)
        if out_dir is None or "offline" in out_dir:
            out_dir = os.path.join(REPO_DIR, "results", "smoke")
        fig_dir = os.path.join(REPO_DIR, "results", "smoke", "figures")
    else:
        if out_dir is None:
            out_dir = os.path.join(REPO_DIR, "results", "offline")
        fig_dir = os.path.join(REPO_DIR, "results", "figures")

    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(fig_dir, exist_ok=True)

    early_n = card["early_n"]
    X, y, _ = extract_matrix_from_df(df, early_n=early_n)

    # 1. Score Global AE (FP32 and INT8)
    scores_fp32 = score_onnx_model(card["onnx_fp32_path"], X)
    scores_int8 = score_onnx_model(card["onnx_int8_path"], X)

    evt_001 = card["evt_calibration"]
    evt_01 = card.get("evt_calibration_01", evt_001)
    ae_thresholds = {
        "evt_001": evt_001["threshold"],
        "evt_01": evt_01["threshold"],
        "conformal_001": evt_001.get("conformal_q", evt_001["empirical_q"]),
        "conformal_01": evt_01.get("conformal_q", evt_01["empirical_q"]),
        "three_sigma": evt_001["three_sigma"],
        "empirical_q": evt_001["empirical_q"],
    }

    met_fp32 = evaluate_scores(y, scores_fp32, ae_thresholds)
    met_fp32["model"] = "Autoencoder_FP32"
    met_fp32["source"] = source_tag

    met_int8 = evaluate_scores(y, scores_int8, ae_thresholds)
    met_int8["model"] = "Autoencoder_INT8"
    met_int8["source"] = source_tag

    model_rows = [met_fp32, met_int8]

    # 2. Score Kitsune-style ensemble if present
    if "kitsune_pkl_path" in card and os.path.exists(card["kitsune_pkl_path"]):
        with open(card["kitsune_pkl_path"], "rb") as f:
            kit_model = pickle.load(f)
        kit_scores = kit_model.score(X)
        kit_evt = card["kitsune_evt_001"]
        kit_evt_01 = card.get("kitsune_evt_01", kit_evt)
        met_kit = evaluate_scores(y, kit_scores, {
            "evt_001": kit_evt["threshold"],
            "evt_01": kit_evt_01["threshold"],
            "three_sigma": kit_evt["three_sigma"],
            "empirical_q": kit_evt["empirical_q"],
        })
        met_kit["model"] = "Kitsune_Style_Ensemble"
        met_kit["source"] = source_tag
        model_rows.append(met_kit)

    # 3. Score Isolation Forest if present
    if "iforest_pkl_path" in card and os.path.exists(card["iforest_pkl_path"]):
        with open(card["iforest_pkl_path"], "rb") as f:
            if_model = pickle.load(f)
        if_scores = -if_model.score_samples(X)
        if_evt = card["iforest_evt_001"]
        if_evt_01 = card.get("iforest_evt_01", if_evt)
        met_if = evaluate_scores(y, if_scores, {
            "evt_001": if_evt["threshold"],
            "evt_01": if_evt_01["threshold"],
            "three_sigma": if_evt["three_sigma"],
            "empirical_q": if_evt["empirical_q"],
        })
        met_if["model"] = "Isolation_Forest"
        met_if["source"] = source_tag
        model_rows.append(met_if)

    # 4. Score Per-Class Autoencoder (Ablation N5) if available
    per_class_cfg = card.get("per_class_models", {})
    if per_class_cfg and "device_class" in df.columns:
        pc_scores = scores_fp32.copy()
        for cls_name, cinfo in per_class_cfg.items():
            mask = (df["device_class"] == cls_name).values
            if np.any(mask) and os.path.exists(cinfo["onnx_path"]):
                # Normalize by class threshold so threshold=1.0 is uniform across classes
                raw_cls_s = score_onnx_model(cinfo["onnx_path"], X[mask])
                pc_scores[mask] = raw_cls_s / max(1e-9, cinfo["evt_001"]) * evt_001["threshold"]
        met_pc = evaluate_scores(y, pc_scores, ae_thresholds)
        met_pc["model"] = "Per_Class_Autoencoder"
        met_pc["source"] = source_tag
        model_rows.append(met_pc)

    models_df = pd.DataFrame(model_rows)
    models_df.to_csv(os.path.join(out_dir, "eval_models.csv"), index=False)
    models_df.to_csv(os.path.join(out_dir, "eval_metrics.csv"), index=False)

    # 5. Per-family & Leave-One-Family-Out (LOFO) Zero-Day table + Time-to-Verdict
    ttv_ms = compute_time_to_verdict_ms(df, early_n=early_n)
    family_rows = []
    if "attack_family" in df.columns:
        held_out_families = {"A3_c2", "A4_exfil"}
        for fam in sorted(df["attack_family"].dropna().unique()):
            if fam in ("none", "benign"):
                continue
            idx = ((df["attack_family"] == fam) | (df["is_attack"] == 0)).values
            fam_met = evaluate_scores(y[idx], scores_int8[idx], ae_thresholds)
            fam_atk_mask = (df["attack_family"] == fam).values
            fam_met["family"] = fam
            fam_met["split_role"] = "HELD_OUT_ZERO_DAY" if fam in held_out_families else "DEV_FAMILY"
            fam_met["payload_packets_at_verdict"] = early_n
            fam_met["mean_time_to_verdict_ms"] = round(float(np.mean(ttv_ms[fam_atk_mask])), 2) if np.any(fam_atk_mask) else 0.0
            fam_met["p95_time_to_verdict_ms"] = round(float(np.percentile(ttv_ms[fam_atk_mask], 95)), 2) if np.any(fam_atk_mask) else 0.0
            fam_met["source"] = source_tag
            family_rows.append(fam_met)

    if family_rows:
        pd.DataFrame(family_rows).to_csv(os.path.join(out_dir, "eval_families_lofo.csv"), index=False)

    # 6. EVT Calibration Curve (N3)
    calib_scores_path = card.get("calib_scores_path", "")
    if calib_scores_path and os.path.exists(calib_scores_path):
        calib_scores = np.load(calib_scores_path)
    else:
        calib_scores = scores_int8[y == 0]

    test_benign_scores = scores_int8[y == 0]
    calib_rows = compute_calibration_curve(calib_scores, test_benign_scores)
    for r in calib_rows:
        r["source"] = source_tag
    calib_csv = os.path.join(out_dir, "calibration_curve.csv")
    pd.DataFrame(calib_rows).to_csv(calib_csv, index=False)
    plot_calibration_curve(calib_rows, os.path.join(fig_dir, "calibration_curve.png"), is_smoke=is_smoke)

    # 7. FP32 vs INT8 Quantization comparison table
    quant_info = card.get("quantization", {})
    quant_row = {
        "source": source_tag,
        "fp32_auroc": met_fp32["auroc"],
        "int8_auroc": met_int8["auroc"],
        "delta_auroc": round(met_int8["auroc"] - met_fp32["auroc"], 6),
        "fp32_tpr_evt001": met_fp32.get("tpr_evt_001", 0.0),
        "int8_tpr_evt001": met_int8.get("tpr_evt_001", 0.0),
        "delta_tpr_evt001": round(met_int8.get("tpr_evt_001", 0.0) - met_fp32.get("tpr_evt_001", 0.0), 6),
        "fp32_size_kb": quant_info.get("fp32_size_kb", 0.0),
        "int8_size_kb": quant_info.get("int8_size_kb", 0.0),
        "size_reduction_pct": quant_info.get("size_reduction_pct", 0.0),
        "fp32_p50_latency_us": quant_info.get("latency_fp32", {}).get("p50_us", 0.0),
        "int8_p50_latency_us": quant_info.get("latency_int8", {}).get("p50_us", 0.0),
        "int8_p99_latency_us": quant_info.get("latency_int8", {}).get("p99_us", 0.0),
    }
    pd.DataFrame([quant_row]).to_csv(os.path.join(out_dir, "quantization_table.csv"), index=False)

    # 7b. Progressive Multi-Checkpoint Inference Evaluation (C1 / N7)
    pareto_rows = []
    if card.get("checkpoint_models"):
        for scheme in ("equal", "front_loaded"):
            for fkey in ("001", "01"):
                p_row = evaluate_progressive_checkpoints(
                    df, card, scheme=scheme, target_fpr_key=fkey, source_tag=source_tag
                )
                if p_row:
                    pareto_rows.append(p_row)
    if pareto_rows:
        pd.DataFrame(pareto_rows).to_csv(os.path.join(out_dir, "progressive_pareto.csv"), index=False)

    # 8. Multi-Seed Sweep over early_n in {4, 6, 8, 12, 16, 24} vs Time-to-Verdict (Requirement B1 & WP5 >=3 seeds)
    if run_n_sweep:
        sweep_rows = []
        benign_mask = (y == 0)
        atk_mask = (y == 1)
        seeds = (42, 43, 44)
        for n_cand in [4, 6, 8, 12, 16, 24]:
            X_n, _, _ = extract_matrix_from_df(df, early_n=n_cand)
            X_ben = X_n[benign_mask]
            if len(X_ben) >= 20:
                n_tr = max(10, int(len(X_ben) * 0.7))
                aurocs, auprcs, tprs, fprs = [], [], [], []
                for sd in seeds:
                    ae_n, _ = train_autoencoder(X_ben[:n_tr], X_ben[n_tr:], input_dim=X_n.shape[1], epochs=8, seed=sd)
                    s_all, _ = ae_n.get_reconstruction_error(X_n)
                    evt_n = fit_evt_threshold(s_all[benign_mask][n_tr:], target_fpr=0.001)
                    m_n = evaluate_scores(y, s_all, {"evt_001": evt_n["threshold"]})
                    aurocs.append(float(m_n["auroc"]))
                    auprcs.append(float(m_n["auprc"]))
                    tprs.append(float(m_n.get("tpr_evt_001", 0.0)))
                    fprs.append(float(m_n.get("fpr_evt_001", 0.0)))

                ttv_n = compute_time_to_verdict_ms(df, early_n=n_cand)
                auroc_ci = 1.96 * float(np.std(aurocs, ddof=1)) / np.sqrt(len(seeds)) if len(seeds) > 1 else 0.0
                tpr_ci = 1.96 * float(np.std(tprs, ddof=1)) / np.sqrt(len(seeds)) if len(seeds) > 1 else 0.0
                sweep_rows.append({
                    "early_n": n_cand,
                    "input_dim": X_n.shape[1],
                    "n_seeds": len(seeds),
                    "auroc": round(float(np.mean(aurocs)), 4),
                    "auroc_ci95_halfwidth": round(auroc_ci, 4),
                    "auprc": round(float(np.mean(auprcs)), 4),
                    "tpr_evt_001": round(float(np.mean(tprs)), 4),
                    "tpr_ci95_halfwidth": round(tpr_ci, 4),
                    "fpr_evt_001": round(float(np.mean(fprs)), 4),
                    "payload_packets_at_verdict": n_cand,
                    "mean_time_to_verdict_atk_ms": round(float(np.mean(ttv_n[atk_mask])), 2) if np.any(atk_mask) else 0.0,
                    "mean_time_to_verdict_benign_ms": round(float(np.mean(ttv_n[benign_mask])), 2),
                    "source": source_tag,
                })
        if sweep_rows:
            pd.DataFrame(sweep_rows).to_csv(os.path.join(out_dir, "eval_n_sweep.csv"), index=False)

    print(f"[OK] Offline evaluation tables written to {out_dir} (source={source_tag})")
    return met_int8


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate offline models, EVT curves, and N sweep")
    parser.add_argument("--test-data", default="results/smoke/smoke_quick_test.csv")
    parser.add_argument("--card", default="models/model_card.json")
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--no-sweep", action="store_true", help="Skip N in {4,6,8,12,16,24} sweep")
    args = parser.parse_args()

    run_offline_evaluation(
        test_data_path=args.test_data,
        model_card_path=args.card,
        out_dir=args.out_dir,
        run_n_sweep=not args.no_sweep,
    )
