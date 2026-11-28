#!/usr/bin/env python3
"""
demo/audit_tqh_c2_real.py — Real-Data Audit of TQH-C2 Testbed D Zeek Flow Summaries (Prompt 8 §3.3 & Prompt 9 Item 4b).

Evidence Type: REAL PUBLIC DATA (TQH-C2 v1.2.0 Testbed D, Zenodo 21523144, CC-BY-4.0).
Computes per-(interval_s, jitter_pct) cell:
  1. Flow counts (total, malicious_c2, benign)
  2. Upper-bound estimated payload-packet checkpoint reachability (max(1, total_pkts - 3))
  3. Host-pair inter-connection CV (min_connections=8, rule CV <= 0.35 and full SlowC2Tracker)
     for BOTH malicious C2 host pairs AND benign background host pairs (false-positive baseline).
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_DIR)

from datasets.adapters.tqh_adapter import load_tqh_parquet_summary
from ips.drift.periodicity import SlowC2Tracker


def compute_pair_stats(sub_df: pd.DataFrame, min_conns: int = 8, cv_thresh: float = 0.35) -> dict:
    """Compute host-pair inter-connection CV and SlowC2Tracker flag counts on (orig_h, resp_h, resp_p)."""
    cvs = []
    med_dts = []
    flagged_cv = 0
    flagged_tracker = 0

    for (orig_h, resp_h, resp_p), grp in sub_df.groupby(["orig_h", "resp_h", "resp_p"]):
        ts = np.sort(grp["ts"].to_numpy(dtype=np.float64))
        if len(ts) < min_conns:
            continue
        dt = np.diff(ts)
        dt_pos = dt[dt > 0]
        if len(dt_pos) < 2:
            continue
        mean_dt = float(np.mean(dt_pos))
        cv = float(np.std(dt_pos) / mean_dt) if mean_dt > 1e-9 else 1.0
        cvs.append(cv)
        med_dts.append(float(np.median(dt_pos)))
        if cv <= cv_thresh:
            flagged_cv += 1

        tracker = SlowC2Tracker(max_history=max(64, len(ts)), min_connections=min_conns, cv_threshold=cv_thresh)
        last_res = None
        for t_val in ts:
            last_res = tracker.record_connection(str(orig_h), str(resp_h), int(resp_p), float(t_val))
        if last_res and last_res["is_c2_beacon"]:
            flagged_tracker += 1

    n_pairs = len(cvs)
    return {
        "pairs_ge_8": n_pairs,
        "median_inter_conn_s": round(float(np.median(med_dts)), 2) if med_dts else None,
        "median_cv": round(float(np.median(cvs)), 4) if cvs else None,
        "min_cv": round(float(np.min(cvs)), 4) if cvs else None,
        "flagged_cv_le_035": flagged_cv,
        "flagged_full_tracker": flagged_tracker,
        "fpr_or_tpr_cv_le_035": round(flagged_cv / n_pairs, 4) if n_pairs > 0 else None,
    }


def main():
    parser = argparse.ArgumentParser(description="Audit TQH-C2 Testbed D with C2 and benign host-pair CV baseline")
    parser.add_argument(
        "--zip-path",
        default=os.path.join(os.environ.get("IPS_DATA_ROOT", r"D:\ips_data"), "tqh_c2", "TQH-C2_features_D.zip"),
    )
    parser.add_argument("--out-csv", default=os.path.join(REPO_DIR, "demo", "evidence", "real", "tqh_c2_audit.csv"))
    args = parser.parse_args()

    df = load_tqh_parquet_summary(args.zip_path)
    rows = []
    for (iv, jt), cell in df.groupby(["interval_s", "jitter_pct"]):
        c2 = cell[cell["is_attack"] == 1]
        ben = cell[cell["is_attack"] == 0]
        c2_pkts = c2["total_pkts"].to_numpy(dtype=int)
        c2_est_pay = np.where(c2["total_bytes"].to_numpy(dtype=float) > 0, np.maximum(1, c2_pkts - 3), 0)
        c2_dur = c2["duration"].fillna(0.0).to_numpy(dtype=float)

        c2_stats = compute_pair_stats(c2, min_conns=8, cv_thresh=0.35)
        ben_stats = compute_pair_stats(ben, min_conns=8, cv_thresh=0.35)

        rows.append(
            {
                "source": "REAL PUBLIC DATA (TQH-C2 Testbed D, Zenodo 21523144)",
                "interval_s": int(iv),
                "jitter_pct": int(jt),
                "total_flows": int(len(cell)),
                "c2_flows": int(len(c2)),
                "benign_flows": int(len(ben)),
                "c2_total_pkts_p50": round(float(np.median(c2_pkts)), 1),
                "c2_total_pkts_p95": round(float(np.percentile(c2_pkts, 95)), 1),
                "c2_pct_raw_pkts_ge_4": round(float((c2_pkts >= 4).mean() * 100.0), 2),
                "c2_pct_raw_pkts_ge_8": round(float((c2_pkts >= 8).mean() * 100.0), 2),
                "c2_pct_raw_pkts_ge_16": round(float((c2_pkts >= 16).mean() * 100.0), 2),
                "c2_pct_est_payload_ge_4": round(float((c2_est_pay >= 4).mean() * 100.0), 2),
                "c2_pct_est_payload_ge_8": round(float((c2_est_pay >= 8).mean() * 100.0), 2),
                "c2_pct_est_payload_ge_16": round(float((c2_est_pay >= 16).mean() * 100.0), 2),
                "c2_duration_p50_s": round(float(np.median(c2_dur)), 4),
                "c2_duration_p95_s": round(float(np.percentile(c2_dur, 95)), 4),
                "c2_duration_max_s": round(float(np.max(c2_dur)), 2),
                "c2_host_pairs_ge_8_conns": c2_stats["pairs_ge_8"],
                "c2_pair_median_inter_conn_s": c2_stats["median_inter_conn_s"],
                "c2_pair_median_cv": c2_stats["median_cv"],
                "c2_pairs_flagged_cv_le_035": c2_stats["flagged_cv_le_035"],
                "c2_pairs_flagged_full_tracker": c2_stats["flagged_full_tracker"],
                "benign_host_pairs_ge_8_conns": ben_stats["pairs_ge_8"],
                "benign_pair_median_inter_conn_s": ben_stats["median_inter_conn_s"],
                "benign_pair_median_cv": ben_stats["median_cv"],
                "benign_pair_min_cv": ben_stats["min_cv"],
                "benign_pairs_flagged_cv_le_035": ben_stats["flagged_cv_le_035"],
                "benign_pairs_flagged_full_tracker": ben_stats["flagged_full_tracker"],
                "benign_pair_fpr_cv_le_035": ben_stats["fpr_or_tpr_cv_le_035"],
            }
        )

    out_df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(os.path.abspath(args.out_csv)), exist_ok=True)
    out_df.to_csv(args.out_csv, index=False)
    print(
        out_df[
            [
                "interval_s",
                "jitter_pct",
                "c2_host_pairs_ge_8_conns",
                "c2_pair_median_cv",
                "c2_pairs_flagged_cv_le_035",
                "benign_host_pairs_ge_8_conns",
                "benign_pair_median_cv",
                "benign_pair_min_cv",
                "benign_pairs_flagged_cv_le_035",
                "benign_pairs_flagged_full_tracker",
            ]
        ].to_string(index=False)
    )
    tot_c2 = int(out_df["c2_host_pairs_ge_8_conns"].sum())
    fl_c2 = int(out_df["c2_pairs_flagged_cv_le_035"].sum())
    tot_ben = int(out_df["benign_host_pairs_ge_8_conns"].sum())
    fl_ben_cv = int(out_df["benign_pairs_flagged_cv_le_035"].sum())
    fl_ben_tr = int(out_df["benign_pairs_flagged_full_tracker"].sum())
    print(
        f"\n[TOTALS] C2 pairs >=8 conns: {fl_c2}/{tot_c2} flagged (CV<=0.35) | Benign pairs >=8 conns: {fl_ben_cv}/{tot_ben} flagged by CV<=0.35 ({fl_ben_tr}/{tot_ben} by full SlowC2Tracker)"
    )
    print(f"[+] Wrote {args.out_csv}")


if __name__ == "__main__":
    main()
