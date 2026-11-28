#!/usr/bin/env python3
"""
demo/audit_iot23_real.py — Streaming Real-Data Audit of Aposemat IoT-23 Benign Honeypot Pcaps (Prompt 8 §3.4).

Evidence Type: REAL PUBLIC DATA (Aposemat IoT-23 Benign Honeypot Captures: 4-1 Hue, 5-1 Echo, 7-1 Somfy).
Strictly excludes CTU-IoT-Malware-Capture-7-1 (Linux.Mirai) via validate_iot23_capture_label().

Streams each .pcap via dpkt (ips/offline/pcap_to_flows.py) without holding the raw pcap in memory,
and computes:
  - Total flows extracted
  - TLS flow fraction (%)
  - Packets-per-flow (payload-bearing) percentiles (p50, p90, p95, max)
  - Fraction (%) of flows reaching checkpoints 4, 8, and 16 payload packets
  - Time-to-reach checkpoints 4, 8, and 16 payload packets (median & p95 in ms)
Writes summary table to demo/evidence/real/iot23_benign_audit.csv.
"""

import os
import sys
import glob
import hashlib
import argparse
import numpy as np
import pandas as pd

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_DIR)

from datasets.adapters.iot23_adapter import adapt_iot23_pcap, validate_iot23_capture_label
from ips.models.eval_offline import compute_time_to_verdict_ms

CAPTURE_DEVICES = {
    "CTU-Honeypot-Capture-4-1": "Philips Hue Smart LED Bridge",
    "CTU-Honeypot-Capture-5-1": "Amazon Echo Smart Speaker",
    "CTU-Honeypot-Capture-7-1": "Somfy Smart Door Lock",
}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def audit_capture(cap_name: str, pcap_paths: list, early_n: int = 16) -> dict:
    validate_iot23_capture_label(cap_name, is_attack=0)
    dfs = []
    total_bytes = 0
    for p in sorted(pcap_paths):
        total_bytes += os.path.getsize(p)
        print(f"  [stream] Parsing {os.path.basename(p)} ({os.path.getsize(p) / 1024 / 1024:.2f} MB) ...", flush=True)
        df_p = adapt_iot23_pcap(p, capture_name=cap_name, early_n=early_n, is_attack=0)
        dfs.append(df_p)

    df = pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()
    n_flows = len(df)
    if n_flows == 0:
        return {
            "source": "REAL PUBLIC DATA (Aposemat IoT-23 Benign)",
            "capture": cap_name,
            "device": CAPTURE_DEVICES.get(cap_name, cap_name),
            "pcap_files": len(pcap_paths),
            "pcap_mb": round(total_bytes / (1024 * 1024), 2),
            "flows": 0,
        }

    vlens = df["raw_valid_len"].to_numpy(dtype=int)
    tls_pct = float(df["encrypted"].astype(bool).mean() * 100.0) if "encrypted" in df.columns else 0.0
    proto_counts = df["proto"].value_counts().to_dict() if "proto" in df.columns else {}

    row = {
        "source": "REAL PUBLIC DATA (Aposemat IoT-23 Benign)",
        "capture": cap_name,
        "device": CAPTURE_DEVICES.get(cap_name, cap_name),
        "pcap_files": len(pcap_paths),
        "pcap_mb": round(total_bytes / (1024 * 1024), 2),
        "flows": int(n_flows),
        "tls_flows": int(df["encrypted"].astype(bool).sum()) if "encrypted" in df.columns else 0,
        "tls_pct": round(tls_pct, 2),
        "tcp_flows": int(proto_counts.get("TCP", 0)),
        "udp_flows": int(proto_counts.get("UDP", 0)),
        "payload_pkts_p50": round(float(np.median(vlens)), 1),
        "payload_pkts_p90": round(float(np.percentile(vlens, 90)), 1),
        "payload_pkts_max": int(np.max(vlens)),
        "pct_reach_k4": round(float((vlens >= 4).mean() * 100.0), 2),
        "pct_reach_k8": round(float((vlens >= 8).mean() * 100.0), 2),
        "pct_reach_k16": round(float((vlens >= 16).mean() * 100.0), 2),
    }

    # Time to reach each checkpoint (computed strictly over flows that reach k)
    for k in (4, 8, 16):
        sub = df[df["raw_valid_len"] >= k]
        if len(sub) > 0:
            ttv = compute_time_to_verdict_ms(sub, early_n=k)
            row[f"ttv_k{k}_p50_ms"] = round(float(np.median(ttv)), 2)
            row[f"ttv_k{k}_p95_ms"] = round(float(np.percentile(ttv, 95)), 2)
        else:
            row[f"ttv_k{k}_p50_ms"] = None
            row[f"ttv_k{k}_p95_ms"] = None

    return row


def main():
    parser = argparse.ArgumentParser(description="Audit downloaded IoT-23 benign honeypot pcaps")
    parser.add_argument("--data-dir", default=os.path.join(os.environ.get("IPS_DATA_ROOT", r"D:\ips_data"), "iot23"))
    parser.add_argument("--out-csv", default=os.path.join(REPO_DIR, "demo", "evidence", "real", "iot23_benign_audit.csv"))
    args = parser.parse_args()

    rows = []
    for cap_name in sorted(CAPTURE_DEVICES.keys()):
        cap_dir = os.path.join(args.data_dir, cap_name)
        pcaps = sorted(glob.glob(os.path.join(cap_dir, "*.pcap")))
        if not pcaps:
            print(f"[!] No .pcap found in {cap_dir}, skipping.")
            continue
        print(f"[*] Auditing {cap_name} ({len(pcaps)} pcap file(s)) ...", flush=True)
        rows.append(audit_capture(cap_name, pcaps, early_n=16))

    if not rows:
        print("[!] No IoT-23 pcaps audited.")
        sys.exit(1)

    out_df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(os.path.abspath(args.out_csv)), exist_ok=True)
    out_df.to_csv(args.out_csv, index=False)
    print("\n=== IoT-23 Benign Real Pcap Audit Summary ===")
    print(
        out_df[
            [
                "capture",
                "pcap_mb",
                "flows",
                "tls_pct",
                "pct_reach_k4",
                "pct_reach_k8",
                "pct_reach_k16",
                "ttv_k4_p50_ms",
                "ttv_k8_p50_ms",
                "ttv_k16_p50_ms",
            ]
        ].to_string(index=False)
    )
    print(f"\n[+] Wrote {args.out_csv}")


if __name__ == "__main__":
    main()
