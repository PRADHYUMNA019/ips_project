#!/usr/bin/env python3
"""
datasets/adapters/tqh_adapter.py — Canonical Adapter for TQH-C2 Testbed D (Merlin HTTP/2-over-TLS) (A2, A7).

Only Testbed D (Merlin over HTTP/2-over-TLS) is used as a TLS C2 family.
Produces the single canonical 3N+8 feature vector via ips.features.build_early_vector
plus standard flow-key metadata columns.
"""
import os
import sys
import io
import zipfile
import warnings
from typing import Dict, Any, Set
import pandas as pd

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)
from ips.features import build_early_vector, get_feature_names
from ips.offline.pcap_to_flows import extract_flows_from_pcap

# Verified against Zenodo record 21523144 (TQH-C2 v1.2.0, CC-BY-4.0, features_D/testbed_D.parquet)
VERIFIED_TQH_PARQUET_COLUMNS: Set[str] = {
    "ts", "uid", "orig_h", "resp_h", "duration",
    "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "orig_p", "resp_p", "proto", "conn_state", "history",
    "orig_ip_bytes", "resp_ip_bytes", "missed_bytes",
    "ja4", "ja4s", "ja4h", "profile", "encryption_profile",
    "interval_s", "jitter_pct", "capture_id", "label_raw", "y",
}


def adapt_tqh_record(
    row: Dict[str, Any],
    early_n: int = 12,
    session_id: str = "tqh_testbed_d",
    split_hint: str = "test-zeroday",
) -> Dict[str, Any]:
    """
    Convert a TQH-C2 Testbed D record into the canonical 3N+8 feature + metadata schema.
    Note: Pre-extracted feature CSV columns in TQH-C2_features_D.zip are marked UNVERIFIED SCHEMA;
    prefer parsing TQH-C2_pcap_D_merlin_h2.zip directly via adapt_tqh_pcap().
    """
    # UNVERIFIED SCHEMA for pre-extracted CSV fallback
    raw_sizes = [int(row.get(f"size_{i}", 80)) for i in range(early_n) if int(row.get(f"size_{i}", 80)) > 0]
    raw_dirs = [int(row.get(f"dir_{i}", i % 2)) for i in range(len(raw_sizes))]
    raw_iats_ms = [float(row.get(f"iat_{i}", 15000.0)) for i in range(max(0, len(raw_sizes) - 1))]

    vec = build_early_vector(raw_sizes, raw_dirs, raw_iats_ms, early_n=early_n)
    feat_names = get_feature_names(early_n)

    out = {
        "src_ip": str(row.get("src_ip", "10.0.1.4")),
        "dst_ip": str(row.get("dst_ip", "10.0.2.10")),
        "sport": int(row.get("sport", 50000)),
        "dport": int(row.get("dport", 443)),
        "proto": str(row.get("proto", "TCP")),
        "start_ts": float(row.get("start_ts", 0.0)),
        "end_ts": float(row.get("end_ts", 0.0)),
        "instance": int(row.get("instance", 0)),
        "session_id": session_id,
        "source": "real-public-tqh",
        "label_family": "A3_c2",
        "is_attack": 1,
        "encrypted": True,
        "domain": "tqh-c2-d",
        "split_hint": split_hint,
        "raw_valid_len": len(raw_sizes),
        "early_n": early_n,
    }
    for fname, val in zip(feat_names, vec):
        out[fname] = float(val)
    return out


def load_tqh_parquet_summary(filepath: str, member: str = "features_D/testbed_D.parquet") -> pd.DataFrame:
    """
    Load verified Zeek-style flow summary table from TQH-C2 Testbed D (Zenodo 21523144).
    Supports .parquet, .zip (containing features_D/testbed_D.parquet), or .json fixture.
    NOTE: TQH-C2_features_D.zip contains flow-level aggregates (orig_pkts/resp_pkts/duration/ja4),
    NOT per-packet early-window arrays. For 3N+8 per-packet vectors, use adapt_tqh_pcap() on the raw pcap.
    """
    if filepath.endswith(".zip"):
        with zipfile.ZipFile(filepath) as zf:
            with zf.open(member) as f:
                df = pd.read_parquet(io.BytesIO(f.read()))
    elif filepath.endswith(".json"):
        df = pd.read_json(filepath)
    else:
        df = pd.read_parquet(filepath)

    missing = VERIFIED_TQH_PARQUET_COLUMNS - set(df.columns)
    if missing:
        warnings.warn(
            f"UNVERIFIED SCHEMA [TQH-C2 Parquet]: missing expected columns {sorted(missing)} in {os.path.basename(filepath)}.",
            UserWarning,
            stacklevel=2,
        )

    out = df.copy()
    out["total_pkts"] = out["orig_pkts"].fillna(0).astype(int) + out["resp_pkts"].fillna(0).astype(int)
    out["total_bytes"] = out["orig_bytes"].fillna(0.0) + out["resp_bytes"].fillna(0.0)
    out["is_attack"] = out["y"].astype(int)
    out["label_family"] = out["label_raw"].astype(str).map(
        lambda v: "A3_c2" if "c2" in v.lower() or "malicious" in v.lower() else "benign"
    )
    out["source"] = "real-public-tqh"
    out["domain"] = "tqh-c2-d"
    return out


def load_and_adapt_tqh_csv(filepath: str, early_n: int = 12, session_id: str = "tqh_testbed_d") -> pd.DataFrame:
    df = pd.read_csv(filepath)
    warnings.warn(
        f"UNVERIFIED SCHEMA [TQH-C2 CSV]: actual columns found in {os.path.basename(filepath)}: {list(df.columns)}.",
        UserWarning,
        stacklevel=2,
    )
    return pd.DataFrame([adapt_tqh_record(r, early_n=early_n, session_id=session_id) for _, r in df.iterrows()])


def adapt_tqh_pcap(pcap_path: str, early_n: int = 12, session_id: str = "tqh_testbed_d") -> pd.DataFrame:
    """Extract canonical early-flow features directly from TQH-C2_pcap_D_merlin_h2.zip pcaps."""
    return extract_flows_from_pcap(
        pcap_path,
        early_n=early_n,
        session_id=session_id,
        source="real-public-tqh",
        label_family="A3_c2",
        is_attack=1,
        domain="tqh-c2-d",
    )
