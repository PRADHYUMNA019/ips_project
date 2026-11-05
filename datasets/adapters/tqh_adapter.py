#!/usr/bin/env python3
"""
datasets/adapters/tqh_adapter.py — Canonical Adapter for TQH-C2 Testbed D (Merlin HTTP/2-over-TLS) (A2, A7).

Only Testbed D (Merlin over HTTP/2-over-TLS) is used as a TLS C2 family.
Produces the single canonical 3N+8 feature vector via ips.features.build_early_vector
plus standard flow-key metadata columns.
"""
import os
import sys
import warnings
from typing import Dict, Any
import pandas as pd

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)
from ips.features import build_early_vector, get_feature_names
from ips.offline.pcap_to_flows import extract_flows_from_pcap


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
