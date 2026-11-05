#!/usr/bin/env python3
"""
datasets/adapters/kitsune_adapter.py — Canonical Adapter for Kitsune Dataset (A4, A7).

Produces the single canonical 3N+8 feature vector via ips.features.build_early_vector
plus standard flow-key metadata columns.
Note: Kitsune pcaps have packets truncated to 200 bytes; adapt_kitsune_pcap() uses
extract_flows_from_pcap() which computes payload length from IP/TCP headers.
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


def adapt_kitsune_record(
    row: Dict[str, Any],
    early_n: int = 12,
    session_id: str = "kitsune_ssl_reneg",
    split_hint: str = "test-zeroday",
) -> Dict[str, Any]:
    """Convert a Kitsune flow record into the canonical 3N+8 feature + metadata schema."""
    # UNVERIFIED SCHEMA for pre-extracted CSV fallback
    raw_sizes = [int(row.get(f"size_{i}", 150)) for i in range(early_n) if int(row.get(f"size_{i}", 150)) > 0]
    raw_dirs = [int(row.get(f"dir_{i}", 0)) for i in range(len(raw_sizes))]
    raw_iats_ms = [float(row.get(f"iat_{i}", 50.0)) for i in range(max(0, len(raw_sizes) - 1))]

    vec = build_early_vector(raw_sizes, raw_dirs, raw_iats_ms, early_n=early_n)
    feat_names = get_feature_names(early_n)

    out = {
        "src_ip": str(row.get("src_ip", "192.168.1.50")),
        "dst_ip": str(row.get("dst_ip", "192.168.1.1")),
        "sport": int(row.get("sport", 50000)),
        "dport": int(row.get("dport", 443)),
        "proto": str(row.get("proto", "TCP")),
        "start_ts": float(row.get("start_ts", 0.0)),
        "end_ts": float(row.get("end_ts", 0.0)),
        "instance": int(row.get("instance", 0)),
        "session_id": session_id,
        "source": "real-public-kitsune",
        "label_family": "A1_ssl_reneg",
        "is_attack": 1,
        "encrypted": True,
        "domain": "kitsune",
        "split_hint": split_hint,
        "raw_valid_len": len(raw_sizes),
        "early_n": early_n,
    }
    for fname, val in zip(feat_names, vec):
        out[fname] = float(val)
    return out


def adapt_kitsune_pcap(pcap_path: str, early_n: int = 12, session_id: str = "kitsune_ssl_reneg", is_attack: int = 1) -> pd.DataFrame:
    """Extract canonical early-flow features from truncated Kitsune pcaps using IP/TCP header lengths."""
    return extract_flows_from_pcap(
        pcap_path,
        early_n=early_n,
        lan_cidrs=["192.168.0.0/16", "10.0.0.0/8"],
        session_id=session_id,
        source="real-public-kitsune",
        label_family="A1_ssl_reneg" if is_attack else "benign",
        is_attack=is_attack,
        domain="kitsune",
    )
