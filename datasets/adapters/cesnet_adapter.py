#!/usr/bin/env python3
"""
datasets/adapters/cesnet_adapter.py — Canonical Adapter for CESNET-TLS-Year22 (A7).

Produces the single canonical 3N+8 feature vector via ips.features.build_early_vector
plus standard flow-key metadata columns.

NOTE: Exact column names in CESNET-TLS-Year22 parquet/CSV files (e.g. PPI_PKT_LENGTHS,
PPI_PKT_DIRECTIONS, PPI_PKT_TIMES vs packets_length/packets_dir/packets_iat) and IPT
units (seconds vs milliseconds) are marked UNVERIFIED SCHEMA until checked against
real downloaded CESNET files.
"""
import os
import sys
import warnings
from typing import Dict, Any, List
import numpy as np
import pandas as pd

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)
from ips.features import build_early_vector, get_feature_names


# UNVERIFIED SCHEMA — candidate column names in CESNET-TLS-Year22 exports
CESNET_LEN_CANDIDATES = ("PPI_PKT_LENGTHS", "packets_length", "pkt_lengths")
CESNET_DIR_CANDIDATES = ("PPI_PKT_DIRECTIONS", "packets_dir", "pkt_dirs")
CESNET_IAT_CANDIDATES = ("PPI_PKT_TIMES", "packets_iat", "pkt_iats")


def _normalize_cesnet_dirs(raw_dirs: List[Any]) -> List[int]:
    """Convert CESNET directions (+1/-1 or 0/1) into canonical 0 (up) / 1 (down)."""
    out = []
    for d in raw_dirs:
        val = int(d)
        if val in (1, 0):
            # If -1 is used for downstream in CESNET PPI, +1 is upstream (0) and -1 is downstream (1)
            out.append(int(val))
        elif val < 0:
            out.append(1)
        else:
            out.append(0)
    return out


def adapt_cesnet_record(
    row: Dict[str, Any],
    early_n: int = 12,
    session_id: str = "cesnet_w01",
    split_hint: str = "calib",
    iat_unit: str = "ms",
) -> Dict[str, Any]:
    """Convert a single CESNET flow record into the canonical early-flow + metadata schema."""
    raw_sizes = None
    raw_dirs = None
    raw_iats = None

    # UNVERIFIED SCHEMA lookup
    for k in CESNET_LEN_CANDIDATES:
        if k in row and isinstance(row[k], (list, np.ndarray)):
            raw_sizes = [int(x) for x in list(row[k])[:early_n]]
            break
    for k in CESNET_DIR_CANDIDATES:
        if k in row and isinstance(row[k], (list, np.ndarray)):
            raw_dirs = list(row[k])[:early_n]
            break
    for k in CESNET_IAT_CANDIDATES:
        if k in row and isinstance(row[k], (list, np.ndarray)):
            raw_iats = [float(x) for x in list(row[k])[: max(0, early_n - 1)]]
            break

    if raw_sizes is None:
        raw_sizes = [int(row[f"size_{i}"]) for i in range(early_n) if f"size_{i}" in row and row[f"size_{i}"] > 0]
    if raw_dirs is None:
        raw_dirs = [int(row.get(f"dir_{i}", 0)) for i in range(len(raw_sizes))]
    else:
        raw_dirs = _normalize_cesnet_dirs(raw_dirs[: len(raw_sizes)])
    if raw_iats is None:
        raw_iats = [float(row.get(f"iat_{i}", 0.0)) for i in range(max(0, len(raw_sizes) - 1))]

    # Convert IATs to milliseconds if source unit is seconds or microseconds
    if iat_unit == "s":
        iats_ms = [x * 1000.0 for x in raw_iats]
    elif iat_unit == "us":
        iats_ms = [x / 1000.0 for x in raw_iats]
    else:
        iats_ms = list(raw_iats)

    vec = build_early_vector(raw_sizes, raw_dirs, iats_ms, early_n=early_n)
    feat_names = get_feature_names(early_n)

    out = {
        "src_ip": str(row.get("src_ip", "0.0.0.0")),
        "dst_ip": str(row.get("dst_ip", "0.0.0.0")),
        "sport": int(row.get("sport", 0)),
        "dport": int(row.get("dport", 443)),
        "proto": str(row.get("proto", "TCP")),
        "start_ts": float(row.get("start_ts", 0.0)),
        "end_ts": float(row.get("end_ts", 0.0)),
        "instance": int(row.get("instance", 0)),
        "session_id": session_id,
        "source": "real-public-cesnet",
        "label_family": "benign",
        "is_attack": 0,
        "encrypted": True,
        "domain": "cesnet-tls-year22",
        "split_hint": split_hint,
        "raw_valid_len": len(raw_sizes),
        "early_n": early_n,
    }
    for fname, val in zip(feat_names, vec):
        out[fname] = float(val)
    return out


def load_and_adapt_cesnet(filepath: str, early_n: int = 12, limit: int = None, session_id: str = "cesnet_w01") -> pd.DataFrame:
    """Load CESNET parquet/csv file, emit UNVERIFIED SCHEMA warning with actual columns, and adapt."""
    if filepath.endswith(".parquet"):
        df = pd.read_parquet(filepath)
    else:
        df = pd.read_csv(filepath)

    cols = list(df.columns)
    warnings.warn(
        f"UNVERIFIED SCHEMA [CESNET-TLS-Year22]: actual columns found in {os.path.basename(filepath)}: {cols}. "
        "Verify inter-packet time units (s vs ms vs us) before publishing numbers.",
        UserWarning,
        stacklevel=2,
    )
    if limit:
        df = df.head(limit)

    records = [adapt_cesnet_record(row, early_n=early_n, session_id=session_id) for _, row in df.iterrows()]
    return pd.DataFrame(records)
