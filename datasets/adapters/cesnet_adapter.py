#!/usr/bin/env python3
"""
datasets/adapters/cesnet_adapter.py — Adapter for CESNET-TLS-Year22 dataset.

Converts CESNET-TLS-Year22 flow records (which record first 30 payload packets)
into the unified early-flow schema (early_n <= 30).
Adds metadata: source="real-public-cesnet", label_family="benign", is_attack=0, encrypted=True.
"""
import os
import pandas as pd
import numpy as np


def adapt_cesnet_record(row, early_n=12, session_id="cesnet_w01", split_hint="train"):
    """Convert a single CESNET flow row/dict into unified early-flow schema."""
    # CESNET schemas typically provide arrays or columns of packet lengths and directions
    # E.g., 'bytes_in', 'bytes_out', 'packets_length', 'packets_dir', 'packets_iat'
    sizes = []
    dirs = []
    iats = []

    # Handle both pre-parsed list columns and flat columns
    if "packets_length" in row and isinstance(row["packets_length"], (list, np.ndarray)):
        raw_sizes = list(row["packets_length"])[:early_n]
        raw_dirs = list(row.get("packets_dir", []))[:early_n]
        raw_iats = list(row.get("packets_iat", []))[:early_n - 1]
    else:
        # Fallback for synthetic/flat representations
        raw_sizes = [row.get(f"size_{i}", 0) for i in range(early_n)]
        raw_dirs = [row.get(f"dir_{i}", 0) for i in range(early_n)]
        raw_iats = [row.get(f"iat_{i}", 0.0) for i in range(early_n - 1)]

    # Pad if shorter than early_n
    valid_len = len(raw_sizes)
    while len(raw_sizes) < early_n:
        raw_sizes.append(0)
        raw_dirs.append(0)
    while len(raw_iats) < early_n - 1:
        raw_iats.append(0.0)

    out = {
        "source": "real-public-cesnet",
        "label_family": "benign",
        "is_attack": 0,
        "encrypted": True,
        "session_id": session_id,
        "split_hint": split_hint,
        "valid_len": valid_len,
        "early_n": early_n,
        "total_pkts": valid_len,
        "total_bytes": sum(raw_sizes[:valid_len]),
        "duration_ms": sum(raw_iats[:max(0, valid_len - 1)]),
    }
    for i in range(early_n):
        out[f"size_{i}"] = int(raw_sizes[i])
        out[f"dir_{i}"] = int(raw_dirs[i])
    for i in range(early_n - 1):
        out[f"iat_{i}"] = float(raw_iats[i])

    return out


def load_and_adapt_cesnet(filepath, early_n=12, limit=None):
    """Load CESNET parquet/csv file and return adapted DataFrame."""
    if filepath.endswith(".parquet"):
        df = pd.read_parquet(filepath)
    else:
        df = pd.read_csv(filepath)

    if limit:
        df = df.head(limit)

    records = [adapt_cesnet_record(row, early_n=early_n) for _, row in df.iterrows()]
    return pd.DataFrame(records)

