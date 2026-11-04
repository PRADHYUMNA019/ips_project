#!/usr/bin/env python3
"""
datasets/adapters/tqh_adapter.py — Adapter for TQH-C2 encrypted C2 dataset.

Converts TQH-C2 flow records / pcap extracts into the unified early-flow schema.
Adds metadata: source="real-public-tqh", label_family="A3_c2", is_attack=1, encrypted=True.
"""
import os
import pandas as pd
import numpy as np


def adapt_tqh_record(row, early_n=12, session_id="tqh_testbed_c", split_hint="test-zeroday"):
    """Convert a single TQH flow record into unified early-flow schema."""
    raw_sizes = [row.get(f"size_{i}", 80) for i in range(early_n)]
    raw_dirs = [row.get(f"dir_{i}", i % 2) for i in range(early_n)]
    raw_iats = [row.get(f"iat_{i}", 15000.0) for i in range(early_n - 1)]

    valid_len = len(raw_sizes)
    while len(raw_sizes) < early_n:
        raw_sizes.append(0)
        raw_dirs.append(0)
    while len(raw_iats) < early_n - 1:
        raw_iats.append(0.0)

    out = {
        "source": "real-public-tqh",
        "label_family": "A3_c2",
        "is_attack": 1,
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
