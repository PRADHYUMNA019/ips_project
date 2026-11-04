#!/usr/bin/env python3
"""
datasets/adapters/kitsune_adapter.py — Adapter for Kitsune SSL Renegotiation dataset.

Converts Kitsune packet features into unified early-flow schema.
Note: Raw pcaps in Kitsune are truncated to 200 bytes, but payload-independent
packet lengths, directions, and IATs remain accurate.
Adds metadata: source="real-public-kitsune", label_family="A1_ssl_reneg", is_attack=1.
"""
import os
import pandas as pd


def adapt_kitsune_record(row, early_n=12, session_id="kitsune_ssl_reneg", split_hint="test-zeroday"):
    """Convert a Kitsune flow record into unified early-flow schema."""
    raw_sizes = [row.get(f"size_{i}", 150) for i in range(early_n)]
    raw_dirs = [row.get(f"dir_{i}", 0) for i in range(early_n)]
    raw_iats = [row.get(f"iat_{i}", 50.0) for i in range(early_n - 1)]

    valid_len = len(raw_sizes)
    while len(raw_sizes) < early_n:
        raw_sizes.append(0)
        raw_dirs.append(0)
    while len(raw_iats) < early_n - 1:
        raw_iats.append(0.0)

    out = {
        "source": "real-public-kitsune",
        "label_family": "A1_ssl_reneg",
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
