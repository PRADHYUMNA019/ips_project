#!/usr/bin/env python3
"""
ips/features.py — Canonical shared feature extraction for early-flow anomaly detection.

This module is the SINGLE SOURCE OF TRUTH for early-flow feature extraction,
shared identically between the offline training pipeline and online eBPF engine.

Features extracted for early-window N payload-bearing packets:
  - sizes[N]: normalized payload bytes (sz / 1500.0)
  - dirs[N]: binary direction (0 = LAN->WAN / Client->Server, 1 = WAN->LAN)
  - log_iats[N-1]: log10(1 + iat_us)
  - Aggregate statistics:
      - bytes_up, bytes_down, pkts_up, pkts_down, frac_upstream
      - mean_log_iat, std_log_iat
      - first_payload_size
      - valid_len (actual payload packets observed <= N)

SHORTCUT-LEARNING GUARD:
  IP addresses, MAC addresses, and Port numbers are strictly EXCLUDED
  to prevent artificial separation of classes by service port.
"""
import math
from typing import List, Dict, Any, Tuple
import numpy as np

FORBIDDEN_COLUMNS = {
    "src_ip", "dst_ip", "src_port", "dst_port", "sport", "dport",
    "ip_src", "ip_dst", "mac_src", "mac_dst", "ip_a", "ip_b", "port_a", "port_b"
}

FEATURE_NAMES_BASE = [
    "bytes_up", "bytes_down", "pkts_up", "pkts_down",
    "frac_upstream", "mean_log_iat", "std_log_iat",
    "first_payload_size", "valid_len"
]


def get_feature_names(early_n: int = 12) -> List[str]:
    """Return ordered list of feature column names for window size N."""
    cols = []
    for i in range(early_n):
        cols.append(f"size_{i}")
    for i in range(early_n):
        cols.append(f"dir_{i}")
    for i in range(early_n - 1):
        cols.append(f"log_iat_{i}")
    cols.extend(FEATURE_NAMES_BASE)
    return cols


def build_early_vector(sizes: List[int], dirs: List[int], iat_ms_list: List[float],
                       early_n: int = 12) -> np.ndarray:
    """Build a fixed-dimension normalized feature vector for a flow.

    Args:
        sizes: Payload sizes in bytes (length <= N)
        dirs: Direction flags (0 or 1, length <= N)
        iat_ms_list: Inter-packet arrival times in ms (length <= N-1)
        early_n: Expected window size N

    Returns:
        1D numpy array of float32 features of length 3*N + 8
    """
    valid_len = min(len(sizes), early_n)

    # 1. Padded and normalized sizes
    norm_sizes = np.zeros(early_n, dtype=np.float32)
    for i in range(valid_len):
        norm_sizes[i] = min(1500.0, float(sizes[i])) / 1500.0

    # 2. Directions
    norm_dirs = np.zeros(early_n, dtype=np.float32)
    for i in range(valid_len):
        norm_dirs[i] = float(dirs[i])

    # 3. Log-IATs (converted to microseconds: us = ms * 1000)
    log_iats = np.zeros(early_n - 1, dtype=np.float32)
    valid_iats = []
    for i in range(min(len(iat_ms_list), early_n - 1)):
        iat_us = max(0.0, float(iat_ms_list[i]) * 1000.0)
        v = math.log10(1.0 + iat_us)
        log_iats[i] = v
        valid_iats.append(v)

    # 4. Aggregates
    bytes_up = 0.0
    bytes_down = 0.0
    pkts_up = 0.0
    pkts_down = 0.0

    for i in range(valid_len):
        sz = float(sizes[i])
        if dirs[i] == 0:
            bytes_up += sz
            pkts_up += 1.0
        else:
            bytes_down += sz
            pkts_down += 1.0

    total_bytes = bytes_up + bytes_down
    frac_upstream = (bytes_up / total_bytes) if total_bytes > 0 else 0.5

    mean_log_iat = float(np.mean(valid_iats)) if valid_iats else 0.0
    std_log_iat = float(np.std(valid_iats)) if valid_iats else 0.0

    first_payload_size = (float(sizes[0]) / 1500.0) if valid_len > 0 else 0.0
    norm_valid_len = float(valid_len) / float(early_n)

    aggregates = np.array([
        bytes_up / 15000.0,
        bytes_down / 15000.0,
        pkts_up / float(early_n),
        pkts_down / float(early_n),
        frac_upstream,
        mean_log_iat / 7.0,  # normalized by max log10(10^7 us = 10s)
        std_log_iat / 3.0,
        first_payload_size,
        norm_valid_len,
    ], dtype=np.float32)

    vec = np.concatenate([norm_sizes, norm_dirs, log_iats, aggregates])
    return vec


def assert_no_forbidden_features(feature_names: List[str]):
    """Guard against shortcut learning: verify forbidden columns are absent."""
    lower_names = {c.lower() for c in feature_names}
    inter = lower_names.intersection(FORBIDDEN_COLUMNS)
    if inter:
        raise ValueError(f"CRITICAL SHORTCUT LEARNING VIOLATION: Forbidden features found: {inter}")

