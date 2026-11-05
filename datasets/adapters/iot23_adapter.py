#!/usr/bin/env python3
"""
datasets/adapters/iot23_adapter.py — Canonical Adapter for Aposemat IoT-23 Pcaps (A3, A7, B6).

CRITICAL GUARD (A3):
  - Benign captures are ONLY:
      * CTU-Honeypot-Capture-4-1 (Philips Hue)
      * CTU-Honeypot-Capture-5-1 (Amazon Echo)
      * CTU-Honeypot-Capture-7-1 (Somfy Door Lock)
  - CTU-IoT-Malware-Capture-7-1 is MALICIOUS (Linux.Mirai) and must NEVER be labelled benign!
"""
import os
import sys
from typing import Dict, Any
import pandas as pd

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)
from ips.features import build_early_vector, get_feature_names
from ips.offline.pcap_to_flows import extract_flows_from_pcap

VALID_IOT23_BENIGN_CAPTURES = {
    "CTU-Honeypot-Capture-4-1",
    "CTU-Honeypot-Capture-5-1",
    "CTU-Honeypot-Capture-7-1",
}


def validate_iot23_capture_label(capture_name: str, is_attack: int):
    """Raise ValueError if a Malware capture (e.g. CTU-IoT-Malware-Capture-7-1) is labelled benign (A3)."""
    if int(is_attack) == 0:
        if "Malware" in capture_name or capture_name not in VALID_IOT23_BENIGN_CAPTURES:
            raise ValueError(
                f"CRITICAL A3 LABEL VIOLATION: Capture '{capture_name}' cannot be labelled benign! "
                f"Valid benign captures are strictly {sorted(VALID_IOT23_BENIGN_CAPTURES)}."
            )


def adapt_iot23_record(
    row: Dict[str, Any],
    early_n: int = 12,
    capture_name: str = "CTU-Honeypot-Capture-4-1",
    is_attack: int = 0,
    label_family: str = "benign",
) -> Dict[str, Any]:
    """Convert an IoT-23 flow record into the canonical 3N+8 feature + metadata schema."""
    validate_iot23_capture_label(capture_name, is_attack)
    raw_sizes = [int(row.get(f"size_{i}", 110)) for i in range(early_n) if int(row.get(f"size_{i}", 110)) > 0]
    raw_dirs = [int(row.get(f"dir_{i}", i % 2)) for i in range(len(raw_sizes))]
    raw_iats_ms = [float(row.get(f"iat_{i}", 180.0)) for i in range(max(0, len(raw_sizes) - 1))]

    vec = build_early_vector(raw_sizes, raw_dirs, raw_iats_ms, early_n=early_n)
    feat_names = get_feature_names(early_n)

    out = {
        "src_ip": str(row.get("src_ip", "192.168.1.100")),
        "dst_ip": str(row.get("dst_ip", "192.168.1.1")),
        "sport": int(row.get("sport", 49152)),
        "dport": int(row.get("dport", 443)),
        "proto": str(row.get("proto", "TCP")),
        "start_ts": float(row.get("start_ts", 0.0)),
        "end_ts": float(row.get("end_ts", 0.0)),
        "instance": int(row.get("instance", 0)),
        "session_id": capture_name,
        "source": "real-public-iot23",
        "label_family": label_family if is_attack else "benign",
        "is_attack": int(is_attack),
        "encrypted": bool(row.get("encrypted", False)),
        "domain": "iot23",
        "split_hint": "cross-domain-test",
        "raw_valid_len": len(raw_sizes),
        "early_n": early_n,
    }
    for fname, val in zip(feat_names, vec):
        out[fname] = float(val)
    return out


def adapt_iot23_pcap(pcap_path: str, capture_name: str, early_n: int = 12, is_attack: int = 0, label_family: str = "benign") -> pd.DataFrame:
    """Extract canonical early-flow features from an IoT-23 capture pcap."""
    validate_iot23_capture_label(capture_name, is_attack)
    return extract_flows_from_pcap(
        pcap_path,
        early_n=early_n,
        lan_cidrs=["192.168.0.0/16", "10.0.0.0/8"],
        session_id=capture_name,
        source="real-public-iot23",
        label_family=label_family if is_attack else "benign",
        is_attack=is_attack,
        domain="iot23",
    )
