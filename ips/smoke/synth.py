#!/usr/bin/env python3
"""
ips/smoke/synth.py — Deterministic Smoke-Data Generator (Rule B0, A8, B3, BUG-03).

Generates semi-synthetic early-flow vectors from device profiles and attack models
using ips.features.build_early_vector plus full flow-key metadata columns.
Reads canonical device_id and IP mappings from configs/devices.yaml (single source of truth).
Every output carries source="synthetic-smoke" and writes only under results/smoke/.
"""

import argparse
import os
import random
import sys
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import yaml

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)
from ips.features import build_early_vector, get_feature_names

SMOKE_BANNER = """
================================================================================
   SMOKE DATA – NOT A RESULT
   [SMOKE DATA GENERATOR] — SYNTHETIC SMOKE TEST VECTORS ONLY
   WARNING: THIS DATA IS GENERATED FOR PIPELINE TESTING AND CODE EXERCISE.
   IT MUST NEVER APPEAR IN PAPER RESULTS, CLAIMS, OR EVALUATION TABLES.
================================================================================
"""

DEFAULT_OUT_DIR = os.path.join(REPO_DIR, "results", "smoke")
DEVICES_YAML_PATH = os.path.join(REPO_DIR, "configs", "devices.yaml")


def _load_device_fleet() -> Tuple[Dict[str, str], Dict[str, List[str]], str, str]:
    """Load canonical device_id -> IP and class -> [device_id] from configs/devices.yaml."""
    ip_map: Dict[str, str] = {}
    class_devs: Dict[str, List[str]] = {}
    attacker_ip = "10.0.1.4"
    server_ip = "10.0.2.10"

    if os.path.exists(DEVICES_YAML_PATH):
        with open(DEVICES_YAML_PATH, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        for dev in cfg.get("devices", []):
            did = str(dev["device_id"])
            dip = str(dev["ip"])
            dcls = str(dev["class"])
            ip_map[did] = dip
            class_devs.setdefault(dcls, []).append(did)
        if "attacker" in cfg and "ip" in cfg["attacker"]:
            attacker_ip = str(cfg["attacker"]["ip"])
            ip_map[str(cfg["attacker"].get("device_id", "attacker"))] = attacker_ip
        if "server" in cfg and "ip" in cfg["server"]:
            server_ip = str(cfg["server"]["ip"])

    if not ip_map:
        ip_map = {
            "sensor-01": "10.0.1.10",
            "sensor-02": "10.0.1.11",
            "sensor-03": "10.0.1.12",
            "sensor-04": "10.0.1.13",
            "plug-01": "10.0.1.20",
            "plug-02": "10.0.1.21",
            "plug-03": "10.0.1.22",
            "therm-01": "10.0.1.30",
            "therm-02": "10.0.1.31",
            "therm-03": "10.0.1.32",
            "cam-01": "10.0.1.40",
            "cam-02": "10.0.1.41",
        }
        class_devs = {
            "sensor": ["sensor-01", "sensor-02", "sensor-03", "sensor-04"],
            "plug": ["plug-01", "plug-02", "plug-03"],
            "thermostat": ["therm-01", "therm-02", "therm-03"],
            "camera": ["cam-01", "cam-02"],
        }

    # Backward-compatible aliases for callers passing legacy names
    ip_map.setdefault("attacker-01", attacker_ip)
    ip_map.setdefault("thermostat-01", ip_map.get("therm-01", "10.0.1.30"))
    ip_map.setdefault("thermostat-02", ip_map.get("therm-02", "10.0.1.31"))
    ip_map.setdefault("thermostat-03", ip_map.get("therm-03", "10.0.1.32"))
    ip_map.setdefault("camera-01", ip_map.get("cam-01", "10.0.1.40"))
    ip_map.setdefault("camera-02", ip_map.get("cam-02", "10.0.1.41"))
    return ip_map, class_devs, attacker_ip, server_ip


DEVICE_IPS, CLASS_DEVICES, DEFAULT_ATTACKER_IP, DEFAULT_SERVER_IP = _load_device_fleet()


def _sample_benign_sequence(
    device_class: str,
    flow_len: int,
    drift_scale: float,
) -> Tuple[List[int], List[int], List[float]]:
    """Sample per-packet (sizes, dirs, iats_ms) for a benign IoT device class."""
    sizes: List[int] = []
    dirs: List[int] = []
    iats: List[float] = []

    profile_map = {
        "sensor": (10_000.0, 0.15, 10.0),
        "plug": (30_000.0, 0.10, 20.0),
        "thermostat": (15_000.0, 0.12, 15.0),
        "camera": (500.0, 0.20, 2.0),
    }
    if device_class not in profile_map:
        for i in range(flow_len):
            dirs.append(0)
            sizes.append(100)
            if i > 0:
                iats.append(1000.0)
        return sizes, dirs, iats

    base_iat_ms, jitter_cv, min_iat = profile_map[device_class]
    mean_iat = base_iat_ms * drift_scale
    for i in range(flow_len):
        if device_class == "camera":
            dirs.append(0 if i % 3 != 0 else 1)
            sizes.append(int(random.gauss(1100, 150)))
        elif device_class == "sensor":
            dirs.append(0 if i % 2 == 0 else 1)
            sizes.append(int(random.gauss(64 if i % 2 == 0 else 48, 9)))
        elif device_class == "plug":
            dirs.append(0 if i % 2 == 0 else 1)
            sizes.append(int(random.gauss(50, 8)))
        else:
            dirs.append(0 if i % 2 == 0 else 1)
            sizes.append(int(random.gauss(140, 25)))
        if i > 0:
            iats.append(max(min_iat, random.gauss(mean_iat, mean_iat * jitter_cv)))
    return sizes, dirs, iats


def _sample_attack_sequence(
    attack_family: str,
    early_n: int,
) -> Tuple[List[int], List[int], List[float]]:
    """Sample per-packet (sizes, dirs, iats_ms) for a synthetic smoke attack family."""
    sizes: List[int] = []
    dirs: List[int] = []
    iats: List[float] = []

    if attack_family == "A1_flood":
        for i in range(early_n):
            dirs.append(0)
            sizes.append(int(random.gauss(64, 5)))
            if i > 0:
                iats.append(max(0.1, random.gauss(2.0, 0.8)))
    elif attack_family == "A2_slowloris":
        for i in range(early_n):
            dirs.append(0)
            sizes.append(random.randint(1, 8))
            if i > 0:
                iats.append(random.uniform(8000.0, 14000.0))
    elif attack_family == "A3_c2":
        base_interval_ms = random.choice([5000.0, 15000.0, 30000.0])
        for i in range(early_n):
            if i % 4 == 0:
                dirs.append(0)
                sizes.append(int(random.gauss(52, 6)))
                if i > 0:
                    jitter = random.uniform(-0.15, 0.15) * base_interval_ms
                    iats.append(max(50.0, base_interval_ms + jitter))
            else:
                dirs.append(1)
                sizes.append(int(random.gauss(920, 45)))
                if i > 0:
                    iats.append(max(0.5, random.gauss(4.0, 1.2)))
    elif attack_family == "A4_exfil":
        for i in range(early_n):
            dirs.append(0)
            sizes.append(int(random.gauss(1400, 30)))
            if i > 0:
                iats.append(max(1.0, random.gauss(10.0, 3.0)))
    elif attack_family == "A5_bruteforce":
        for i in range(early_n):
            dirs.append(0 if i % 2 == 0 else 1)
            sizes.append(int(random.gauss(120, 20)))
            if i > 0:
                iats.append(random.uniform(100.0, 400.0))
    else:
        for i in range(early_n):
            dirs.append(0)
            sizes.append(50)
            if i > 0:
                iats.append(20.0)
    return sizes, dirs, iats


def generate_flow_vector(
    early_n: int = 16,
    device_class: str = "sensor",
    device_id: str = "sensor-01",
    is_attack: bool = False,
    attack_family: str = "none",
    session_id: str = "smoke_sess_01",
    drift_scale: float = 1.0,
    start_ts: float = 1700000000.0,
    instance: int = 0,
) -> Dict[str, Any]:
    """Generate a single canonical early-flow + metadata row."""
    flow_len = early_n
    if not is_attack and device_class in ("sensor", "plug") and early_n >= 12 and random.random() < 0.15:
        flow_len = random.choice([6, 10])

    if not is_attack:
        sizes, dirs, iats = _sample_benign_sequence(device_class, flow_len, drift_scale)
    else:
        sizes, dirs, iats = _sample_attack_sequence(attack_family, early_n)

    sizes = [max(1, s) for s in sizes[:early_n]]
    dirs = dirs[:early_n]
    iats = [max(0.01, t) for t in iats[: early_n - 1]]
    duration_ms = sum(iats)

    vec = build_early_vector(sizes, dirs, iats, early_n=early_n)
    feat_names = get_feature_names(early_n)

    src_ip = DEVICE_IPS.get(device_id, DEFAULT_ATTACKER_IP if is_attack else "10.0.1.10")
    dport = 8443 if device_class == "camera" or attack_family in ("A1_flood", "A2_slowloris", "A3_c2", "A4_exfil") else 8883

    row: Dict[str, Any] = {
        "src_ip": src_ip,
        "dst_ip": DEFAULT_SERVER_IP,
        "sport": random.randint(40000, 60000),
        "dport": dport,
        "proto": "TCP",
        "start_ts": float(start_ts),
        "end_ts": float(start_ts + duration_ms / 1000.0),
        "instance": int(instance),
        "session_id": session_id,
        "source": "synthetic-smoke",
        "label_family": attack_family if is_attack else "benign",
        "attack_family": attack_family if is_attack else "none",
        "is_attack": 1 if is_attack else 0,
        "encrypted": True,
        "domain": "testbed-smoke",
        "device_id": device_id,
        "device_class": device_class,
        "raw_valid_len": len(sizes),
        "early_n": early_n,
        "total_pkts": early_n,
        "total_bytes": sum(sizes),
        "duration_ms": duration_ms,
    }
    for fname, val in zip(feat_names, vec):
        row[fname] = float(val)
    return row


def generate_smoke_dataset(
    n_benign: int = 1000,
    n_attack: int = 200,
    early_n: int = 12,
    session_id: str = "smoke_sess_01",
    out_csv: Optional[str] = None,
    out_parquet: Optional[str] = None,
    seed: int = 42,
) -> pd.DataFrame:
    """Generate a deterministically seeded smoke dataset for benign and attack traffic."""
    random.seed(seed)
    np.random.seed(seed)
    print(SMOKE_BANNER)
    rows: List[Dict[str, Any]] = []
    classes = ["sensor", "plug", "thermostat", "camera"]
    t_cur = 1700000000.0

    for i in range(n_benign):
        cls = random.choice(classes)
        dev_candidates = CLASS_DEVICES.get(cls, [f"{cls}-01"])
        dev_id = random.choice(dev_candidates)
        rows.append(
            generate_flow_vector(
                early_n=early_n,
                device_class=cls,
                device_id=dev_id,
                is_attack=False,
                attack_family="none",
                session_id=session_id,
                start_ts=t_cur + i * 2.0,
                instance=i,
            )
        )

    families = ["A1_flood", "A2_slowloris", "A3_c2", "A4_exfil", "A5_bruteforce"]
    for i in range(n_attack):
        fam = random.choice(families)
        rows.append(
            generate_flow_vector(
                early_n=early_n,
                device_class="attacker",
                device_id="attacker",
                is_attack=True,
                attack_family=fam,
                session_id=session_id,
                start_ts=t_cur + (n_benign + i) * 2.0,
                instance=i,
            )
        )

    df = pd.DataFrame(rows)
    os.makedirs(DEFAULT_OUT_DIR, exist_ok=True)
    if out_csv is None:
        out_csv = os.path.join(DEFAULT_OUT_DIR, f"{session_id}.csv")
    os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
    df.to_csv(out_csv, index=False)
    if out_parquet is not None:
        os.makedirs(os.path.dirname(os.path.abspath(out_parquet)), exist_ok=True)
        df.to_parquet(out_parquet, index=False)
    print(f"[OK] Generated {len(df)} smoke flow vectors (seed={seed}) -> {out_csv}")
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic smoke flow vectors")
    parser.add_argument("--benign", type=int, default=1000)
    parser.add_argument("--attack", type=int, default=200)
    parser.add_argument("--early-n", type=int, default=12)
    parser.add_argument("--session", default="smoke_train_sess")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    generate_smoke_dataset(
        n_benign=args.benign,
        n_attack=args.attack,
        early_n=args.early_n,
        session_id=args.session,
        seed=args.seed,
    )
