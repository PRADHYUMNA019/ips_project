#!/usr/bin/env python3
"""
ips/smoke/synth.py — Deterministic Smoke-Data Generator (Rule B0, A8, B3).

Generates semi-synthetic early-flow vectors from device profiles and attack models
using ips.features.build_early_vector plus full flow-key metadata columns.
Every output carries source="synthetic-smoke" and writes only under results/smoke/.
"""
import os
import sys
import random
import argparse
import pandas as pd
import numpy as np

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

DEVICE_IPS = {
    "sensor-01": "10.0.1.11", "sensor-02": "10.0.1.12", "sensor-03": "10.0.1.13", "sensor-04": "10.0.1.14",
    "plug-01": "10.0.1.21", "plug-02": "10.0.1.22", "plug-03": "10.0.1.23",
    "thermostat-01": "10.0.1.31", "thermostat-02": "10.0.1.32", "thermostat-03": "10.0.1.33",
    "camera-01": "10.0.1.41", "camera-02": "10.0.1.42",
    "attacker-01": "10.0.1.4",
}


def generate_flow_vector(
    early_n: int = 12,
    device_class: str = "sensor",
    device_id: str = "sensor-01",
    is_attack: bool = False,
    attack_family: str = "none",
    session_id: str = "smoke_sess_01",
    drift_scale: float = 1.0,
    start_ts: float = 1700000000.0,
    instance: int = 0,
):
    """Generate a single canonical early-flow + metadata row."""
    sizes = []
    dirs = []
    iats = []

    if not is_attack:
        if device_class == "sensor":
            mean_iat = 10.0 * 1000.0 * drift_scale
            for i in range(early_n):
                dirs.append(0 if i % 2 == 0 else 1)
                sizes.append(int(random.gauss(64 if i % 2 == 0 else 48, 9)))
                if i > 0:
                    iats.append(max(10.0, random.gauss(mean_iat, mean_iat * 0.15)))
        elif device_class == "plug":
            mean_iat = 30.0 * 1000.0 * drift_scale
            for i in range(early_n):
                dirs.append(0 if i % 2 == 0 else 1)
                sizes.append(int(random.gauss(50, 8)))
                if i > 0:
                    iats.append(max(20.0, random.gauss(mean_iat, mean_iat * 0.10)))
        elif device_class == "thermostat":
            mean_iat = 15.0 * 1000.0 * drift_scale
            for i in range(early_n):
                dirs.append(0 if i % 2 == 0 else 1)
                sizes.append(int(random.gauss(140, 25)))
                if i > 0:
                    iats.append(max(15.0, random.gauss(mean_iat, mean_iat * 0.12)))
        elif device_class == "camera":
            mean_iat = 0.5 * 1000.0 * drift_scale
            for i in range(early_n):
                dirs.append(0 if i % 3 != 0 else 1)
                sizes.append(int(random.gauss(1100, 150)))
                if i > 0:
                    iats.append(max(2.0, random.gauss(mean_iat, mean_iat * 0.20)))
        else:
            for i in range(early_n):
                dirs.append(0)
                sizes.append(100)
                if i > 0:
                    iats.append(1000.0)
    else:
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
                dirs.append(0 if i % 2 == 0 else 1)
                sizes.append(int(random.gauss(80, 5)))
                if i > 0:
                    jitter = random.uniform(-0.15, 0.15) * base_interval_ms
                    iats.append(max(50.0, base_interval_ms + jitter))
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

    sizes = [max(1, s) for s in sizes[:early_n]]
    dirs = dirs[:early_n]
    iats = [max(0.01, t) for t in iats[: early_n - 1]]
    duration_ms = sum(iats)

    vec = build_early_vector(sizes, dirs, iats, early_n=early_n)
    feat_names = get_feature_names(early_n)

    src_ip = DEVICE_IPS.get(device_id, "10.0.1.4" if is_attack else "10.0.1.11")
    dport = 8443 if device_class == "camera" or attack_family in ("A1_flood", "A2_slowloris", "A3_c2", "A4_exfil") else 8883

    row = {
        "src_ip": src_ip,
        "dst_ip": "10.0.2.10",
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
    out_csv: str = None,
    out_parquet: str = None,
    seed: int = 42,
):
    """Generate a deterministically seeded smoke dataset for benign and attack traffic."""
    random.seed(seed)
    np.random.seed(seed)
    print(SMOKE_BANNER)
    rows = []
    classes = ["sensor", "plug", "thermostat", "camera"]
    t_cur = 1700000000.0

    for i in range(n_benign):
        cls = random.choice(classes)
        max_idx = 4 if cls == "sensor" else (2 if cls == "camera" else 3)
        dev_id = f"{cls}-{random.randint(1, max_idx):02d}"
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
                device_id="attacker-01",
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
    df.to_csv(out_csv, index=False)
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
