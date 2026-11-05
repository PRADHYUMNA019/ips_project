#!/usr/bin/env python3
"""
ips/smoke/synth.py — Smoke-data generator for local pipeline testing.

Generates semi-synthetic early-flow vectors from device profiles and attack models.
Every output carries source="synthetic-smoke" and writes only under results/smoke/.

SMOKE DATA IS NOT A RESEARCH RESULT. IT IS ONLY FOR PIPELINE SMOKE TESTING ON NON-LINUX HOSTS.
"""
import os
import random
import math
import argparse
import pandas as pd
import numpy as np

SMOKE_BANNER = """
================================================================================
   [SMOKE DATA GENERATOR] — SYNTHETIC SMOKE TEST VECTORS ONLY
   WARNING: THIS DATA IS GENERATED FOR PIPELINE TESTING AND CODE EXERCISE.
   IT MUST NEVER APPEAR IN PAPER RESULTS, CLAIMS, OR EVALUATION TABLES.
================================================================================
"""

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_OUT_DIR = os.path.join(REPO_DIR, "results", "smoke")


def generate_flow_vector(early_n=12, device_class="sensor", device_id="sensor-01",
                         is_attack=False, attack_family="none", session_id="smoke_sess_01",
                         drift_scale=1.0):
    """Generate a single early-flow vector with N payload packets."""
    sizes = []
    dirs = []
    iats = []

    if not is_attack:
        # Benign IoT device profiles
        if device_class == "sensor":
            # Small periodic telemetry (48-80 B) with echoes (32-64 B), ~10s IAT
            mean_iat = 10.0 * 1000.0 * drift_scale  # in ms
            for i in range(early_n):
                if i % 2 == 0:
                    dirs.append(0)  # client -> server
                    sizes.append(int(random.gauss(64, 10)))
                else:
                    dirs.append(1)  # server -> client (echo)
                    sizes.append(int(random.gauss(48, 8)))
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
            # High throughput bursts (800-1400 B), fast 0.5s IAT
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
        # Attack families A1 - A5
        if attack_family == "A1_flood":
            # Fast volumetric flood (very low IAT < 5ms, uniform small sizes)
            for i in range(early_n):
                dirs.append(0)
                sizes.append(int(random.gauss(64, 5)))
                if i > 0:
                    iats.append(max(0.1, random.gauss(2.0, 0.8)))

        elif attack_family == "A2_slowloris":
            # Slow-rate DoS: tiny chunks (1-8 B) with long gaps (8-15 s)
            for i in range(early_n):
                dirs.append(0)
                sizes.append(random.randint(1, 8))
                if i > 0:
                    iats.append(random.uniform(8000.0, 14000.0))

        elif attack_family == "A3_c2":
            # C2 beaconing over TLS: fixed interval with jitter (e.g. 5s or 30s)
            base_interval_ms = random.choice([5000.0, 15000.0, 30000.0])
            for i in range(early_n):
                dirs.append(0 if i % 2 == 0 else 1)
                sizes.append(int(random.gauss(80, 5)))
                if i > 0:
                    jitter = random.uniform(-0.15, 0.15) * base_interval_ms
                    iats.append(max(50.0, base_interval_ms + jitter))

        elif attack_family == "A4_exfil":
            # Large chunk uploads, constant or high sizes (1300-1460 B) upstream
            for i in range(early_n):
                dirs.append(0)
                sizes.append(int(random.gauss(1400, 30)))
                if i > 0:
                    iats.append(max(1.0, random.gauss(10.0, 3.0)))

        elif attack_family == "A5_bruteforce":
            # Credential brute force: short bursts then pause
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

    # Clean bounds
    sizes = [max(1, s) for s in sizes[:early_n]]
    dirs = dirs[:early_n]
    iats = [max(0.01, t) for t in iats[:early_n - 1]]

    row = {
        "device_id": device_id,
        "device_class": device_class,
        "is_attack": 1 if is_attack else 0,
        "attack_family": attack_family,
        "source": "synthetic-smoke",
        "session_id": session_id,
        "early_n": early_n,
        "total_pkts": early_n,
        "total_bytes": sum(sizes),
        "duration_ms": sum(iats),
    }
    for idx, s in enumerate(sizes):
        row[f"size_{idx}"] = s
    for idx, d in enumerate(dirs):
        row[f"dir_{idx}"] = d
    for idx, t in enumerate(iats):
        row[f"iat_{idx}"] = t

    return row


def generate_smoke_dataset(n_benign=1000, n_attack=200, early_n=12,
                           session_id="smoke_sess_01", out_csv=None, out_parquet=None):
    """Generate a combined smoke dataset for benign and attack traffic."""
    print(SMOKE_BANNER)
    rows = []
    classes = ["sensor", "plug", "thermostat", "camera"]

    # Benign
    for i in range(n_benign):
        cls = random.choice(classes)
        dev_id = f"{cls}-{random.randint(1, 3):02d}"
        rows.append(generate_flow_vector(
            early_n=early_n,
            device_class=cls,
            device_id=dev_id,
            is_attack=False,
            attack_family="none",
            session_id=session_id,
        ))

    # Attacks across families A1-A5
    families = ["A1_flood", "A2_slowloris", "A3_c2", "A4_exfil", "A5_bruteforce"]
    for i in range(n_attack):
        fam = random.choice(families)
        rows.append(generate_flow_vector(
            early_n=early_n,
            device_class="attacker",
            device_id="attacker-01",
            is_attack=True,
            attack_family=fam,
            session_id=session_id,
        ))

    df = pd.DataFrame(rows)
    os.makedirs(DEFAULT_OUT_DIR, exist_ok=True)

    if out_csv is None:
        out_csv = os.path.join(DEFAULT_OUT_DIR, f"{session_id}.csv")
    if out_parquet is None:
        out_parquet = os.path.join(DEFAULT_OUT_DIR, f"{session_id}.parquet")

    df.to_csv(out_csv, index=False)
    try:
        df.to_parquet(out_parquet, index=False)
    except Exception:
        pass

    print(f"[OK] Generated {len(df)} smoke flow vectors ({n_benign} benign, {n_attack} attacks)")
    print(f"     Saved to: {out_csv}")
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic smoke flow vectors")
    parser.add_argument("--benign", type=int, default=1000, help="Number of benign flows")
    parser.add_argument("--attack", type=int, default=200, help="Number of attack flows")
    parser.add_argument("--early-n", type=int, default=12, help="Payload packets per early flow")
    parser.add_argument("--session", default="smoke_train_sess", help="Session label")
    args = parser.parse_args()

    generate_smoke_dataset(
        n_benign=args.benign,
        n_attack=args.attack,
        early_n=args.early_n,
        session_id=args.session,
    )

