#!/usr/bin/env python3
"""
ips/data/build_splits.py — Session-Level Dataset Split & LOFO Fold Builder (WP2b, B2).

Enforces the 4 mandatory split integrity guarantees (B2a-d):
  (a) Session-disjoint splits: no session_id may appear in more than one split.
  (b) Held-out family isolation: held-out zero-day families (e.g. A3_c2, A4_exfil)
      must never appear in train, calibration, or validation splits.
  (c) Calibration sample-size warning: if calibration flow count < min_calibration_flows
      (default 3000), emits a loud UserWarning that FPR=1e-3 cannot be empirically verified.
  (d) Attack-window contamination guard: benign flows captured during an active attack window
      (`in_attack_window == True`) must never be mixed into benign train/calibration/validation.

Outputs `results/splits/splits.json` and updates the split summary table in `docs/spec.md`.

Usage:
  python -m ips.data.build_splits --check
"""
import os
import sys
import json
import warnings
import argparse
from typing import Dict, Any, List, Set, Tuple
import pandas as pd

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)

from ips.smoke.synth import generate_smoke_dataset

DEFAULT_HELD_OUT_FAMILIES = ("A3_c2", "A4_exfil")
ALL_ATTACK_FAMILIES = ("A1_flood", "A2_slowloris", "A3_c2", "A4_exfil", "A5_bruteforce")


def verify_split_integrity(
    splits: Dict[str, pd.DataFrame],
    held_out_families: Tuple[str, ...] = DEFAULT_HELD_OUT_FAMILIES,
    min_calibration_flows: int = 3000,
) -> Dict[str, Any]:
    """
    Assert all 4 split integrity rules (B2a-d). Raises ValueError on any leakage violation.
    """
    benign_split_names = [k for k in ("train", "calibration", "validation", "test_benign") if k in splits]

    # (a) Assert no session_id appears in two splits
    session_map: Dict[str, Set[str]] = {}
    for s_name, df in splits.items():
        if df is None or len(df) == 0 or "session_id" not in df.columns:
            session_map[s_name] = set()
        else:
            session_map[s_name] = set(df["session_id"].astype(str).unique())

    checked_names = list(splits.keys())
    for i in range(len(checked_names)):
        for j in range(i + 1, len(checked_names)):
            k1, k2 = checked_names[i], checked_names[j]
            # Allow test_benign and test_attacks to come from separate session namespaces;
            # never allow any overlap across train, calibration, validation, test!
            overlap = session_map[k1].intersection(session_map[k2])
            if overlap:
                raise ValueError(
                    f"CRITICAL SPLIT LEAKAGE (B2a): session_id(s) {overlap} appear in both '{k1}' and '{k2}'!"
                )

    # (b) Assert held-out families are absent from train, calibration, and validation;
    #     and train/calibration are 100% benign (is_attack == 0)
    held_set = set(held_out_families)
    for b_name in ("train", "calibration"):
        if b_name in splits and len(splits[b_name]) > 0:
            df_b = splits[b_name]
            if "is_attack" in df_b.columns and (df_b["is_attack"].astype(int) != 0).any():
                raise ValueError(f"CRITICAL SPLIT LEAKAGE (B2b): attack flows found in benign split '{b_name}'!")

    for check_name in ("train", "calibration", "validation"):
        if check_name in splits and len(splits[check_name]) > 0:
            df_c = splits[check_name]
            for col in ("label_family", "attack_family"):
                if col in df_c.columns:
                    fams = set(df_c[col].astype(str).unique())
                    bad = fams.intersection(held_set)
                    if bad:
                        raise ValueError(
                            f"CRITICAL ZERO-DAY LEAKAGE (B2b): held-out family {bad} found in '{check_name}'!"
                        )

    # (c) Calibration sample count warning
    cal_df = splits.get("calibration", pd.DataFrame())
    n_cal = len(cal_df)
    if n_cal < min_calibration_flows:
        warnings.warn(
            f"CALIBRATION SAMPLE WARNING (B2c): calibration split has {n_cal} flows "
            f"(< min_calibration_flows={min_calibration_flows}). "
            f"Target FPR=1e-3 cannot be empirically verified below 3/N_cal = {3.0 / max(1, n_cal):.5f}!",
            UserWarning,
            stacklevel=2,
        )

    # (d) Assert benign flows from an attack window are not mixed into benign train/calibration/validation
    for b_name in ("train", "calibration", "validation"):
        if b_name in splits and len(splits[b_name]) > 0:
            df_b = splits[b_name]
            if "in_attack_window" in df_b.columns:
                ben_in_atk = df_b[(df_b.get("is_attack", 0) == 0) & (df_b["in_attack_window"] == True)]
                if len(ben_in_atk) > 0:
                    raise ValueError(
                        f"CRITICAL CONTAMINATION (B2d): {len(ben_in_atk)} benign flows from an active attack window "
                        f"were mixed into '{b_name}'!"
                    )

    return {
        "passed": True,
        "split_counts": {k: len(v) for k, v in splits.items()},
        "calibration_flows": n_cal,
        "calibration_sufficient_for_1e3": n_cal >= min_calibration_flows,
    }


def build_lofo_folds(attack_families: Tuple[str, ...] = ALL_ATTACK_FAMILIES) -> List[Dict[str, Any]]:
    """
    Construct Leave-One-Attack-Family-Out (LOFO) fold definitions.
    In fold F:
      - held_out_family = F (evaluated strictly once; never used for tuning)
      - dev_families = all families != F (usable with validation benign for threshold/model checks)
    """
    folds = []
    for fam in attack_families:
        dev_fams = [f for f in attack_families if f != fam]
        folds.append({
            "fold_id": f"lofo_{fam}",
            "held_out_family": fam,
            "dev_families": dev_fams,
        })
    return folds


def build_splits_from_sessions(
    session_dfs: Dict[str, pd.DataFrame],
    held_out_families: Tuple[str, ...] = DEFAULT_HELD_OUT_FAMILIES,
    min_calibration_flows: int = 3000,
) -> Tuple[Dict[str, pd.DataFrame], Dict[str, Any]]:
    """
    Assemble session-level splits from a dictionary of `{split_role: df}` and verify integrity.
    Filters out any `in_attack_window == True` benign flows from train/calibration/validation.
    """
    splits: Dict[str, pd.DataFrame] = {}
    for role, df in session_dfs.items():
        df_copy = df.copy()
        if role in ("train", "calibration") and "in_attack_window" in df_copy.columns:
            df_copy = df_copy[df_copy["in_attack_window"] == False].copy()
        splits[role] = df_copy

    report = verify_split_integrity(
        splits,
        held_out_families=held_out_families,
        min_calibration_flows=min_calibration_flows,
    )
    report["lofo_folds"] = build_lofo_folds()
    return splits, report


def update_spec_md_split_table(report: Dict[str, Any], spec_path: str = None, is_smoke: bool = False):
    """
    Write or update the session-split summary table inside docs/spec.md (B2).
    Per Rule B0, smoke-data counts are written to results/smoke/split_table.md
    and docs/spec.md keeps 'NOT RUN (needs real data)' unless real data exist.
    """
    if spec_path is None:
        spec_path = os.path.join(REPO_DIR, "docs", "spec.md")

    counts = report.get("split_counts", {})
    if is_smoke:
        smoke_dir = os.path.join(REPO_DIR, "results", "smoke")
        os.makedirs(smoke_dir, exist_ok=True)
        smoke_md = os.path.join(smoke_dir, "split_table.md")
        smoke_lines = [
            "> **SYNTHETIC SMOKE DATA ONLY — DO NOT CITE AS EXPERIMENTAL RESULTS**",
            "",
            "| Split Role | Smoke Flow Count | Allowed Families | Integrity Check |",
            "|------------|------------------|------------------|-----------------|",
            f"| `train` | {counts.get('train', 0)} | Benign only (`is_attack == 0`) | Session-disjoint, no attack-window flows |",
            f"| `calibration` | {counts.get('calibration', 0)} | Benign only (`is_attack == 0`) | EVT / Conformal threshold fit (`min_calibration_flows=3000`) |",
            f"| `validation` | {counts.get('validation', 0)} | Benign + DEV families (`A1, A2, A5`) | Held-out zero-day families (`A3_c2, A4_exfil`) strictly excluded |",
            f"| `test` | {counts.get('test', 0)} | Benign test session + Held-out families (`A3_c2, A4_exfil`) | Evaluated once per LOFO fold |",
        ]
        with open(smoke_md, "w", encoding="utf-8") as sf:
            sf.write("\n".join(smoke_lines) + "\n")

    if not os.path.exists(spec_path):
        return

    c_train = "NOT RUN (needs real data)" if is_smoke else str(counts.get("train", 0))
    c_cal = "NOT RUN (needs real data)" if is_smoke else str(counts.get("calibration", 0))
    c_val = "NOT RUN (needs real data)" if is_smoke else str(counts.get("validation", 0))
    c_test = "NOT RUN (needs real data)" if is_smoke else str(counts.get("test", 0))

    marker_start = "<!-- SPLIT_TABLE_START -->"
    marker_end = "<!-- SPLIT_TABLE_END -->"
    table_lines = [
        marker_start,
        "### Session-Disjoint Split Table (`ips/data/build_splits.py`)",
        "",
        "| Split Role | Flow Count | Allowed Families | Integrity Check |",
        "|------------|------------|------------------|-----------------|",
        f"| `train` | {c_train} | Benign only (`is_attack == 0`) | Session-disjoint, no attack-window flows |",
        f"| `calibration` | {c_cal} | Benign only (`is_attack == 0`) | EVT / Conformal threshold fit (`min_calibration_flows=3000`) |",
        f"| `validation` | {c_val} | Benign + DEV families (`A1, A2, A5`) | Held-out zero-day families (`A3_c2, A4_exfil`) strictly excluded |",
        f"| `test` | {c_test} | Benign test session + Held-out families (`A3_c2, A4_exfil`) | Evaluated once per LOFO fold |",
        marker_end,
    ]
    block = "\n".join(table_lines)

    with open(spec_path, "r", encoding="utf-8") as f:
        content = f.read()

    if marker_start in content and marker_end in content:
        pre = content.split(marker_start)[0]
        post = content.split(marker_end)[1]
        new_content = pre + block + post
    else:
        new_content = content.rstrip() + "\n\n" + block + "\n"

    with open(spec_path, "w", encoding="utf-8") as f:
        f.write(new_content)


def run_check_cli(min_calibration_flows: int = 3000):
    """Generate smoke session splits, run all B2 leakage assertions, and write results/splits/splits.json."""
    df_train = generate_smoke_dataset(n_benign=600, n_attack=0, early_n=16, session_id="smoke_s1_train", seed=101)
    df_cal = generate_smoke_dataset(n_benign=400, n_attack=0, early_n=16, session_id="smoke_s2_calib", seed=102)
    df_val_raw = generate_smoke_dataset(n_benign=200, n_attack=100, early_n=16, session_id="smoke_s3_val", seed=103)
    # Remove held-out families from validation split
    df_val = df_val_raw[~df_val_raw["label_family"].isin(DEFAULT_HELD_OUT_FAMILIES)].copy()
    df_test = generate_smoke_dataset(n_benign=300, n_attack=150, early_n=16, session_id="smoke_s4_test", seed=104)

    splits, report = build_splits_from_sessions(
        {
            "train": df_train,
            "calibration": df_cal,
            "validation": df_val,
            "test": df_test,
        },
        held_out_families=DEFAULT_HELD_OUT_FAMILIES,
        min_calibration_flows=min_calibration_flows,
    )

    out_dir = os.path.join(REPO_DIR, "results", "splits")
    os.makedirs(out_dir, exist_ok=True)
    out_json = os.path.join(out_dir, "splits.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    update_spec_md_split_table(report, is_smoke=True)
    print(f"[+] Split integrity check PASSED. Wrote {out_json}")
    print(json.dumps(report["split_counts"], indent=2))


def main():
    parser = argparse.ArgumentParser(description="Build and verify session-disjoint dataset splits (WP2b)")
    parser.add_argument("--check", action="store_true", help="Run split integrity verification")
    parser.add_argument("--min-calibration-flows", type=int, default=3000)
    args = parser.parse_args()
    run_check_cli(min_calibration_flows=args.min_calibration_flows)


if __name__ == "__main__":
    main()
