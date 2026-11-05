#!/usr/bin/env python3
"""
tests/test_splits_and_joins.py — V1 unit tests for WP2b (build_splits.py, label_join.py, cross_domain.py).
"""
import os
import pandas as pd
import pytest

from ips.data.label_join import join_flows_to_manifest, join_flows_to_engine_events
from ips.data.build_splits import (
    verify_split_integrity,
    build_splits_from_sessions,
    build_lofo_folds,
    run_check_cli,
)
from ips.eval.cross_domain import run_cross_domain_experiment


def test_split_integrity_assertions_a_b_c_d():
    """B2(a-d): Verify all 4 split leakage and sample-count checks."""
    df_s1 = pd.DataFrame([
        {"session_id": "s1", "is_attack": 0, "label_family": "benign", "in_attack_window": False}
        for _ in range(100)
    ])
    df_s2 = pd.DataFrame([
        {"session_id": "s2", "is_attack": 0, "label_family": "benign", "in_attack_window": False}
        for _ in range(100)
    ])
    df_s3_val = pd.DataFrame([
        {"session_id": "s3", "is_attack": 0, "label_family": "benign", "in_attack_window": False},
        {"session_id": "s3", "is_attack": 1, "label_family": "A1_flood", "in_attack_window": True},
    ])

    # (c) Calibration has 100 < 3000 flows -> must emit UserWarning
    with pytest.warns(UserWarning, match="CALIBRATION SAMPLE WARNING"):
        res = verify_split_integrity(
            {"train": df_s1, "calibration": df_s2, "validation": df_s3_val},
            min_calibration_flows=3000,
        )
    assert res["passed"] is True
    assert res["calibration_sufficient_for_1e3"] is False

    # (a) Session appears in both train and calibration -> must raise ValueError
    with pytest.raises(ValueError, match="CRITICAL SPLIT LEAKAGE"):
        verify_split_integrity({"train": df_s1, "calibration": df_s1}, min_calibration_flows=10)

    # (b) Held-out family A3_c2 in validation -> must raise ValueError
    df_bad_val = pd.DataFrame([
        {"session_id": "s4", "is_attack": 1, "label_family": "A3_c2", "in_attack_window": True}
    ])
    with pytest.raises(ValueError, match="CRITICAL ZERO-DAY LEAKAGE"):
        verify_split_integrity({"train": df_s1, "calibration": df_s2, "validation": df_bad_val}, min_calibration_flows=10)

    # (d) Benign flow captured during an attack window mixed into train -> must raise ValueError
    df_contaminated = pd.DataFrame([
        {"session_id": "s5", "is_attack": 0, "label_family": "benign", "in_attack_window": True}
    ])
    with pytest.raises(ValueError, match="CRITICAL CONTAMINATION"):
        verify_split_integrity({"train": df_contaminated, "calibration": df_s2}, min_calibration_flows=10)


def test_label_join_manifest_and_engine_events():
    """B3: Verify join_flows_to_manifest and join_flows_to_engine_events on hand-built examples."""
    flows = pd.DataFrame([
        # Flow 0: clean benign before attack window
        {"src_ip": "10.0.1.11", "dst_ip": "10.0.2.10", "sport": 50001, "dport": 8883, "proto": "TCP", "start_ts": 100.0, "end_ts": 105.0},
        # Flow 1: benign flow from sensor-01 DURING attack window (must be flagged in_attack_window=True, is_attack=0)
        {"src_ip": "10.0.1.11", "dst_ip": "10.0.2.10", "sport": 50002, "dport": 8883, "proto": "TCP", "start_ts": 205.0, "end_ts": 208.0},
        # Flow 2: attacker flow during attack window (must be labelled is_attack=1, A4_exfil)
        {"src_ip": "10.0.1.4", "dst_ip": "10.0.2.10", "sport": 55000, "dport": 8443, "proto": "TCP", "start_ts": 202.0, "end_ts": 210.0},
    ])
    manifest = pd.DataFrame([
        {"family": "A4_exfil", "src_ip": "10.0.1.4", "dst_ip": "10.0.2.10", "dst_port": 8443, "start_ts": 200.0, "end_ts": 220.0}
    ])

    joined = join_flows_to_manifest(flows, manifest)
    assert joined.iloc[0]["is_attack"] == 0 and bool(joined.iloc[0]["in_attack_window"]) is False
    assert joined.iloc[1]["is_attack"] == 0 and bool(joined.iloc[1]["in_attack_window"]) is True
    assert joined.iloc[2]["is_attack"] == 1 and joined.iloc[2]["label_family"] == "A4_exfil"

    # Join to engine events
    events = [
        {"ip_a": "10.0.1.11", "port_a": 50001, "ip_b": "10.0.2.10", "port_b": 8883, "proto": "TCP", "score": 0.04, "verdict_written": "BYPASS"},
        {"ip_a": "10.0.1.4", "port_a": 55000, "ip_b": "10.0.2.10", "port_b": 8443, "proto": "TCP", "score": 0.62, "verdict_written": "DROP"},
    ]
    ev_joined = join_flows_to_engine_events(joined, events)
    assert bool(ev_joined.iloc[0]["engine_matched"]) is True
    assert ev_joined.iloc[0]["engine_verdict"] == "BYPASS"
    assert bool(ev_joined.iloc[2]["engine_matched"]) is True
    assert ev_joined.iloc[2]["engine_verdict"] == "DROP"


def test_build_splits_cli_and_cross_domain(tmp_path):
    """B2 & B6: Verify build_splits CLI and cross_domain experiment run cleanly."""
    with pytest.warns(UserWarning, match="CALIBRATION SAMPLE WARNING"):
        run_check_cli(min_calibration_flows=3000)

    folds = build_lofo_folds()
    assert len(folds) == 5
    for fold in folds:
        assert fold["held_out_family"] not in fold["dev_families"]

    df_cd = run_cross_domain_experiment(str(tmp_path), early_n=8, is_smoke=True)
    assert len(df_cd) == 5
    assert "cross_domain_fpr" in df_cd.columns
    assert "ks_statistic" in df_cd.columns
    assert "top_3_shift_features" in df_cd.columns

