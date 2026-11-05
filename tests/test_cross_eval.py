#!/usr/bin/env python3
"""tests/test_cross_eval.py - Cross-domain evaluation data leakage guards (B7)."""

import pytest
import pandas as pd
import numpy as np


def assert_no_cross_domain_leakage(train_df: pd.DataFrame, eval_df: pd.DataFrame, dataset_name: str = "TON_IOT"):
    """
    Sentinel guard: strictly assert that zero flow keys, indices, or session IDs
    from the training domain bleed into the target evaluation domain (B7).
    """
    # 1. Check index intersection
    index_overlap = set(train_df.index).intersection(set(eval_df.index))
    if index_overlap:
        raise ValueError(f"CRITICAL CROSS-DOMAIN LEAKAGE [{dataset_name}]: {len(index_overlap)} row indices overlap!")

    # 2. Check flow_id / flow_key intersection if present
    for key_col in ["flow_id", "flow_key"]:
        if key_col in train_df.columns and key_col in eval_df.columns:
            key_overlap = set(train_df[key_col]).intersection(set(eval_df[key_col]))
            if key_overlap:
                raise ValueError(
                    f"CRITICAL CROSS-DOMAIN LEAKAGE [{dataset_name}]: {len(key_overlap)} {key_col} values overlap between train and eval!"
                )

    # 3. Check 5-tuple key overlap if endpoint columns present
    tup_cols = ["ip_a", "port_a", "ip_b", "port_b", "proto"]
    if all(c in train_df.columns for c in tup_cols) and all(c in eval_df.columns for c in tup_cols):
        train_tuples = set(zip(*(train_df[c] for c in tup_cols)))
        eval_tuples = set(zip(*(eval_df[c] for c in tup_cols)))
        tup_overlap = train_tuples.intersection(eval_tuples)
        if tup_overlap:
            raise ValueError(
                f"CRITICAL CROSS-DOMAIN LEAKAGE [{dataset_name}]: {len(tup_overlap)} 5-tuples overlap between train and eval!"
            )


def test_cross_domain_leakage_guard_ton_iot():
    """B7: Verify cross-domain evaluation strictly guards against train/test data leakage."""
    # Synthetic train domain
    train_df = pd.DataFrame(
        {
            "flow_id": [f"train_flow_{i}" for i in range(50)],
            "ip_a": ["10.0.1.11"] * 50,
            "port_a": list(range(1000, 1050)),
            "ip_b": ["10.0.2.10"] * 50,
            "port_b": [8883] * 50,
            "proto": ["TCP"] * 50,
            "size_0": np.random.uniform(0.1, 0.5, 50),
        },
        index=[f"idx_tr_{i}" for i in range(50)],
    )

    # Clean out-of-domain evaluation set (e.g. TON_IOT)
    eval_df_clean = pd.DataFrame(
        {
            "flow_id": [f"ton_iot_flow_{i}" for i in range(50)],
            "ip_a": ["192.168.1.150"] * 50,
            "port_a": list(range(2000, 2050)),
            "ip_b": ["192.168.1.1"] * 50,
            "port_b": [443] * 50,
            "proto": ["TCP"] * 50,
            "size_0": np.random.uniform(0.1, 0.5, 50),
        },
        index=[f"idx_eval_{i}" for i in range(50)],
    )

    # Clean evaluation must pass without raising
    assert_no_cross_domain_leakage(train_df, eval_df_clean, dataset_name="TON_IOT")

    # Injected leakage 1: row index leakage
    eval_df_leaked_idx = eval_df_clean.copy()
    eval_df_leaked_idx.index = ["idx_tr_0"] + list(eval_df_clean.index[1:])
    with pytest.raises(ValueError, match="CRITICAL CROSS-DOMAIN LEAKAGE.*row indices overlap"):
        assert_no_cross_domain_leakage(train_df, eval_df_leaked_idx, dataset_name="TON_IOT")

    # Injected leakage 2: flow_id leakage
    eval_df_leaked_flow = eval_df_clean.copy()
    eval_df_leaked_flow.loc[eval_df_leaked_flow.index[0], "flow_id"] = "train_flow_0"
    with pytest.raises(ValueError, match="CRITICAL CROSS-DOMAIN LEAKAGE.*values overlap"):
        assert_no_cross_domain_leakage(train_df, eval_df_leaked_flow, dataset_name="TON_IOT")

    # Injected leakage 3: 5-tuple leakage
    eval_df_leaked_tuple = eval_df_clean.copy()
    eval_df_leaked_tuple.loc[eval_df_leaked_tuple.index[0], "ip_a"] = "10.0.1.11"
    eval_df_leaked_tuple.loc[eval_df_leaked_tuple.index[0], "port_a"] = 1000
    eval_df_leaked_tuple.loc[eval_df_leaked_tuple.index[0], "ip_b"] = "10.0.2.10"
    eval_df_leaked_tuple.loc[eval_df_leaked_tuple.index[0], "port_b"] = 8883
    eval_df_leaked_tuple.loc[eval_df_leaked_tuple.index[0], "proto"] = "TCP"
    with pytest.raises(ValueError, match="CRITICAL CROSS-DOMAIN LEAKAGE.*5-tuples overlap"):
        assert_no_cross_domain_leakage(train_df, eval_df_leaked_tuple, dataset_name="TON_IOT")
