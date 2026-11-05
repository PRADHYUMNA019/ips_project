#!/usr/bin/env python3
"""
tests/test_reproduce.py — V1 unit tests for WP9 (ips/eval/reproduce.py and Rule B0 isolation).
"""
import os
import pandas as pd
import pytest

from ips.eval.reproduce import _load_real_csv, generate_results_md


def test_reproduce_rejects_smoke_data(tmp_path):
    """Verify Rule B0: _load_real_csv raises RuntimeError if source=='synthetic-smoke'."""
    smoke_csv = str(tmp_path / "fake_real.csv")
    df = pd.DataFrame([{"model": "ae", "pr_auc": 0.99, "source": "synthetic-smoke"}])
    df.to_csv(smoke_csv, index=False)

    with pytest.raises(RuntimeError, match="CRITICAL B0 VIOLATION"):
        _load_real_csv(smoke_csv)


def test_generate_results_md_truthful_when_no_real_data(tmp_path):
    """Verify generate_results_md produces truthful NOT RUN placeholders when real data is absent."""
    out_md = str(tmp_path / "RESULTS.md")
    generate_results_md(out_md)
    assert os.path.exists(out_md)
    with open(out_md, "r", encoding="utf-8") as f:
        text = f.read()
    assert "NOT RUN" in text
    assert "synthetic-smoke" in text  # mentioned in Rule B0 header note

