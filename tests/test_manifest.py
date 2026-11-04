#!/usr/bin/env python3
"""
tests/test_manifest.py — Unit tests for ground-truth manifest logger.
"""
import os
import tempfile
import pytest
from traffic.manifest import ManifestWriter, MANIFEST_HEADER


def test_manifest_writer_and_reader():
    """Verify episode logging and retrieval with type integrity."""
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        tmp_path = f.name

    try:
        writer = ManifestWriter(tmp_path, run_id="test_run_001")
        assert os.path.exists(tmp_path)

        # Record A1 episode
        t0 = 1000.0
        t1 = 1010.5
        writer.record_episode(
            family="A1_flood",
            src_ip="10.0.1.4",
            dst_ip="10.0.2.10",
            dst_port=8883,
            start_ts=t0,
            end_ts=t1,
            params={"attempts": 50, "flood_type": "handshake"},
        )

        # Record A3 episode
        t2 = 1015.0
        t3 = 1045.0
        writer.record_episode(
            family="A3_c2",
            src_ip="10.0.1.4",
            dst_ip="10.0.2.10",
            dst_port=8883,
            start_ts=t2,
            end_ts=t3,
            params={"interval": 5.0, "jitter": 0.3},
        )

        # Read back
        records = ManifestWriter.load_manifest(tmp_path)
        assert len(records) == 2, f"Expected 2 records, got {len(records)}"

        r0 = records[0]
        assert r0["run_id"] == "test_run_001"
        assert r0["family"] == "A1_flood"
        assert r0["src_ip"] == "10.0.1.4"
        assert r0["dst_port"] == 8883
        assert r0["start_ts"] == 1000.0
        assert r0["end_ts"] == 1010.5
        assert r0["params"]["attempts"] == 50

        r1 = records[1]
        assert r1["family"] == "A3_c2"
        assert r1["params"]["interval"] == 5.0

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
