#!/usr/bin/env python3
"""
tests/test_features.py — Unit tests for canonical shared features and shortcut guard.
"""
import os
import math
import tempfile
import pytest
import numpy as np
import dpkt

from ips.features import (
    build_early_vector,
    get_feature_names,
    assert_no_forbidden_features,
    FORBIDDEN_COLUMNS,
)
from ips.offline.pcap_to_flows import extract_flows_from_pcap


def test_feature_vector_dimension():
    """Verify feature vector length equals 3*N + 8 for various N."""
    for n in [4, 6, 8, 12, 16, 24]:
        names = get_feature_names(early_n=n)
        assert len(names) == 3 * n + 8, f"Mismatch for N={n}: len={len(names)}"
        assert_no_forbidden_features(names)

        sizes = [100] * n
        dirs = [0] * n
        iats = [10.0] * (n - 1)
        vec = build_early_vector(sizes, dirs, iats, early_n=n)
        assert vec.shape == (3 * n + 8,)
        assert np.all(np.isfinite(vec))


def test_shortcut_guard():
    """Verify that forbidden columns trigger ValueError."""
    safe_names = ["size_0", "dir_0", "log_iat_0", "frac_upstream"]
    assert_no_forbidden_features(safe_names)

    for col in FORBIDDEN_COLUMNS:
        with pytest.raises(ValueError, match="CRITICAL SHORTCUT LEARNING VIOLATION"):
            assert_no_forbidden_features(safe_names + [col])


def test_short_flow_masking_and_valid_len():
    """Verify that a flow with only 3 packets in N=12 is properly padded and has valid_len=3/12."""
    sizes = [120, 80, 200]
    dirs = [0, 1, 0]
    iats = [5.0, 10.0]
    vec = build_early_vector(sizes, dirs, iats, early_n=12)

    # First 3 sizes normalized (120/1500, 80/1500, 200/1500)
    assert pytest.approx(vec[0], 0.001) == 120.0 / 1500.0
    assert pytest.approx(vec[1], 0.001) == 80.0 / 1500.0
    assert pytest.approx(vec[2], 0.001) == 200.0 / 1500.0
    # Remaining 9 sizes are 0
    for i in range(3, 12):
        assert vec[i] == 0.0

    # Directions: dirs[0]=0, dirs[1]=1, dirs[2]=0, others 0
    assert vec[12] == 0.0
    assert vec[13] == 1.0
    assert vec[14] == 0.0
    for i in range(15, 24):
        assert vec[i] == 0.0

    # valid_len is the last aggregate feature: 3 / 12 = 0.25
    assert pytest.approx(vec[-1], 0.001) == 0.25


def test_pcap_to_flows_golden_fixture():
    """Golden-file equivalence test on synthetic pcap with known sizes and IATs."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        tmp_pcap = f.name
        writer = dpkt.pcap.Writer(f)

        # 3 packets: 100B at t=100.0, 200B at t=100.2 (IAT=200ms), 300B at t=100.5 (IAT=300ms)
        pkts_spec = [
            (100.0, b"A" * 100, 54321, 8883, True),   # Client -> Server
            (100.2, b"B" * 200, 8883, 54321, False),  # Server -> Client
            (100.5, b"C" * 300, 54321, 8883, True),   # Client -> Server
        ]

        for ts, payload, sport, dport, is_lan in pkts_spec:
            src_ip = b"\x0a\x00\x01\x0a" if is_lan else b"\x0a\x00\x02\x0a"
            dst_ip = b"\x0a\x00\x02\x0a" if is_lan else b"\x0a\x00\x01\x0a"
            tcp = dpkt.tcp.TCP(sport=sport, dport=dport, data=payload, flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK)
            ip = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_TCP, data=tcp)
            ip.len = len(ip)
            eth = dpkt.ethernet.Ethernet(src=b"\x00"*6, dst=b"\x00"*6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
            writer.writepkt(eth, ts=ts)
        writer.close()

    try:
        df = extract_flows_from_pcap(tmp_pcap, early_n=12)
        assert len(df) == 1, f"Expected 1 flow, got {len(df)}"
        row = df.iloc[0]

        assert row["raw_valid_len"] == 3
        assert pytest.approx(row["valid_len"], 0.001) == 3.0 / 12.0
        assert pytest.approx(row["size_0"], 0.001) == 100.0 / 1500.0
        assert pytest.approx(row["size_1"], 0.001) == 200.0 / 1500.0
        assert pytest.approx(row["size_2"], 0.001) == 300.0 / 1500.0

        assert row["dir_0"] == 0.0  # LAN -> WAN
        assert row["dir_1"] == 1.0  # WAN -> LAN
        assert row["dir_2"] == 0.0  # LAN -> WAN

        # IAT 0: 200ms = 200,000 us -> log10(1 + 200000) ~ 5.301
        expected_log_iat0 = math.log10(1.0 + 200000.0)
        assert pytest.approx(row["log_iat_0"], 0.01) == expected_log_iat0

        # IAT 1: 300ms = 300,000 us -> log10(1 + 300000) ~ 5.477
        expected_log_iat1 = math.log10(1.0 + 300000.0)
        assert pytest.approx(row["log_iat_1"], 0.01) == expected_log_iat1

    finally:
        if os.path.exists(tmp_pcap):
            os.remove(tmp_pcap)
