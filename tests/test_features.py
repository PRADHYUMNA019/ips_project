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
    split_metadata_and_features,
    FORBIDDEN_COLUMNS,
    METADATA_COLUMNS,
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


def test_truncated_packet_header_length(tmp_path):
    """A4(a): Verify truncated 200-byte packet uses ip.len - ip.hl*4 - tcp.off*4 (1400B), not len(tcp.data)."""
    pcap_path = str(tmp_path / "truncated.pcap")
    with open(pcap_path, "wb") as f:
        writer = dpkt.pcap.Writer(f, snaplen=200)
        # Build a packet with 1400B payload (total IP len = 1440), then truncate frame to 200 bytes
        tcp = dpkt.tcp.TCP(sport=50000, dport=8443, data=b"X" * 1400, flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK)
        ip = dpkt.ip.IP(src=b"\x0a\x00\x01\x0b", dst=b"\x0a\x00\x02\x0a", p=dpkt.ip.IP_PROTO_TCP, data=tcp)
        ip.len = 20 + 20 + 1400  # 1440 bytes in IP header
        eth = dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x00" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
        raw_frame = bytes(eth)[:200]  # simulate Kitsune 200B snaplen truncation
        writer.writepkt(raw_frame, ts=200.0)
        writer.close()

    df = extract_flows_from_pcap(pcap_path, early_n=12, lan_cidrs=["10.0.1.0/24"])
    assert len(df) == 1
    row = df.iloc[0]
    # size_0 must reflect the true 1400B payload from IP header, NOT the truncated 146B slice
    assert pytest.approx(row["size_0"], 0.001) == 1400.0 / 1500.0


def test_reused_5tuple_flow_instances_and_metadata(tmp_path):
    """A4(b) & B3: Verify FIN/new-SYN on same 5-tuple emits distinct instances and split_metadata_and_features works."""
    pcap_path = str(tmp_path / "reused.pcap")
    with open(pcap_path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        src = b"\xc0\xa8\x01\x0a"  # 192.168.1.10
        dst = b"\x0a\x00\x02\x0a"  # 10.0.2.10

        # Instance 0: SYN, 200B payload, FIN
        for ts, flg, data in [
            (10.0, dpkt.tcp.TH_SYN, b""),
            (10.1, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"A" * 200),
            (10.2, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK, b""),
            # Instance 1 on same 5-tuple: SYN, 600B payload
            (20.0, dpkt.tcp.TH_SYN, b""),
            (20.1, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"B" * 600),
        ]:
            tcp = dpkt.tcp.TCP(sport=51111, dport=8883, flags=flg, data=data)
            ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, data=tcp)
            ip.len = len(ip)
            writer.writepkt(bytes(dpkt.ethernet.Ethernet(data=ip)), ts=ts)
        writer.close()

    df = extract_flows_from_pcap(pcap_path, early_n=8, lan_prefix=None, lan_cidrs=["192.168.0.0/16"])
    assert len(df) == 2
    assert list(df["instance"]) == [0, 1]
    assert pytest.approx(df.iloc[0]["size_0"], 0.001) == 200.0 / 1500.0
    assert pytest.approx(df.iloc[1]["size_0"], 0.001) == 600.0 / 1500.0

    for col in METADATA_COLUMNS:
        assert col in df.columns

    meta_df, x_mat, feat_cols = split_metadata_and_features(df, early_n=8)
    assert x_mat.shape == (2, 3 * 8 + 8)
    for col in METADATA_COLUMNS:
        assert col not in feat_cols
        assert col in meta_df.columns


def test_direction_asymmetry_and_frac_upstream_b3():
    """B3 (DEF-06 / M2): Explicitly verify directional byte asymmetry and frac_upstream calculation."""
    from ips.features import build_early_vector, get_feature_names

    names = get_feature_names(8)
    idx_frac = names.index("frac_upstream")
    idx_bytes_up = names.index("bytes_up")
    idx_bytes_down = names.index("bytes_down")

    # 1. 500 up (dir=0), 1500 down (dir=1) -> frac_upstream = 500 / 2000 = 0.25
    vec1 = build_early_vector([500, 1500], [0, 1], [10.0], early_n=8)
    assert vec1[idx_frac] == pytest.approx(0.25, abs=1e-5)
    assert vec1[idx_bytes_up] == pytest.approx(500.0 / 15000.0, abs=1e-5)
    assert vec1[idx_bytes_down] == pytest.approx(1500.0 / 15000.0, abs=1e-5)

    # 2. Reverse direction: 1500 up (dir=0), 500 down (dir=1) -> frac_upstream = 1500 / 2000 = 0.75
    vec2 = build_early_vector([1500, 500], [0, 1], [10.0], early_n=8)
    assert vec2[idx_frac] == pytest.approx(0.75, abs=1e-5)
    assert vec2[idx_bytes_up] == pytest.approx(1500.0 / 15000.0, abs=1e-5)
    assert vec2[idx_bytes_down] == pytest.approx(500.0 / 15000.0, abs=1e-5)


