#!/usr/bin/env python3
"""
tests/test_dataset_adapters.py — Unit tests for dataset adapters (A2, A3, A7) and audit_pcap.py.
"""
import math
import os
import sys
import tempfile
import warnings
import pandas as pd
import pytest
import dpkt

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_DIR)

from ips.features import split_metadata_and_features, METADATA_COLUMNS
from datasets.audit_pcap import is_tls_handshake, is_plaintext_marker, audit_single_pcap
from datasets.adapters.cesnet_adapter import adapt_cesnet_record, load_and_adapt_cesnet
from datasets.adapters.tqh_adapter import adapt_tqh_record
from datasets.adapters.kitsune_adapter import adapt_kitsune_record
from datasets.adapters.iot23_adapter import adapt_iot23_record, validate_iot23_capture_label


def test_tls_handshake_detector():
    """Verify TLS 1.0 - 1.3 handshake record header identification."""
    valid_tls_12 = bytes([0x16, 0x03, 0x03, 0x00, 0x10]) + b"ClientHelloData"
    assert is_tls_handshake(valid_tls_12) is True

    valid_tls_13 = bytes([0x16, 0x03, 0x01, 0x00, 0x20]) + b"InitialHandshake"
    assert is_tls_handshake(valid_tls_13) is True

    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert is_tls_handshake(http_payload) is False
    assert is_tls_handshake(b"") is False
    assert is_tls_handshake(b"\x16\x03") is False


def test_plaintext_marker():
    """Verify HTTP and MQTT plaintext markers."""
    assert is_plaintext_marker(b"POST /api HTTP/1.1", 80) is True
    assert is_plaintext_marker(b"GET / HTTP/1.1", 8080) is True
    assert is_plaintext_marker(bytes([0x10, 0x0c, 0x00, 0x04]) + b"MQTT", 1883) is True
    assert is_plaintext_marker(b"random_binary_payload", 8883) is False


def test_audit_single_pcap_fixture():
    """Create a minimal synthetic pcap with 1 TLS packet and audit it."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        tmp_name = f.name
        writer = dpkt.pcap.Writer(f)

        tls_payload = bytes([0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
        tcp = dpkt.tcp.TCP(sport=54321, dport=8883, data=tls_payload)
        tcp.flags = dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK
        ip = dpkt.ip.IP(src=b"\x0a\x00\x01\x0a", dst=b"\x0a\x00\x02\x0a", p=dpkt.ip.IP_PROTO_TCP, data=tcp)
        ip.len = len(ip)
        eth = dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x00" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)

        writer.writepkt(eth, ts=1000.0)
        writer.close()

    try:
        report = audit_single_pcap(tmp_name)
        assert report["packets"] == 1
        assert report["flows"] == 1
        assert report["tls_flows"] == 1
        assert report["tls_share_pct"] == 100.0
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)


def test_cesnet_adapter_canonical_schema_and_warning(tmp_path):
    """A7: Verify CESNET adapter outputs canonical build_early_vector features + metadata and warns on unverified schema."""
    dummy_row = {
        "packets_length": [60, 48, 120, 80],
        "packets_dir": [0, 1, 0, 1],
        "packets_iat": [10.5, 20.2, 15.0],
    }
    res = adapt_cesnet_record(dummy_row, early_n=12)
    assert res["source"] == "real-public-cesnet"
    assert res["label_family"] == "benign"
    assert res["is_attack"] == 0
    assert res["raw_valid_len"] == 4
    assert pytest.approx(res["valid_len"], 0.001) == 4.0 / 12.0
    assert pytest.approx(res["size_0"], 0.001) == 60.0 / 1500.0
    assert pytest.approx(res["size_3"], 0.001) == 80.0 / 1500.0
    assert res["size_4"] == 0.0
    assert res["dir_1"] == 1.0
    assert pytest.approx(res["log_iat_0"], 0.01) == math.log10(1.0 + 10500.0)

    df = pd.DataFrame([res])
    meta_df, x_mat, feat_cols = split_metadata_and_features(df, early_n=12)
    assert x_mat.shape == (1, 44)
    for col in METADATA_COLUMNS:
        assert col in meta_df.columns

    # Verify runtime UNVERIFIED SCHEMA warning when loading file
    csv_path = str(tmp_path / "cesnet_sample.csv")
    pd.DataFrame([{"size_0": 100, "dir_0": 0, "iat_0": 12.0}]).to_csv(csv_path, index=False)
    with pytest.warns(UserWarning, match="UNVERIFIED SCHEMA"):
        load_and_adapt_cesnet(csv_path, early_n=12)


def test_tqh_and_kitsune_canonical_adapters():
    """A7: Verify TQH-C2 D and Kitsune adapters output canonical 3N+8 vector + metadata."""
    tqh_res = adapt_tqh_record({f"size_{i}": 90 for i in range(12)}, early_n=12)
    assert tqh_res["source"] == "real-public-tqh"
    assert tqh_res["session_id"] == "tqh_testbed_d"
    assert tqh_res["label_family"] == "A3_c2"
    assert tqh_res["is_attack"] == 1
    assert pytest.approx(tqh_res["size_0"], 0.001) == 90.0 / 1500.0

    kit_res = adapt_kitsune_record({f"size_{i}": 150 for i in range(12)}, early_n=12)
    assert kit_res["source"] == "real-public-kitsune"
    assert kit_res["label_family"] == "A1_ssl_reneg"
    assert kit_res["is_attack"] == 1
    assert pytest.approx(kit_res["size_0"], 0.001) == 150.0 / 1500.0

    df = pd.DataFrame([tqh_res, kit_res])
    _, x_mat, _ = split_metadata_and_features(df, early_n=12)
    assert x_mat.shape == (2, 44)


def test_iot23_adapter_and_mirai_guard():
    """A3 & A7: Verify IoT-23 benign captures work and CTU-IoT-Malware-Capture-7-1 is rejected as benign."""
    hue_res = adapt_iot23_record({f"size_{i}": 120 for i in range(8)}, early_n=12, capture_name="CTU-Honeypot-Capture-4-1", is_attack=0)
    assert hue_res["source"] == "real-public-iot23"
    assert hue_res["is_attack"] == 0
    assert hue_res["domain"] == "iot23"

    # Attempting to label CTU-IoT-Malware-Capture-7-1 (Linux.Mirai) as benign must fail loudly!
    with pytest.raises(ValueError, match="CRITICAL A3 LABEL VIOLATION"):
        validate_iot23_capture_label("CTU-IoT-Malware-Capture-7-1", is_attack=0)
