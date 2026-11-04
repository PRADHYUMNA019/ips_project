#!/usr/bin/env python3
"""
tests/test_dataset_adapters.py — Unit tests for dataset adapters and audit_pcap.py.
"""
import io
import os
import sys
import tempfile
import pytest
import dpkt

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_DIR)

from datasets.audit_pcap import is_tls_handshake, is_plaintext_marker, audit_single_pcap
from datasets.adapters.cesnet_adapter import adapt_cesnet_record
from datasets.adapters.tqh_adapter import adapt_tqh_record
from datasets.adapters.kitsune_adapter import adapt_kitsune_record


def test_tls_handshake_detector():
    """Verify TLS 1.0 - 1.3 handshake record header identification."""
    # 0x16 (Handshake), 0x03 (Major), 0x03 (TLS 1.2), 0x00 0x10 (Length)
    valid_tls_12 = bytes([0x16, 0x03, 0x03, 0x00, 0x10]) + b"ClientHelloData"
    assert is_tls_handshake(valid_tls_12) is True

    valid_tls_13 = bytes([0x16, 0x03, 0x01, 0x00, 0x20]) + b"InitialHandshake"
    assert is_tls_handshake(valid_tls_13) is True

    # Plain text HTTP
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert is_tls_handshake(http_payload) is False

    # Empty or short
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
    # Construct a small pcap using dpkt
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        tmp_name = f.name
        writer = dpkt.pcap.Writer(f)

        # Build Ethernet + IP + TCP + TLS ClientHello
        tls_payload = bytes([0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
        tcp = dpkt.tcp.TCP(sport=54321, dport=8883, data=tls_payload)
        tcp.flags = dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK
        ip = dpkt.ip.IP(src=b"\x0a\x00\x01\x0a", dst=b"\x0a\x00\x02\x0a", p=dpkt.ip.IP_PROTO_TCP, data=tcp)
        ip.len = len(ip)
        eth = dpkt.ethernet.Ethernet(src=b"\x00"*6, dst=b"\x00"*6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)

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


def test_cesnet_adapter_schema():
    """Verify CESNET adapter outputs standard early-flow schema."""
    dummy_row = {
        "packets_length": [60, 48, 120, 80],
        "packets_dir": [0, 1, 0, 1],
        "packets_iat": [10.5, 20.2, 15.0],
    }
    res = adapt_cesnet_record(dummy_row, early_n=12)
    assert res["source"] == "real-public-cesnet"
    assert res["label_family"] == "benign"
    assert res["is_attack"] == 0
    assert res["early_n"] == 12
    assert res["valid_len"] == 4
    assert res["size_0"] == 60
    assert res["size_3"] == 80
    assert res["size_4"] == 0  # padded
    assert res["dir_1"] == 1
    assert res["iat_0"] == 10.5


def test_tqh_adapter_schema():
    """Verify TQH adapter outputs standard early-flow schema."""
    dummy_row = {f"size_{i}": 85 for i in range(12)}
    res = adapt_tqh_record(dummy_row, early_n=12)
    assert res["source"] == "real-public-tqh"
    assert res["label_family"] == "A3_c2"
    assert res["is_attack"] == 1
    assert res["encrypted"] is True
    assert res["split_hint"] == "test-zeroday"


def test_kitsune_adapter_schema():
    """Verify Kitsune adapter outputs standard early-flow schema."""
    dummy_row = {f"size_{i}": 150 for i in range(12)}
    res = adapt_kitsune_record(dummy_row, early_n=12)
    assert res["source"] == "real-public-kitsune"
    assert res["label_family"] == "A1_ssl_reneg"
    assert res["is_attack"] == 1
    assert res["split_hint"] == "test-zeroday"
