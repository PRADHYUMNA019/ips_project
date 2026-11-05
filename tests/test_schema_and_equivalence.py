#!/usr/bin/env python3
"""
tests/test_schema_and_equivalence.py — V1 unit tests for WP6 (schema.py, ebpf/ips_engine.c, equivalence.py).
"""
import os
import json
import socket
import ctypes
import pytest
import dpkt

from ips.engine.schema import (
    SCHEMA_VERSION,
    VERDICT_BYPASS,
    VERDICT_DROP,
    load_system_config,
    generate_c_header,
    make_ctypes_schemas,
    make_flow_key,
    flow_key_to_canonical_tuple,
    event_to_dict,
    ip_to_u32,
)
from ips.eval.equivalence import (
    extract_raw_pcap_flows,
    load_kernel_events_jsonl,
    compare_flows,
    write_equivalence_report,
)


def test_c_header_and_ctypes_sync_across_early_n():
    """Verify changing early_n / checkpoints updates C header macros and ctypes struct sizes consistently (F10, C1)."""
    for n in (4, 8, 12, 16, 24):
        cfg = {"system": {"early_n": n, "flow_map_max": 2048, "verdict_map_max": 4096}}
        hdr = generate_c_header(cfg)
        assert f"#define EARLY_N {n}" in hdr
        assert f"#define EARLY_N_MINUS_1 {n - 1}" in hdr
        assert "#define SCHEMA_VERSION 3" in hdr

        schemas = make_ctypes_schemas(n)
        assert ctypes.sizeof(schemas.FlowKey) == 16
        assert ctypes.sizeof(schemas.VerdictEntry) == 16
        assert ctypes.sizeof(schemas.CfgEntry) == 16
        assert ctypes.sizeof(schemas.StatsEntry) == 56
        # EarlyFlowEvent must be 8-byte aligned for ringbuf_reserve
        assert ctypes.sizeof(schemas.EarlyFlowEvent) % 8 == 0

    default_hdr = generate_c_header()
    assert "#define NUM_CHECKPOINTS 3" in default_hdr
    assert "#define CKPT_0 4" in default_hdr
    assert "#define CKPT_1 8" in default_hdr
    assert "#define CKPT_2 16" in default_hdr
    assert "#define EARLY_N 16" in default_hdr


def test_flow_key_canonical_symmetry():
    """Verify FlowKey produces identical canonical key regardless of packet direction."""
    fk1 = make_flow_key("10.0.1.11", 50123, "10.0.2.10", 8443, "TCP")
    fk2 = make_flow_key("10.0.2.10", 8443, "10.0.1.11", 50123, "TCP")
    assert bytes(fk1) == bytes(fk2)
    tup = flow_key_to_canonical_tuple(fk1)
    assert tup == ("10.0.1.11", 50123, "10.0.2.10", 8443, "TCP")


def test_early_flow_event_roundtrip():
    """Verify EarlyFlowEvent ctypes struct serializes cleanly via event_to_dict."""
    schemas = make_ctypes_schemas(12)
    ev = schemas.EarlyFlowEvent()
    ev.schema_version = SCHEMA_VERSION
    ev.proto = 6
    ev.valid_len = 4
    ev.flags_seen = 0x18
    ev.ip_a = ip_to_u32("10.0.1.11")
    ev.port_a = 49152
    ev.ip_b = ip_to_u32("10.0.2.10")
    ev.port_b = 8883
    ev.initiator_ip = ip_to_u32("10.0.1.11")
    ev.initiator_port = 49152
    ev.total_pkts = 7
    ev.total_bytes = 640
    ev.first_ts_ns = 1_000_000_000
    ev.last_ts_ns = 1_050_000_000

    for i, sz in enumerate([210, 140, 95, 120]):
        ev.sizes[i] = sz
    for i, d in enumerate([0, 1, 0, 1]):
        ev.dirs[i] = d
    for i, dt in enumerate([10_000_000, 15_000_000, 25_000_000]):
        ev.iat_ns[i] = dt

    d = event_to_dict(ev)
    assert d["schema_version"] == 3
    assert d["checkpoint_idx"] == 0
    assert d["proto"] == "TCP"
    assert d["ip_a"] == "10.0.1.11"
    assert d["ip_b"] == "10.0.2.10"
    assert d["sizes"] == [210, 140, 95, 120]
    assert d["dirs"] == [0, 1, 0, 1]
    assert d["iat_ns"] == [10_000_000, 15_000_000, 25_000_000]


def test_equivalence_verifier_pass_and_mismatch(tmp_path):
    """Build a synthetic pcap + kernel JSONL fixture and verify 100% equivalence (N6)."""
    pcap_path = str(tmp_path / "test_equiv.pcap")
    jsonl_path = str(tmp_path / "test_equiv.jsonl")
    report_path = str(tmp_path / "report.md")

    early_n = 6
    flows_spec = [
        ("10.0.1.11", 51001, "10.0.2.10", 8443, [180, 950, 64, 128, 256, 90], [0, 1, 0, 1, 0, 1]),
        ("10.0.1.21", 52002, "10.0.2.10", 8883, [120, 80, 48, 48, 60, 60], [0, 1, 0, 1, 0, 1]),
    ]

    with open(pcap_path, "wb") as pf, open(jsonl_path, "w", encoding="utf-8") as jf:
        writer = dpkt.pcap.Writer(pf)
        base_ts = 1700000000.0
        for f_idx, (lip, lport, wip, wport, sizes, dirs) in enumerate(flows_spec):
            t_cur = base_ts + f_idx * 10.0
            # Pure SYN (0-byte payload, should be ignored by both kernel & offline feature vector)
            syn_tcp = dpkt.tcp.TCP(sport=lport, dport=wport, flags=dpkt.tcp.TH_SYN, data=b"")
            syn_ip = dpkt.ip.IP(src=socket.inet_aton(lip), dst=socket.inet_aton(wip), p=dpkt.ip.IP_PROTO_TCP, data=syn_tcp)
            syn_ip.len = len(syn_ip)
            writer.writepkt(bytes(dpkt.ethernet.Ethernet(data=syn_ip)), ts=t_cur)

            iats_ns = []
            prev_ts_ns = None
            for p_i, (sz, d) in enumerate(zip(sizes, dirs)):
                t_cur += 0.020 * (p_i + 1)
                src = lip if d == 0 else wip
                dst = wip if d == 0 else lip
                sp = lport if d == 0 else wport
                dp = wport if d == 0 else lport
                tcp = dpkt.tcp.TCP(sport=sp, dport=dp, flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, data=b"A" * sz)
                ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=dpkt.ip.IP_PROTO_TCP, data=tcp)
                ip.len = len(ip)
                writer.writepkt(bytes(dpkt.ethernet.Ethernet(data=ip)), ts=t_cur)
                cur_ns = int(round(t_cur * 1e9))
                if prev_ts_ns is not None:
                    iats_ns.append((cur_ns - prev_ts_ns) + 15_000)  # 15 us simulated kernel-vs-libpcap delta
                prev_ts_ns = cur_ns

            ev_obj = {
                "event_type": "EARLY_FLOW",
                "schema_version": 2,
                "ip_a": lip,
                "port_a": lport,
                "ip_b": wip,
                "port_b": wport,
                "proto": "TCP",
                "sizes": sizes,
                "dirs": dirs,
                "iat_ns": iats_ns,
            }
            jf.write(json.dumps(ev_obj) + "\n")

    pcap_flows = extract_raw_pcap_flows(pcap_path, early_n=early_n)
    kern_events = load_kernel_events_jsonl(jsonl_path)
    metrics = compare_flows(pcap_flows, kern_events, early_n=early_n)
    write_equivalence_report(metrics, report_path)

    assert metrics["matched_flows"] == 2
    assert metrics["size_exact_match_rate"] == 1.0
    assert metrics["dir_exact_match_rate"] == 1.0
    assert metrics["iat_diff_p99_us"] == pytest.approx(15.0, abs=1.0)
    assert metrics["passed"] is True
    assert os.path.exists(report_path)

    # Corrupt one size and verify equivalence fails
    kern_events[0]["sizes"][0] = 999
    bad_metrics = compare_flows(pcap_flows, kern_events, early_n=early_n)
    assert bad_metrics["size_exact_match_rate"] == 0.5
    assert bad_metrics["passed"] is False


def test_ebpf_c_sources_present_and_valid():
    """Static verification of ebpf/ips_engine.c and ebpf/xdp_v1.c (F11)."""
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    v2_path = os.path.join(repo_root, "ebpf", "ips_engine.c")
    v1_path = os.path.join(repo_root, "ebpf", "xdp_v1.c")
    assert os.path.exists(v2_path)
    assert os.path.exists(v1_path)

    with open(v2_path, "r", encoding="utf-8") as f:
        src = f.read()
    for token in ("verdict_map", "flow_state", "tier0_map", "cfg_map", "stats_map", "BPF_RINGBUF_OUTPUT", "xdp_ips_prog", "emitted_mask", "checkpoint_idx"):
        assert token in src


def test_multi_checkpoint_equivalence():
    """C1 / N6: Verify per-checkpoint equivalence across checkpoints [4, 8, 16] and short flows ending at 6."""
    sizes_16 = [100 + i * 10 for i in range(16)]
    dirs_16 = [i % 2 for i in range(16)]
    iats_15 = [10_000_000] * 15

    # Flow 1: reaches all 3 checkpoints (4, 8, 16)
    pf_full = {
        "ip_a": "10.0.1.11", "port_a": 50001, "ip_b": "10.0.2.10", "port_b": 8443, "proto": "TCP",
        "sizes": sizes_16, "dirs": dirs_16, "iat_ns": iats_15, "valid_len": 16,
    }
    # Flow 2: short flow of 6 packets, only reaches checkpoint 4
    pf_short = {
        "ip_a": "10.0.1.21", "port_a": 50002, "ip_b": "10.0.2.10", "port_b": 8883, "proto": "TCP",
        "sizes": sizes_16[:6], "dirs": dirs_16[:6], "iat_ns": iats_15[:5], "valid_len": 6,
    }

    kernel_events = [
        # Flow 1 checkpoints: 4, 8, 16
        {
            "ip_a": "10.0.1.11", "port_a": 50001, "ip_b": "10.0.2.10", "port_b": 8443, "proto": "TCP",
            "valid_len": 4, "checkpoint_idx": 0,
            "sizes": sizes_16[:4], "dirs": dirs_16[:4], "iat_ns": iats_15[:3],
        },
        {
            "ip_a": "10.0.1.11", "port_a": 50001, "ip_b": "10.0.2.10", "port_b": 8443, "proto": "TCP",
            "valid_len": 8, "checkpoint_idx": 1,
            "sizes": sizes_16[:8], "dirs": dirs_16[:8], "iat_ns": iats_15[:7],
        },
        {
            "ip_a": "10.0.1.11", "port_a": 50001, "ip_b": "10.0.2.10", "port_b": 8443, "proto": "TCP",
            "valid_len": 16, "checkpoint_idx": 2,
            "sizes": sizes_16[:16], "dirs": dirs_16[:16], "iat_ns": iats_15[:15],
        },
        # Flow 2 checkpoint: 4 only (short flow ends at 6)
        {
            "ip_a": "10.0.1.21", "port_a": 50002, "ip_b": "10.0.2.10", "port_b": 8883, "proto": "TCP",
            "valid_len": 4, "checkpoint_idx": 0,
            "sizes": sizes_16[:4], "dirs": dirs_16[:4], "iat_ns": iats_15[:3],
        },
    ]

    metrics = compare_flows([pf_full, pf_short], kernel_events, early_n=16)
    assert metrics["passed"] is True
    assert metrics["matched_flows"] == 4
    assert metrics["per_checkpoint"]["4"]["matched_events"] == 2
    assert metrics["per_checkpoint"]["8"]["matched_events"] == 1
    assert metrics["per_checkpoint"]["16"]["matched_events"] == 1
    assert metrics["per_checkpoint"]["4"]["size_exact_match_rate"] == 1.0
    assert metrics["per_checkpoint"]["8"]["size_exact_match_rate"] == 1.0
    assert metrics["per_checkpoint"]["16"]["size_exact_match_rate"] == 1.0

