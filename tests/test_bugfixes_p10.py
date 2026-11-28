#!/usr/bin/env python3
"""
tests/test_bugfixes_p10.py — RED -> GREEN regression tests for bugs found in Prompt 10 Phase 1.

Covers:
  - BUG-01: Silent all-ones fallback in build_valid_mask_matrix + 0-length flow & ablated matrix handling
  - BUG-02: Unbounded map growth and missing Tier-0 SYN token bucket in MockBPFBackend
  - BUG-03: Device ID/IP mismatch between ips/smoke/synth.py and configs/devices.yaml + ignored out_parquet
  - BUG-04: Silent except-pass in IPSEngine._load_model_and_thresholds and unused reason in _handle_schema_mismatch
  - BUG-05: Unchecked URL scheme in datasets/download_tqh_c2_win.py::download_resumable (Bandit B310)
  - BUG-06: Duplicate C constants instead of single-source ebpf/generated_constants.h + automated C struct parser
  - BUG-07: Non-initial IPv4 fragments misparsed as TCP/UDP headers in pcap_to_flows.py & ebpf/ips_engine.c + packet conservation stats
"""

from __future__ import annotations

import ctypes
import os
import socket
from pathlib import Path

import dpkt
import numpy as np
import pytest
import yaml

from datasets.download_tqh_c2_win import download_resumable
from ips.engine.engine import IPSEngine, MockBPFBackend
from ips.engine.schema import make_flow_key
from ips.features import build_early_vector, build_valid_mask_matrix
from ips.offline.pcap_to_flows import extract_flows_from_pcap
from ips.smoke.synth import generate_smoke_dataset

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_bug01_build_valid_mask_raises_on_invalid_and_masks_zero_len():
    """BUG-01: build_valid_mask_matrix must raise ValueError on invalid dims/valid_len and mask 0-pkt vectors."""
    # 1. Invalid feature dimension (16 != 3N+8) must raise ValueError, not silently return ones
    bad_dim = np.ones((2, 16), dtype=np.float32)
    with pytest.raises(ValueError, match="3\\*N \\+ 8"):
        build_valid_mask_matrix(bad_dim)

    # 2. Out-of-range valid_len (> 1.0001 or < 0.0 or NaN) must raise ValueError
    bad_vlen = np.ones((2, 20), dtype=np.float32)  # 3*4 + 8 = 20
    bad_vlen[0, -1] = 1.5
    with pytest.raises(ValueError, match="valid_len"):
        build_valid_mask_matrix(bad_vlen)

    neg_vlen = np.ones((20,), dtype=np.float32)
    neg_vlen[-1] = -0.1
    with pytest.raises(ValueError, match="valid_len"):
        build_valid_mask_matrix(neg_vlen)

    # 3. Empty 0-payload flow (valid_len == 0.0) must mask all 3N-1 per-packet slots to 0.0
    zero_vec = build_early_vector([], [], [], early_n=4)
    assert zero_vec[-1] == 0.0
    mask0 = build_valid_mask_matrix(zero_vec)
    assert np.all(mask0[:11] == 0.0), "All size_0..3, dir_0..3, log_iat_0..2 slots must be masked for 0-pkt flow"
    assert np.all(mask0[11:] == 1.0), "Aggregate slots remain active"


def test_bug02_mock_backend_lru_capacity_and_tier0_syn_bucket():
    """BUG-02: MockBPFBackend must enforce LRU capacity caps and Tier-0 SYN token-bucket rate limiting."""
    backend = MockBPFBackend(early_n=4, checkpoints=[4], flow_map_max=12, verdict_map_max=8)
    backend.cfg["tier0_enabled"] = 1
    backend.cfg["tier0_rate"] = 10
    backend.cfg["tier0_capacity"] = 5

    t0 = 1_000_000_000
    # 1. Insert 30 distinct flows and 20 verdicts -> maps must never exceed configured max capacity
    for i in range(30):
        sport = 40000 + i
        backend.simulate_packet("10.0.1.10", sport, "10.0.2.10", 8883, "TCP", 64, 0, t0 + i * 1000)
        if i < 20:
            fk = make_flow_key("10.0.1.10", sport, "10.0.2.10", 8883, "TCP")
            backend.set_verdict(fk, 1, t0 + 60_000_000_000)

    assert len(backend.flow_state) <= 12, f"flow_state grew to {len(backend.flow_state)} > flow_map_max=12"
    assert len(backend.verdict_map) <= 8, f"verdict_map grew to {len(backend.verdict_map)} > verdict_map_max=8"

    # 2. Burst of 10 pure SYNs from 10.0.1.4 at same timestamp with capacity=5 -> must trigger Tier-0 XDP_DROP
    actions = []
    for i in range(10):
        act, _ = backend.simulate_packet(
            "10.0.1.4", 50000 + i, "10.0.2.10", 8443, "TCP", 0, 0, t0 + 1_000_000, tcp_flags=0x02, is_syn_only=True
        )
        actions.append(act)
    assert "XDP_DROP" in actions
    assert backend.stats["pkts_dropped_tier0"] >= 5


def test_bug03_synth_matches_devices_yaml_and_writes_parquet(tmp_path):
    """BUG-03: synth.py must use exact device_ids and IPs from configs/devices.yaml and honour out_parquet."""
    with open(REPO_ROOT / "configs" / "devices.yaml", encoding="utf-8") as f:
        dev_cfg = yaml.safe_load(f)
    yaml_id_to_ip = {d["device_id"]: str(d["ip"]) for d in dev_cfg["devices"]}

    pq_path = tmp_path / "smoke_out.parquet"
    csv_path = tmp_path / "smoke_out.csv"
    df = generate_smoke_dataset(
        n_benign=80,
        n_attack=20,
        early_n=8,
        session_id="test_bug03",
        out_csv=str(csv_path),
        out_parquet=str(pq_path),
        seed=42,
    )
    assert pq_path.exists(), "generate_smoke_dataset ignored out_parquet parameter"

    benign_df = df[df["is_attack"] == 0]
    for _, row in benign_df.iterrows():
        did = str(row["device_id"])
        sip = str(row["src_ip"])
        assert did in yaml_id_to_ip, f"Generated device_id '{did}' missing from configs/devices.yaml"
        assert sip == yaml_id_to_ip[did], f"IP mismatch for {did}: synth={sip} vs yaml={yaml_id_to_ip[did]}"


def test_bug04_engine_logs_corrupt_card_and_schema_mismatch_reason(tmp_path):
    """BUG-04: IPSEngine must record load warnings on corrupt model_card and record schema mismatch reasons."""
    bad_card = tmp_path / "corrupt_card.json"
    bad_card.write_text("{not valid json", encoding="utf-8")

    cfg = {
        "system": {"early_n": 8, "checkpoints": [4, 8]},
        "engine": {"model_card": str(bad_card)},
    }
    engine = IPSEngine(config=cfg, backend=MockBPFBackend(early_n=8, checkpoints=[4, 8]))
    assert len(engine.load_warnings) >= 1
    assert any("corrupt_card.json" in w or "JSON" in w or "Expecting" in w for w in engine.load_warnings)

    short_buf = ctypes.create_string_buffer(8)
    res = engine.parse_ringbuf_event(short_buf, 8)
    assert res is None
    assert len(engine.schema_mismatch_reasons) == 1
    assert "Buffer size 8" in engine.schema_mismatch_reasons[0]


def test_bug05_downloader_rejects_non_https_schemes(tmp_path):
    """BUG-05: download_resumable must reject file:// and http:// URLs (Bandit B310)."""
    dest = str(tmp_path / "blocked.bin")
    with pytest.raises(ValueError, match=r"(?i)https"):
        download_resumable("file:///C:/Windows/win.ini", dest)
    with pytest.raises(ValueError, match=r"(?i)https"):
        download_resumable("http://zenodo.org/records/21523144/files/README_v120.md", dest)
    assert not os.path.exists(dest)


def test_bug06_generated_constants_header_and_c_struct_parser_sync():
    """BUG-06: ebpf/generated_constants.h must exist, be included by ips_engine.c, and match C struct parser."""
    from ips.engine.c_struct_parser import verify_all_c_structs_match_ctypes
    from ips.engine.schema import generate_c_header

    gen_h = REPO_ROOT / "ebpf" / "generated_constants.h"
    assert gen_h.exists(), "ebpf/generated_constants.h missing"
    assert gen_h.read_text(encoding="utf-8") == generate_c_header(), "ebpf/generated_constants.h out of sync with schema.py"

    c_src = (REPO_ROOT / "ebpf" / "ips_engine.c").read_text(encoding="utf-8")
    assert '#include "generated_constants.h"' in c_src

    report = verify_all_c_structs_match_ctypes(early_n=16)
    assert report["passed"] is True, f"C struct layout mismatch: {report}"


def test_bug07_pcap_fragment_guard_and_packet_conservation(tmp_path):
    """BUG-07: Non-initial IPv4 fragments must not be parsed as TCP/UDP headers, and packet counts must conserve."""
    pcap_path = tmp_path / "mixed_frags.pcap"
    with open(pcap_path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        # 1. Valid UDP packet (port 53000 -> 443, 64B payload)
        udp1 = dpkt.udp.UDP(sport=53000, dport=443, data=b"Q" * 64)
        udp1.ulen = len(udp1)
        ip1 = dpkt.ip.IP(src=socket.inet_aton("10.0.1.10"), dst=socket.inet_aton("10.0.2.10"), p=dpkt.ip.IP_PROTO_UDP, data=udp1)
        ip1.len = len(ip1)
        writer.writepkt(bytes(dpkt.ethernet.Ethernet(data=ip1)), ts=100.0)

        # 2. Non-initial IPv4 UDP fragment (frag offset = 1480B; payload has arbitrary bytes, NOT a UDP header!)
        ip_frag = dpkt.ip.IP(
            src=socket.inet_aton("10.0.1.10"),
            dst=socket.inet_aton("10.0.2.10"),
            p=dpkt.ip.IP_PROTO_UDP,
            offset=1480,  # non-zero fragment byte offset!
            data=b"\x12\x34\x56\x78\x00\x20\x00\x00" + b"F" * 24,
        )
        ip_frag.len = 20 + 32
        writer.writepkt(bytes(dpkt.ethernet.Ethernet(data=ip_frag)), ts=100.01)

        # 3. ARP frame
        arp = dpkt.arp.ARP()
        writer.writepkt(bytes(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_ARP, data=arp)), ts=100.02)

        # 4. IPv6 frame
        ip6 = dpkt.ip6.IP6(src=b"\x00" * 16, dst=b"\x00" * 16, nxt=17, data=b"V" * 16)
        writer.writepkt(bytes(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP6, data=ip6)), ts=100.03)
        writer.close()

    df = extract_flows_from_pcap(str(pcap_path), early_n=8)
    assert len(df) == 1, f"Non-initial IPv4 fragment spawned bogus flow(s): got {len(df)} flows"
    stats = df.attrs.get("packet_stats")
    assert stats is not None, "df.attrs['packet_stats'] missing"
    assert stats["total_packets"] == 4
    assert stats["assigned_packets"] == 1
    assert stats["skipped"]["ip_fragment"] == 1
    assert stats["assigned_packets"] + sum(stats["skipped"].values()) == stats["total_packets"]

    c_src = (REPO_ROOT / "ebpf" / "ips_engine.c").read_text(encoding="utf-8")
    assert "frag_off" in c_src, "ebpf/ips_engine.c does not guard against non-initial IPv4 fragments"


def test_bug08_train_cli_model_dir_and_seed_determinism(tmp_path):
    """BUG-08 & §1.4: train.py CLI accepts --model-dir, and seeded runs produce byte-identical outputs."""
    import subprocess
    import sys
    from ips.drift.evasion_cost import run_cost_of_evasion_experiment

    d1 = tmp_path / "run1"
    d2 = tmp_path / "run2"
    d1.mkdir()
    d2.mkdir()

    c1 = d1 / "smoke.csv"
    c2 = d2 / "smoke.csv"
    generate_smoke_dataset(n_benign=60, n_attack=15, early_n=8, session_id="det_s", out_csv=str(c1), seed=77)
    generate_smoke_dataset(n_benign=60, n_attack=15, early_n=8, session_id="det_s", out_csv=str(c2), seed=77)
    assert c1.read_bytes() == c2.read_bytes(), "generate_smoke_dataset is not byte-identical across identical seeds"

    e1 = d1 / "ev1"
    e2 = d2 / "ev2"
    run_cost_of_evasion_experiment(out_dir=str(e1), budget_q=40, is_smoke=True, seed=77)
    run_cost_of_evasion_experiment(out_dir=str(e2), budget_q=40, is_smoke=True, seed=77)
    assert (e1 / "evasion_cost_curve.csv").read_bytes() == (e2 / "evasion_cost_curve.csv").read_bytes()

    m_dir = tmp_path / "cli_models"
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "ips" / "models" / "train.py"),
            "--data",
            str(c1),
            "--early-n",
            "8",
            "--epochs",
            "2",
            "--seed",
            "42",
            "--model-dir",
            str(m_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"train.py --model-dir failed: {proc.stderr}"
    assert (m_dir / "model_card.json").exists()
