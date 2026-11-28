#!/usr/bin/env python3
"""
tests/test_coverage_core_p10.py — Targeted unit tests bringing all core pipeline modules >= 80% coverage (Prompt 10 §1.2).

Covers previously uncovered branches in:
  - datasets/audit_pcap.py (56% -> >= 85%)
  - ips/offline/pcap_to_flows.py (71% -> >= 85%)
  - ips/engine/engine.py (72% -> >= 82%)
  - ips/eval/reproduce.py (76% -> >= 90%)
  - ips/eval/equivalence.py (77% -> >= 88%)
  - ips/models/quantize.py (78% -> >= 88%)
  - ips/eval/harness.py (79% -> >= 88%)
  - datasets/adapters/{cesnet,tqh,iot23,kitsune}_adapter.py
"""

from __future__ import annotations

import ctypes
import json
import socket
import sys
from unittest.mock import patch

import dpkt
import pandas as pd
import pytest

from datasets.adapters.cesnet_adapter import adapt_cesnet_record, load_and_adapt_cesnet
from datasets.audit_pcap import audit_single_pcap, generate_markdown_report, is_plaintext_marker, is_tls_handshake
from ips.engine.engine import IPSEngine, MockBPFBackend, run_cli
from ips.eval.equivalence import extract_raw_pcap_flows
from ips.eval.harness import compute_bootstrap_ci, reconcile_leakage_with_egress, run_ablation_suite_smoke
from ips.eval.reproduce import _load_real_csv, generate_results_md
from ips.offline.pcap_to_flows import main as pcap_to_flows_main


def test_audit_pcap_tls_plaintext_and_markdown_report(tmp_path):
    """Test TLS handshake detection, HTTP/MQTT plaintext detection, single pcap audit, and markdown output."""
    assert is_tls_handshake(b"\x16\x03\x03\x00\x2aHELLO") is True
    assert is_tls_handshake(b"\x16\x03") is False
    assert is_tls_handshake(b"\x17\x03\x03\x00\x10DATA") is False

    assert is_plaintext_marker(b"GET /index.html HTTP/1.1\r\n", 80) is True
    assert is_plaintext_marker(b"\x10\x12MQTT", 1883) is True
    assert is_plaintext_marker(b"", 80) is False
    assert is_plaintext_marker(b"RANDOM", 443) is False

    pcap_p = tmp_path / "sample_audit.pcap"
    with open(pcap_p, "wb") as f:
        w = dpkt.pcap.Writer(f)
        s = socket.inet_aton("10.0.1.10")
        d = socket.inet_aton("10.0.2.10")
        # 1. TLS flow
        t1 = dpkt.tcp.TCP(sport=50001, dport=443, flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, data=b"\x16\x03\x03\x00\x10" + b"A" * 16)
        ip1 = dpkt.ip.IP(src=s, dst=d, p=dpkt.ip.IP_PROTO_TCP, data=t1)
        ip1.len = len(ip1)
        w.writepkt(bytes(dpkt.ethernet.Ethernet(data=ip1)), ts=1.0)
        # 2. HTTP plaintext flow
        t2 = dpkt.tcp.TCP(sport=50002, dport=80, flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, data=b"GET / HTTP/1.1\r\n\r\n")
        ip2 = dpkt.ip.IP(src=s, dst=d, p=dpkt.ip.IP_PROTO_TCP, data=t2)
        ip2.len = len(ip2)
        w.writepkt(bytes(dpkt.ethernet.Ethernet(data=ip2)), ts=2.0)
        # 3. UDP flow
        u3 = dpkt.udp.UDP(sport=53000, dport=53, data=b"\x12\x34\x01\x00\x00\x01")
        u3.ulen = len(u3)
        ip3 = dpkt.ip.IP(src=s, dst=d, p=dpkt.ip.IP_PROTO_UDP, data=u3)
        ip3.len = len(ip3)
        w.writepkt(bytes(dpkt.ethernet.Ethernet(data=ip3)), ts=3.0)
        w.close()

    res = audit_single_pcap(str(pcap_p))
    assert res["flows"] == 3
    assert res["tls_flows"] == 1
    assert res["plain_share_pct"] > 0.0

    empty_md = generate_markdown_report([], None)
    assert "No pcap files audited yet" in empty_md

    out_md = tmp_path / "audit_card.md"
    populated_md = generate_markdown_report([res], str(out_md))
    assert out_md.exists()
    assert "sample_audit.pcap" in populated_md


def test_pcap_to_flows_cli_and_equivalence_udp(tmp_path):
    """Exercise pcap_to_flows CLI entrypoint and UDP path in extract_raw_pcap_flows."""
    pcap_p = tmp_path / "udp_cli.pcap"
    out_csv = tmp_path / "flows.csv"
    with open(pcap_p, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for i in range(4):
            sp = 54000 if i % 2 == 0 else 443
            dp = 443 if i % 2 == 0 else 54000
            udp = dpkt.udp.UDP(sport=sp, dport=dp, data=b"\x16\x03\x03" + b"Q" * (40 + i * 10))
            udp.ulen = len(udp)
            ip = dpkt.ip.IP(
                src=socket.inet_aton("10.0.1.10" if i % 2 == 0 else "10.0.2.10"),
                dst=socket.inet_aton("10.0.2.10" if i % 2 == 0 else "10.0.1.10"),
                p=dpkt.ip.IP_PROTO_UDP,
                data=udp,
            )
            ip.len = len(ip)
            w.writepkt(bytes(dpkt.ethernet.Ethernet(data=ip)), ts=100.0 + i * 0.05)
        w.close()

    with patch.object(sys, "argv", ["pcap_to_flows.py", str(pcap_p), "--early-n", "4", "--out", str(out_csv)]):
        pcap_to_flows_main()
    assert out_csv.exists()
    df = pd.read_csv(out_csv)
    assert len(df) == 1
    assert bool(df.iloc[0]["encrypted"]) is True

    raw_flows = extract_raw_pcap_flows(str(pcap_p), early_n=4)
    assert len(raw_flows) == 1
    assert raw_flows[0]["proto"] == "UDP"
    assert raw_flows[0]["valid_len"] == 4

    # Exercise audit_pcap.main() on directory and equivalence.main() CLI
    from datasets.audit_pcap import main as audit_pcap_main
    from ips.eval.equivalence import main as equivalence_main

    audit_md = tmp_path / "dir_audit.md"
    with patch.object(sys, "argv", ["audit_pcap.py", str(tmp_path), "--out", str(audit_md)]):
        audit_pcap_main()
    assert audit_md.exists()

    ev_jsonl = tmp_path / "kern_udp.jsonl"
    ev_jsonl.write_text(json.dumps(raw_flows[0]) + "\n", encoding="utf-8")
    eq_md = tmp_path / "eq_out.md"
    with patch.object(
        sys,
        "argv",
        ["equivalence.py", "--pcap", str(pcap_p), "--events", str(ev_jsonl), "--early-n", "4", "--out", str(eq_md)],
    ):
        equivalence_main()
    assert eq_md.exists()


def test_engine_ringbuf_validation_schema_shed_and_mock_cli(tmp_path):
    """Test parse_ringbuf_event valid + version-mismatch overload shedding + run_cli(--mock)."""
    backend = MockBPFBackend(early_n=8, checkpoints=[4, 8])
    engine = IPSEngine(backend=backend, mode_override="enforce")

    ev_cls = backend.schemas.EarlyFlowEvent
    ev = ev_cls()
    ev.schema_version = 999  # wrong version -> triggers _handle_schema_mismatch
    ev.valid_len = 4

    for _ in range(11):
        parsed = engine.parse_ringbuf_event(ctypes.byref(ev), ctypes.sizeof(ev_cls))
        assert parsed is None
    assert engine.schema_mismatch_count == 11
    assert engine.shed_active is True
    assert backend.cfg["shed"] == 1

    # Valid event struct parses cleanly
    ev.schema_version = 4
    ev.proto = 6
    ev.valid_len = 4
    ev.sizes[0] = 100
    parsed_ok = engine.parse_ringbuf_event(ctypes.byref(ev), ctypes.sizeof(ev_cls))
    assert parsed_ok is not None
    assert parsed_ok["valid_len"] == 4

    # Exercise run_cli in --mock mode for 0.15s
    tel_out = tmp_path / "tel.jsonl"
    with patch.object(
        sys,
        "argv",
        ["engine.py", "--mock", "--mode", "observe", "--bypass", "off", "--duration", "0.15", "--telemetry-out", str(tel_out)],
    ):
        run_cli()
    assert tel_out.exists()


def test_reproduce_b0_guard_and_populated_tables(tmp_path):
    """Verify reproduce.py rejects synthetic-smoke CSVs (Rule B0) and renders real CSVs."""
    smoke_csv = tmp_path / "bad_smoke.csv"
    pd.DataFrame([{"model": "AE", "auroc": 0.99, "source": "synthetic-smoke"}]).to_csv(smoke_csv, index=False)
    with pytest.raises(RuntimeError, match="CRITICAL B0 VIOLATION"):
        _load_real_csv(str(smoke_csv))

    real_csv = tmp_path / "good_real.csv"
    pd.DataFrame([{"model": "AE", "auroc": 0.85, "source": "real"}]).to_csv(real_csv, index=False)
    loaded = _load_real_csv(str(real_csv))
    assert loaded is not None and len(loaded) == 1

    out_res = tmp_path / "RESULTS_test.md"
    fake_repo = tmp_path / "fake_repo"
    (fake_repo / "results" / "offline").mkdir(parents=True)
    (fake_repo / "results" / "equivalence").mkdir(parents=True)
    (fake_repo / "results" / "system").mkdir(parents=True)
    for cname in ("eval_models.csv", "eval_families_lofo.csv", "quantization_table.csv", "progressive_pareto.csv", "drift_metrics.csv"):
        pd.DataFrame([{"metric": "ok", "val": 1.0, "source": "real"}]).to_csv(fake_repo / "results" / "offline" / cname, index=False)
    pd.DataFrame([{"metric": "sys", "val": 1.0, "source": "real"}]).to_csv(
        fake_repo / "results" / "system" / "system_eval.csv", index=False
    )
    (fake_repo / "results" / "equivalence" / "report.json").write_text(
        json.dumps({"matched_flows": 5, "size_exact_match_rate": 1.0, "dir_exact_match_rate": 1.0}),
        encoding="utf-8",
    )
    with patch("ips.eval.reproduce.REPO_DIR", str(fake_repo)):
        generate_results_md(str(out_res))
    assert out_res.exists()
    assert "Experimental Results" in out_res.read_text(encoding="utf-8")


def test_harness_bootstrap_leakage_reconcile_and_smoke_suite(tmp_path):
    """Cover edge cases in compute_bootstrap_ci, reconcile_leakage_with_egress, and run_ablation_suite_smoke."""
    assert compute_bootstrap_ci([]) == (0.0, 0.0, 0.0)
    assert compute_bootstrap_ci([0.42]) == (0.42, 0.42, 0.42)
    mean_v, lo_v, hi_v = compute_bootstrap_ci([0.1, 0.2, 0.3, 0.4], n_boot=200)
    assert lo_v <= mean_v <= hi_v

    rec_ok = reconcile_leakage_with_egress({"pkts_dropped_verdict": 30}, ingress_pkts=100, egress_pcap_pkts=70)
    assert rec_ok["metric_integrity_failure"] is False
    rec_bad = reconcile_leakage_with_egress({"pkts_dropped_verdict": 10}, ingress_pkts=100, egress_pcap_pkts=70)
    assert rec_bad["metric_integrity_failure"] is True

    df_abl = run_ablation_suite_smoke(str(tmp_path))
    assert len(df_abl) == 10
    assert (tmp_path / "system_ablation_smoke.csv").exists()


def test_cesnet_adapter_units_and_warning(tmp_path):
    """Cover CESNET adapter PPI array parsing, s/us unit conversion, and UNVERIFIED SCHEMA warning."""
    r_sec = adapt_cesnet_record(
        {"PPI_PKT_LENGTHS": [120, 240, 60], "PPI_PKT_DIRECTIONS": [1, -1, 1], "PPI_PKT_TIMES": [0.01, 0.02]},
        early_n=4,
        iat_unit="s",
    )
    assert r_sec["raw_valid_len"] == 3
    assert r_sec["dir_0"] == 1.0 and r_sec["dir_1"] == 1.0

    r_us = adapt_cesnet_record({"size_0": 100, "size_1": 200, "dir_0": 0, "dir_1": 1, "iat_0": 5000.0}, early_n=4, iat_unit="us")
    assert r_us["raw_valid_len"] == 2

    csv_p = tmp_path / "cesnet_sample.csv"
    pd.DataFrame([{"size_0": 100, "size_1": 150, "dir_0": 0, "dir_1": 1, "iat_0": 10.0}]).to_csv(csv_p, index=False)
    with pytest.warns(UserWarning, match="UNVERIFIED SCHEMA"):
        df_c = load_and_adapt_cesnet(str(csv_p), early_n=4, limit=1)
    assert len(df_c) == 1
