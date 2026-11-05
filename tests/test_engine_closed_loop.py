#!/usr/bin/env python3
"""
tests/test_engine_closed_loop.py — V1 unit tests for WP7 (ips/engine/engine.py and ips/eval/harness.py).
"""
import pytest
from ips.engine.schema import (
    load_system_config,
    make_flow_key,
    VERDICT_NONE,
    VERDICT_BYPASS,
    VERDICT_DROP,
)
from ips.engine.engine import IPSEngine, MockBPFBackend
from ips.eval.harness import (
    compute_bootstrap_ci,
    compute_attack_leakage,
    simulate_closed_loop_workload,
)


def test_observe_vs_enforce_and_explainability():
    """Verify observe mode logs decisions + top-3 features without inserting kernel verdicts."""
    cfg = load_system_config()
    cfg["system"]["early_n"] = 6
    backend = MockBPFBackend(early_n=6)
    engine = IPSEngine(config=cfg, backend=backend, mode_override="observe", bypass_override=True)
    engine.ort_session = None
    engine.threshold = 0.05

    ev = {
        "ip_a": "10.0.1.4",
        "port_a": 55100,
        "ip_b": "10.0.2.10",
        "port_b": 8443,
        "proto": "TCP",
        "initiator_ip": "10.0.1.4",
        "valid_len": 6,
        "total_pkts": 8,
        "first_ts_ns": 1_000_000_000,
        "last_ts_ns": 1_000_300_000,
        "sizes": [1400] * 6,
        "dirs": [0] * 6,
        "iat_ns": [50_000] * 5,
    }
    dec = engine.handle_early_flow_event(ev, now_ns=1_000_500_000)
    assert dec["is_anomaly"] is True
    assert dec["verdict_written"] == "NONE"
    assert dec["payload_packets_at_verdict"] == 6
    assert dec["time_to_verdict_ms"] >= 0.3
    assert len(dec["top_3_features"]) == 3
    assert len(backend.verdict_map) == 0


def test_enforce_per_flow_drop_and_ttl_expiry():
    """Verify per-5-tuple DROP blocks only the offending flow and expires after drop_ttl_s."""
    cfg = load_system_config()
    cfg["system"]["early_n"] = 4
    cfg["system"]["drop_ttl_s"] = 10
    backend = MockBPFBackend(early_n=4)
    engine = IPSEngine(config=cfg, backend=backend, mode_override="enforce", bypass_override=True)
    engine.ort_session = None
    engine.threshold = 0.08

    now_ns = 1_000_000_000
    # Send 4 attack packets on port 50001 -> triggers EARLY_FLOW and DROP verdict
    for i in range(4):
        now_ns += 40_000
        act, ev = backend.simulate_packet("10.0.1.4", 50001, "10.0.2.10", 8443, "TCP", 1400, 0, now_ns)
        assert act == "XDP_PASS"
        if ev is not None:
            dec = engine.handle_early_flow_event(ev, now_ns=now_ns)
            assert dec["verdict_written"] == "DROP"

    # Packet 5 on port 50001 must be dropped in XDP
    act5, _ = backend.simulate_packet("10.0.1.4", 50001, "10.0.2.10", 8443, "TCP", 1400, 0, now_ns + 100_000)
    assert act5 == "XDP_DROP"

    # Concurrent flow from same IP on port 50002 must NOT be dropped (per-5-tuple isolation!)
    act_other, _ = backend.simulate_packet("10.0.1.4", 50002, "10.0.2.10", 8443, "TCP", 120, 0, now_ns + 100_000)
    assert act_other == "XDP_PASS"

    # Advance past 10s TTL -> port 50001 verdict expires and passes again
    after_ttl_ns = now_ns + int(11 * 1e9)
    act_expired, _ = backend.simulate_packet("10.0.1.4", 50001, "10.0.2.10", 8443, "TCP", 120, 0, after_ttl_ns)
    assert act_expired == "XDP_PASS"


def test_fast_path_bypass_ablation():
    """Verify bypass: on vs bypass: off ablation (N2)."""
    res_on = simulate_closed_loop_workload(early_n=8, bypass_enabled=True, mode="enforce")
    res_off = simulate_closed_loop_workload(early_n=8, bypass_enabled=False, mode="enforce")

    assert res_on["pkts_bypassed"] > 0
    assert res_on["bypass_fraction"] > 0.5
    assert res_off["pkts_bypassed"] == 0
    assert res_off["bypass_fraction"] == 0.0
    # Post-verdict attack packet leakage must be 0 in enforce mode
    assert res_on["post_verdict_leaked_pkts"] == 0


def test_watchdog_load_shedding_and_cooldown_recovery():
    """Verify watchdog activates shed=1 on ring-buffer overload and recovers after cooldown_s."""
    cfg = load_system_config()
    cfg["engine"]["watchdog"]["max_ringbuf_failures_per_s"] = 50
    cfg["engine"]["watchdog"]["cooldown_s"] = 10
    backend = MockBPFBackend(early_n=6)
    engine = IPSEngine(config=cfg, backend=backend, mode_override="enforce")

    # Normal state at t=1.0s
    w0 = engine.step_watchdog(now_s=1.0)
    assert w0["shed_active"] is False
    assert backend.cfg["shed"] == 0

    # Simulate 200 ring-buffer failures within 1 second -> triggers shed=1 at t=2.0s
    backend.stats["ringbuf_drop_failures"] += 200
    w1 = engine.step_watchdog(now_s=2.0)
    assert w1["shed_active"] is True
    assert w1["action"] == "WATCHDOG_SHED_ON"
    assert backend.cfg["shed"] == 1

    # At t=7.0s (only 5s elapsed < 10s cooldown), shed stays active
    w2 = engine.step_watchdog(now_s=7.0)
    assert w2["shed_active"] is True
    assert backend.cfg["shed"] == 1

    # At t=13.0s (>= 10s cooldown with 0 new failures), shed recovers to 0
    w3 = engine.step_watchdog(now_s=13.0)
    assert w3["shed_active"] is False
    assert w3["action"] == "WATCHDOG_SHED_OFF"
    assert backend.cfg["shed"] == 0


def test_attack_leakage_and_bootstrap_ci():
    """Verify attack-packet leakage decomposition and bootstrap CI calculation."""
    leak = compute_attack_leakage(
        total_attack_pkts_sent=500,
        wan_egress_attack_pkts=60,
        attack_flows_detected=5,
        early_n=10,
        handshake_pkts_per_flow=2,
    )
    assert leak["dropped_attack_pkts"] == 440
    assert leak["pre_verdict_leaked_pkts"] == 60
    assert leak["post_verdict_leaked_pkts"] == 0
    assert leak["leakage_rate"] == pytest.approx(0.12)

    mean_v, lo, hi = compute_bootstrap_ci([10.0, 12.0, 14.0, 16.0, 18.0])
    assert mean_v == pytest.approx(14.0)
    assert lo <= mean_v <= hi
