#!/usr/bin/env python3
"""
tests/test_engine_closed_loop.py — V1 unit tests for WP7 (ips/engine/engine.py and ips/eval/harness.py).
"""
import pytest
import numpy as np
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
    reconcile_leakage_with_egress,
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

    mean_v, lo, hi = compute_bootstrap_ci([10.0, 12.0, 14.0, 16.0, 18.0], seed=42)
    assert mean_v == pytest.approx(14.0)
    assert lo <= mean_v <= hi

    # B5: Non-tautological bootstrap CI assertions:
    # 1. CI width is strictly positive
    assert (hi - lo) > 0.0

    # 2. Seed determinism: fixed seed produces identical bounds
    mean_v2, lo2, hi2 = compute_bootstrap_ci([10.0, 12.0, 14.0, 16.0, 18.0], seed=42)
    assert (mean_v, lo, hi) == (mean_v2, lo2, hi2)

    # 3. Sample size shrinkage: CI width shrinks as sample size increases
    np.random.seed(42)
    sample_small = np.random.normal(14.0, 2.0, size=10).tolist()
    sample_large = np.random.normal(14.0, 2.0, size=500).tolist()
    _, lo_s, hi_s = compute_bootstrap_ci(sample_small, seed=42)
    _, lo_l, hi_l = compute_bootstrap_ci(sample_large, seed=42)
    width_small = hi_s - lo_s
    width_large = hi_l - lo_l
    assert width_large < width_small, f"Expected CI width shrinkage: {width_large} >= {width_small}"


def test_progressive_checkpoints_early_drop_late_bypass():
    """C1 / N7: Verify early DROP at checkpoint 4, CONTINUE at 4 & 8, late BYPASS at 16, and short flow ending at 6."""
    cfg = load_system_config()
    cfg["system"]["checkpoints"] = [4, 8, 16]
    cfg["system"]["early_n"] = 16
    backend = MockBPFBackend(early_n=16, checkpoints=[4, 8, 16])
    engine = IPSEngine(config=cfg, backend=backend, mode_override="enforce", bypass_override=True)
    engine.ort_session = None
    engine.ckpt_sessions = {}
    engine.threshold = 0.08
    engine.ckpt_thresholds = {4: 0.08, 8: 0.08, 16: 0.08}

    now_ns = 1_000_000_000

    # 1. Attack flow on port 60001: dropped at checkpoint 4!
    emitted_atk = []
    for p_i in range(10):
        now_ns += 50_000
        act, ev = backend.simulate_packet("10.0.1.4", 60001, "10.0.2.10", 8443, "TCP", 1400, 0, now_ns)
        if ev is not None:
            dec = engine.handle_early_flow_event(ev, now_ns=now_ns)
            emitted_atk.append(dec)
        if p_i >= 4:
            assert act == "XDP_DROP"
    assert len(emitted_atk) == 1
    assert emitted_atk[0]["checkpoint_n"] == 4
    assert emitted_atk[0]["verdict_written"] == "DROP"

    # 2. Long benign flow on port 40001: CONTINUE at 4 and 8, BYPASS at 16, XDP_PASS_BYPASS for 17..20
    emitted_ben = []
    for p_i in range(20):
        now_ns += 250_000_000
        act, ev = backend.simulate_packet("10.0.1.11", 40001, "10.0.2.10", 8883, "TCP", 110, p_i % 2, now_ns)
        if ev is not None:
            dec = engine.handle_early_flow_event(ev, now_ns=now_ns)
            emitted_ben.append(dec)
        if p_i >= 16:
            assert act == "XDP_PASS_BYPASS"
    assert [d["checkpoint_n"] for d in emitted_ben] == [4, 8, 16]
    assert [d["verdict_written"] for d in emitted_ben] == ["CONTINUE", "CONTINUE", "BYPASS"]

    # 3. Short benign flow (6 packets) on port 40002: emits checkpoint 4 (CONTINUE) and finishes without bypass entry
    emitted_short = []
    for p_i in range(6):
        now_ns += 250_000_000
        act, ev = backend.simulate_packet("10.0.1.12", 40002, "10.0.2.10", 8883, "TCP", 110, p_i % 2, now_ns)
        if ev is not None:
            dec = engine.handle_early_flow_event(ev, now_ns=now_ns)
            emitted_short.append(dec)
    assert len(emitted_short) == 1
    assert emitted_short[0]["checkpoint_n"] == 4
    assert emitted_short[0]["verdict_written"] == "CONTINUE"


def test_operational_harm_and_netem_impairment_c10_c11(tmp_path):
    """C10 & C11: Verify operational-harm translation and netem impairment feature ablations."""
    from ips.eval.harness import compute_operational_harm_metrics
    from ips.eval.impairment import run_impairment_study
    from ips.smoke.synth import generate_smoke_dataset

    harm = compute_operational_harm_metrics(fpr=0.001, drop_ttl_s=60.0, flows_per_device_day=288, fleet_size=12)
    assert harm["expected_dropped_benign_flows_per_device_day"] == pytest.approx(0.288, abs=1e-4)
    assert harm["expected_dropped_benign_flows_per_fleet_day"] == pytest.approx(3.456, abs=1e-3)
    assert harm["time_blocked_per_fp_s"] == 60.0
    assert harm["recovery_time_s"] > 60.0

    df_tr = generate_smoke_dataset(
        n_benign=80, n_attack=0, early_n=8, session_id="smoke_c11_tr",
        out_csv=str(tmp_path / "tr.csv"), seed=401
    )
    df_cal = generate_smoke_dataset(
        n_benign=60, n_attack=0, early_n=8, session_id="smoke_c11_cal",
        out_csv=str(tmp_path / "cal.csv"), seed=402
    )
    df_te = generate_smoke_dataset(
        n_benign=60, n_attack=30, early_n=8, session_id="smoke_c11_te",
        out_csv=str(tmp_path / "te.csv"), seed=403
    )
    imp_df = run_impairment_study(df_tr, df_cal, df_te, early_n=8, epochs=3, seed=42, out_dir=str(tmp_path))
    assert len(imp_df) == 15  # 3 ablations * 5 impairment profiles
    assert set(imp_df["ablation_mode"].unique()) == {"full_features", "no_iat_features", "no_size_features"}
    assert (tmp_path / "netem_impairment.csv").exists()


def test_ringbuf_malformed_event_and_schema_mismatch_b1():
    """B1 (DEF-04): Ringbuffer event parser safely rejects truncated buffer and schema mismatches, triggering shedding after >10."""
    import ctypes
    from ips.engine.engine import IPSEngine, MockBPFBackend
    from ips.engine.schema import make_ctypes_schemas, SCHEMA_VERSION

    backend = MockBPFBackend(early_n=16, checkpoints=[4, 8, 16])
    engine = IPSEngine(backend=backend)

    # 1. Truncated buffer (smaller than EarlyFlowEvent)
    truncated_buf = (ctypes.c_char * 10)(*b"1234567890")
    res = engine.parse_ringbuf_event(truncated_buf, size=10)
    assert res is None
    assert engine.schema_mismatch_count == 1
    assert not backend.cfg["shed"]

    # 2. Mismatched schema version (e.g. 99)
    schemas = make_ctypes_schemas(16)
    ev = schemas.EarlyFlowEvent()
    ev.schema_version = 99
    raw_bytes = ctypes.string_at(ctypes.byref(ev), ctypes.sizeof(ev))
    buf = (ctypes.c_char * len(raw_bytes)).from_buffer_copy(raw_bytes)

    res = engine.parse_ringbuf_event(buf, size=len(raw_bytes))
    assert res is None
    assert engine.schema_mismatch_count == 2
    assert not backend.cfg["shed"]

    # 3. Exceed 10 mismatches -> watchdog triggers fail-open load shedding
    for _ in range(9):
        engine.parse_ringbuf_event(truncated_buf, size=10)

    assert engine.schema_mismatch_count == 11
    assert engine.shed_active is True
    assert backend.cfg["shed"] == 1, "Load shedding must activate after >10 schema mismatches"


def test_confusion_matrix_and_decision_metrics_b2():
    """B2 (DEF-05 / M15): Hand-computed 2x2 confusion matrix verification and edge case handling."""
    from ips.eval.harness import evaluate_run_metrics

    # Hand-crafted 2x2 matrix: TP=10, FP=2, FN=3, TN=85 (Total=100)
    decisions = []
    # 10 TP
    for i in range(10):
        decisions.append({
            "ip_a": "10.0.1.4", "port_a": 1000 + i, "ip_b": "10.0.2.10", "port_b": 8883,
            "proto": "TCP", "initiator_ip": "10.0.1.4", "is_anomaly": True,
            "time_to_verdict_ms": 2.5, "payload_packets_at_verdict": 4,
        })
    # 3 FN
    for i in range(3):
        decisions.append({
            "ip_a": "10.0.1.4", "port_a": 2000 + i, "ip_b": "10.0.2.10", "port_b": 8883,
            "proto": "TCP", "initiator_ip": "10.0.1.4", "is_anomaly": False,
        })
    # 2 FP
    for i in range(2):
        decisions.append({
            "ip_a": "10.0.1.11", "port_a": 3000 + i, "ip_b": "10.0.2.10", "port_b": 8883,
            "proto": "TCP", "initiator_ip": "10.0.1.11", "is_anomaly": True,
            "time_to_verdict_ms": 3.0, "payload_packets_at_verdict": 4,
        })
    # 85 TN
    for i in range(85):
        decisions.append({
            "ip_a": "10.0.1.11", "port_a": 4000 + i, "ip_b": "10.0.2.10", "port_b": 8883,
            "proto": "TCP", "initiator_ip": "10.0.1.11", "is_anomaly": False,
        })

    res = evaluate_run_metrics(decisions, attacker_ips=["10.0.1.4"])

    assert res["tp"] == 10
    assert res["fn"] == 3
    assert res["fp"] == 2
    assert res["tn"] == 85

    # Hand-calculated theoretical metrics:
    # TPR = 10 / 13 = 0.7692307...
    assert res["tpr"] == pytest.approx(10.0 / 13.0, abs=1e-4)
    # FPR = 2 / 87 = 0.0229885... (M15 mutates denominator to 13, which would give 2/13 = 0.1538)
    assert res["fpr"] == pytest.approx(2.0 / 87.0, abs=1e-4)
    # Precision = 10 / 12 = 0.833333...
    assert res["precision"] == pytest.approx(10.0 / 12.0, abs=1e-4)
    # F1 = 2 * (10/12) * (10/13) / ( (10/12) + (10/13) ) = 0.8000
    assert res["f1"] == pytest.approx(0.8000, abs=1e-4)

    # Edge Case 1: All Negatives (0 attack flows, 50 benign flows)
    all_neg = [
        {"ip_a": "10.0.1.11", "port_a": 5000 + i, "ip_b": "10.0.2.10", "port_b": 8883,
         "proto": "TCP", "initiator_ip": "10.0.1.11", "is_anomaly": False}
        for i in range(50)
    ]
    res_neg = evaluate_run_metrics(all_neg, attacker_ips=["10.0.1.4"])
    assert res_neg["tp"] == 0 and res_neg["fn"] == 0 and res_neg["fp"] == 0 and res_neg["tn"] == 50
    assert res_neg["tpr"] == 0.0 and res_neg["fpr"] == 0.0 and res_neg["precision"] == 0.0 and res_neg["f1"] == 0.0

    # Edge Case 2: All Positives (50 attack flows, 0 benign flows)
    all_pos = [
        {"ip_a": "10.0.1.4", "port_a": 6000 + i, "ip_b": "10.0.2.10", "port_b": 8883,
         "proto": "TCP", "initiator_ip": "10.0.1.4", "is_anomaly": True}
        for i in range(50)
    ]
    res_pos = evaluate_run_metrics(all_pos, attacker_ips=["10.0.1.4"])
    assert res_pos["tp"] == 50 and res_pos["fn"] == 0 and res_pos["fp"] == 0 and res_pos["tn"] == 0
    assert res_pos["tpr"] == 1.0 and res_pos["fpr"] == 0.0 and res_pos["precision"] == 1.0 and res_pos["f1"] == 1.0

    # Edge Case 3: Empty decisions list (Zero division)
    res_empty = evaluate_run_metrics([], attacker_ips=["10.0.1.4"])
    assert res_empty["tp"] == 0 and res_empty["fpr"] == 0.0 and res_empty["tpr"] == 0.0


def test_leakage_reconciliation_against_egress_pcap_b8():
    """B8: Compare engine-reported drops against egress capture and detect miscounting."""
    # Scenario 1: Exact reconciliation (100 sent, 20 egressed -> 80 dropped in kernel)
    stats_ok = {"pkts_dropped_verdict": 80}
    rec_ok = reconcile_leakage_with_egress(stats_ok, ingress_pkts=100, egress_pcap_pkts=20)
    assert rec_ok["metric_integrity_failure"] is False
    assert rec_ok["discrepancy"] == 0

    # Scenario 2: Engine miscount (e.g. engine reports 80 drops, but wire only saw 50 dropped / 50 leaked)
    stats_divergent = {"pkts_dropped_verdict": 80}
    rec_fail = reconcile_leakage_with_egress(stats_divergent, ingress_pkts=100, egress_pcap_pkts=50)
    assert rec_fail["metric_integrity_failure"] is True
    assert rec_fail["expected_dropped"] == 50
    assert rec_fail["engine_reported_dropped"] == 80
    assert rec_fail["discrepancy"] == 30





