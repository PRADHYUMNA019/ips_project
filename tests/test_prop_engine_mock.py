#!/usr/bin/env python3
"""
tests/test_prop_engine_mock.py — Property-based tests for IPSEngine + MockBPFBackend (Prompt 10 §1.3).

Verifies across randomized packet/event streams:
  1. Decisions log timestamps are monotonically non-decreasing when fed monotonic packet clocks.
  2. Verdict map expiry deadlines always satisfy expiry_ns > now_ns at insertion (no negative TTL).
  3. Sticky DROP invariant: a flow with an active DROP verdict NEVER flips to BYPASS before drop_ttl_ns expires.
  4. Bounded LRU map invariant: flow_state and verdict_map NEVER exceed flow_map_max / verdict_map_max.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ips.engine.engine import IPSEngine, MockBPFBackend
from ips.engine.schema import VERDICT_BYPASS, VERDICT_DROP, make_flow_key


@given(
    events=st.lists(
        st.tuples(
            st.integers(min_value=1, max_value=24),  # flow slot (24 > map_max=10 to force LRU eviction)
            st.integers(min_value=0, max_value=1460),  # payload bytes
            st.integers(min_value=0, max_value=1),  # direction
            st.integers(min_value=100_000, max_value=5_000_000_000),  # delta_ns (0.1ms .. 5s)
            st.booleans(),  # force high-anomaly score vs benign
        ),
        min_size=5,
        max_size=90,
    )
)
@settings(max_examples=60, deadline=None)
def test_prop_engine_invariants_under_random_streams(events):
    """Random packet streams preserve monotonic timeline, positive TTLs, sticky DROP, and bounded map sizes."""
    flow_max = 4
    verdict_max = 4
    cfg = {
        "system": {
            "early_n": 8,
            "checkpoints": [4, 8],
            "flow_map_max": flow_max,
            "verdict_map_max": verdict_max,
            "bypass_ttl_s": 120,
            "drop_ttl_s": 30,
        },
        "engine": {"mode": "enforce"},
    }
    backend = MockBPFBackend(early_n=8, checkpoints=[4, 8], flow_map_max=flow_max, verdict_map_max=verdict_max)
    engine = IPSEngine(config=cfg, backend=backend, mode_override="enforce", bypass_override=True)
    engine.ort_session = None
    engine.ckpt_sessions = {}
    engine.threshold = 0.08
    engine.ckpt_thresholds = {4: 0.08, 8: 0.08}

    now_ns = 1_000_000_000
    active_drops: dict[bytes, int] = {}  # key -> drop_expiry_ns

    for flow_slot, payload_len, direction, dt_ns, is_high_anom in events:
        now_ns += dt_ns
        src_ip = "10.0.1.4" if is_high_anom else f"10.0.1.{10 + (flow_slot % 4)}"
        sport = 45000 + flow_slot
        fk = make_flow_key(src_ip, sport, "10.0.2.10", 8883, "TCP")
        k_bytes = bytes(fk)

        eff_payload = 1450 if is_high_anom else min(payload_len, 120)
        _, ev = backend.simulate_packet(src_ip, sport, "10.0.2.10", 8883, "TCP", eff_payload, direction, now_ns)

        assert len(backend.flow_state) <= flow_max
        assert len(backend.verdict_map) <= verdict_max

        if ev is not None:
            dec = engine.handle_early_flow_event(ev, now_ns=now_ns)
            assert len(backend.verdict_map) <= verdict_max

            if k_bytes in backend.verdict_map:
                act, exp_ns = backend.verdict_map[k_bytes]
                if dec["verdict_written"] in ("DROP", "BYPASS"):
                    assert exp_ns > now_ns, f"Negative or zero TTL written: exp_ns={exp_ns}, now_ns={now_ns}"
                if act == VERDICT_DROP and dec["verdict_written"] == "DROP":
                    active_drops[k_bytes] = exp_ns
                if k_bytes in active_drops and now_ns < active_drops[k_bytes]:
                    assert act != VERDICT_BYPASS, "DROP -> BYPASS flip occurred before DROP TTL expired!"

    # Verify sorted decision timeline
    timestamps = [d["timestamp_ns"] for d in engine.decisions_log]
    assert timestamps == sorted(timestamps), "Unsorted verdict timeline produced!"
