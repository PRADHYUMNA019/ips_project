#!/usr/bin/env python3
"""
tests/test_kernel_source_invariants.py — V1 source-text BPF invariant guards, negative mutation
tests, and randomized C-control-flow vs MockBPFBackend trace equivalence (Prompt 10 §2.2 & §2.3).

NOTE: Every source check in this file is a static source-text guard (`STATIC ANALYSIS`, V1),
NOT kernel execution (`V2`).
"""

from __future__ import annotations

import os
import re

from hypothesis import given, settings
from hypothesis import strategies as st

from ips.engine.bpf_source_checker import (
    check_allowed_helpers_only,
    check_bounded_loops,
    check_bpf_stack_limit,
    check_constant_divisors_only,
    check_emitted_mask_after_submit,
    check_map_lookup_null_guards,
    check_no_floating_point,
    check_packet_bounds_guards,
    check_ringbuf_reserve_submit_pairing,
    run_all_bpf_source_checks,
)
from ips.engine.c_control_flow_model import CControlFlowModel
from ips.engine.engine import MockBPFBackend
from ips.engine.schema import make_flow_key

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
C_FILE = os.path.join(REPO_DIR, "ebpf", "ips_engine.c")


def _read_c_source() -> str:
    with open(C_FILE, "r", encoding="utf-8") as f:
        return f.read()


def test_all_bpf_source_invariants_pass_on_ips_engine_c():
    """source-text guard, not execution: verify ebpf/ips_engine.c passes all 9 BPF static rules."""
    res = run_all_bpf_source_checks(_read_c_source())
    assert res["passed"] is True, f"BPF static source checks failed: {res['errors']}"


def test_rule_bounded_loops_positive_and_negative():
    """source-text guard, not execution: bounded loops with #pragma unroll required; negative test catches unbounded loop."""
    src = _read_c_source()
    assert check_bounded_loops(src) == []

    # Negative 1: remove #pragma unroll
    mut_no_unroll = src.replace("#pragma unroll", "", 1)
    assert len(check_bounded_loops(mut_no_unroll)) >= 1

    # Negative 2: inject while loop
    mut_while = src.replace("return XDP_PASS;\n}", "    while (data < data_end) { data++; }\n    return XDP_PASS;\n}", 1)
    assert len(check_bounded_loops(mut_while)) >= 1


def test_rule_map_lookup_null_checked_positive_and_negative():
    """source-text guard, not execution: every map lookup pointer must be NULL-checked before dereference."""
    src = _read_c_source()
    assert check_map_lookup_null_guards(src) == []

    # Negative: remove NULL check on scratch_map.lookup
    mut = src.replace("if (!scratch) {\n            return XDP_PASS;\n        }", "")
    errs = check_map_lookup_null_guards(mut)
    assert any("scratch" in e for e in errs), f"Expected NULL-check violation for 'scratch', got {errs}"


def test_rule_packet_bounds_checked_positive_and_negative():
    """source-text guard, not execution: every packet header pointer is checked against data_end before use."""
    src = _read_c_source()
    assert check_packet_bounds_guards(src) == []

    # Negative: remove UDP bounds check
    mut = src.replace("if ((void *)(udp + 1) > data_end) {\n            return XDP_PASS;\n        }", "")
    errs = check_packet_bounds_guards(mut)
    assert any("udp" in e for e in errs), f"Expected packet bounds violation for 'udp', got {errs}"


def test_rule_stack_under_512_bytes_positive_and_negative():
    """source-text guard, not execution: local stack per BPF function <= 512 bytes."""
    src = _read_c_source()
    assert check_bpf_stack_limit(src) == []

    # Negative: allocate 600-byte array on stack inside xdp_ips_prog
    mut = src.replace("int zero = 0;", "int zero = 0;\n    __u8 huge_stack_buf[600] = {};", 1)
    errs = check_bpf_stack_limit(mut)
    assert len(errs) >= 1 and "512B" in errs[0]


def test_rule_allowed_helpers_only_positive_and_negative():
    """source-text guard, not execution: disallow non-BPF libc/user functions inside BPF C source."""
    src = _read_c_source()
    assert check_allowed_helpers_only(src) == []

    # Negative: call printf() inside xdp_ips_prog
    mut = src.replace("int zero = 0;", 'int zero = 0;\n    printf("bad");', 1)
    errs = check_allowed_helpers_only(mut)
    assert any("printf" in e for e in errs)


def test_rule_no_floating_point_positive_and_negative():
    """source-text guard, not execution: disallow float/double types and literals in kernel C."""
    src = _read_c_source()
    assert check_no_floating_point(src) == []

    mut = src.replace("int zero = 0;", "int zero = 0;\n    double bad_fp = 1.25;", 1)
    assert len(check_no_floating_point(mut)) >= 1


def test_rule_constant_divisors_only_positive_and_negative():
    """source-text guard, not execution: disallow division by runtime variables or zero."""
    src = _read_c_source()
    assert check_constant_divisors_only(src) == []

    mut = src.replace("/ 1000000ULL;", "/ rate;", 1)
    errs = check_constant_divisors_only(mut)
    assert any("rate" in e for e in errs)


def test_rule_ringbuf_pairing_positive_and_negative():
    """source-text guard, not execution: every reserved ringbuf slot must be submitted/discarded without early return."""
    src = _read_c_source()
    assert check_ringbuf_reserve_submit_pairing(src) == []

    # Negative: inject early return between ringbuf_reserve and ringbuf_submit (leaking reserved slot!)
    mut = src.replace(
        "ev->schema_version = SCHEMA_VERSION;", "if (dir == 1) return XDP_PASS;\n        ev->schema_version = SCHEMA_VERSION;", 1
    )
    errs = check_ringbuf_reserve_submit_pairing(mut)
    assert any("leaks ringbuf slot" in e for e in errs)


def test_emitted_mask_set_after_ringbuf_submit_positive_and_negative():
    """source-text guard, not execution: emitted_mask |= appears once, strictly after ringbuf_submit (Prompt 6)."""
    src = _read_c_source()
    assert check_emitted_mask_after_submit(src) == []

    # Locate the if (ckpt_hit >= 0) block brace balance as well
    ckpt_block_match = re.search(r"if\s*\(\s*ckpt_hit\s*>=\s*0\s*\)\s*\{", src)
    assert ckpt_block_match is not None

    # Negative 1: move emitted_mask |= before ringbuf_reserve
    mut_before = src.replace("rec->emitted_mask |= (__u8)(1U << ckpt_hit);", "", 1).replace(
        "if (ckpt_hit >= 0) {", "if (ckpt_hit >= 0) {\n        rec->emitted_mask |= (__u8)(1U << ckpt_hit);", 1
    )
    assert len(check_emitted_mask_after_submit(mut_before)) >= 1

    # Negative 2: remove emitted_mask |= altogether (Prompt 6 blocker regression)
    mut_missing = src.replace("rec->emitted_mask |= (__u8)(1U << ckpt_hit);", "", 1)
    assert len(check_emitted_mask_after_submit(mut_missing)) >= 1


@given(
    trace=st.lists(
        st.tuples(
            st.sampled_from(["10.0.1.10", "10.0.1.11", "10.0.1.4"]),
            st.sampled_from([50001, 50002]),
            st.sampled_from(["TCP", "UDP"]),
            st.integers(min_value=0, max_value=1400),
            st.integers(min_value=0, max_value=1),
            st.sampled_from([5_000_000, 100_000_000, 130_000_000_000]),  # 5ms, 100ms, 130s (>120s idle!)
            st.sampled_from([0x18, 0x02, 0x01]),  # PSH|ACK, pure SYN, FIN
            st.booleans(),  # shed toggle
            st.booleans(),  # ringbuf_full toggle
        ),
        min_size=10,
        max_size=60,
    )
)
@settings(max_examples=50, deadline=None)
def test_c_control_flow_model_equals_mock_bpf_backend_on_random_traces(trace):
    """
    Prompt 10 §2.3: Feed identical randomized packet traces (including SYN floods, FIN+SYN reuse,
    >120s idle resets, load shedding, ringbuf-full retries, and verdict TTL expiry) into BOTH
    the statement-by-statement CControlFlowModel and MockBPFBackend and assert 100% identical
    XDP actions, emitted event sequences, and telemetry counters.
    """
    c_model = CControlFlowModel(early_n=8, checkpoints=[4, 8], flow_map_max=8, verdict_map_max=8)
    mock = MockBPFBackend(early_n=8, checkpoints=[4, 8], flow_map_max=8, verdict_map_max=8)

    c_model.cfg["tier0_capacity"] = 6
    mock.cfg["tier0_capacity"] = 6

    now_ns = 1_000_000_000
    for idx, (sip, sport, proto, plen, direction, dt_ns, flags, shed, rb_full) in enumerate(trace):
        now_ns += dt_ns
        is_syn_only = (proto == "TCP") and (flags == 0x02)
        eff_plen = 0 if is_syn_only else plen

        c_model.cfg["shed"] = 1 if shed else 0
        mock.set_shed(1 if shed else 0)
        c_model.ringbuf_full = rb_full
        mock.simulate_ringbuf_full = rb_full

        # Periodically inject identical short-TTL verdicts to test verdict lookup & TTL expiration parity
        if idx == 12:
            fk = make_flow_key(sip, sport, "10.0.2.10", 8443, proto)
            mock.set_verdict(fk, 2, now_ns + 50_000_000)
            c_model.set_verdict_by_endpoints(sip, sport, "10.0.2.10", 8443, proto, 2, now_ns + 50_000_000)

        act_c, ev_c = c_model.xdp_ips_prog(
            sip, sport, "10.0.2.10", 8443, proto, eff_plen, direction, now_ns, tcp_flags=flags, is_syn_only=is_syn_only
        )
        act_m, ev_m = mock.simulate_packet(
            sip, sport, "10.0.2.10", 8443, proto, eff_plen, direction, now_ns, tcp_flags=flags, is_syn_only=is_syn_only
        )

        assert act_c == act_m, f"Step {idx}: action mismatch C={act_c} vs Mock={act_m}"
        assert (ev_c is None) == (ev_m is None), f"Step {idx}: event emission mismatch C={ev_c} vs Mock={ev_m}"
        if ev_c is not None and ev_m is not None:
            for field in (
                "schema_version",
                "proto",
                "valid_len",
                "checkpoint_idx",
                "ip_a",
                "port_a",
                "ip_b",
                "port_b",
                "total_pkts",
                "total_bytes",
                "sizes",
                "dirs",
                "iat_ns",
            ):
                assert ev_c[field] == ev_m[field], f"Step {idx} field '{field}' mismatch: C={ev_c[field]} vs Mock={ev_m[field]}"

    assert c_model.stats == mock.get_stats(), f"Telemetry counter divergence: C={c_model.stats} vs Mock={mock.get_stats()}"
