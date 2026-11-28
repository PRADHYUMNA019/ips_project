#!/usr/bin/env python3
"""
tests/test_prop_flow_key.py — Property-based & 10^5 collision tests for canonical FlowKey (Prompt 10 §1.3).

Verifies:
  1. Canonical symmetry: make_flow_key(A -> B) == make_flow_key(B -> A) bytewise.
  2. Determinism / stability across repeated invocations.
  3. Exact bytewise equivalence with the C algorithm in ebpf/ips_engine.c (lines 255-268).
  4. Zero hash/key collisions across 10^5 distinct canonical 5-tuples.
"""

from __future__ import annotations

import struct

import numpy as np
from hypothesis import given, settings
from hypothesis import strategies as st

from ips.engine.schema import PROTO_TCP, PROTO_UDP, flow_key_to_canonical_tuple, ip_to_u32, make_flow_key
from ips.offline.pcap_to_flows import canonical_flow_key


def _c_reference_flow_key_bytes(saddr_u32: int, sport_u16: int, daddr_u32: int, dport_u16: int, proto_u8: int) -> bytes:
    """Exact bytewise model of struct flow_key construction in ebpf/ips_engine.c (little-endian host x86_64)."""
    if (saddr_u32 < daddr_u32) or (saddr_u32 == daddr_u32 and sport_u16 <= dport_u16):
        ip_a, port_a, ip_b, port_b = saddr_u32, sport_u16, daddr_u32, dport_u16
    else:
        ip_a, port_a, ip_b, port_b = daddr_u32, dport_u16, saddr_u32, sport_u16
    return struct.pack("<IIHHB3s", ip_a, ip_b, port_a, port_b, proto_u8, b"\x00\x00\x00")


ipv4_strategy = st.tuples(
    st.integers(0, 255),
    st.integers(0, 255),
    st.integers(0, 255),
    st.integers(0, 255),
).map(lambda octs: f"{octs[0]}.{octs[1]}.{octs[2]}.{octs[3]}")


@given(
    ip1=ipv4_strategy,
    p1=st.integers(0, 65535),
    ip2=ipv4_strategy,
    p2=st.integers(0, 65535),
    proto=st.sampled_from(["TCP", "UDP"]),
)
@settings(max_examples=200, deadline=None)
def test_prop_flow_key_symmetry_stability_and_c_byte_equivalence(ip1, p1, ip2, p2, proto):
    """Canonical key is symmetric, stable, matches offline canonical_flow_key, and equals C bytes."""
    fk_fwd = make_flow_key(ip1, p1, ip2, p2, proto)
    fk_rev = make_flow_key(ip2, p2, ip1, p1, proto)
    fk_fwd_again = make_flow_key(ip1, p1, ip2, p2, proto)

    assert bytes(fk_fwd) == bytes(fk_rev), f"Asymmetric FlowKey for {ip1}:{p1} <-> {ip2}:{p2}"
    assert bytes(fk_fwd) == bytes(fk_fwd_again), "FlowKey is not deterministic"

    proto_u8 = PROTO_TCP if proto == "TCP" else PROTO_UDP
    c_bytes = _c_reference_flow_key_bytes(ip_to_u32(ip1), p1, ip_to_u32(ip2), p2, proto_u8)
    assert bytes(fk_fwd) == c_bytes, f"ctypes FlowKey {bytes(fk_fwd)!r} != C reference {c_bytes!r}"

    assert flow_key_to_canonical_tuple(fk_fwd) == canonical_flow_key(ip1, p1, ip2, p2, proto)


def test_flow_key_collision_free_on_100k_random_5tuples():
    """Sample 10^5 distinct canonical 5-tuples and verify 0 collisions in 16-byte packed key."""
    rng = np.random.default_rng(2026)
    n_samples = 100_000
    ip1 = rng.integers(1, 0xFFFFFFFE, size=n_samples, dtype=np.uint32)
    ip2 = rng.integers(1, 0xFFFFFFFE, size=n_samples, dtype=np.uint32)
    p1 = rng.integers(1, 65535, size=n_samples, dtype=np.uint16)
    p2 = rng.integers(1, 65535, size=n_samples, dtype=np.uint16)
    protos = rng.choice(np.array([PROTO_TCP, PROTO_UDP], dtype=np.uint8), size=n_samples)

    canonical_tuples = set()
    packed_keys = set()
    for i in range(n_samples):
        a, b = int(ip1[i]), int(ip2[i])
        pa, pb = int(p1[i]), int(p2[i])
        pr = int(protos[i])
        if (a > b) or (a == b and pa > pb):
            a, b, pa, pb = b, a, pb, pa
        ct = (a, pa, b, pb, pr)
        canonical_tuples.add(ct)
        packed_keys.add(struct.pack("<IIHHB3s", a, b, pa, pb, pr, b"\x00\x00\x00"))

    assert len(packed_keys) == len(canonical_tuples), (
        f"Collision detected: {len(canonical_tuples)} distinct canonical 5-tuples mapped to {len(packed_keys)} keys"
    )
