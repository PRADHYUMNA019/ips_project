#!/usr/bin/env python3
"""
tests/test_prop_pcap_to_flows.py — Fuzz & packet-conservation property tests for pcap_to_flows (Prompt 10 §1.3).

Builds randomized synthetic pcaps containing mixtures of:
  - Normal IPv4 TCP & UDP packets
  - Snaplen-truncated frames
  - Corrupt / sub-14-byte Ethernet frames
  - IPv6 frames
  - Non-initial IPv4 fragments
  - ICMP (IPv4 non-TCP/UDP)
  - ARP frames
  - 802.1Q VLAN-tagged frames
Verifies:
  1. extract_flows_from_pcap NEVER crashes on arbitrary frame sequences.
  2. Strict packet conservation: total_packets == assigned_packets + sum(skipped.values()).
"""

from __future__ import annotations

import socket
import struct
import tempfile
import os

import dpkt
from hypothesis import given, settings
from hypothesis import strategies as st

from ips.offline.pcap_to_flows import extract_flows_from_pcap


def _build_frame(kind: str, payload_size: int, trunc_len: int) -> bytes:
    src = socket.inet_aton("10.0.1.10")
    dst = socket.inet_aton("10.0.2.10")

    if kind == "corrupt":
        return b"\xff\x00\x01"[: max(1, min(trunc_len, 3))]
    if kind == "arp":
        return bytes(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_ARP, data=dpkt.arp.ARP()))
    if kind == "ipv6":
        ip6 = dpkt.ip6.IP6(src=b"\x00" * 16, dst=b"\x00" * 16, nxt=17, data=b"6" * 12)
        return bytes(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP6, data=ip6))
    if kind == "icmp":
        icmp = dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"ping"))
        ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_ICMP, data=icmp)
        ip.len = len(ip)
        return bytes(dpkt.ethernet.Ethernet(data=ip))
    if kind == "frag":
        ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_UDP, offset=1480, data=b"F" * 24)
        ip.len = len(ip)
        return bytes(dpkt.ethernet.Ethernet(data=ip))
    if kind == "vlan_tcp":
        tcp = dpkt.tcp.TCP(sport=50100, dport=8883, flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, data=b"V" * payload_size)
        ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, data=tcp)
        ip.len = len(ip)
        # Raw 802.1Q header: dst(6) + src(6) + 0x8100 + TCI(2) + 0x0800 + IP
        return (b"\x00" * 12) + struct.pack("!HHH", 0x8100, 100, 0x0800) + bytes(ip)
    if kind == "udp":
        udp = dpkt.udp.UDP(sport=53001, dport=443, data=b"U" * payload_size)
        udp.ulen = len(udp)
        ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_UDP, data=udp)
        ip.len = len(ip)
        raw = bytes(dpkt.ethernet.Ethernet(data=ip))
        return raw[:trunc_len] if trunc_len > 0 else raw

    # Default: TCP (possibly truncated)
    tcp = dpkt.tcp.TCP(sport=50200, dport=8443, flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, data=b"T" * payload_size)
    ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(ip)
    raw = bytes(dpkt.ethernet.Ethernet(data=ip))
    return raw[:trunc_len] if trunc_len > 0 else raw


@given(
    specs=st.lists(
        st.tuples(
            st.sampled_from(["tcp", "udp", "corrupt", "arp", "ipv6", "icmp", "frag", "vlan_tcp"]),
            st.integers(min_value=0, max_value=600),
            st.sampled_from([0, 24, 54, 96, 200]),
            st.floats(min_value=0.001, max_value=5.0, allow_nan=False, allow_infinity=False),
        ),
        min_size=1,
        max_size=40,
    )
)
@settings(max_examples=60, deadline=None)
def test_prop_pcap_fuzz_never_crashes_and_conserves_packet_counts(specs):
    """Fuzzed pcaps never crash extract_flows_from_pcap and strictly conserve packet counts."""
    fd, pcap_path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        with open(pcap_path, "wb") as f:
            writer = dpkt.pcap.Writer(f)
            ts = 1_700_000_000.0
            for kind, psize, tlen, dt in specs:
                ts += dt
                frame = _build_frame(kind, psize, tlen)
                writer.writepkt(frame, ts=ts)
            writer.close()

        df = extract_flows_from_pcap(pcap_path, early_n=8)
        stats = df.attrs["packet_stats"]
        assert stats["total_packets"] == len(specs)
        total_accounted = stats["assigned_packets"] + sum(stats["skipped"].values())
        assert total_accounted == len(specs), (
            f"Packet conservation violated: total={len(specs)}, accounted={total_accounted}, stats={stats}"
        )
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
