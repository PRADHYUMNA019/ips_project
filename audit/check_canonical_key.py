#!/usr/bin/env python3
"""audit/check_canonical_key.py - Audit canonical flow key consistency across C, Python engine, and offline extractor.

Prompt 4 requirement:
Compare how the flow key is canonicalised in C, in Python engine (ips/engine/schema.py),
and in the offline extractor (ips/offline/pcap_to_flows.py).
Verify if string comparison, raw network-byte-order comparison, or host-order integer comparison
produce discrepancies.
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path
from typing import Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from ips.engine.schema import make_flow_key, u32_to_ip, ip_to_u32, flow_key_to_canonical_tuple
from ips.offline.pcap_to_flows import canonical_flow_key as offline_canonical_key


def c_simulate_canonical_key(src_ip: str, sport: int, dst_ip: str, dport: int, proto: int = 6) -> Tuple[int, int, int, int, int]:
    """
    Simulate exact C logic from ebpf/ips_engine.c lines 254-315:
    saddr = bpf_ntohl(ip->saddr);
    daddr = bpf_ntohl(ip->daddr);
    sport = bpf_ntohs(tcp->source);
    dport = bpf_ntohs(tcp->dest);
    if ((saddr < daddr) || (saddr == daddr && sport <= dport)) { ... }
    """
    # Network byte order bytes
    saddr_raw = socket.inet_aton(src_ip)
    daddr_raw = socket.inet_aton(dst_ip)
    # bpf_ntohl: network to host uint32
    saddr = struct.unpack("!I", saddr_raw)[0]
    daddr = struct.unpack("!I", daddr_raw)[0]
    sp = int(sport) & 0xFFFF
    dp = int(dport) & 0xFFFF

    if (saddr < daddr) or (saddr == daddr and sp <= dp):
        return (saddr, sp, daddr, dp, proto)
    else:
        return (daddr, dp, saddr, sp, proto)


def raw_network_order_key(src_ip: str, sport: int, dst_ip: str, dport: int, proto: int = 6) -> Tuple[int, int, int, int, int]:
    """
    Simulate what happens if C compared raw __be32/__be16 without bpf_ntohl (the bug flagged in Prompt 4).
    On a little-endian machine, raw __be32 treated as uint32 is byte-swapped!
    """
    saddr_le = struct.unpack("<I", socket.inet_aton(src_ip))[0]
    daddr_le = struct.unpack("<I", socket.inet_aton(dst_ip))[0]
    sp_le = struct.unpack("<H", struct.pack("!H", sport))[0]
    dp_le = struct.unpack("<H", struct.pack("!H", dport))[0]
    if (saddr_le < daddr_le) or (saddr_le == daddr_le and sp_le <= dp_le):
        return (saddr_le, sp_le, daddr_le, dp_le, proto)
    else:
        return (daddr_le, dp_le, saddr_le, sp_le, proto)


def string_compare_key(src_ip: str, sport: int, dst_ip: str, dport: int, proto: str = "TCP") -> Tuple[str, int, str, int, str]:
    """Simulate buggy string comparison."""
    if (src_ip < dst_ip) or (src_ip == dst_ip and sport <= dport):
        return (src_ip, sport, dst_ip, dport, proto)
    else:
        return (dst_ip, dport, src_ip, sport, proto)


def run_checks():
    print("=== Auditing Canonical Key Consistency Across C, Engine, and Offline Extractor ===")

    test_pairs = [
        # (src_ip, sport, dst_ip, dport, description)
        ("10.0.1.11", 55555, "10.0.2.10", 8883, "Standard IoT to server"),
        ("10.0.2.10", 8883, "10.0.1.11", 55555, "Reverse direction of above"),
        ("10.0.1.20", 443, "10.0.1.3", 443, "String order differs from integer order ('10.0.1.20' < '10.0.1.3' vs 20 > 3)"),
        ("10.0.1.3", 443, "10.0.1.20", 443, "Reverse of above"),
        ("10.0.1.11", 256, "10.0.1.11", 1, "Port 256 (0x0100) vs Port 1 (0x0001): endianness sensitivity"),
        ("10.0.1.11", 1, "10.0.1.11", 256, "Reverse of above"),
        ("192.168.1.100", 50000, "10.0.1.1", 80, "Different subnets high vs low octets"),
        ("10.0.1.1", 80, "192.168.1.100", 50000, "Reverse of above"),
        ("10.0.1.11", 8080, "10.0.1.11", 8080, "Identical endpoints"),
        ("1.2.3.4", 1234, "4.3.2.1", 4321, "Reversed octets"),
    ]

    mismatches = 0
    raw_be_discrepancies = 0

    print(f"{'Case':<40} | {'C Host-Order':<22} | {'Python Engine':<22} | {'Offline Extractor':<22} | {'Raw BE Bug'}")
    print("-" * 125)

    for src_ip, sport, dst_ip, dport, desc in test_pairs:
        # 1. C logic
        c_res = c_simulate_canonical_key(src_ip, sport, dst_ip, dport)
        c_ipa_str = u32_to_ip(c_res[0])
        c_ipb_str = u32_to_ip(c_res[2])
        c_summary = f"{c_ipa_str}:{c_res[1]} <-> {c_ipb_str}:{c_res[3]}"

        # 2. Python engine FlowKey
        fk = make_flow_key(src_ip, sport, dst_ip, dport, "TCP")
        py_summary = f"{u32_to_ip(fk.ip_a)}:{fk.port_a} <-> {u32_to_ip(fk.ip_b)}:{fk.port_b}"

        # 3. Offline pcap_to_flows
        off_res = offline_canonical_key(src_ip, sport, dst_ip, dport, "TCP")
        off_summary = f"{off_res[0]}:{off_res[1]} <-> {off_res[2]}:{off_res[3]}"

        # 4. Check if raw __be comparison would have diverged
        raw_be = raw_network_order_key(src_ip, sport, dst_ip, dport)
        # Check if raw_be chose a different side as side A
        c_chose_src_as_a = (c_res[0] == ip_to_u32(src_ip) and c_res[1] == sport)
        saddr_le = struct.unpack("<I", socket.inet_aton(src_ip))[0]
        raw_chose_src_as_a = (raw_be[0] == saddr_le and raw_be[1] == struct.unpack("<H", struct.pack("!H", sport))[0])
        diverged = (c_chose_src_as_a != raw_chose_src_as_a)
        if diverged:
            raw_be_discrepancies += 1

        match = (c_summary == py_summary == off_summary)
        if not match:
            mismatches += 1

        div_flag = "DIVERGES!" if diverged else "same"
        print(f"{desc[:40]:<40} | {c_summary:<22} | {py_summary:<22} | {off_summary:<22} | {div_flag}")

    print("\nSummary:")
    print(f"- Total test cases: {len(test_pairs)}")
    print(f"- Mismatches between C, Python Engine, and Offline Extractor: {mismatches}")
    print(f"- Cases where raw __be comparison (without bpf_ntohl) WOULD HAVE DIVERGED: {raw_be_discrepancies}")

    if mismatches > 0:
        print("ERROR: Canonical key mismatch detected!")
        sys.exit(1)
    else:
        print("SUCCESS: C, Python Engine, and Offline Extractor agree 100% on all test cases.")
        if raw_be_discrepancies > 0:
            print(f"NOTE: Confirmed that bpf_ntohl() in C lines 254-255 is strictly required: without it, {raw_be_discrepancies} cases would diverge.")


if __name__ == "__main__":
    run_checks()
