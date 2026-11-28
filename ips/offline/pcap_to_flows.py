#!/usr/bin/env python3
"""
ips/offline/pcap_to_flows.py — Extract canonical bidirectional early-flow vectors from pcap (A4, B3).

Key properties (A4 & B3):
  - Payload length comes from IP/TCP/UDP HEADER fields (`ip.len - ip.hl*4 - tcp.off*4` for TCP;
    `udp.ulen - 8` for UDP), NOT `len(tcp.data)`, so truncated pcaps (e.g. Kitsune 200B snaplen)
    preserve true packet payload lengths.
  - Emits finished flow instances on TCP FIN/RST or when a new SYN arrives for the same 5-tuple,
    incrementing `instance` per 5-tuple so reused 5-tuples keep every flow instance.
  - Accepts `lan_cidrs` (list of CIDR strings, e.g. ["10.0.1.0/24"]) to determine packet direction.
  - Includes flow-key and provenance metadata (`src_ip, dst_ip, sport, dport, proto, start_ts,
    end_ts, instance, session_id, source, label_family, is_attack, encrypted, domain`).
"""

import os
import sys
import socket
import ipaddress
import argparse
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple
import yaml
import pandas as pd

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)
from ips.features import build_early_vector, get_feature_names, assert_no_forbidden_features

try:
    import dpkt
except ImportError:
    dpkt = None


def ip_to_u32(ip_str: str) -> int:
    """Convert dotted-quad IPv4 string to host-order uint32 (big-endian numeric value)."""
    return int.from_bytes(socket.inet_aton(ip_str), "big")


def canonical_flow_key(src_ip: str, sport: int, dst_ip: str, dport: int, proto: str) -> Tuple[str, int, str, int, str]:
    """Derive canonical bidirectional 5-tuple flow key ordered by numeric (IP, port)."""
    ep1 = (ip_to_u32(src_ip), int(sport))
    ep2 = (ip_to_u32(dst_ip), int(dport))
    if ep1 <= ep2:
        return (src_ip, int(sport), dst_ip, int(dport), str(proto).upper())
    else:
        return (dst_ip, int(dport), src_ip, int(sport), str(proto).upper())


def _is_in_lan(ip_str: str, networks: List[ipaddress.IPv4Network], lan_prefix: Optional[str] = None) -> bool:
    if lan_prefix and ip_str.startswith(lan_prefix):
        return True
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return any(addr in net for net in networks)
    except Exception:
        return False


def _detect_tls_record(payload_bytes: bytes, sport: int, dport: int) -> bool:
    if (
        len(payload_bytes) >= 3
        and payload_bytes[0] in (0x16, 0x17)
        and payload_bytes[1] == 0x03
        and payload_bytes[2] in (0x01, 0x02, 0x03, 0x04)
    ):
        return True
    if sport in (443, 8443, 8883) or dport in (443, 8443, 8883):
        return True
    return False


def _finalize_flow(
    flow: Dict[str, Any],
    early_n: int,
    feat_names: List[str],
    session_id: str,
    source: str,
    label_family: str,
    is_attack: int,
    domain: str,
) -> Dict[str, Any]:
    sizes = flow["sizes"]
    dirs = flow["dirs"]
    ts_list = flow["timestamps"]
    iat_ms = []
    for i in range(1, len(ts_list)):
        iat_ms.append(max(0.0, (ts_list[i] - ts_list[i - 1]) * 1000.0))

    vec = build_early_vector(sizes, dirs, iat_ms, early_n=early_n)
    rec = {
        "src_ip": flow["src_ip"],
        "dst_ip": flow["dst_ip"],
        "sport": int(flow["sport"]),
        "dport": int(flow["dport"]),
        "proto": flow["proto"],
        "ip_a": flow["ip_a"],
        "port_a": int(flow["port_a"]),
        "ip_b": flow["ip_b"],
        "port_b": int(flow["port_b"]),
        "start_ts": float(flow["start_ts"]),
        "end_ts": float(flow["end_ts"]),
        "instance": int(flow["instance"]),
        "session_id": session_id,
        "source": source,
        "label_family": label_family,
        "is_attack": int(is_attack),
        "encrypted": bool(flow["encrypted"]),
        "domain": domain,
        "raw_valid_len": len(sizes),
    }
    for fname, val in zip(feat_names, vec):
        rec[fname] = float(val)
    return rec


def _default_flow_idle_s() -> float:
    """Load system.flow_idle_s from configs/system.yaml (matching ebpf/ips_engine.c FLOW_IDLE_NS)."""
    cfg_path = os.path.join(REPO_DIR, "configs", "system.yaml")
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return float(data.get("system", {}).get("flow_idle_s", 120.0))
        except Exception:
            return 120.0
    return 120.0


def extract_flows_from_pcap(
    filepath: str,
    early_n: int = 12,
    lan_prefix: Optional[str] = "10.0.1.",
    lan_cidrs: Optional[List[str]] = None,
    session_id: str = "pcap_session",
    source: str = "pcap",
    label_family: str = "benign",
    is_attack: int = 0,
    domain: str = "testbed",
    flow_idle_s: Optional[float] = None,
) -> pd.DataFrame:
    """Parse pcap into a canonical early-flow DataFrame using kernel-matching idle/SYN/FIN rules."""
    if dpkt is None:
        raise RuntimeError("dpkt is required for pcap parsing")

    idle_limit_s = _default_flow_idle_s() if flow_idle_s is None else float(flow_idle_s)

    if lan_cidrs is None:
        lan_cidrs = ["10.0.1.0/24"]
    networks = []
    for c in lan_cidrs:
        try:
            networks.append(ipaddress.IPv4Network(c, strict=False))
        except ValueError:
            continue

    feat_names = get_feature_names(early_n)
    assert_no_forbidden_features(feat_names)

    active_flows: Dict[Tuple[str, int, str, int, str], Dict[str, Any]] = {}
    instance_counts: Dict[Tuple[str, int, str, int, str], int] = defaultdict(int)
    completed_records: List[Dict[str, Any]] = []
    skipped_counts: Dict[str, int] = {
        "corrupt_frame": 0,
        "arp": 0,
        "ipv6": 0,
        "non_ipv4": 0,
        "ip_fragment": 0,
        "non_tcp_udp": 0,
    }
    total_packets = 0
    assigned_packets = 0

    with open(filepath, "rb") as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)

        for ts, buf in reader:
            total_packets += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                eth_data = eth.data
                # Unwrap single or stacked 802.1Q VLAN tags if dpkt returned raw or VLAN object
                while hasattr(eth_data, "data") and type(eth_data).__name__ in ("VLANtag8021Q", "Dot1Q"):
                    eth_data = eth_data.data
                if isinstance(eth_data, dpkt.arp.ARP):
                    skipped_counts["arp"] += 1
                    continue
                if isinstance(eth_data, dpkt.ip6.IP6):
                    skipped_counts["ipv6"] += 1
                    continue
                if not isinstance(eth_data, dpkt.ip.IP):
                    skipped_counts["non_ipv4"] += 1
                    continue
                ip = eth_data
                # Non-initial IPv4 fragments carry no L4 header (BUG-07)
                frag_bytes = int(getattr(ip, "offset", 0))
                raw_foff = int(getattr(ip, "_flags_offset", 0)) & 0x1FFF
                if frag_bytes > 0 or raw_foff > 0:
                    skipped_counts["ip_fragment"] += 1
                    continue
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                ip_tot_len = int(getattr(ip, "len", 0))
                ip_hdr_len = int(getattr(ip, "hl", 5)) * 4

                is_syn_only = False
                tcp_flags = 0

                if isinstance(ip.data, dpkt.tcp.TCP):
                    l4 = ip.data
                    proto = "TCP"
                    sport = int(l4.sport)
                    dport = int(l4.dport)
                    tcp_hdr_len = int(getattr(l4, "off", 5)) * 4
                    # A4(a): Compute payload length from IP/TCP headers (handles truncated pcaps)
                    if ip_tot_len >= (ip_hdr_len + tcp_hdr_len):
                        payload_len = ip_tot_len - ip_hdr_len - tcp_hdr_len
                    else:
                        payload_len = len(l4.data)
                    raw_payload = bytes(l4.data) if l4.data else b""
                    tcp_flags = int(l4.flags)
                    is_syn_only = bool(tcp_flags & dpkt.tcp.TH_SYN) and not bool(tcp_flags & dpkt.tcp.TH_ACK)
                elif isinstance(ip.data, dpkt.udp.UDP):
                    l4 = ip.data
                    proto = "UDP"
                    sport = int(l4.sport)
                    dport = int(l4.dport)
                    udp_ulen = int(getattr(l4, "ulen", 0))
                    if udp_ulen >= 8:
                        payload_len = udp_ulen - 8
                    elif ip_tot_len >= (ip_hdr_len + 8):
                        payload_len = ip_tot_len - ip_hdr_len - 8
                    else:
                        payload_len = len(l4.data)
                    raw_payload = bytes(l4.data) if l4.data else b""
                else:
                    skipped_counts["non_tcp_udp"] += 1
                    continue

                assigned_packets += 1
                ckey = canonical_flow_key(src_ip, sport, dst_ip, dport, proto)

                # Kernel-matching flow restart rule (ebpf/ips_engine.c):
                # Restart on (a) pure SYN when FIN/RST (0x05) was seen OR valid_len > 0,
                # or (b) inter-packet idle gap > flow_idle_s (default 120s from configs/system.yaml).
                if ckey in active_flows:
                    cur = active_flows[ckey]
                    reinit = False
                    if is_syn_only and ((cur["flags_seen"] & 0x05) != 0 or len(cur["sizes"]) > 0):
                        reinit = True
                    elif idle_limit_s > 0.0 and (float(ts) - cur["last_seen_ts"]) > idle_limit_s:
                        reinit = True
                    if reinit:
                        old_flow = active_flows.pop(ckey)
                        if len(old_flow["sizes"]) > 0:
                            completed_records.append(
                                _finalize_flow(old_flow, early_n, feat_names, session_id, source, label_family, is_attack, domain)
                            )
                            instance_counts[ckey] += 1

                if ckey not in active_flows:
                    inst_idx = instance_counts[ckey]
                    active_flows[ckey] = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "sport": sport,
                        "dport": dport,
                        "proto": proto,
                        "ip_a": ckey[0],
                        "port_a": ckey[1],
                        "ip_b": ckey[2],
                        "port_b": ckey[3],
                        "start_ts": float(ts),
                        "end_ts": float(ts),
                        "last_seen_ts": float(ts),
                        "flags_seen": 0,
                        "instance": inst_idx,
                        "sizes": [],
                        "dirs": [],
                        "timestamps": [],
                        "encrypted": _detect_tls_record(raw_payload, sport, dport),
                        "emitted": False,
                    }

                flow = active_flows[ckey]
                flow["end_ts"] = float(ts)
                flow["last_seen_ts"] = float(ts)
                flow["flags_seen"] |= tcp_flags
                if _detect_tls_record(raw_payload, sport, dport):
                    flow["encrypted"] = True

                if payload_len > 0 and len(flow["sizes"]) < early_n:
                    direction = 0 if _is_in_lan(src_ip, networks, lan_prefix) else 1
                    flow["sizes"].append(int(payload_len))
                    flow["dirs"].append(int(direction))
                    flow["timestamps"].append(float(ts))
            except Exception:
                skipped_counts["corrupt_frame"] += 1
                continue

    for _ckey, flow in active_flows.items():
        if len(flow["sizes"]) > 0:
            completed_records.append(_finalize_flow(flow, early_n, feat_names, session_id, source, label_family, is_attack, domain))

    df = pd.DataFrame(completed_records)
    df.attrs["packet_stats"] = {
        "total_packets": total_packets,
        "assigned_packets": assigned_packets,
        "skipped": skipped_counts,
    }
    return df


def main():
    parser = argparse.ArgumentParser(description="Extract canonical early-flow features from pcap")
    parser.add_argument("pcap", help="Input .pcap or .pcapng file")
    parser.add_argument("--early-n", type=int, default=12)
    parser.add_argument("--lan-cidr", action="append", dest="lan_cidrs", default=None)
    parser.add_argument("--session-id", default="pcap_session")
    parser.add_argument("--source", default="pcap")
    parser.add_argument("--label-family", default="benign")
    parser.add_argument("--is-attack", type=int, default=0)
    parser.add_argument("--domain", default="testbed")
    parser.add_argument("--flow-idle-s", type=float, default=None, help="Override flow idle timeout (s); defaults to configs/system.yaml")
    parser.add_argument("--out", required=True, help="Output CSV path")
    args = parser.parse_args()

    records = extract_flows_from_pcap(
        args.pcap,
        early_n=args.early_n,
        lan_cidrs=args.lan_cidrs,
        session_id=args.session_id,
        source=args.source,
        label_family=args.label_family,
        is_attack=args.is_attack,
        domain=args.domain,
        flow_idle_s=args.flow_idle_s,
    )
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    df = pd.DataFrame(records)
    df.to_csv(args.out, index=False)
    print(f"[+] Extracted {len(df)} flows from {args.pcap} -> {args.out}")


if __name__ == "__main__":
    main()
