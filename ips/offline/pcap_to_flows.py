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
import numpy as np
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
    if len(payload_bytes) >= 3 and payload_bytes[0] in (0x16, 0x17) and payload_bytes[1] == 0x03 and payload_bytes[2] in (0x01, 0x02, 0x03, 0x04):
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
) -> List[Dict[str, Any]]:
    """Parse pcap into a list of canonical early-flow feature + metadata dictionaries."""
    if dpkt is None:
        raise RuntimeError("dpkt is required for pcap parsing")

    if lan_cidrs is None:
        lan_cidrs = ["10.0.1.0/24"]
    networks = []
    for c in lan_cidrs:
        try:
            networks.append(ipaddress.IPv4Network(c, strict=False))
        except Exception:
            pass

    feat_names = get_feature_names(early_n)
    assert_no_forbidden_features(feat_names)

    active_flows: Dict[Tuple[str, int, str, int, str], Dict[str, Any]] = {}
    instance_counts: Dict[Tuple[str, int, str, int, str], int] = defaultdict(int)
    completed_records: List[Dict[str, Any]] = []

    with open(filepath, "rb") as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)

        for ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                ip_tot_len = int(getattr(ip, "len", 0))
                ip_hdr_len = int(getattr(ip, "hl", 5)) * 4

                is_syn_only = False
                is_fin_or_rst = False

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
                    flags = int(l4.flags)
                    is_syn_only = bool(flags & dpkt.tcp.TH_SYN) and not bool(flags & dpkt.tcp.TH_ACK)
                    is_fin_or_rst = bool(flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST))
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
                    continue

                ckey = canonical_flow_key(src_ip, sport, dst_ip, dport, proto)

                # A4(b): If a new SYN arrives for an existing 5-tuple with recorded payload packets,
                # emit the previous flow instance before starting a new instance!
                if is_syn_only and ckey in active_flows:
                    old_flow = active_flows.pop(ckey)
                    if len(old_flow["sizes"]) > 0:
                        completed_records.append(
                            _finalize_flow(old_flow, early_n, feat_names, session_id, source, label_family, is_attack, domain)
                        )

                if ckey not in active_flows:
                    inst_idx = instance_counts[ckey]
                    instance_counts[ckey] += 1
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
                        "instance": inst_idx,
                        "sizes": [],
                        "dirs": [],
                        "timestamps": [],
                        "encrypted": _detect_tls_record(raw_payload, sport, dport),
                        "emitted": False,
                    }

                flow = active_flows[ckey]
                flow["end_ts"] = float(ts)
                if _detect_tls_record(raw_payload, sport, dport):
                    flow["encrypted"] = True

                if payload_len > 0 and len(flow["sizes"]) < early_n:
                    direction = 0 if _is_in_lan(src_ip, networks, lan_prefix) else 1
                    flow["sizes"].append(int(payload_len))
                    flow["dirs"].append(int(direction))
                    flow["timestamps"].append(float(ts))

                # Emit on FIN/RST if flow has payload packets, or keep tracking until FIN/RST/new SYN
                if is_fin_or_rst and ckey in active_flows:
                    fin_flow = active_flows.pop(ckey)
                    if len(fin_flow["sizes"]) > 0:
                        completed_records.append(
                            _finalize_flow(fin_flow, early_n, feat_names, session_id, source, label_family, is_attack, domain)
                        )
            except Exception:
                continue

    for ckey, flow in active_flows.items():
        if len(flow["sizes"]) > 0:
            completed_records.append(
                _finalize_flow(flow, early_n, feat_names, session_id, source, label_family, is_attack, domain)
            )

    return pd.DataFrame(completed_records)


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
    )
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    df = pd.DataFrame(records)
    df.to_csv(args.out, index=False)
    print(f"[+] Extracted {len(df)} flows from {args.pcap} -> {args.out}")


if __name__ == "__main__":
    main()
