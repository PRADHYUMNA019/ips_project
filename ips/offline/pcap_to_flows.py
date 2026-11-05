#!/usr/bin/env python3
"""
ips/offline/pcap_to_flows.py — Extract canonical bidirectional early-flow vectors from pcap.

Parses pcap/pcapng files, groups packets into bidirectional flows, counts only
payload-bearing packets (payload_len > 0), and emits normalized feature vectors
using ips.features.build_early_vector.

Usage:
  python ips/offline/pcap_to_flows.py <input.pcap> [--early-n 12] [--out flows.csv]
"""
import os
import sys
import socket
import argparse
from collections import defaultdict
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


def canonical_flow_key(src_ip: str, sport: int, dst_ip: str, dport: int, proto: str):
    """Derive canonical bidirectional 5-tuple flow key ordered by numeric (IP, port)."""
    ep1 = (ip_to_u32(src_ip), int(sport))
    ep2 = (ip_to_u32(dst_ip), int(dport))
    if ep1 <= ep2:
        return (src_ip, int(sport), dst_ip, int(dport), str(proto).upper())
    else:
        return (dst_ip, int(dport), src_ip, int(sport), str(proto).upper())


def extract_flows_from_pcap(filepath: str, early_n: int = 12, lan_prefix: str = "10.0.1."):
    """Parse pcap into a list of early-flow feature dictionaries."""
    if dpkt is None:
        raise RuntimeError("dpkt is required for pcap parsing")

    # Flow tracker: key -> { 'sizes': [], 'dirs': [], 'timestamps': [], 'instance': int, 'syn_seen': bool }
    active_flows = {}
    completed_records = []

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
                proto_num = ip.p

                if proto_num == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    sport, dport = tcp.sport, tcp.dport
                    payload = tcp.data
                    proto_name = "TCP"
                    is_syn = (tcp.flags & dpkt.tcp.TH_SYN) != 0
                    is_fin = (tcp.flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST)) != 0
                elif proto_num == dpkt.ip.IP_PROTO_UDP:
                    udp = ip.data
                    sport, dport = udp.sport, udp.dport
                    payload = udp.data
                    proto_name = "UDP"
                    is_syn = False
                    is_fin = False
                else:
                    continue

                # Direction: LAN->WAN = 0 (Client->Server), WAN->LAN = 1 (Server->Client)
                direction = 0 if src_ip.startswith(lan_prefix) else 1

                flow_key = canonical_flow_key(src_ip, sport, dst_ip, dport, proto_name)

                # Flow state lifecycle
                if flow_key not in active_flows or is_syn:
                    # New flow instance
                    active_flows[flow_key] = {
                        "sizes": [],
                        "dirs": [],
                        "timestamps": [],
                        "flow_key": flow_key,
                        "start_ts": ts,
                        "emitted": False,
                    }

                st = active_flows[flow_key]

                # We only track PAYLOAD-bearing packets for early window
                payload_len = len(payload)
                if payload_len > 0 and len(st["sizes"]) < early_n:
                    st["sizes"].append(payload_len)
                    st["dirs"].append(direction)
                    st["timestamps"].append(ts)

                if is_fin and not st["emitted"]:
                    # Flow finished before N
                    st["emitted"] = True

            except Exception:
                continue

    # Emit records for all observed flows
    feature_names = get_feature_names(early_n)
    assert_no_forbidden_features(feature_names)

    for key, st in active_flows.items():
        sizes = st["sizes"]
        dirs = st["dirs"]
        timestamps = st["timestamps"]

        iats = []
        for i in range(1, len(timestamps)):
            dt_ms = (timestamps[i] - timestamps[i - 1]) * 1000.0
            iats.append(max(0.01, dt_ms))

        feat_vec = build_early_vector(sizes, dirs, iats, early_n=early_n)

        record = {
            "start_ts": st["start_ts"],
            "raw_valid_len": len(sizes),
            "early_n": early_n,
        }
        for name, val in zip(feature_names, feat_vec):
            record[name] = float(val)

        completed_records.append(record)

    return pd.DataFrame(completed_records)


def main():
    parser = argparse.ArgumentParser(description="Extract early-flow features from pcap")
    parser.add_argument("pcap", help="Input pcap file")
    parser.add_argument("--early-n", type=int, default=12, help="Payload packets per window")
    parser.add_argument("--out", default=None, help="Output csv or parquet path")
    args = parser.parse_args()

    df = extract_flows_from_pcap(args.pcap, early_n=args.early_n)
    print(f"[OK] Extracted {len(df)} flow vectors from {args.pcap}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        if args.out.endswith(".parquet"):
            df.to_parquet(args.out, index=False)
        else:
            df.to_csv(args.out, index=False)
        print(f"     Saved to: {args.out}")


if __name__ == "__main__":
    main()
