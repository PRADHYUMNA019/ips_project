#!/usr/bin/env python3
"""
ips/eval/equivalence.py — Kernel-vs-Offline Feature Equivalence Verifier (N6, WP6).

Compares early-flow records extracted offline by ips/offline/pcap_to_flows.py
against EARLY_FLOW events emitted by the XDP fast path (ebpf/ips_engine.c)
recorded as JSONL during the same capture.

Reports:
  - Flow matching rate by canonical 5-tuple (ip_a, port_a, ip_b, port_b, proto)
  - Exact-match rate for sizes[0..N-1] (must be 100% on non-fragmented flows)
  - Exact-match rate for dirs[0..N-1] (must be 100% when attached to both v-lan-gw and v-wan-gw)
  - IAT absolute difference distribution (p50, p95, p99 in microseconds)
  - Normalized feature vector max absolute difference

Usage:
  python ips/eval/equivalence.py --pcap capture.pcap --events events.jsonl --out results/equivalence/report.md
"""
import os
import sys
import json
import argparse
from collections import defaultdict
from typing import List, Dict, Any, Tuple
import numpy as np

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)

from ips.features import build_early_vector
from ips.offline.pcap_to_flows import extract_flows_from_pcap, canonical_flow_key


def load_kernel_events_jsonl(jsonl_path: str) -> List[Dict[str, Any]]:
    """Load kernel EARLY_FLOW events from a JSONL file."""
    events = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("event_type", "EARLY_FLOW") == "EARLY_FLOW" or "sizes" in obj:
                events.append(obj)
    return events


def extract_raw_pcap_flows(pcap_path: str, early_n: int = 12, lan_prefix: str = "10.0.1.") -> List[Dict[str, Any]]:
    """
    Parse a pcap using the exact same rules as pcap_to_flows.py, returning raw
    sizes, dirs, and iat_ns alongside canonical keys for direct comparison with kernel events.
    """
    import dpkt
    import socket

    active = {}
    completed = []

    with open(pcap_path, "rb") as f:
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

                if isinstance(ip.data, dpkt.tcp.TCP):
                    l4 = ip.data
                    proto = "TCP"
                    sport, dport = int(l4.sport), int(l4.dport)
                    payload_len = len(l4.data)
                    is_syn = bool(l4.flags & dpkt.tcp.TH_SYN) and not bool(l4.flags & dpkt.tcp.TH_ACK)
                elif isinstance(ip.data, dpkt.udp.UDP):
                    l4 = ip.data
                    proto = "UDP"
                    sport, dport = int(l4.sport), int(l4.dport)
                    payload_len = len(l4.data)
                    is_syn = False
                else:
                    continue

                ckey = canonical_flow_key(src_ip, sport, dst_ip, dport, proto)
                if is_syn and ckey in active and len(active[ckey]["sizes"]) > 0:
                    completed.append(active.pop(ckey))

                if ckey not in active:
                    active[ckey] = {
                        "ip_a": ckey[0],
                        "port_a": ckey[1],
                        "ip_b": ckey[2],
                        "port_b": ckey[3],
                        "proto": ckey[4],
                        "sizes": [],
                        "dirs": [],
                        "timestamps_ns": [],
                    }

                flow = active[ckey]
                if payload_len > 0 and len(flow["sizes"]) < early_n:
                    direction = 0 if src_ip.startswith(lan_prefix) else 1
                    flow["sizes"].append(int(payload_len))
                    flow["dirs"].append(int(direction))
                    flow["timestamps_ns"].append(int(round(ts * 1e9)))
                    if len(flow["sizes"]) == early_n:
                        completed.append(active.pop(ckey))
            except Exception:
                continue

    for ckey, flow in active.items():
        if len(flow["sizes"]) > 0:
            completed.append(flow)

    for flow in completed:
        ts_ns = flow["timestamps_ns"]
        flow["iat_ns"] = [max(0, ts_ns[i] - ts_ns[i - 1]) for i in range(1, len(ts_ns))]
        flow["valid_len"] = len(flow["sizes"])
    return completed


def compare_flows(
    pcap_flows: List[Dict[str, Any]],
    kernel_events: List[Dict[str, Any]],
    early_n: int = 12,
) -> Dict[str, Any]:
    """
    Match offline pcap flows and kernel EARLY_FLOW events by canonical 5-tuple
    and compute size/direction exact-match rates and IAT error quantiles.
    """
    pcap_by_key = defaultdict(list)
    for pf in pcap_flows:
        ckey = canonical_flow_key(pf["ip_a"], pf["port_a"], pf["ip_b"], pf["port_b"], pf["proto"])
        pcap_by_key[ckey].append(pf)

    kern_by_key = defaultdict(list)
    for ke in kernel_events:
        ckey = canonical_flow_key(ke["ip_a"], ke["port_a"], ke["ip_b"], ke["port_b"], ke["proto"])
        kern_by_key[ckey].append(ke)

    matched_pairs = 0
    size_exact_matches = 0
    dir_exact_matches = 0
    iat_diffs_us = []
    vec_max_diffs = []

    for ckey, k_list in kern_by_key.items():
        p_list = pcap_by_key.get(ckey, [])
        for idx, ke in enumerate(k_list):
            if idx >= len(p_list):
                break
            pf = p_list[idx]
            matched_pairs += 1

            k_sizes = [int(x) for x in ke["sizes"][:early_n]]
            p_sizes = [int(x) for x in pf["sizes"][:early_n]]
            if k_sizes == p_sizes:
                size_exact_matches += 1

            k_dirs = [int(x) for x in ke["dirs"][:early_n]]
            p_dirs = [int(x) for x in pf["dirs"][:early_n]]
            if k_dirs == p_dirs:
                dir_exact_matches += 1

            k_iats = [int(x) for x in ke.get("iat_ns", [])[: early_n - 1]]
            p_iats = [int(x) for x in pf.get("iat_ns", [])[: early_n - 1]]
            min_len = min(len(k_iats), len(p_iats))
            for i in range(min_len):
                diff_us = abs(k_iats[i] - p_iats[i]) / 1000.0
                iat_diffs_us.append(diff_us)

            k_vec = build_early_vector(k_sizes, k_dirs, [x / 1e6 for x in k_iats], early_n=early_n)
            p_vec = build_early_vector(p_sizes, p_dirs, [x / 1e6 for x in p_iats], early_n=early_n)
            vec_max_diffs.append(float(np.max(np.abs(k_vec - p_vec))))

    size_match_rate = (size_exact_matches / matched_pairs) if matched_pairs > 0 else 0.0
    dir_match_rate = (dir_exact_matches / matched_pairs) if matched_pairs > 0 else 0.0

    if iat_diffs_us:
        arr = np.array(iat_diffs_us, dtype=np.float64)
        iat_p50 = float(np.percentile(arr, 50))
        iat_p95 = float(np.percentile(arr, 95))
        iat_p99 = float(np.percentile(arr, 99))
        iat_max = float(np.max(arr))
    else:
        iat_p50 = iat_p95 = iat_p99 = iat_max = 0.0

    return {
        "pcap_flow_count": len(pcap_flows),
        "kernel_event_count": len(kernel_events),
        "matched_flows": matched_pairs,
        "size_exact_match_rate": size_match_rate,
        "dir_exact_match_rate": dir_exact_rate if False else dir_match_rate,
        "iat_diff_p50_us": iat_p50,
        "iat_diff_p95_us": iat_p95,
        "iat_diff_p99_us": iat_p99,
        "iat_diff_max_us": iat_max,
        "feature_vec_max_abs_diff": float(np.max(vec_max_diffs)) if vec_max_diffs else 0.0,
        "passed": (
            matched_pairs > 0
            and size_match_rate == 1.0
            and dir_match_rate == 1.0
            and iat_p99 <= 1000.0  # within 1 ms (1000 us) p99
        ),
    }


def write_equivalence_report(metrics: Dict[str, Any], out_md_path: str):
    """Write human-readable equivalence report to Markdown and JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(out_md_path)), exist_ok=True)
    status_str = "PASS" if metrics["passed"] else "FAIL"
    lines = [
        "# Kernel-vs-Offline Feature Equivalence Report (N6)",
        "",
        f"- **Overall Status**: **{status_str}**",
        f"- **Offline Pcap Flows**: {metrics['pcap_flow_count']}",
        f"- **Kernel `EARLY_FLOW` Events**: {metrics['kernel_event_count']}",
        f"- **Matched Canonical Flows**: {metrics['matched_flows']}",
        "",
        "## Equivalence Metrics",
        "",
        "| Metric | Value | Target |",
        "|--------|-------|--------|",
        f"| `sizes[0..N-1]` Exact Match Rate | {metrics['size_exact_match_rate']*100:.2f}% | 100.00% |",
        f"| `dirs[0..N-1]` Exact Match Rate | {metrics['dir_exact_match_rate']*100:.2f}% | 100.00% |",
        f"| `|IAT_kernel - IAT_pcap|` p50 | {metrics['iat_diff_p50_us']:.2f} us | < 200 us |",
        f"| `|IAT_kernel - IAT_pcap|` p95 | {metrics['iat_diff_p95_us']:.2f} us | < 500 us |",
        f"| `|IAT_kernel - IAT_pcap|` p99 | {metrics['iat_diff_p99_us']:.2f} us | < 1000 us |",
        f"| Max Normalized Feature Vector Diff | {metrics['feature_vec_max_abs_diff']:.6f} | < 0.05 |",
        "",
    ]
    with open(out_md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    json_path = os.path.splitext(out_md_path)[0] + ".json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Verify kernel-vs-offline feature equivalence")
    parser.add_argument("--pcap", required=True, help="Path to pcap file")
    parser.add_argument("--events", required=True, help="Path to kernel EARLY_FLOW JSONL file")
    parser.add_argument("--early-n", type=int, default=12)
    parser.add_argument("--out", default=os.path.join(REPO_DIR, "results", "equivalence", "report.md"))
    args = parser.parse_args()

    pcap_flows = extract_raw_pcap_flows(args.pcap, early_n=args.early_n)
    kernel_events = load_kernel_events_jsonl(args.events)
    metrics = compare_flows(pcap_flows, kernel_events, early_n=args.early_n)
    write_equivalence_report(metrics, args.out)
    print(f"[+] Equivalence report written to {args.out}: {'PASS' if metrics['passed'] else 'FAIL'}")
    if not metrics["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
