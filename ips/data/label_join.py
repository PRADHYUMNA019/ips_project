#!/usr/bin/env python3
"""
ips/data/label_join.py — Join extracted flows to experiment manifests and engine events (WP2b, B3).

Provides:
  1. join_flows_to_manifest(flows_df, manifest_df):
     Labels flows using ground-truth attack episodes (src_ip + dst_ip + dport + time window)
     and flags benign flows that occurred during an active attack window (`in_attack_window=True`)
     so they are never mixed into clean benign train/calibration/validation splits (B2d).
  2. join_flows_to_engine_events(flows_df, events_list):
     Joins offline pcap flows to kernel/engine EARLY_FLOW JSONL events by canonical 5-tuple
     and flow instance order.
"""
from collections import defaultdict
from typing import List, Dict, Any
import pandas as pd

from ips.offline.pcap_to_flows import canonical_flow_key


def join_flows_to_manifest(
    flows_df: pd.DataFrame,
    manifest_df: pd.DataFrame,
    time_pad_s: float = 0.5,
) -> pd.DataFrame:
    """
    Join flow metadata (`src_ip, dst_ip, dport, start_ts, end_ts`) against an experiment
    manifest (`src_ip, dst_ip, dst_port, start_ts, end_ts, family`).
    """
    out = flows_df.copy()
    if "is_attack" not in out.columns:
        out["is_attack"] = 0
    if "label_family" not in out.columns:
        out["label_family"] = "benign"
    out["in_attack_window"] = False

    if manifest_df is None or len(manifest_df) == 0:
        return out

    episodes = manifest_df.to_dict(orient="records")

    for idx, row in out.iterrows():
        f_start = float(row.get("start_ts", 0.0))
        f_end = float(row.get("end_ts", f_start))
        f_src = str(row.get("src_ip", ""))
        f_dst = str(row.get("dst_ip", ""))
        f_dport = int(row.get("dport", 0))

        for ep in episodes:
            ep_start = float(ep.get("start_ts", 0.0)) - time_pad_s
            ep_end = float(ep.get("end_ts", ep_start)) + time_pad_s
            # Check temporal overlap
            if f_end >= ep_start and f_start <= ep_end:
                out.at[idx, "in_attack_window"] = True
                ep_src = str(ep.get("src_ip", ""))
                ep_dst = str(ep.get("dst_ip", ""))
                ep_dport = int(ep.get("dst_port", 0))
                if f_src == ep_src and (not ep_dst or f_dst == ep_dst) and (ep_dport <= 0 or f_dport == ep_dport):
                    out.at[idx, "is_attack"] = 1
                    out.at[idx, "label_family"] = str(ep.get("family", "unknown_attack"))
                    break

    return out


def join_flows_to_engine_events(
    flows_df: pd.DataFrame,
    events: List[Dict[str, Any]],
) -> pd.DataFrame:
    """
    Join offline extracted flows (`flows_df`) to user-space engine `EARLY_FLOW` event dicts
    by canonical 5-tuple `(ip_a, port_a, ip_b, port_b, proto)` and instance order.
    """
    out = flows_df.copy()
    out["engine_matched"] = False
    out["engine_score"] = None
    out["engine_verdict"] = None

    ev_by_key = defaultdict(list)
    for ev in events:
        ip1 = str(ev.get("ip_a", ev.get("src_ip", "0.0.0.0")))
        p1 = int(ev.get("port_a", ev.get("sport", 0)))
        ip2 = str(ev.get("ip_b", ev.get("dst_ip", "0.0.0.0")))
        p2 = int(ev.get("port_b", ev.get("dport", 0)))
        proto = str(ev.get("proto", "TCP"))
        ckey = canonical_flow_key(ip1, p1, ip2, p2, proto)
        ev_by_key[ckey].append(ev)

    seen_counts = defaultdict(int)
    for idx, row in out.iterrows():
        ckey = canonical_flow_key(
            str(row["src_ip"]),
            int(row["sport"]),
            str(row["dst_ip"]),
            int(row["dport"]),
            str(row.get("proto", "TCP")),
        )
        inst = seen_counts[ckey]
        seen_counts[ckey] += 1
        candidates = ev_by_key.get(ckey, [])
        if inst < len(candidates):
            matched_ev = candidates[inst]
            out.at[idx, "engine_matched"] = True
            out.at[idx, "engine_score"] = matched_ev.get("score", None)
            out.at[idx, "engine_verdict"] = matched_ev.get("verdict_written", None)

    return out
