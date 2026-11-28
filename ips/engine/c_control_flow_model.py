#!/usr/bin/env python3
"""
ips/engine/c_control_flow_model.py — Faithful statement-by-statement Python reference model
of `ebpf/ips_engine.c` (`xdp_ips_prog` + `check_tier0_syn`) using fixed-width unsigned integer
semantics (Prompt 10 §2.3).

Used to cross-verify `MockBPFBackend.simulate_packet` on randomized packet traces so any
control-flow divergence between C (`ebpf/ips_engine.c`) and `MockBPFBackend` is caught automatically.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from ips.engine.schema import (
    PROTO_TCP,
    PROTO_UDP,
    SCHEMA_VERSION,
    VERDICT_BYPASS,
    VERDICT_DROP,
    ip_to_u32,
    u32_to_ip,
)


class CControlFlowModel:
    """Line-by-line Python translation of ebpf/ips_engine.c::xdp_ips_prog."""

    def __init__(
        self,
        early_n: int = 16,
        checkpoints: Optional[List[int]] = None,
        flow_map_max: int = 4096,
        verdict_map_max: int = 4096,
        tier0_map_max: int = 1024,
        flow_idle_ns: int = 120 * 1_000_000_000,
    ):
        self.early_n = int(early_n)
        self.early_n_minus_1 = self.early_n - 1
        self.checkpoints = sorted(checkpoints) if checkpoints else [self.early_n]
        self.num_checkpoints = len(self.checkpoints)
        self.ckpt_0 = self.checkpoints[0]
        self.ckpt_1 = self.checkpoints[1] if self.num_checkpoints >= 2 else self.early_n
        self.ckpt_2 = self.checkpoints[2] if self.num_checkpoints >= 3 else self.early_n

        self.flow_map_max = int(flow_map_max)
        self.verdict_map_max = int(verdict_map_max)
        self.tier0_map_max = int(tier0_map_max)
        self.flow_idle_ns = int(flow_idle_ns)
        self.tier0_block_ttl_ns = 30 * 1_000_000_000

        self.verdict_map: OrderedDict[Tuple[int, int, int, int, int], Dict[str, int]] = OrderedDict()
        self.flow_state: OrderedDict[Tuple[int, int, int, int, int], Dict[str, Any]] = OrderedDict()
        self.tier0_map: OrderedDict[int, Dict[str, int]] = OrderedDict()

        self.cfg = {
            "lan_ifindex": 1,
            "shed": 0,
            "debug": 0,
            "tier0_enabled": 1,
            "tier0_rate": 50,
            "tier0_capacity": 100,
        }
        self.stats = {
            "pkts_seen": 0,
            "pkts_bypassed": 0,
            "pkts_dropped_verdict": 0,
            "pkts_dropped_tier0": 0,
            "events_emitted": 0,
            "ringbuf_drop_failures": 0,
            "flow_insert_failures": 0,
            "ckpt_retry": 0,
            "ckpt_skipped_shed": 0,
        }
        self.ringbuf_full = False

    def _lru_put(self, table: OrderedDict[Any, Any], max_entries: int, key: Any, val: Any) -> None:
        if key in table:
            table.move_to_end(key)
        elif len(table) >= max_entries:
            table.popitem(last=False)
        table[key] = val

    def _canonical_key(self, saddr: int, sport: int, daddr: int, dport: int, proto_u8: int) -> Tuple[int, int, int, int, int]:
        if (saddr < daddr) or (saddr == daddr and sport <= dport):
            return (saddr, daddr, sport, dport, proto_u8)
        return (daddr, saddr, dport, sport, proto_u8)

    def set_verdict_by_endpoints(self, src_ip: str, sport: int, dst_ip: str, dport: int, proto: str, action: int, expiry_ns: int) -> None:
        p_u8 = PROTO_TCP if proto.upper() == "TCP" else PROTO_UDP
        key = self._canonical_key(ip_to_u32(src_ip), sport & 0xFFFF, ip_to_u32(dst_ip), dport & 0xFFFF, p_u8)
        self._lru_put(self.verdict_map, self.verdict_map_max, key, {"action": int(action) & 0xFF, "expiry_ns": int(expiry_ns)})

    def _check_tier0_syn(self, saddr: int, now_ns: int) -> int:
        rate = self.cfg["tier0_rate"] if self.cfg["tier0_rate"] else 50
        cap = self.cfg["tier0_capacity"] if self.cfg["tier0_capacity"] else 100
        cap_fp = cap * 1000

        if saddr not in self.tier0_map:
            init_b = {
                "last_ts_ns": now_ns,
                "blocked_until_ns": 0,
                "tokens_fp": ((cap - 1) * 1000) if cap > 1 else 0,
            }
            self._lru_put(self.tier0_map, self.tier0_map_max, saddr, init_b)
            return 0

        self.tier0_map.move_to_end(saddr)
        b = self.tier0_map[saddr]
        if b["blocked_until_ns"] > now_ns:
            self.stats["pkts_dropped_tier0"] += 1
            return 1

        elapsed_ns = (now_ns - b["last_ts_ns"]) if now_ns > b["last_ts_ns"] else 0
        add_fp = (elapsed_ns * rate) // 1_000_000
        new_tokens = b["tokens_fp"] + add_fp
        if new_tokens > cap_fp:
            new_tokens = cap_fp
        b["last_ts_ns"] = now_ns

        if new_tokens < 1000:
            b["tokens_fp"] = 0
            b["blocked_until_ns"] = now_ns + self.tier0_block_ttl_ns
            self.stats["pkts_dropped_tier0"] += 1
            return 1

        b["tokens_fp"] = new_tokens - 1000
        return 0

    def xdp_ips_prog(
        self,
        src_ip: str,
        sport: int,
        dst_ip: str,
        dport: int,
        proto: str,
        payload_len: int,
        direction: int,
        now_ns: int,
        tcp_flags: int = 0,
        is_syn_only: bool = False,
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        self.stats["pkts_seen"] += 1

        proto_u8 = PROTO_TCP if proto.upper() == "TCP" else PROTO_UDP
        saddr = ip_to_u32(src_ip)
        daddr = ip_to_u32(dst_ip)
        sport_u16 = int(sport) & 0xFFFF
        dport_u16 = int(dport) & 0xFFFF
        dir_u8 = int(direction) & 0xFF
        flags_u8 = int(tcp_flags) & 0xFF
        ip_tot_len = (int(payload_len) & 0xFFFF) + 40

        key = self._canonical_key(saddr, sport_u16, daddr, dport_u16, proto_u8)

        # 1. Verdict cache lookup + monotonic TTL check
        if key in self.verdict_map:
            v = self.verdict_map[key]
            if now_ns < v["expiry_ns"]:
                if v["action"] == VERDICT_DROP:
                    self.stats["pkts_dropped_verdict"] += 1
                    return ("XDP_DROP", None)
                if v["action"] == VERDICT_BYPASS:
                    self.stats["pkts_bypassed"] += 1
                    return ("XDP_PASS_BYPASS", None)
            else:
                del self.verdict_map[key]

        # 2. Tier-0 per-source SYN token bucket
        if is_syn_only and self.cfg["tier0_enabled"]:
            if self._check_tier0_syn(saddr, now_ns):
                return ("XDP_DROP", None)

        # 3. Lookup or initialize flow_state
        rec = self.flow_state.get(key)
        reinit = False
        if rec is not None:
            if is_syn_only and (((rec["flags_seen"] & 0x05) != 0) or rec["valid_len"] > 0):
                reinit = True
            elif (now_ns - rec["last_seen_ns"]) > self.flow_idle_ns:
                reinit = True

        if rec is None or reinit:
            scratch: Dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                "proto": proto_u8,
                "valid_len": 0,
                "flags_seen": flags_u8,
                "emitted_mask": 0,
                "ip_a": key[0],
                "ip_b": key[1],
                "port_a": key[2],
                "port_b": key[3],
                "initiator_ip": saddr,
                "initiator_port": sport_u16,
                "total_pkts": 1,
                "total_bytes": ip_tot_len,
                "first_ts_ns": now_ns,
                "last_ts_ns": now_ns,
                "last_seen_ns": now_ns,
                "iat_ns": [0] * self.early_n_minus_1,
                "sizes": [0] * self.early_n,
                "dirs": [0] * self.early_n,
            }
            if payload_len > 0:
                scratch["sizes"][0] = int(payload_len)
                scratch["dirs"][0] = dir_u8
                scratch["valid_len"] = 1
            self._lru_put(self.flow_state, self.flow_map_max, key, scratch)
            return ("XDP_PASS", None)

        self.flow_state.move_to_end(key)
        rec["total_pkts"] += 1
        rec["total_bytes"] += ip_tot_len
        rec["flags_seen"] |= flags_u8
        rec["last_seen_ns"] = now_ns

        if payload_len > 0 and rec["valid_len"] < self.early_n:
            idx = rec["valid_len"]
            if idx > 0 and (idx - 1) < self.early_n_minus_1:
                delta = (now_ns - rec["last_ts_ns"]) if now_ns > rec["last_ts_ns"] else 0
                rec["iat_ns"][idx - 1] = delta
            if idx < self.early_n:
                rec["sizes"][idx] = int(payload_len)
                rec["dirs"][idx] = dir_u8
                rec["valid_len"] = idx + 1
            rec["last_ts_ns"] = now_ns

        # 4. Progressive checkpoint else-if chain
        ckpt_hit = -1
        if rec["valid_len"] >= self.ckpt_0 and not (rec["emitted_mask"] & (1 << 0)):
            ckpt_hit = 0
        elif self.num_checkpoints >= 2 and rec["valid_len"] >= self.ckpt_1 and not (rec["emitted_mask"] & (1 << 1)):
            ckpt_hit = 1
        elif self.num_checkpoints >= 3 and rec["valid_len"] >= self.ckpt_2 and not (rec["emitted_mask"] & (1 << 2)):
            ckpt_hit = 2
        elif rec["valid_len"] >= self.early_n and not (rec["emitted_mask"] & (1 << (self.num_checkpoints - 1))):
            ckpt_hit = self.num_checkpoints - 1

        if ckpt_hit >= 0:
            if self.cfg["shed"]:
                self.stats["ckpt_skipped_shed"] += 1
                return ("XDP_PASS", None)
            if self.ringbuf_full:
                self.stats["ringbuf_drop_failures"] += 1
                self.stats["ckpt_retry"] += 1
                return ("XDP_PASS", None)

            vlen = rec["valid_len"]
            ev = {
                "schema_version": SCHEMA_VERSION,
                "proto": "TCP" if rec["proto"] == PROTO_TCP else "UDP",
                "valid_len": vlen,
                "checkpoint_idx": ckpt_hit,
                "flags_seen": rec["flags_seen"],
                "ip_a": u32_to_ip(rec["ip_a"]),
                "port_a": rec["port_a"],
                "ip_b": u32_to_ip(rec["ip_b"]),
                "port_b": rec["port_b"],
                "initiator_ip": u32_to_ip(rec["initiator_ip"]),
                "initiator_port": rec["initiator_port"],
                "total_pkts": rec["total_pkts"],
                "total_bytes": rec["total_bytes"],
                "first_ts_ns": rec["first_ts_ns"],
                "last_ts_ns": rec["last_ts_ns"],
                "sizes": rec["sizes"][:vlen],
                "dirs": rec["dirs"][:vlen],
                "iat_ns": rec["iat_ns"][: max(0, vlen - 1)],
            }
            self.stats["events_emitted"] += 1
            rec["emitted_mask"] |= 1 << ckpt_hit
            return ("XDP_PASS", ev)

        return ("XDP_PASS", None)
