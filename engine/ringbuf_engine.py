#!/usr/bin/env python3
"""
engine/ringbuf_engine.py — two-tier inline IPS core engine.

Kernel (XDP): bidirectional flow tracking, first-12-packet feature capture,
feature event to ring buffer, drop-map enforcement.
User space (this file): consume events, print features, write verdicts.

The decision rule is a PLACEHOLDER (mean-IAT threshold) proving the closed
loop. Phase 4 replaces it with the INT8 autoencoder + EVT threshold.

Run:  sudo python3 engine/ringbuf_engine.py     (Ctrl-C to stop)
"""
import os
import ctypes
import socket
import struct
import time

from bcc import BPF

try:
    import yaml
    _cfg_path = os.path.join(os.path.dirname(__file__), "..", "configs", "system.yaml")
    with open(_cfg_path, "r") as _f:
        _cfg = yaml.safe_load(_f) or {}
    EARLY_N = int(_cfg.get("system", {}).get("early_n", 12))
    AUTO_BLOCK_MEAN_IAT_MS = float(_cfg.get("engine", {}).get("auto_block_mean_iat_ms", 50.0))
except Exception:
    EARLY_N = 12
    AUTO_BLOCK_MEAN_IAT_MS = 50.0

IFACE = "v-lan-gw"

XDP_SRC = r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

#define EARLY_N 12

#ifndef __constant_htons
#define __constant_htons(x) __builtin_bswap16(x)
#endif

struct flow_key {
    u32 a_ip;
    u32 b_ip;
    u16 a_port;
    u16 b_port;
    u8  proto;
    u8  pad[3];
};

struct flow_state {
    u16 pkt_count;
    u16 sizes[EARLY_N];
    u8  dirs[EARLY_N];
    u64 iats_ns[EARLY_N - 1];
    u64 last_ts_ns;
};

struct ips_event {
    u32 src_ip;
    u32 dst_ip;
    u64 ts_ns;
    u64 iat_ns;
    u16 src_port;
    u16 dst_port;
    u16 pkt_len;
    u8  event_type; // 1 = PKT_TRACE, 2 = EARLY_FLOW, 3 = PKT_DROP
    u8  proto;
    u8  pkt_index;
    u8  dir;
    u8  pad[2];
    u16 sizes[EARLY_N];
    u8  dirs[EARLY_N];
    u64 iats_ns[EARLY_N - 1];
};

BPF_HASH(flow_state, struct flow_key, struct flow_state, 4096);
BPF_HASH(drop_map, u32, u8, 256);
BPF_RINGBUF_OUTPUT(events, 1 << 17);
BPF_PERCPU_ARRAY(scratch_evt, struct ips_event, 1);
BPF_PERCPU_ARRAY(zero_state, struct flow_state, 1);

int xdp_engine(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->ihl != 5) return XDP_PASS;

    u32 zero_idx = 0;
    struct ips_event *evt = scratch_evt.lookup(&zero_idx);
    if (!evt) return XDP_PASS;

    u32 saddr = ip->saddr;
    u8 *blocked = drop_map.lookup(&saddr);
    if (blocked && *blocked) {
        __builtin_memset(evt, 0, sizeof(*evt));
        evt->event_type = 3; // PKT_DROP
        evt->src_ip = ip->saddr;
        evt->dst_ip = ip->daddr;
        evt->proto  = ip->protocol;
        evt->pkt_len = (u16)(data_end - data);
        evt->ts_ns  = bpf_ktime_get_ns();
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + 20;
            if ((void *)(tcp + 1) <= data_end) {
                evt->src_port = tcp->source;
                evt->dst_port = tcp->dest;
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + 20;
            if ((void *)(udp + 1) <= data_end) {
                evt->src_port = udp->source;
                evt->dst_port = udp->dest;
            }
        }
        events.ringbuf_output(evt, sizeof(*evt), 0);
        return XDP_DROP;
    }

    u16 sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + 20;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        sport = tcp->source; dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + 20;
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        sport = udp->source; dport = udp->dest;
    } else {
        return XDP_PASS;
    }

    struct flow_key key = {};
    u8 dir;
    if (ip->saddr < ip->daddr ||
        (ip->saddr == ip->daddr && sport < dport)) {
        key.a_ip = ip->saddr; key.a_port = sport;
        key.b_ip = ip->daddr; key.b_port = dport;
        dir = 1;
    } else {
        key.a_ip = ip->daddr; key.a_port = dport;
        key.b_ip = ip->saddr; key.b_port = sport;
        dir = 0;
    }
    key.proto = ip->protocol;

    u64 now = bpf_ktime_get_ns();
    u64 len = (__u64)(data_end - data);

    struct flow_state *zero = zero_state.lookup(&zero_idx);
    if (!zero) return XDP_PASS;
    struct flow_state *st = flow_state.lookup_or_try_init(&key, zero);
    if (!st) return XDP_PASS;

    u16 n = st->pkt_count;
    if (n == 0) {
        st->pkt_count = 1;
        st->sizes[0]  = (u16)len;
        st->dirs[0]   = dir;
        st->last_ts_ns = now;

        __builtin_memset(evt, 0, sizeof(*evt));
        evt->event_type = 1; // PKT_TRACE
        evt->src_ip = ip->saddr; evt->dst_ip = ip->daddr;
        evt->src_port = sport;   evt->dst_port = dport;
        evt->proto = ip->protocol;
        evt->pkt_len = (u16)len;
        evt->pkt_index = 1;
        evt->dir = dir;
        evt->ts_ns = now;
        events.ringbuf_output(evt, sizeof(*evt), 0);
        return XDP_PASS;
    }
    if (n >= EARLY_N) {
        return XDP_PASS;
    }

    u64 iat = now - st->last_ts_ns;
    st->iats_ns[n - 1] = iat;
    st->sizes[n] = (u16)len;
    st->dirs[n]  = dir;
    st->pkt_count = n + 1;
    st->last_ts_ns = now;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = 1; // PKT_TRACE
    evt->src_ip = ip->saddr; evt->dst_ip = ip->daddr;
    evt->src_port = sport;   evt->dst_port = dport;
    evt->proto = ip->protocol;
    evt->pkt_len = (u16)len;
    evt->pkt_index = (u8)st->pkt_count;
    evt->dir = dir;
    evt->ts_ns = now;
    evt->iat_ns = iat;
    events.ringbuf_output(evt, sizeof(*evt), 0);

    if (st->pkt_count == EARLY_N) {
        __builtin_memset(evt, 0, sizeof(*evt));
        evt->event_type = 2; // EARLY_FLOW
        evt->src_ip = ip->saddr; evt->dst_ip = ip->daddr;
        evt->src_port = sport;   evt->dst_port = dport;
        evt->proto = ip->protocol;
        evt->pkt_len = (u16)len;
        evt->pkt_index = (u8)st->pkt_count;
        evt->ts_ns = now;
        #pragma unroll
        for (int i = 0; i < EARLY_N; i++) {
            evt->sizes[i] = st->sizes[i];
            evt->dirs[i]  = st->dirs[i];
        }
        #pragma unroll
        for (int i = 0; i < EARLY_N - 1; i++)
            evt->iats_ns[i] = st->iats_ns[i];
        events.ringbuf_output(evt, sizeof(*evt), 0);
    }
    return XDP_PASS;
}
"""

class IPSEvent(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("ts_ns", ctypes.c_uint64),
        ("iat_ns", ctypes.c_uint64),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("pkt_len", ctypes.c_uint16),
        ("event_type", ctypes.c_uint8),
        ("proto", ctypes.c_uint8),
        ("pkt_index", ctypes.c_uint8),
        ("dir", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 2),
        ("sizes", ctypes.c_uint16 * EARLY_N),
        ("dirs", ctypes.c_uint8 * EARLY_N),
        ("iats_ns", ctypes.c_uint64 * (EARLY_N - 1)),
    ]

def ip_str(v):
    return socket.inet_ntoa(struct.pack("=I", v))

def main():
    bpf = BPF(text=XDP_SRC)
    fn = bpf.load_func("xdp_engine", BPF.XDP)
    try:
        try:
            bpf.attach_xdp(IFACE, fn)
        except Exception:
            bpf.attach_xdp(IFACE, fn, flags=2)   # generic/SKB mode fallback
    except Exception as e:
        print(f"\033[91m[engine ERROR] Failed to attach XDP to '{IFACE}'.\033[0m")
        print(f"               Ensure network topology is up: 'sudo ./scripts/topology.sh create'")
        print(f"               Details: {e}")
        return

    print("\033[1;32m" + "="*84)
    print(f"  [TWO-TIER INLINE IPS ENGINE] Online & Attached to '{IFACE}'")
    print(f"  Architecture  : eBPF/XDP Fast-Path <---> User-Space Feature Engine (RingBuffer)")
    print(f"  Early-N Window: First {EARLY_N} packets per flow")
    print(f"  Anomaly Rule  : Auto-Quarantine if mean IAT < {AUTO_BLOCK_MEAN_IAT_MS} ms")
    print("="*84 + "\033[0m\n")

    events = bpf["events"]
    drop_map = bpf["drop_map"]
    stats = {"tracked": 0, "evaluated": 0, "dropped": 0}

    def on_event(cpu, data, size):
        e = IPSEvent.from_buffer_copy(data)
        proto_str = "TCP" if e.proto == 6 else ("UDP" if e.proto == 17 else f"P({e.proto})")
        src_str = f"{ip_str(e.src_ip)}:{socket.ntohs(e.src_port)}"
        dst_str = f"{ip_str(e.dst_ip)}:{socket.ntohs(e.dst_port)}"
        ts = time.strftime('%H:%M:%S')

        if e.event_type == 1:
            # Per-packet early flow trace
            stats["tracked"] += 1
            dir_str = "OUT" if e.dir == 1 else "IN "
            iat_ms = e.iat_ns / 1e6
            print(f"\033[90m[{ts}]\033[0m \033[33m[FLOW TRACK #{e.pkt_index:2d}/{EARLY_N}]\033[0m "
                  f"{src_str:<21} -> {dst_str:<21} [{proto_str:<3}] "
                  f"len={e.pkt_len:<4}B dir={dir_str} iat={iat_ms:6.2f}ms")

        elif e.event_type == 2:
            # 12-packet early-flow feature completion
            stats["evaluated"] += 1
            mean_iat_ms = sum(e.iats_ns) / (EARLY_N - 1) / 1e6
            is_anomaly = (e.proto == 6 and mean_iat_ms < AUTO_BLOCK_MEAN_IAT_MS)
            sizes_list = list(e.sizes)
            dirs_list = ["OUT" if d == 1 else "IN" for d in e.dirs]
            iats_ms_list = [round(x / 1e6, 2) for x in e.iats_ns]

            print("\n" + "\033[1;36m" + "="*84)
            print(f" >>> [IPS VERDICT ENGINE] 12-PACKET EARLY-FLOW SIGNATURE CAPTURED (Flow #{stats['evaluated']}) <<<")
            print("="*84 + "\033[0m")
            print(f"  \033[1mFlow 5-Tuple   :\033[0m {src_str} -> {dst_str} [{proto_str}]")
            print(f"  \033[1mPacket Sizes(B):\033[0m {sizes_list}")
            print(f"  \033[1mDirections     :\033[0m {dirs_list}")
            print(f"  \033[1mIAT Vector (ms):\033[0m {iats_ms_list}")
            print(f"  \033[1mMean IAT       :\033[0m \033[1;33m{mean_iat_ms:.2f} ms\033[0m  (Anomaly Threshold: < {AUTO_BLOCK_MEAN_IAT_MS:.1f} ms)")

            if is_anomaly:
                drop_map[ctypes.c_uint(e.src_ip)] = ctypes.c_ubyte(1)
                print(f"  \033[1;41;37m VERDICT: MALICIOUS (PERIODIC C2 BEACON ANOMALY DETECTED) \033[0m")
                print(f"  \033[1;31m>>> INLINE ENFORCEMENT: Writing {ip_str(e.src_ip)} to eBPF drop_map (KERNEL DROP ACTIVE) <<<\033[0m")
            else:
                print(f"  \033[1;42;30m VERDICT: BENIGN (NORMAL IoT TRAFFIC DYNAMICS) \033[0m")
                print(f"  \033[32m>>> FAST-PATH CACHE: Allowing flow without user-space penalty <<<\033[0m")
            print("\033[1;36m" + "="*84 + "\033[0m\n")

        elif e.event_type == 3:
            # Dropped packet intercepted in XDP
            stats["dropped"] += 1
            print(f"\033[90m[{ts}]\033[0m \033[1;31m[KERNEL XDP_DROP #{stats['dropped']:<4d}]\033[0m "
                  f"INTERCEPTED & REJECTED: {src_str:<21} -> {dst_str:<21} [{proto_str}] len={e.pkt_len:<4}B "
                  f"\033[31m[REASON: IP in drop_map]\033[0m")

    events.open_ring_buffer(on_event)
    try:
        while True:
            bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        print("\n\033[1;33m[engine] Stopping engine and detaching XDP...\033[0m")
    finally:
        try:
            bpf.remove_xdp(IFACE)
        except Exception:
            bpf.remove_xdp(IFACE, flags=2)
    print(f"[engine] Detached cleanly. Summary: {stats['tracked']} pkts tracked, {stats['evaluated']} flows evaluated, {stats['dropped']} packets dropped in kernel.")


if __name__ == "__main__":
    main()
