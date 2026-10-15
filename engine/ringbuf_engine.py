#!/usr/bin/env python3
"""
engine/ringbuf_engine.py — two-tier IPS core (30% slice).

Kernel (XDP): bidirectional flow tracking, first-12-packet feature capture,
feature event to ring buffer, drop-map enforcement.
User space (this file): consume events, print features, write verdicts.

The decision rule is a PLACEHOLDER (mean-IAT threshold) proving the closed
loop. Phase 4 replaces it with the INT8 autoencoder + EVT threshold.

Run:  sudo python3 engine/ringbuf_engine.py     (Ctrl-C to stop)
"""
import ctypes
import socket
import struct
import time

from bcc import BPF

EARLY_N = 12
IFACE = "v-lan-gw"
AUTO_BLOCK_MEAN_IAT_MS = 50.0   # placeholder rule

XDP_SRC = r"""
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#define EARLY_N 12

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

struct feature_event {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  proto;
    u8  pkt_count;
    u16 sizes[EARLY_N];
    u8  dirs[EARLY_N];
    u64 iats_ns[EARLY_N - 1];
    u64 ts_ns;
};

BPF_HASH(flow_state, struct flow_key, struct flow_state, 4096);
BPF_HASH(drop_map, u32, u8, 256);
BPF_RINGBUF_OUTPUT(events, 1 << 12);

int xdp_engine(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->ihl < 5) return XDP_PASS;

    u32 saddr = ip->saddr;
    u8 *blocked = drop_map.lookup(&saddr);
    if (blocked && *blocked) return XDP_DROP;

    u16 sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        sport = tcp->source; dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip->ihl * 4;
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

    struct flow_state zero = {};
    struct flow_state *st = flow_state.lookup_or_try_init(&key, &zero);
    if (!st) return XDP_PASS;

    u16 n = st->pkt_count;
    if (n == 0) {
        st->pkt_count = 1;
        st->sizes[0]  = (u16)len;
        st->dirs[0]   = dir;
        st->last_ts_ns = now;
        return XDP_PASS;
    }
    if (n >= EARLY_N) {
        return XDP_PASS;
    }

    st->iats_ns[n - 1] = now - st->last_ts_ns;
    st->sizes[n] = (u16)len;
    st->dirs[n]  = dir;
    st->pkt_count = n + 1;
    st->last_ts_ns = now;

    if (st->pkt_count == EARLY_N) {
        struct feature_event evt = {};
        evt.src_ip = ip->saddr; evt.dst_ip = ip->daddr;
        evt.src_port = sport;   evt.dst_port = dport;
        evt.proto = ip->protocol;
        evt.pkt_count = st->pkt_count;
        #pragma unroll
        for (int i = 0; i < EARLY_N; i++) {
            evt.sizes[i] = st->sizes[i];
            evt.dirs[i]  = st->dirs[i];
        }
        #pragma unroll
        for (int i = 0; i < EARLY_N - 1; i++)
            evt.iats_ns[i] = st->iats_ns[i];
        evt.ts_ns = now;
        events.ringbuf_output(&evt, sizeof(evt), 0);
    }
    return XDP_PASS;
}
"""


def ip_str(v):
    return socket.inet_ntoa(struct.pack("=I", v))


def main():
    bpf = BPF(text=XDP_SRC)
    fn = bpf.load_func("xdp_engine", BPF.XDP)
    try:
        bpf.attach_xdp(IFACE, fn)
    except Exception:
        bpf.attach_xdp(IFACE, fn, flags=2)   # generic/SKB mode fallback
    print(f"[engine] XDP attached to {IFACE} — listening for feature events")
    print("[engine] benign TLS telemetry flows have mean_iat >= ~250 ms")
    print("[engine] a 20 ms beacon will trip the placeholder rule\n")

    events = bpf["events"]
    drop_map = bpf["drop_map"]

    def on_event(cpu, data, size):
        e = events.event(data)
        mean_iat_ms = sum(e.iats_ns) / (EARLY_N - 1) / 1e6
        print(f"[{time.strftime('%H:%M:%S')}] "
              f"{ip_str(e.src_ip)}:{e.src_port} -> "
              f"{ip_str(e.dst_ip)}:{e.dst_port} proto={e.proto} "
              f"sizes={list(e.sizes)} mean_iat={mean_iat_ms:8.1f} ms")
        # placeholder rule — replaced by model + EVT in Phase 4
        if e.proto == 6 and mean_iat_ms < AUTO_BLOCK_MEAN_IAT_MS:
            drop_map[ctypes.c_uint(e.src_ip)] = ctypes.c_ubyte(1)
            print(f"    >>> VERDICT DROP written to kernel drop_map for "
                  f"{ip_str(e.src_ip)} (placeholder rule)")

    events.open_ring_buffer(on_event)
    try:
        while True:
            bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            bpf.remove_xdp(IFACE)
        except Exception:
            bpf.remove_xdp(IFACE, flags=2)
    print("[engine] detached, clean exit")


if __name__ == "__main__":
    main()
