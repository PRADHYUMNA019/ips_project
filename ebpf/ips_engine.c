// ebpf/ips_engine.c — Kernel Fast Path v2 (XDP/eBPF for BCC)
//
// Addresses defects F3-F5, F7-F11 from the 30% audit:
//   - F3: Bidirectional awareness via attachment to both gateway ports (v-lan-gw and v-wan-gw);
//         direction derived from ctx->ingress_ifindex vs cfg.lan_ifindex (0=LAN->WAN, 1=WAN->LAN).
//   - F4: Real kernel verdict cache (verdict_map, LRU_HASH) with BYPASS (1) and DROP (2) actions.
//   - F5: Monotonic TTL expiration (bpf_ktime_get_ns() < expiry_ns) enforced in XDP.
//   - F7: Bounded BPF_MAP_TYPE_LRU_HASH for flow_state, verdict_map, and tier0_map.
//   - F8: Emits ONE aggregated EARLY_FLOW event per flow at payload packet N (not per-packet).
//   - F9: Variable IP/TCP header parsing; payload-only counting for early-flow features.
//   - F10: Constants (EARLY_N, map sizes) injected by ips/engine/schema.py from configs/system.yaml.
//   - F11: Single source file loaded by ips/engine/engine.py; ebpf/xdp_v1.c kept as no-op baseline.

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

#ifndef SCHEMA_VERSION
#define SCHEMA_VERSION 4
#endif

#ifndef FLOW_IDLE_NS
#define FLOW_IDLE_NS (120ULL * 1000000000ULL)
#endif

#ifndef NUM_CHECKPOINTS
#define NUM_CHECKPOINTS 3
#endif

#ifndef CKPT_0
#define CKPT_0 4
#endif

#ifndef CKPT_1
#define CKPT_1 8
#endif

#ifndef CKPT_2
#define CKPT_2 16
#endif

#ifndef EARLY_N
#define EARLY_N 16
#endif

#ifndef EARLY_N_MINUS_1
#define EARLY_N_MINUS_1 (EARLY_N - 1)
#endif

#ifndef FLOW_MAP_MAX
#define FLOW_MAP_MAX 4096
#endif

#ifndef VERDICT_MAP_MAX
#define VERDICT_MAP_MAX 4096
#endif

#ifndef TIER0_DEFAULT_RATE
#define TIER0_DEFAULT_RATE 50
#endif

#ifndef TIER0_DEFAULT_CAPACITY
#define TIER0_DEFAULT_CAPACITY 100
#endif

#ifndef TIER0_BLOCK_TTL_NS
#define TIER0_BLOCK_TTL_NS (30ULL * 1000000000ULL)
#endif

#define VERDICT_NONE   0
#define VERDICT_BYPASS 1
#define VERDICT_DROP   2

struct flow_key {
    __u32 ip_a;
    __u32 ip_b;
    __u16 port_a;
    __u16 port_b;
    __u8  proto;
    __u8  pad[3];
} __attribute__((packed));

struct verdict_entry {
    __u8  action;      // 1 = BYPASS, 2 = DROP
    __u8  pad[7];
    __u64 expiry_ns;   // bpf_ktime_get_ns() deadline
} __attribute__((packed));

struct cfg_entry {
    __u32 lan_ifindex;
    __u8  shed;
    __u8  debug;
    __u8  tier0_enabled;
    __u8  pad;
    __u32 tier0_rate;
    __u32 tier0_capacity;
} __attribute__((packed));

struct stats_entry {
    __u64 pkts_seen;
    __u64 pkts_bypassed;
    __u64 pkts_dropped_verdict;
    __u64 pkts_dropped_tier0;
    __u64 events_emitted;
    __u64 ringbuf_drop_failures;
    __u64 flow_insert_failures;
    __u64 ckpt_retry;
    __u64 ckpt_skipped_shed;
} __attribute__((packed));

struct tier0_bucket {
    __u64 last_ts_ns;
    __u64 blocked_until_ns;
    __u32 tokens_fp;   // fixed-point tokens * 1000
    __u32 pad;
} __attribute__((packed));

struct flow_record {
    __u32 schema_version;
    __u8  proto;
    __u8  valid_len;
    __u8  flags_seen;
    __u8  emitted_mask; // bitmask of emitted checkpoints 0..K-1 (C1 / N7)
    __u32 ip_a;
    __u32 ip_b;
    __u16 port_a;
    __u16 port_b;
    __u32 initiator_ip;
    __u16 initiator_port;
    __u16 pad2;
    __u32 total_pkts;
    __u32 total_bytes;
    __u32 pad3;
    __u64 first_ts_ns;
    __u64 last_ts_ns;
    __u64 last_seen_ns;
    __u64 iat_ns[EARLY_N_MINUS_1];
    __u16 sizes[EARLY_N];
    __u8  dirs[EARLY_N];
} __attribute__((packed));

// Event structure pushed to user space via ring buffer (matches ips/engine/schema.py)
struct early_flow_event {
    __u32 schema_version;
    __u8  proto;
    __u8  valid_len;
    __u8  flags_seen;
    __u8  checkpoint_idx; // 0..K-1 progressive checkpoint index (C1 / N7)
    __u32 ip_a;
    __u32 ip_b;
    __u16 port_a;
    __u16 port_b;
    __u32 initiator_ip;
    __u16 initiator_port;
    __u16 pad2;
    __u32 total_pkts;
    __u32 total_bytes;
    __u32 pad3;
    __u64 first_ts_ns;
    __u64 last_ts_ns;
    __u64 iat_ns[EARLY_N_MINUS_1];
    __u16 sizes[EARLY_N];
    __u8  dirs[EARLY_N];
#if ((3 * EARLY_N) % 8) != 0
    __u8  tail_pad[8 - ((3 * EARLY_N) % 8)];
#endif
} __attribute__((packed));

// BPF Maps
BPF_TABLE("lru_hash", struct flow_key, struct verdict_entry, verdict_map, VERDICT_MAP_MAX);
BPF_TABLE("lru_hash", struct flow_key, struct flow_record, flow_state, FLOW_MAP_MAX);
BPF_TABLE("lru_hash", __u32, struct tier0_bucket, tier0_map, 1024);
BPF_ARRAY(cfg_map, struct cfg_entry, 1);
BPF_PERCPU_ARRAY(stats_map, struct stats_entry, 1);
BPF_PERCPU_ARRAY(scratch_map, struct flow_record, 1);
BPF_RINGBUF_OUTPUT(events, 1 << 16); // 64 KB ring buffer

static __always_inline int check_tier0_syn(__u32 src_ip, __u64 now_ns,
                                           struct cfg_entry *cfg,
                                           struct stats_entry *st) {
    struct tier0_bucket *b = tier0_map.lookup(&src_ip);
    __u32 rate = cfg->tier0_rate ? cfg->tier0_rate : TIER0_DEFAULT_RATE;
    __u32 cap  = cfg->tier0_capacity ? cfg->tier0_capacity : TIER0_DEFAULT_CAPACITY;
    __u32 cap_fp = cap * 1000U;

    if (!b) {
        struct tier0_bucket init_b = {};
        init_b.last_ts_ns = now_ns;
        init_b.blocked_until_ns = 0;
        init_b.tokens_fp = (cap > 1) ? ((cap - 1) * 1000U) : 0;
        tier0_map.update(&src_ip, &init_b);
        return 0;
    }

    if (b->blocked_until_ns > now_ns) {
        if (st) st->pkts_dropped_tier0++;
        return 1; // DROP
    }

    __u64 elapsed_ns = (now_ns > b->last_ts_ns) ? (now_ns - b->last_ts_ns) : 0;
    // Refill tokens: elapsed_ns * rate / 1e6 gives millitokens
    __u64 add_fp = (elapsed_ns * (__u64)rate) / 1000000ULL;
    __u64 new_tokens = (__u64)b->tokens_fp + add_fp;
    if (new_tokens > (__u64)cap_fp) {
        new_tokens = (__u64)cap_fp;
    }
    b->last_ts_ns = now_ns;

    if (new_tokens < 1000ULL) {
        b->tokens_fp = 0;
        b->blocked_until_ns = now_ns + TIER0_BLOCK_TTL_NS;
        if (st) st->pkts_dropped_tier0++;
        return 1; // DROP
    }

    b->tokens_fp = (__u32)(new_tokens - 1000ULL);
    return 0;
}

int xdp_ips_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    int zero = 0;
    struct stats_entry *st = stats_map.lookup(&zero);
    if (st) {
        st->pkts_seen++;
    }

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Only inspect IPv4; pass IPv6 / ARP (documented in LIMITATIONS.md)
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 ip_hdr_len = (__u32)ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }
    if ((void *)ip + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    __u8 proto = ip->protocol;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
        return XDP_PASS;
    }

    __u32 saddr = bpf_ntohl(ip->saddr);
    __u32 daddr = bpf_ntohl(ip->daddr);
    __u16 sport = 0;
    __u16 dport = 0;
    __u32 l4_hdr_len = 0;
    __u8  tcp_flags = 0;
    __u8  is_syn_only = 0;

    void *l4 = (void *)ip + ip_hdr_len;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        l4_hdr_len = (__u32)tcp->doff * 4;
        if (l4_hdr_len < sizeof(struct tcphdr) || (void *)tcp + l4_hdr_len > data_end) {
            return XDP_PASS;
        }
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
        if (tcp->syn) tcp_flags |= 0x02;
        if (tcp->ack) tcp_flags |= 0x10;
        if (tcp->fin) tcp_flags |= 0x01;
        if (tcp->rst) tcp_flags |= 0x04;
        if (tcp->psh) tcp_flags |= 0x08;
        if (tcp->syn && !tcp->ack) {
            is_syn_only = 1;
        }
    } else {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        l4_hdr_len = sizeof(struct udphdr);
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    }

    __u64 now_ns = bpf_ktime_get_ns();
    struct cfg_entry *cfg = cfg_map.lookup(&zero);

    // Direction from ingress interface index (F3): 0 = LAN->WAN, 1 = WAN->LAN
    __u8 dir = 0;
    if (cfg && cfg->lan_ifindex != 0) {
        dir = (ctx->ingress_ifindex == cfg->lan_ifindex) ? 0 : 1;
    }

    // Build canonical bidirectional flow key
    struct flow_key key = {};
    key.proto = proto;
    if ((saddr < daddr) || (saddr == daddr && sport <= dport)) {
        key.ip_a = saddr;
        key.port_a = sport;
        key.ip_b = daddr;
        key.port_b = dport;
    } else {
        key.ip_a = daddr;
        key.port_a = dport;
        key.ip_b = saddr;
        key.port_b = sport;
    }

    // 1. Check Verdict Cache (F4, F5)
    struct verdict_entry *v = verdict_map.lookup(&key);
    if (v) {
        if (now_ns < v->expiry_ns) {
            if (v->action == VERDICT_DROP) {
                if (st) st->pkts_dropped_verdict++;
                return XDP_DROP;
            }
            if (v->action == VERDICT_BYPASS) {
                if (st) st->pkts_bypassed++;
                return XDP_PASS;
            }
        } else {
            // Verdict expired -> remove and treat as unknown
            verdict_map.delete(&key);
        }
    }

    // 2. Check Tier-0 per-source new-flow-rate guard on TCP SYN (rule-based, not ML)
    if (is_syn_only && cfg && cfg->tier0_enabled) {
        if (check_tier0_syn(saddr, now_ns, cfg, st)) {
            return XDP_DROP;
        }
    }

    // Compute L4 payload length from IP total_len (more accurate than frame len when Ethernet padded)
    __u16 ip_tot_len = bpf_ntohs(ip->tot_len);
    __u32 hdr_sum = ip_hdr_len + l4_hdr_len;
    __u16 payload_len = 0;
    if (ip_tot_len > hdr_sum) {
        payload_len = ip_tot_len - (__u16)hdr_sum;
    }

    // 3. Lookup or initialize flow_state (F7, F9, A1)
    struct flow_record *rec = flow_state.lookup(&key);
    int reinit = 0;
    if (rec) {
        if (is_syn_only && ((rec->flags_seen & 0x05) != 0 || rec->valid_len > 0)) {
            reinit = 1;
        } else if ((now_ns - rec->last_seen_ns) > FLOW_IDLE_NS) {
            reinit = 1;
        }
    }

    if (!rec || reinit) {
        struct flow_record *scratch = scratch_map.lookup(&zero);
        if (!scratch) {
            return XDP_PASS;
        }
        __builtin_memset(scratch, 0, sizeof(*scratch));
        scratch->schema_version = SCHEMA_VERSION;
        scratch->proto = proto;
        scratch->ip_a = key.ip_a;
        scratch->ip_b = key.ip_b;
        scratch->port_a = key.port_a;
        scratch->port_b = key.port_b;
        scratch->initiator_ip = saddr;
        scratch->initiator_port = sport;
        scratch->first_ts_ns = now_ns;
        scratch->last_ts_ns = now_ns;
        scratch->last_seen_ns = now_ns;
        scratch->total_pkts = 1;
        scratch->total_bytes = ip_tot_len;
        scratch->flags_seen = tcp_flags;

        if (payload_len > 0) {
            scratch->sizes[0] = payload_len;
            scratch->dirs[0] = dir;
            scratch->valid_len = 1;
        }

        flow_state.update(&key, scratch);
        return XDP_PASS;
    }

    // Update existing flow_record
    rec->total_pkts += 1;
    rec->total_bytes += ip_tot_len;
    rec->flags_seen |= tcp_flags;
    rec->last_seen_ns = now_ns;

    if (payload_len > 0 && rec->valid_len < EARLY_N) {
        __u8 idx = rec->valid_len;
        if (idx > 0 && (idx - 1) < EARLY_N_MINUS_1) {
            __u64 delta = (now_ns > rec->last_ts_ns) ? (now_ns - rec->last_ts_ns) : 0;
            rec->iat_ns[idx - 1] = delta;
        }
        if (idx < EARLY_N) {
            rec->sizes[idx] = payload_len;
            rec->dirs[idx] = dir;
            rec->valid_len = idx + 1;
        }
        rec->last_ts_ns = now_ns;
    }

    // 4. Emit ONE EARLY_FLOW event at each progressive checkpoint CKPT_k (F8, C1/N7, A2)
    int ckpt_hit = -1;
    if (rec->valid_len >= CKPT_0 && !(rec->emitted_mask & (1U << 0))) {
        ckpt_hit = 0;
    }
#if NUM_CHECKPOINTS >= 2
    else if (rec->valid_len >= CKPT_1 && !(rec->emitted_mask & (1U << 1))) {
        ckpt_hit = 1;
    }
#endif
#if NUM_CHECKPOINTS >= 3
    else if (rec->valid_len >= CKPT_2 && !(rec->emitted_mask & (1U << 2))) {
        ckpt_hit = 2;
    }
#endif
    else if (rec->valid_len >= EARLY_N && !(rec->emitted_mask & (1U << (NUM_CHECKPOINTS - 1)))) {
        ckpt_hit = NUM_CHECKPOINTS - 1;
    }

    if (ckpt_hit >= 0) {
        if (cfg && cfg->shed) {
            // Load shedding active: do not emit, leave bit unset for later retry, fail open
            if (st) st->ckpt_skipped_shed++;
            return XDP_PASS;
        }

        struct early_flow_event *ev = events.ringbuf_reserve(sizeof(struct early_flow_event));
        if (!ev) {
            if (st) {
                st->ringbuf_drop_failures++;
                st->ckpt_retry++;
            }
            return XDP_PASS;
        }

        ev->schema_version = SCHEMA_VERSION;
        ev->proto = rec->proto;
        ev->valid_len = rec->valid_len;
        ev->flags_seen = rec->flags_seen;
        ev->checkpoint_idx = (__u8)ckpt_hit;
        ev->ip_a = rec->ip_a;
        ev->ip_b = rec->ip_b;
        ev->port_a = rec->port_a;
        ev->port_b = rec->port_b;
        ev->initiator_ip = rec->initiator_ip;
        ev->initiator_port = rec->initiator_port;
        ev->pad2 = 0;
        ev->total_pkts = rec->total_pkts;
        ev->total_bytes = rec->total_bytes;
        ev->pad3 = 0;
        ev->first_ts_ns = rec->first_ts_ns;
        ev->last_ts_ns = rec->last_ts_ns;

        #pragma unroll
        for (int i = 0; i < EARLY_N_MINUS_1; i++) {
            ev->iat_ns[i] = rec->iat_ns[i];
        }
        #pragma unroll
        for (int i = 0; i < EARLY_N; i++) {
            ev->sizes[i] = rec->sizes[i];
            ev->dirs[i] = rec->dirs[i];
        }

        events.ringbuf_submit(ev, 0);
        if (st) st->events_emitted++;
        rec->emitted_mask |= (__u8)(1U << ckpt_hit);
    }

    return XDP_PASS;
}

