#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_FLOWS 4096

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];
};

struct flow_stats {
    __u64 pkts;
    __u64 bytes;
    __u64 last_ts_ns;
    __u64 iat_sum_ns;
    __u64 iat_max_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __be32);
    __type(value, __u8);
} drop_map SEC(".maps");

SEC("xdp")
int xdp_v1(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->ihl < 5)
        return XDP_PASS;

    __u8 *drop = bpf_map_lookup_elem(&drop_map, &ip->saddr);
    if (drop && *drop == 1)
        return XDP_DROP;

    __u64 now = bpf_ktime_get_ns();
    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .proto  = ip->protocol,
    };
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip->ihl * 4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    }

    __u64 len = (__u64)(data_end - data);
    struct flow_stats *st = bpf_map_lookup_elem(&flow_map, &key);
    if (st) {
        __u64 iat = now - st->last_ts_ns;
        st->pkts += 1;
        st->bytes += len;
        st->iat_sum_ns += iat;
        if (iat > st->iat_max_ns)
            st->iat_max_ns = iat;
        st->last_ts_ns = now;
    } else {
        struct flow_stats init = { .pkts = 1, .bytes = len, .last_ts_ns = now };
        bpf_map_update_elem(&flow_map, &key, &init, BPF_ANY);
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
