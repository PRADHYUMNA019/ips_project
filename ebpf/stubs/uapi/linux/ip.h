/* STATIC-ANALYSIS STUB ONLY */
#ifndef _STUB_UAPI_LINUX_IP_H
#define _STUB_UAPI_LINUX_IP_H
#include <uapi/linux/bpf.h>

struct iphdr {
    __u8   ihl:4,
           version:4;
    __u8   tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8   ttl;
    __u8   protocol;
    __u16  check;
    __be32 saddr;
    __be32 daddr;
};

#endif
