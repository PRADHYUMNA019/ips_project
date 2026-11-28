/* STATIC-ANALYSIS STUB ONLY */
#ifndef _STUB_UAPI_LINUX_IF_ETHER_H
#define _STUB_UAPI_LINUX_IF_ETHER_H
#include <uapi/linux/bpf.h>

#define ETH_ALEN 6
#define ETH_P_IP 0x0800

struct ethhdr {
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    __be16        h_proto;
} __attribute__((packed));

#endif
