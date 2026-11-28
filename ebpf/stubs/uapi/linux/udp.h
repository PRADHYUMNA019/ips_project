/* STATIC-ANALYSIS STUB ONLY */
#ifndef _STUB_UAPI_LINUX_UDP_H
#define _STUB_UAPI_LINUX_UDP_H
#include <uapi/linux/bpf.h>

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __u16  check;
};

#endif
