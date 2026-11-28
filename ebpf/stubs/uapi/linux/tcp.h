/* STATIC-ANALYSIS STUB ONLY */
#ifndef _STUB_UAPI_LINUX_TCP_H
#define _STUB_UAPI_LINUX_TCP_H
#include <uapi/linux/bpf.h>

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16  res1:4,
           doff:4,
           fin:1,
           syn:1,
           rst:1,
           psh:1,
           ack:1,
           urg:1,
           ece:1,
           cwr:1;
    __be16 window;
    __u16  check;
    __be16 urg_ptr;
};

#endif
