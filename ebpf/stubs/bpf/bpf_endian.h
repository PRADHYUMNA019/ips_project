/* STATIC-ANALYSIS STUB ONLY */
#ifndef _STUB_BPF_ENDIAN_H
#define _STUB_BPF_ENDIAN_H
#include <uapi/linux/bpf.h>

#define bpf_htons(x) ((__be16)__builtin_bswap16((__u16)(x)))
#define bpf_ntohs(x) ((__u16)__builtin_bswap16((__u16)(x)))
#define bpf_htonl(x) ((__be32)__builtin_bswap32((__u32)(x)))
#define bpf_ntohl(x) ((__u32)__builtin_bswap32((__u32)(x)))

#endif
