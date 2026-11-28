/*
 * ebpf/stubs/bcc_standalone_shim.h — STATIC-ANALYSIS / STANDALONE CLANG SHIM ONLY.
 *
 * Translates BCC table DSL macros (BPF_TABLE, BPF_ARRAY, BPF_PERCPU_ARRAY, BPF_RINGBUF_OUTPUT)
 * into strongly-typed C function-pointer dispatch structs backed by standard BPF helper IDs
 * so standalone `zig cc` / `clang -target bpf` with `-Wall -Wextra` can type-check every
 * lookup/update/delete/ringbuf call in `ebpf/ips_engine.c` without BCC's runtime rewriter.
 *
 * NEVER included during real BCC runtime loading (`BCCKernelBackend`).
 */
#ifndef _STUB_BCC_STANDALONE_SHIM_H
#define _STUB_BCC_STANDALONE_SHIM_H

#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries)         \
    struct _bcc_map_##_name##_btf {                                                \
        int (*max_entries)[_max_entries];                                          \
        _key_type *key;                                                            \
        _leaf_type *value;                                                         \
    } _name##_btf SEC(".maps");                                                    \
    static __always_inline _leaf_type *_bcc_##_name##_lookup(const _key_type *k) { \
        return (_leaf_type *)bpf_map_lookup_elem(&_name##_btf, k);                 \
    }                                                                              \
    static __always_inline int _bcc_##_name##_update(const _key_type *k,           \
                                                     const _leaf_type *v) {        \
        return (int)bpf_map_update_elem(&_name##_btf, k, v, BPF_ANY);              \
    }                                                                              \
    static __always_inline int _bcc_##_name##_delete(const _key_type *k) {         \
        return (int)bpf_map_delete_elem(&_name##_btf, k);                          \
    }                                                                              \
    struct _bcc_ops_##_name {                                                      \
        _leaf_type *(*lookup)(const _key_type *);                                  \
        int (*update)(const _key_type *, const _leaf_type *);                      \
        int (*delete)(const _key_type *);                                          \
    };                                                                             \
    static const struct _bcc_ops_##_name _name = {                                 \
        .lookup = _bcc_##_name##_lookup,                                           \
        .update = _bcc_##_name##_update,                                           \
        .delete = _bcc_##_name##_delete,                                           \
    }

#define BPF_ARRAY(_name, _leaf_type, _max_entries) \
    BPF_TABLE("array", int, _leaf_type, _name, _max_entries)

#define BPF_PERCPU_ARRAY(_name, _leaf_type, _max_entries) \
    BPF_TABLE("percpu_array", int, _leaf_type, _name, _max_entries)

#define BPF_RINGBUF_OUTPUT(_name, _num_pages)                                       \
    struct _bcc_rb_##_name##_btf {                                                  \
        int (*type)[BPF_MAP_TYPE_RINGBUF];                                          \
        int (*max_entries)[(_num_pages) * 4096];                                    \
    } _name##_btf SEC(".maps");                                                     \
    static __always_inline void *_bcc_##_name##_reserve(__u64 sz) {                 \
        return bpf_ringbuf_reserve(&_name##_btf, sz, 0);                            \
    }                                                                               \
    static __always_inline void _bcc_##_name##_submit(void *d, __u64 flags) {       \
        bpf_ringbuf_submit(d, flags);                                               \
    }                                                                               \
    static __always_inline void _bcc_##_name##_discard(void *d, __u64 flags) {      \
        bpf_ringbuf_discard(d, flags);                                              \
    }                                                                               \
    struct _bcc_rb_ops_##_name {                                                    \
        void *(*ringbuf_reserve)(__u64);                                            \
        void (*ringbuf_submit)(void *, __u64);                                      \
        void (*ringbuf_discard)(void *, __u64);                                     \
    };                                                                              \
    static const struct _bcc_rb_ops_##_name _name = {                               \
        .ringbuf_reserve = _bcc_##_name##_reserve,                                  \
        .ringbuf_submit = _bcc_##_name##_submit,                                    \
        .ringbuf_discard = _bcc_##_name##_discard,                                  \
    }

#endif
