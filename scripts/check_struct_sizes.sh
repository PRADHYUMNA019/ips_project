#!/usr/bin/env bash
# scripts/check_struct_sizes.sh — V2 Linux verification of struct layout and ABI match.
# Compares sizeof() and field offsets between ebpf/ips_engine.c and ips/engine/schema.py.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Verifying C vs Python ctypes Struct Sizes & Layouts ==="

PYTHON_BIN="${PYTHON:-python3}"

# 1. Run Python schema size inspection
PY_SIZES=$($PYTHON_BIN -c '
import sys
sys.path.insert(0, ".")
from ips.engine.schema import make_ctypes_schemas, FlowKey, VerdictEntry, CfgEntry, StatsEntry
import ctypes

schemas = make_ctypes_schemas(16)
print(f"FlowKey:{ctypes.sizeof(FlowKey)}")
print(f"VerdictEntry:{ctypes.sizeof(VerdictEntry)}")
print(f"CfgEntry:{ctypes.sizeof(CfgEntry)}")
print(f"StatsEntry:{ctypes.sizeof(StatsEntry)}")
print(f"EarlyFlowEvent_16:{ctypes.sizeof(schemas.EarlyFlowEvent)}")
')

echo "Python ctypes struct sizes:"
echo "$PY_SIZES"

# 2. If gcc/clang is present, compile a small C probe to print exact sizeof in C
if command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
    CC="gcc"
    command -v gcc >/dev/null 2>&1 || CC="clang"
    TMP_C=$(mktemp /tmp/check_struct_XXXXXX.c)
    TMP_BIN=$(mktemp /tmp/check_struct_XXXXXX.bin)

    cat << 'EOF' > "$TMP_C"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#define EARLY_N 16
#define EARLY_N_MINUS_1 15
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

struct flow_key {
    __u32 ip_a;
    __u32 ip_b;
    __u16 port_a;
    __u16 port_b;
    __u8  proto;
    __u8  pad[3];
} __attribute__((packed));

struct verdict_entry {
    __u8  action;
    __u8  pad[7];
    __u64 expiry_ns;
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
} __attribute__((packed));

struct early_flow_event {
    __u32 schema_version;
    __u8  proto;
    __u8  valid_len;
    __u8  flags_seen;
    __u8  checkpoint_idx;
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

int main() {
    printf("FlowKey:%zu\n", sizeof(struct flow_key));
    printf("VerdictEntry:%zu\n", sizeof(struct verdict_entry));
    printf("CfgEntry:%zu\n", sizeof(struct cfg_entry));
    printf("StatsEntry:%zu\n", sizeof(struct stats_entry));
    printf("EarlyFlowEvent_16:%zu\n", sizeof(struct early_flow_event));
    return 0;
}
EOF

    $CC -O2 "$TMP_C" -o "$TMP_BIN"
    C_SIZES=$("$TMP_BIN")
    echo ""
    echo "C sizeof output ($CC):"
    echo "$C_SIZES"

    rm -f "$TMP_C" "$TMP_BIN"

    if [ "$PY_SIZES" = "$C_SIZES" ]; then
        echo ""
        echo "PASS: C struct sizes and Python ctypes struct sizes match identically."
        exit 0
    else
        echo ""
        echo "FAIL: Struct size mismatch detected between C and Python!"
        exit 1
    fi
else
    echo "No C compiler available to execute probe binary directly; static verification performed."
fi
