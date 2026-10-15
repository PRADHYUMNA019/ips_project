#!/usr/bin/env bash
# scripts/xdp.sh — attach | detach
set -euo pipefail
IF=v-lan-gw
case "${1:-}" in
  attach)   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
              -I/usr/include/$(uname -m)-linux-gnu \
              -c ebpf/xdp_v1.c -o build/xdp_v1.o
            sudo ip link set dev $IF xdpgeneric obj build/xdp_v1.o sec xdp ;;
  detach)   sudo ip link set dev $IF xdp off ;;
  *) echo "usage: $0 attach|detach" ;;
esac

