#!/usr/bin/env bash
# scripts/xdp.sh — attach | detach (with self-verification)
set -euo pipefail
IF=v-lan-gw
case "${1:-}" in
  attach)   mkdir -p build
            if ! command -v clang >/dev/null 2>&1; then
              echo "[FAIL] 'clang' is not installed! Install via: sudo apt install -y clang llvm" >&2
              exit 1
            fi
            clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
              -I/usr/include/$(uname -m)-linux-gnu -I/usr/include \
              -c ebpf/xdp_v1.c -o build/xdp_v1.o
            sudo ip link set dev $IF xdpgeneric obj build/xdp_v1.o sec xdp
            if ip link show $IF | grep -q xdp; then
              echo "[OK] xdp_v1 attached to $IF"
            else
              echo "[FAIL] attach did not stick"; exit 1
            fi ;;
  detach)   sudo ip link set dev $IF xdpgeneric off 2>/dev/null || true
            sudo ip link set dev $IF xdp off 2>/dev/null || true
            if ip link show $IF | grep -q xdp; then
              echo "[WARN] XDP still attached to $IF"; exit 1
            else
              echo "[OK] detached, no XDP on $IF"
            fi ;;
  *) echo "usage: $0 attach|detach" ;;
esac
