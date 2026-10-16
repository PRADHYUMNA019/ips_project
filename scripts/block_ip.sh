#!/usr/bin/env bash
# scripts/block_ip.sh — block <ip> | unblock <ip> | list
set -euo pipefail
get_drop_map_id() {
  local id=""
  if command -v jq >/dev/null 2>&1; then
    id=$(sudo bpftool -j -p map show 2>/dev/null | jq -r '.[] | select(.name=="drop_map") | .id' 2>/dev/null | head -n 1 || true)
  fi
  if [ -z "$id" ] || [ "$id" = "null" ]; then
    id=$(sudo bpftool map show 2>/dev/null | awk '/name drop_map/ {sub(/:.*/, "", $1); print $1}' | head -n 1 || true)
  fi
  echo "$id"
}

ID=$(get_drop_map_id)
if [ -z "${ID:-}" ] || [ "$ID" = "null" ]; then
  echo "[FAIL] drop_map not found. Ensure xdp_v1 is attached (sudo ./scripts/xdp.sh attach) or engine is running." >&2
  exit 1
fi
case "${1:-}" in
  block)
    KEY=$(printf '%02x %02x %02x %02x' $(echo "$2" | tr '.' ' '))
    sudo bpftool map update id "$ID" key hex $KEY value hex 01 ;;
  unblock)
    KEY=$(printf '%02x %02x %02x %02x' $(echo "$2" | tr '.' ' '))
    sudo bpftool map delete id "$ID" key hex $KEY ;;
  list)  sudo bpftool -j -p map dump id "$ID" ;;
  *) echo "usage: $0 block|unblock|list <ip>" ;;
esac

