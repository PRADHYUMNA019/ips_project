#!/usr/bin/env bash
# scripts/block_ip.sh — block <ip> | unblock <ip> | list
set -euo pipefail
ID=$(sudo bpftool -j -p map show | jq -r '.[] | select(.name=="drop_map") | .id')
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

