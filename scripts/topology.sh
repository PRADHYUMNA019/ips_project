#!/usr/bin/env bash
# scripts/topology.sh — create | teardown | show
set -euo pipefail
LAN=10.0.1; WAN=10.0.2

create_ns() {  # name ip bridge gw
  local ns=$1 ipaddr=$2 br=$3 gw=$4
  ip netns add "$ns"
  ip link add "${ns}-gw" type veth peer name "${ns}-eth0"
  ip link set "${ns}-eth0" netns "$ns"
  ip link set "${ns}-gw" master "$br"
  ip link set "${ns}-gw" up
  ip -n "$ns" addr add "$ipaddr/24" dev "${ns}-eth0"
  ip -n "$ns" link set "${ns}-eth0" up
  ip -n "$ns" link set lo up
  ip -n "$ns" route add default via "$gw"
}

create() {
  teardown >/dev/null 2>&1 || true
  ip link add br-lan type bridge;  ip link set br-lan up
  ip link add br-wan type bridge;  ip link set br-wan up
  ip link add v-lan-gw type veth peer name v-lan-br
  ip link add v-wan-gw type veth peer name v-wan-br
  ip addr add $LAN.1/24 dev v-lan-gw
  ip addr add $WAN.1/24 dev v-wan-gw
  ip link set v-lan-gw up; ip link set v-wan-br master br-wan; ip link set v-wan-br up
  ip link set v-lan-br master br-lan; ip link set v-lan-br up; ip link set v-wan-gw up
  create_ns iot1     $LAN.2  br-lan $LAN.1
  create_ns iot2     $LAN.3  br-lan $LAN.1
  create_ns attacker $LAN.4  br-lan $LAN.1
  create_ns srv      $WAN.10 br-wan $WAN.1
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  iptables -P FORWARD ACCEPT >/dev/null 2>&1 || true
  iptables -I FORWARD 1 -j ACCEPT >/dev/null 2>&1 || true
  echo "[OK] topology up"
}

teardown() {
  for ns in iot1 iot2 attacker srv; do
    ip netns del "$ns" 2>/dev/null || true
  done
  for link in v-lan-gw v-lan-br v-wan-gw v-wan-br br-lan br-wan iot1-gw iot2-gw attacker-gw srv-gw; do
    ip link del "$link" 2>/dev/null || true
  done
  echo "[OK] topology down"
}

show() { ip -br link; echo; ip netns list; echo; ip route; }

case "${1:-}" in
  create) create ;;
  teardown) teardown ;;
  show) show ;;
  *) echo "usage: $0 create|teardown|show" ;;
esac

