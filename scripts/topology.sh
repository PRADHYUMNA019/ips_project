#!/usr/bin/env bash
# scripts/topology.sh — create | teardown | show
#
# Creates a per-device network namespace topology.  Each device in
# configs/devices.yaml gets its own netns and veth pair on br-lan.
# The attacker and server namespaces are always created.
#
# Requires: bash, iproute2, sysctl, iptables.
# Run as root:  sudo ./scripts/topology.sh create|teardown|show
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEVICES_YAML="$REPO_DIR/configs/devices.yaml"

LAN_PREFIX="10.0.1"
WAN_PREFIX="10.0.2"
LAN_GW="${LAN_PREFIX}.1"
WAN_GW="${WAN_PREFIX}.1"
SRV_IP="${WAN_PREFIX}.10"

# ---------------------------------------------------------------------------
# Parse devices.yaml with pure bash (no python/yq dependency).
# Extracts device_id and ip for every entry under "devices:".
# ---------------------------------------------------------------------------
parse_devices() {
  local in_devices=0
  while IFS= read -r line; do
    # Trim leading whitespace for easier matching
    local trimmed="${line#"${line%%[![:space:]]*}"}"

    # Detect the "devices:" top-level key
    if [[ "$trimmed" == "devices:" ]]; then
      in_devices=1
      continue
    fi

    # Exit the devices block when a new top-level key appears
    if [[ $in_devices -eq 1 && "$trimmed" =~ ^[a-z] && ! "$trimmed" =~ ^- ]]; then
      in_devices=0
    fi

    if [[ $in_devices -eq 1 ]]; then
      if [[ "$trimmed" =~ ^-[[:space:]]*device_id:[[:space:]]*(.+) ]]; then
        current_id="${BASH_REMATCH[1]}"
      fi
      if [[ "$trimmed" =~ ^ip:[[:space:]]*[\"\']?([0-9.]+) ]]; then
        echo "${current_id} ${BASH_REMATCH[1]}"
      fi
    fi
  done < "$DEVICES_YAML"
}

# ---------------------------------------------------------------------------
create_ns() {
  # create_ns <name> <ip> <bridge> <gateway>
  local ns=$1 ipaddr=$2 br=$3 gw=$4
  ip netns add "$ns" 2>/dev/null || true
  ip link add "${ns}-gw" type veth peer name "${ns}-eth0" 2>/dev/null || true
  ip link set "${ns}-eth0" netns "$ns"
  ip link set "${ns}-gw" master "$br"
  ip link set "${ns}-gw" up
  ip -n "$ns" addr add "$ipaddr/24" dev "${ns}-eth0" 2>/dev/null || true
  ip -n "$ns" link set "${ns}-eth0" up
  ip -n "$ns" link set lo up
  ip -n "$ns" route add default via "$gw" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
create() {
  echo "[topology] Creating topology from $DEVICES_YAML ..."
  teardown >/dev/null 2>&1 || true

  # Bridges
  ip link add br-lan type bridge;  ip link set br-lan up
  ip link add br-wan type bridge;  ip link set br-wan up

  # Gateway veth pairs (LAN side + WAN side)
  ip link add v-lan-gw type veth peer name v-lan-br
  ip link add v-wan-gw type veth peer name v-wan-br
  ip addr add ${LAN_GW}/24 dev v-lan-gw
  ip addr add ${WAN_GW}/24 dev v-wan-gw
  ip link set v-lan-gw up
  ip link set v-wan-gw up
  ip link set v-lan-br master br-lan; ip link set v-lan-br up
  ip link set v-wan-br master br-wan; ip link set v-wan-br up

  # Per-device namespaces from devices.yaml
  local count=0
  while read -r dev_id dev_ip; do
    create_ns "$dev_id" "$dev_ip" br-lan "$LAN_GW"
    count=$((count + 1))
  done < <(parse_devices)
  echo "[topology]   created $count device namespace(s)"

  # Attacker namespace (always present)
  create_ns attacker "${LAN_PREFIX}.4" br-lan "$LAN_GW"

  # Server namespace (WAN side)
  create_ns srv "$SRV_IP" br-wan "$WAN_GW"

  # Enable forwarding
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  iptables -P FORWARD ACCEPT >/dev/null 2>&1 || true
  iptables -I FORWARD 1 -j ACCEPT >/dev/null 2>&1 || true

  echo "[OK] topology up  ($(( count + 2 )) namespaces: $count devices + attacker + srv)"
}

# ---------------------------------------------------------------------------
teardown() {
  # Tear down device namespaces
  if [ -f "$DEVICES_YAML" ]; then
    while read -r dev_id dev_ip; do
      ip netns del "$dev_id" 2>/dev/null || true
      ip link del "${dev_id}-gw" 2>/dev/null || true
    done < <(parse_devices)
  fi
  # Legacy namespaces (from the old topology) + always-present ones
  for ns in iot1 iot2 attacker srv; do
    ip netns del "$ns" 2>/dev/null || true
  done
  for link in v-lan-gw v-lan-br v-wan-gw v-wan-br br-lan br-wan \
              iot1-gw iot2-gw attacker-gw srv-gw; do
    ip link del "$link" 2>/dev/null || true
  done
  echo "[OK] topology down"
}

# ---------------------------------------------------------------------------
show() {
  echo "=== Network Namespaces ==="
  ip netns list 2>/dev/null || echo "(none)"
  echo ""
  echo "=== Links ==="
  ip -br link 2>/dev/null || true
  echo ""
  echo "=== Host routes ==="
  ip route 2>/dev/null || true
  echo ""
  # Show per-device IPs
  if [ -f "$DEVICES_YAML" ]; then
    echo "=== Device Namespace IPs ==="
    while read -r dev_id dev_ip; do
      printf "  %-14s %s\n" "$dev_id" "$dev_ip"
    done < <(parse_devices)
    echo "  attacker       ${LAN_PREFIX}.4"
    echo "  srv            ${SRV_IP}"
  fi
}

# ---------------------------------------------------------------------------
case "${1:-}" in
  create)   create ;;
  teardown) teardown ;;
  show)     show ;;
  *) echo "usage: $0 create|teardown|show" ;;
esac
