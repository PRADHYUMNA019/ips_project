#!/usr/bin/env bash
# scripts/collect.sh <split_name> <target_flows> [time_scale]
#
# Collects benign IoT traffic until target_flows is reached.
# Runs in Linux network namespaces.
set -euo pipefail

SPLIT=${1:?Usage: $0 <split_name> <target_flows> [time_scale]}
TARGET_FLOWS=${2:?Usage: $0 <split_name> <target_flows> [time_scale]}
TIME_SCALE=${3:-1.0}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$REPO_DIR/results/data/$SPLIT"
mkdir -p "$OUT_DIR"

echo "================================================================================"
echo "  BENIGN DATASET COLLECTION: $SPLIT"
echo "  Target Flows : $TARGET_FLOWS"
echo "  Time Scale   : $TIME_SCALE"
echo "  Destination  : $OUT_DIR"
echo "================================================================================"

# Initialize topology
sudo "$REPO_DIR/scripts/topology.sh" create
sudo "$REPO_DIR/scripts/gen_certs.sh"

# Start TLS server in srv
echo "[collect] Starting TLS Server in srv..."
sudo ip netns exec srv nohup python3 "$REPO_DIR/traffic/tls_server.py" > "$OUT_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 2

# Start packet capture on gateway interfaces (ingress only per port)
echo "[collect] Starting tcpdump on v-lan-gw and v-wan-gw..."
sudo tcpdump -Q in -i v-lan-gw -w "$OUT_DIR/lan_ingress.pcap" 2>/dev/null &
TCPDUMP_LAN_PID=$!
sudo tcpdump -Q in -i v-wan-gw -w "$OUT_DIR/wan_ingress.pcap" 2>/dev/null &
TCPDUMP_WAN_PID=$!
sleep 1

# Launch benign fleet
echo "[collect] Launching 12 IoT devices across namespaces (time_scale=$TIME_SCALE)..."
PIDS=()
while read -r dev_id dev_ip; do
    sudo ip netns exec "$dev_id" nohup python3 "$REPO_DIR/traffic/benign_iot_generator.py" \
        --device-from-config "$dev_id" \
        --duration 7200 \
        --time-scale "$TIME_SCALE" > "$OUT_DIR/${dev_id}.log" 2>&1 &
    PIDS+=($!)
done < <(bash "$REPO_DIR/scripts/topology.sh" list)

echo "[collect] Devices active. Monitoring flow count in $OUT_DIR/lan_ingress.pcap..."

current_flows=0
while [ "$current_flows" -lt "$TARGET_FLOWS" ]; do
    sleep 10
    if [ -f "$OUT_DIR/lan_ingress.pcap" ]; then
        # Count TCP SYN packets as conservative proxy for new flows
        current_flows=$(tcpdump -r "$OUT_DIR/lan_ingress.pcap" "tcp[tcpflags] & tcp-syn != 0" 2>/dev/null | wc -l || echo 0)
        echo "  [Progress] Captured ~$current_flows / $TARGET_FLOWS flows..."
    fi
done

echo "[OK] Reached target flows (~$current_flows flows captured)."

# Cleanup
echo "[collect] Cleaning up processes and topology..."
for pid in "${PIDS[@]}"; do
    sudo kill -9 "$pid" 2>/dev/null || true
done
sudo kill -SIGINT "$TCPDUMP_LAN_PID" 2>/dev/null || true
sudo kill -SIGINT "$TCPDUMP_WAN_PID" 2>/dev/null || true
sudo kill -9 "$SERVER_PID" 2>/dev/null || true
sudo "$REPO_DIR/scripts/topology.sh" teardown

echo "[OK] Collection complete for split '$SPLIT'. Raw pcaps in $OUT_DIR"

