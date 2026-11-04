#!/usr/bin/env bash
# scripts/run_experiment.sh <config_path>
#
# Orchestrates a complete end-to-end experiment run from scenario YAML.
set -euo pipefail

CONFIG=${1:?Usage: $0 <config_path>}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RUN_ID="exp_$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$REPO_DIR/results/$RUN_ID"
mkdir -p "$OUT_DIR"

echo "================================================================================"
echo "  EXPERIMENT ORCHESTRATOR: $RUN_ID"
echo "  Config: $CONFIG"
echo "  Results directory: $OUT_DIR"
echo "================================================================================"

# Record provenance
cp "$CONFIG" "$OUT_DIR/config.yaml"
git rev-parse HEAD > "$OUT_DIR/git_commit.txt" 2>/dev/null || echo "not_git" > "$OUT_DIR/git_commit.txt"

# 1. Setup topology
sudo "$REPO_DIR/scripts/topology.sh" teardown >/dev/null 2>&1 || true
sudo "$REPO_DIR/scripts/topology.sh" create
sudo "$REPO_DIR/scripts/gen_certs.sh"

# 2. Start services
echo "[exp] Starting TLS & HTTPS services in srv..."
sudo ip netns exec srv nohup python3 "$REPO_DIR/traffic/tls_server.py" > "$OUT_DIR/tls_server.log" 2>&1 &
SRV_PID=$!
sudo ip netns exec srv nohup python3 "$REPO_DIR/traffic/services/https_server.py" 443 > "$OUT_DIR/https_server.log" 2>&1 &
HTTPS_PID=$!
sleep 2

# 3. Start packet capture (ingress on both gateway ports)
echo "[exp] Starting packet capture..."
sudo tcpdump -Q in -i v-lan-gw -w "$OUT_DIR/lan_ingress.pcap" 2>/dev/null &
PCAP_LAN_PID=$!
sudo tcpdump -Q in -i v-wan-gw -w "$OUT_DIR/wan_ingress.pcap" 2>/dev/null &
PCAP_WAN_PID=$!
sudo tcpdump -Q out -i v-wan-gw -w "$OUT_DIR/wan_egress.pcap" 2>/dev/null &
PCAP_EGRESS_PID=$!
sleep 1

# 4. Start benign background fleet
echo "[exp] Launching benign IoT fleet..."
FLEET_PIDS=()
while read -r dev_id dev_ip; do
    sudo ip netns exec "$dev_id" nohup python3 "$REPO_DIR/traffic/benign_iot_generator.py" \
        --device-from-config "$dev_id" \
        --duration 3600 > "$OUT_DIR/${dev_id}.log" 2>&1 &
    FLEET_PIDS+=($!)
done < <(bash "$REPO_DIR/scripts/topology.sh" list)

# 5. Run scenario phases
MANIFEST="$OUT_DIR/manifest.csv"
echo "[exp] Executing scenario attack phases (manifest -> $MANIFEST)..."

# Run A1
echo "  >>> Executing A1 (Volumetric Flood)..."
sudo ip netns exec attacker python3 "$REPO_DIR/traffic/attacks/a1_flood.py" \
    --duration 10 --manifest "$MANIFEST" --run-id "$RUN_ID" || true
sleep 3

# Run A2
echo "  >>> Executing A2 (Slow-Rate DoS)..."
sudo ip netns exec attacker python3 "$REPO_DIR/traffic/attacks/a2_slowloris.py" \
    --duration 15 --manifest "$MANIFEST" --run-id "$RUN_ID" || true
sleep 3

# Run A3
echo "  >>> Executing A3 (C2 Beaconing)..."
sudo ip netns exec attacker python3 "$REPO_DIR/traffic/attacks/a3_c2_beacon.py" \
    --duration 20 --interval 5.0 --jitter 0.30 --manifest "$MANIFEST" --run-id "$RUN_ID" || true
sleep 3

# Run A4
echo "  >>> Executing A4 (Exfiltration)..."
sudo ip netns exec attacker python3 "$REPO_DIR/traffic/attacks/a4_exfiltration.py" \
    --duration 15 --manifest "$MANIFEST" --run-id "$RUN_ID" || true
sleep 3

# Run A5
echo "  >>> Executing A5 (MQTT Brute Force)..."
sudo ip netns exec attacker python3 "$REPO_DIR/traffic/attacks/a5_bruteforce.py" \
    --attempts 15 --manifest "$MANIFEST" --run-id "$RUN_ID" || true
sleep 2

# 6. Teardown
echo "[exp] Scenario complete. Tearing down background jobs..."
for pid in "${FLEET_PIDS[@]}"; do
    sudo kill -9 "$pid" 2>/dev/null || true
done
sudo kill -SIGINT "$PCAP_LAN_PID" 2>/dev/null || true
sudo kill -SIGINT "$PCAP_WAN_PID" 2>/dev/null || true
sudo kill -SIGINT "$PCAP_EGRESS_PID" 2>/dev/null || true
sudo kill -9 "$SRV_PID" "$HTTPS_PID" 2>/dev/null || true
sudo "$REPO_DIR/scripts/topology.sh" teardown >/dev/null 2>&1 || true

echo "[OK] Experiment $RUN_ID completed. Outputs stored in $OUT_DIR"
