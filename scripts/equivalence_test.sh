#!/usr/bin/env bash
# scripts/equivalence_test.sh — Live 50-flow Kernel-vs-Offline Equivalence Test (N6, WP6).
#
# Runs on Linux inside the network namespace testbed:
#   1. Starts TLS server on srv (10.0.2.10:8443)
#   2. Attaches ips.engine in observe mode logging EARLY_FLOW events to JSONL
#   3. Captures packets on v-lan-gw with tcpdump
#   4. Generates 50 short TLS flows from sensor-01 and plug-01
#   5. Compares offline pcap flows vs kernel EARLY_FLOW events via ips/eval/equivalence.py
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$REPO_DIR/results/equivalence"
mkdir -p "$OUT_DIR"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: scripts/equivalence_test.sh requires root on Linux." >&2
    exit 1
fi

bash "$REPO_DIR/scripts/gen_certs.sh"
bash "$REPO_DIR/scripts/topology.sh" create

PCAP_FILE="$OUT_DIR/equiv_capture.pcap"
EVENTS_FILE="$OUT_DIR/equiv_events.jsonl"
rm -f "$PCAP_FILE" "$EVENTS_FILE"

cleanup() {
    kill $(jobs -p) 2>/dev/null || true
}
trap cleanup EXIT

echo "[*] Starting TLS server in srv namespace..."
ip netns exec srv python3 "$REPO_DIR/traffic/tls_server.py" >/dev/null 2>&1 &
sleep 1

echo "[*] Starting tcpdump on gw (v-lan-gw)..."
ip netns exec gw tcpdump -i v-lan-gw -n -U -w "$PCAP_FILE" "tcp port 8443" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

echo "[*] Starting IPS engine in observe mode..."
ip netns exec gw python3 -m ips.engine \
    --config "$REPO_DIR/configs/system.yaml" \
    --mode observe \
    --events-out "$EVENTS_FILE" \
    --duration 25 >/dev/null 2>&1 &
ENGINE_PID=$!
sleep 2

echo "[*] Generating 50 TLS flows across sensor-01 and plug-01..."
ip netns exec sensor-01 python3 "$REPO_DIR/traffic/benign_iot_generator.py" \
    --device-from-config sensor-01 \
    --connection persistent \
    --time-scale 50 \
    --duration 18 >/dev/null 2>&1 &
ip netns exec plug-01 python3 "$REPO_DIR/traffic/benign_iot_generator.py" \
    --device-from-config plug-01 \
    --connection persistent \
    --time-scale 50 \
    --duration 18 >/dev/null 2>&1 &

wait $ENGINE_PID || true
kill -INT $TCPDUMP_PID 2>/dev/null || true
sleep 1

echo "[*] Running ips/eval/equivalence.py..."
python3 "$REPO_DIR/ips/eval/equivalence.py" \
    --pcap "$PCAP_FILE" \
    --events "$EVENTS_FILE" \
    --out "$OUT_DIR/report.md"

