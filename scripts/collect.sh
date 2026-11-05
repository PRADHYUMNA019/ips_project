#!/usr/bin/env bash
# scripts/collect.sh — Collect benign testbed traffic across the 12-device fleet (A5, A6).
#
# Starts real mosquitto (TLS 8883) and HTTPS server (port 443) in srv namespace,
# runs all 12 devices in their respective namespaces using process groups (setsid),
# captures pcap on v-lan-gw and v-wan-gw, extracts flows, and writes
# results/data/<split>/meta.json with target/achieved flow counts and git provenance.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SPLIT="train"
SESSION_ID="benign_s1"
DURATION=300
TIME_SCALE=1.0
TARGET_FLOWS=500
LEGACY_ECHO=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --split) SPLIT="$2"; shift 2 ;;
        --session) SESSION_ID="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --time-scale) TIME_SCALE="$2"; shift 2 ;;
        --target-flows) TARGET_FLOWS="$2"; shift 2 ;;
        --legacy-echo) LEGACY_ECHO=1; shift ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

OUT_DIR="$REPO_DIR/results/data/$SPLIT"
mkdir -p "$OUT_DIR"

PGIDS=()
cleanup() {
    for pg in "${PGIDS[@]}"; do
        if [[ -n "$pg" ]]; then
            kill -TERM -- "-$pg" 2>/dev/null || true
        fi
    done
    sleep 1
    for pg in "${PGIDS[@]}"; do
        if [[ -n "$pg" ]]; then
            kill -KILL -- "-$pg" 2>/dev/null || true
        fi
    done
    # Verify no stray generator or service processes remain
    pkill -f "benign_iot_generator.py" 2>/dev/null || true
    pkill -f "traffic/services/https_server.py" 2>/dev/null || true
}
trap cleanup EXIT

START_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GIT_COMMIT="$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"

bash "$REPO_DIR/scripts/gen_certs.sh"
bash "$REPO_DIR/scripts/topology.sh" create

echo "[*] Starting Mosquitto (TLS 8883) and HTTPS server (443) in srv namespace..."
if command -v mosquitto >/dev/null 2>&1; then
    setsid ip netns exec srv mosquitto -c "$REPO_DIR/traffic/services/mosquitto.conf" >"$OUT_DIR/mosquitto_${SESSION_ID}.log" 2>&1 &
    PGIDS+=("$!")
else
    setsid ip netns exec srv python3 "$REPO_DIR/traffic/tls_server.py" >"$OUT_DIR/tls_echo_${SESSION_ID}.log" 2>&1 &
    PGIDS+=("$!")
    LEGACY_ECHO=1
fi

setsid ip netns exec srv python3 "$REPO_DIR/traffic/services/https_server.py" 443 >"$OUT_DIR/https_${SESSION_ID}.log" 2>&1 &
PGIDS+=("$!")
sleep 1.5

PCAP_LAN="$OUT_DIR/${SESSION_ID}_lan.pcap"
setsid ip netns exec gw tcpdump -i v-lan-gw -n -U -w "$PCAP_LAN" >"$OUT_DIR/tcpdump_${SESSION_ID}.log" 2>&1 &
TCPDUMP_PGID="$!"
PGIDS+=("$TCPDUMP_PGID")
sleep 1

ECHO_FLAG=""
if [[ "$LEGACY_ECHO" -eq 1 ]]; then
    ECHO_FLAG="--legacy-echo"
fi

echo "[*] Launching 12-device IoT fleet for ${DURATION}s (time_scale=${TIME_SCALE})..."
while read -r dev_id dev_ip dev_cls dev_prof dev_conn; do
    [[ -z "$dev_id" ]] && continue
    setsid ip netns exec "$dev_id" python3 "$REPO_DIR/traffic/benign_iot_generator.py" \
        --device-from-config "$dev_id" \
        --duration "$DURATION" \
        --time-scale "$TIME_SCALE" \
        $ECHO_FLAG >"$OUT_DIR/gen_${dev_id}.log" 2>&1 &
    PGIDS+=("$!")
done < <(bash "$REPO_DIR/scripts/topology.sh" list)

sleep "$DURATION"

kill -INT -- "-$TCPDUMP_PGID" 2>/dev/null || true
sleep 1

CSV_OUT="$OUT_DIR/${SESSION_ID}_flows.csv"
python3 "$REPO_DIR/ips/offline/pcap_to_flows.py" "$PCAP_LAN" \
    --session-id "$SESSION_ID" \
    --source "real-testbed" \
    --label-family "benign" \
    --is-attack 0 \
    --domain "testbed" \
    --out "$CSV_OUT"

END_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
python3 - "$CSV_OUT" "$OUT_DIR/meta.json" "$SPLIT" "$SESSION_ID" "$TARGET_FLOWS" "$TIME_SCALE" "$START_TIME" "$END_TIME" "$GIT_COMMIT" <<'PYEOF'
import sys, json, os
import pandas as pd

csv_path, meta_path, split, session_id, target_flows, time_scale, start_t, end_t, commit = sys.argv[1:10]
achieved = 0
if os.path.exists(csv_path):
    try:
        df = pd.read_csv(csv_path)
        achieved = len(df)
    except Exception:
        achieved = 0

meta = {
    "split": split,
    "session_id": session_id,
    "target_flows": int(target_flows),
    "achieved_flows": int(achieved),
    "time_scale": float(time_scale),
    "start_time": start_t,
    "end_time": end_t,
    "git_commit": commit,
}
with open(meta_path, "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2)
print(f"[+] Wrote {meta_path} (achieved_flows={achieved} / target={target_flows})")
PYEOF
