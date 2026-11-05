#!/usr/bin/env bash
# scripts/run_experiment.sh — YAML-driven Multi-Phase Experiment Runner (A5, A6).
#
# Reads a scenario YAML (e.g. configs/experiments/demo_scenario.yaml):
#   - Starts real mosquitto (8883) and HTTPS server (443) in srv namespace
#   - Optionally starts ips.engine when scenario YAML sets ips_engine.enabled: true
#   - Executes each phase (benign warm-up + attacks A1..A5) with process-group cleanup (setsid)
#   - Uses hping3 for A1 SYN flood when available, falling back to traffic/attacks/a1_flood.py
#   - Verifies no stray processes remain via pgrep at exit
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SCENARIO_YAML="${1:-$REPO_DIR/configs/experiments/demo_scenario.yaml}"
RUN_ID="${2:-exp_$(date +%Y%m%d_%H%M%S)}"
OUT_DIR="$REPO_DIR/results/$RUN_ID"
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
    pkill -f "benign_iot_generator.py" 2>/dev/null || true
    pkill -f "traffic/services/https_server.py" 2>/dev/null || true
    if pgrep -f "benign_iot_generator.py" >/dev/null 2>&1; then
        echo "WARNING: stray generator processes still detected" >&2
    fi
}
trap cleanup EXIT

bash "$REPO_DIR/scripts/gen_certs.sh"
bash "$REPO_DIR/scripts/topology.sh" create

echo "[*] Starting services in srv namespace (Mosquitto TLS 8883 + HTTPS 443)..."
if command -v mosquitto >/dev/null 2>&1; then
    setsid ip netns exec srv mosquitto -c "$REPO_DIR/traffic/services/mosquitto.conf" >"$OUT_DIR/mosquitto.log" 2>&1 &
    PGIDS+=("$!")
else
    setsid ip netns exec srv python3 "$REPO_DIR/traffic/tls_server.py" >"$OUT_DIR/tls_echo.log" 2>&1 &
    PGIDS+=("$!")
fi
setsid ip netns exec srv python3 "$REPO_DIR/traffic/services/https_server.py" 443 >"$OUT_DIR/https.log" 2>&1 &
PGIDS+=("$!")
sleep 1.5

# Start tcpdump on both gateway interfaces
PCAP_LAN="$OUT_DIR/lan.pcap"
PCAP_WAN="$OUT_DIR/wan.pcap"
setsid ip netns exec gw tcpdump -i v-lan-gw -n -U -w "$PCAP_LAN" >"$OUT_DIR/tcpdump_lan.log" 2>&1 &
TCPDUMP_LAN_PG="$!"
PGIDS+=("$TCPDUMP_LAN_PG")

setsid ip netns exec gw tcpdump -i v-wan-gw -n -U -w "$PCAP_WAN" >"$OUT_DIR/tcpdump_wan.log" 2>&1 &
TCPDUMP_WAN_PG="$!"
PGIDS+=("$TCPDUMP_WAN_PG")
sleep 1

# Check if scenario YAML enables ips.engine
ENGINE_CFG=$(python3 - "$SCENARIO_YAML" <<'PYEOF'
import sys, yaml
with open(sys.argv[1], "r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f) or {}
eng = cfg.get("ips_engine", {})
if eng.get("enabled", False):
    print(f"1|{eng.get('mode', 'observe')}|{eng.get('bypass', 'on')}")
else:
    print("0|observe|on")
PYEOF
)
IFS="|" read -r ENG_EN ENG_MODE ENG_BYPASS <<<"$ENGINE_CFG"
if [[ "$ENG_EN" == "1" ]]; then
    echo "[*] Starting ips.engine (mode=$ENG_MODE, bypass=$ENG_BYPASS)..."
    setsid ip netns exec gw python3 -m ips.engine \
        --config "$REPO_DIR/configs/system.yaml" \
        --mode "$ENG_MODE" \
        --bypass "$ENG_BYPASS" \
        --events-out "$OUT_DIR/engine_events.jsonl" \
        --telemetry-out "$OUT_DIR/engine_telemetry.jsonl" >"$OUT_DIR/engine.log" 2>&1 &
    PGIDS+=("$!")
    sleep 2
fi

# Start background benign fleet across all 12 devices for total duration
TOTAL_DUR=$(python3 - "$SCENARIO_YAML" <<'PYEOF'
import sys, yaml
with open(sys.argv[1], "r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f) or {}
print(int(cfg.get("duration_total_s", 120)))
PYEOF
)
echo "[*] Starting background benign fleet for ${TOTAL_DUR}s..."
while read -r dev_id dev_ip dev_cls dev_prof dev_conn; do
    [[ -z "$dev_id" ]] && continue
    setsid ip netns exec "$dev_id" python3 "$REPO_DIR/traffic/benign_iot_generator.py" \
        --device-from-config "$dev_id" \
        --duration "$TOTAL_DUR" >"$OUT_DIR/gen_${dev_id}.log" 2>&1 &
    PGIDS+=("$!")
done < <(bash "$REPO_DIR/scripts/topology.sh" list)

MANIFEST_PATH="$OUT_DIR/manifest.csv"

# Iterate through YAML phases
python3 - "$SCENARIO_YAML" <<'PYEOF' | while IFS="|" read -r p_name p_dur p_type p_target p_port p_int p_jit; do
import sys, yaml
with open(sys.argv[1], "r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f) or {}
for p in cfg.get("phases", []):
    name = p.get("name", "phase")
    dur = p.get("duration_s", 10)
    atk = p.get("attack", p.get("traffic", "benign"))
    tip = p.get("target_ip", "10.0.2.10")
    tport = p.get("target_port", 8883)
    params = p.get("params", {}) or {}
    interval = params.get("interval", 5.0)
    jitter = params.get("jitter", 0.2)
    print(f"{name}|{dur}|{atk}|{tip}|{tport}|{interval}|{jitter}")
PYEOF
    echo "[*] Phase '$p_name' (${p_dur}s): type=$p_type target=${p_target}:${p_port}"
    case "$p_type" in
        benign)
            sleep "$p_dur"
            ;;
        A1_flood)
            if command -v hping3 >/dev/null 2>&1; then
                python3 - "$MANIFEST_PATH" "$RUN_ID" "$p_target" "$p_port" "$p_dur" <<'MPEOF' &
import sys, time
from traffic.manifest import ManifestWriter
m_path, r_id, tip, tport, dur = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
t0 = time.time()
time.sleep(dur)
ManifestWriter(m_path, run_id=r_id).record_episode("A1_flood", "10.0.1.4", tip, tport, t0, time.time(), {"tool": "hping3"})
MPEOF
                setsid ip netns exec attacker timeout "$p_dur" hping3 -S -p "$p_port" -i u1000 "$p_target" >/dev/null 2>&1 || true
            else
                ip netns exec attacker python3 "$REPO_DIR/traffic/attacks/a1_flood.py" \
                    --target "$p_target" --port "$p_port" --duration "$p_dur" \
                    --manifest "$MANIFEST_PATH" --run-id "$RUN_ID" || true
            fi
            ;;
        A2_slowloris)
            ip netns exec attacker python3 "$REPO_DIR/traffic/attacks/a2_slowloris.py" \
                --target "$p_target" --port "$p_port" --duration "$p_dur" \
                --manifest "$MANIFEST_PATH" --run-id "$RUN_ID" || true
            ;;
        A3_c2)
            ip netns exec attacker python3 "$REPO_DIR/traffic/attacks/a3_c2_beacon.py" \
                --target "$p_target" --port "$p_port" --duration "$p_dur" \
                --interval "$p_int" --jitter "$p_jit" \
                --manifest "$MANIFEST_PATH" --run-id "$RUN_ID" || true
            ;;
        A4_exfil)
            ip netns exec attacker python3 "$REPO_DIR/traffic/attacks/a4_exfiltration.py" \
                --target "$p_target" --port "$p_port" --duration "$p_dur" \
                --manifest "$MANIFEST_PATH" --run-id "$RUN_ID" || true
            ;;
        A5_bruteforce)
            ip netns exec attacker python3 "$REPO_DIR/traffic/attacks/a5_bruteforce.py" \
                --target "$p_target" --port "$p_port" --duration "$p_dur" \
                --manifest "$MANIFEST_PATH" --run-id "$RUN_ID" || true
            ;;
        *)
            sleep "$p_dur"
            ;;
    esac
done

kill -INT -- "-$TCPDUMP_LAN_PG" 2>/dev/null || true
kill -INT -- "-$TCPDUMP_WAN_PG" 2>/dev/null || true
sleep 1

echo "[+] Experiment $RUN_ID completed. Artifacts in $OUT_DIR"
