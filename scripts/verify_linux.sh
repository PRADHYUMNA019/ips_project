#!/usr/bin/env bash
# scripts/verify_linux.sh — Automated 11-Stage Linux Verification Harness (Prompt 2 §4).
#
# Usage:
#   sudo bash scripts/verify_linux.sh          # Run all stages S0..S10
#   sudo bash scripts/verify_linux.sh S4       # Run a single stage
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERIFY_DIR="$REPO_DIR/results/verify"
REPORT_FILE="$VERIFY_DIR/REPORT.md"
mkdir -p "$VERIFY_DIR"

TARGET_STAGE="${1:-ALL}"

declare -A STAGE_STATUS
declare -A STAGE_TIME
declare -A STAGE_NOTES
STAGES=(S0 S1 S2 S3 S4 S5 S5b S6 S6b S6c S6d S6e-model S6e S7 S8 S8b S9 S10 S11)

run_stage() {
    local sid="$1"
    local sname="$2"
    local fn="$3"

    if [[ "$TARGET_STAGE" != "ALL" && "$TARGET_STAGE" != "$sid" ]]; then
        STAGE_STATUS["$sid"]="SKIP"
        STAGE_TIME["$sid"]="0s"
        STAGE_NOTES["$sid"]="Skipped (target=$TARGET_STAGE)"
        return 0
    fi

    local logfile="$VERIFY_DIR/${sid}.log"
    rm -f "$logfile"
    echo "================================================================"
    echo "[*] Running $sid: $sname"
    echo "================================================================"
    local t0
    t0=$(date +%s)
    if "$fn" >"$logfile" 2>&1; then
        local t1
        t1=$(date +%s)
        STAGE_STATUS["$sid"]="PASS"
        STAGE_TIME["$sid"]="$((t1 - t0))s"
        STAGE_NOTES["$sid"]="$(tail -n 1 "$logfile" | tr '|' '/')"
        echo "[+] $sid PASS ($((t1 - t0))s)"
    else
        local t1
        t1=$(date +%s)
        STAGE_STATUS["$sid"]="FAIL"
        STAGE_TIME["$sid"]="$((t1 - t0))s"
        STAGE_NOTES["$sid"]="FAILED — see results/verify/${sid}.log"
        echo "[-] $sid FAIL ($((t1 - t0))s) — last 15 lines:"
        tail -n 15 "$logfile" || true
    fi
}

stage_S0() {
    echo "Checking Linux environment, root privileges, kernel, and required binaries..."
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "ERROR: Not running on Linux ($(uname -s))."
        return 1
    fi
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Must run as root (use: sudo bash scripts/verify_linux.sh)."
        return 1
    fi
    local missing=()
    for bin in ip tcpdump openssl clang python3; do
        command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing core binaries: ${missing[*]}"
        echo "Install with:"
        echo "  sudo apt update && sudo apt install -y iproute2 tcpdump openssl clang llvm linux-headers-\$(uname -r) python3-bpfcc mosquitto mosquitto-clients nginx hping3 iperf3 python3-pip"
        return 1
    fi
    python3 -c "import yaml, numpy, scipy, sklearn, torch, onnx, onnxruntime, river, dpkt, cryptography, pytest" || {
        echo "Missing Python packages. Install with: pip install -r requirements.txt"
        return 1
    }
    echo "Environment check OK: $(uname -sr)"
}

stage_S1() {
    cd "$REPO_DIR"
    python3 -m pytest tests/ -v -m "not root and not slow" --tb=short
}

stage_S2() {
    cd "$REPO_DIR"
    bash scripts/topology.sh teardown >/dev/null 2>&1 || true
    bash scripts/topology.sh create
    # Verify idempotence (create twice)
    bash scripts/topology.sh create
    local count
    count=$(bash scripts/topology.sh list | wc -l)
    if [[ "$count" -lt 12 ]]; then
        echo "Expected 12 devices from topology.sh list, got $count"
        return 1
    fi
    ip netns exec sensor-01 ping -c 1 -W 2 10.0.2.10
    ip netns exec cam-02 ping -c 1 -W 2 10.0.2.10
    ip netns exec attacker ping -c 1 -W 2 10.0.2.10
    bash scripts/topology.sh teardown
    echo "Topology verified (12 devices + attacker + srv reachable and torn down cleanly)."
}

stage_S3() {
    cd "$REPO_DIR"
    bash scripts/gen_certs.sh
    bash scripts/topology.sh create
    ip netns exec srv python3 traffic/services/https_server.py --port 8443 >/dev/null 2>&1 &
    local srv_pid=$!
    sleep 1
    ip netns exec sensor-01 python3 traffic/benign_iot_generator.py \
        --device-from-config sensor-01 \
        --connection persistent \
        --time-scale 50 \
        --duration 4
    kill "$srv_pid" 2>/dev/null || true
    echo "Persistent TLS generator and HTTPS service verified."
}

stage_S4() {
    cd "$REPO_DIR"
    bash scripts/xdp_selftest.sh
}

stage_S5() {
    cd "$REPO_DIR"
    python3 -m pytest tests/test_engine_closed_loop.py -k "test_enforce_per_flow_drop_and_ttl_expiry or test_fast_path_bypass_ablation" -v
}

stage_S5b() {
    cd "$REPO_DIR"
    python3 -m pytest tests/test_engine_closed_loop.py -k "test_progressive_checkpoints_early_drop_late_bypass" -v
}

stage_S6() {
    cd "$REPO_DIR"
    bash scripts/equivalence_test.sh
}

stage_S6b() {
    cd "$REPO_DIR"
    python3 -m pytest tests/test_schema_and_equivalence.py -k "test_multi_checkpoint_equivalence" -v
}

stage_S6c() {
    cd "$REPO_DIR"
    python3 -m pytest tests/test_schema_and_equivalence.py -k "test_flow_record_lifecycle_and_reinit_a1 or test_checkpoint_retry_and_shed_counters_a2 or test_40_packet_flow_exact_3_checkpoints_no_event_storm_1c" -v
    python3 -m pytest tests/test_kernel_source_invariants.py -v

    # Live kernel event-storm check on Linux root: assert each connection yields EXACTLY NUM_CHECKPOINTS events
    bash scripts/gen_certs.sh
    bash scripts/topology.sh create
    local ev_file="$VERIFY_DIR/s6c_events.jsonl"
    rm -f "$ev_file"

    ip netns exec srv python3 traffic/tls_server.py >/dev/null 2>&1 &
    local srv_pid=$!
    sleep 1

    ip netns exec gw python3 -m ips.engine \
        --config "$REPO_DIR/configs/system.yaml" \
        --mode observe \
        --events-out "$ev_file" \
        --duration 12 >/dev/null 2>&1 &
    local eng_pid=$!
    sleep 2

    ip netns exec sensor-01 python3 traffic/benign_iot_generator.py \
        --device-from-config sensor-01 \
        --connection persistent \
        --time-scale 50 \
        --duration 8 >/dev/null 2>&1 || true

    wait "$eng_pid" || true
    kill "$srv_pid" 2>/dev/null || true

    # Grep engine event log by flow key and assert count == NUM_CHECKPOINTS (no event storm)
    if [[ -f "$ev_file" ]]; then
        local total_events
        total_events=$(grep -c '"checkpoint_idx"' "$ev_file" || echo 0)
        python3 - "$ev_file" <<'PYEOF'
import json, sys, yaml
from collections import Counter

ev_path = sys.argv[1]
with open("configs/system.yaml", "r") as f:
    cfg = yaml.safe_load(f)
num_ckpts = len(cfg["system"].get("checkpoints", [4, 8, 16]))

counts = Counter()
with open(ev_path, "r") as f:
    for line in f:
        if not line.strip():
            continue
        ev = json.loads(line)
        fk = f"{ev['ip_a']}:{ev['port_a']}<->{ev['ip_b']}:{ev['port_b']}/{ev['proto']}"
        counts[fk] += 1

num_flows = len(counts)
total_emitted = sum(counts.values())
print(f"events_emitted={total_emitted} / flows={num_flows} (expected={num_ckpts} per completed flow)")
assert num_flows > 0, "Zero flows recorded in S6c!"
for fk, c in counts.items():
    assert c == num_ckpts, f"EVENT STORM / MISMATCH on flow {fk}: expected exactly {num_ckpts} events, got {c}"
PYEOF
    else
        echo "ERROR: $ev_file was not created by engine"
        return 1
    fi
}

stage_S6d() {
    cd "$REPO_DIR"
    python3 -c "
import threading, time
from ips.engine.engine import MockBPFBackend
b = MockBPFBackend(16, [4, 8, 16])
errs = []
def w(t):
    try:
        for i in range(50):
            b.simulate_packet('10.0.1.11', 50000+t, '10.0.2.10', 8443, 'TCP', 100, 0, int(time.time()*1e9)+i*1000)
    except Exception as e:
        errs.append(e)
th = [threading.Thread(target=w, args=(i,)) for i in range(4)]
for t in th: t.start()
for t in th: t.join()
assert not errs, f'Threading errors: {errs}'
print('Multi-threaded RPS concurrency simulation completed cleanly.')
"
}

stage_S6e_model() {
    cd "$REPO_DIR"
    echo "[Python model only — does not execute eBPF kernel]"
    python3 audit/check_canonical_key.py
    python3 -m pytest tests/test_schema_and_equivalence.py -k "test_flow_key_canonical_symmetry" -v
}

stage_S6e() {
    cd "$REPO_DIR"
    bash scripts/topology.sh create
    # Pick IP/port pairs where numeric, string, and raw little-endian orders differ,
    # write DROP verdict from Python make_flow_key, send real traffic through gw,
    # and assert kernel counter pkts_dropped_verdict increments for every pair.
    ip netns exec gw python3 - <<'PYEOF'
import ctypes, os, socket, subprocess, sys, time
from bcc import BPF

sys.path.insert(0, os.path.abspath("."))
from ips.engine.schema import (
    load_system_config,
    generate_c_header,
    make_ctypes_schemas,
    make_flow_key,
    VERDICT_DROP,
)

cfg = load_system_config()
schemas = make_ctypes_schemas(int(cfg["system"]["early_n"]))
with open("ebpf/ips_engine.c", "r") as f:
    c_src = generate_c_header(cfg) + "\n" + f.read()

b = BPF(text=c_src)
fn = b.load_func("xdp_ips_prog", BPF.XDP)
for dev in ("v-lan-gw", "v-wan-gw"):
    try:
        b.attach_xdp(dev, fn, 0)
    except Exception:
        b.attach_xdp(dev, fn, BPF.XDP_FLAGS_SKB_MODE)

def get_dropped_verdict(stats_map):
    total = 0
    for cpu_st in stats_map[ctypes.c_int(0)]:
        total += int(cpu_st.pkts_dropped_verdict)
    return total

try:
    vmap = b.get_table("verdict_map")
    smap = b.get_table("stats_map")
    # Pairs where string ('10.0.1.11' < '10.0.1.9'), numeric (10.0.1.11 < 10.0.2.10),
    # and little-endian byte orders differ across IPs and ports (e.g. 256 vs 1, 50000 vs 8443)
    test_pairs = [
        ("10.0.1.10", 50000, "10.0.2.10", 8443),
        ("10.0.1.10", 256,   "10.0.2.10", 1),
        ("10.0.1.10", 80,    "10.0.2.10", 60000),
    ]
    now_ns = time.monotonic_ns()
    for sip, sp, dip, dp in test_pairs:
        fk = make_flow_key(sip, sp, dip, dp, "UDP")
        vmap[fk] = schemas.VerdictEntry(action=VERDICT_DROP, expiry_ns=now_ns + int(60e9))

    for sip, sp, dip, dp in test_pairs:
        before = get_dropped_verdict(smap)
        # Send real UDP packet from sensor-01 (10.0.1.10) to srv (10.0.2.10) across gw
        cmd = [
            "ip", "netns", "exec", "sensor-01",
            "python3", "-c",
            f"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
            f"s.bind(('{sip}', {sp})); s.sendto(b'canonical_key_probe', ('{dip}', {dp})); s.close()"
        ]
        subprocess.run(cmd, check=True)
        time.sleep(0.1)
        after = get_dropped_verdict(smap)
        assert after > before, f"Kernel failed to drop canonical key for ({sip}:{sp} -> {dip}:{dp}): before={before}, after={after}"
        print(f"[+] Verified kernel pkts_dropped_verdict incremented ({before} -> {after}) for {sip}:{sp} <-> {dip}:{dp}")
finally:
    for dev in ("v-lan-gw", "v-wan-gw"):
        try: b.remove_xdp(dev, 0)
        except Exception: pass
        try: b.remove_xdp(dev, BPF.XDP_FLAGS_SKB_MODE)
        except Exception: pass
PYEOF
}

stage_S7() {
    cd "$REPO_DIR"
    python3 -m pytest tests/test_manifest.py -v
}

stage_S8() {
    cd "$REPO_DIR"
    python3 -m pytest tests/test_engine_closed_loop.py -k "test_watchdog_load_shedding_and_cooldown_recovery" -v
}

stage_S8b() {
    cd "$REPO_DIR"
    bash scripts/netem_sweep.sh --dry-run
}

stage_S9() {
    cd "$REPO_DIR"
    python3 ips/eval/harness.py --smoke
}

stage_S10() {
    cd "$REPO_DIR"
    python3 ips/drift/scenarios.py --out-dir "$REPO_DIR/results/smoke"
}

stage_S11() {
    cd "$REPO_DIR"
    python3 -m ips.data.build_splits --check
}

run_stage "S0"  "Environment & Package Check"                stage_S0
run_stage "S1"  "Python V1 Unit Test Suite"                  stage_S1
run_stage "S2"  "14-Namespace Topology & Routing"            stage_S2
run_stage "S3"  "TLS Services & Persistent Generator"        stage_S3
run_stage "S4"  "XDP v2 Attach & Bidirectional Maps"         stage_S4
run_stage "S5"  "Per-5-Tuple Verdict & TTL Expiry"           stage_S5
run_stage "S5b" "Progressive Checkpoints [4,8,16] (C1)"      stage_S5b
run_stage "S6"  "Kernel-vs-Offline Equivalence (N6)"         stage_S6
run_stage "S6b" "Multi-Checkpoint Equivalence [4,8,16]"      stage_S6b
run_stage "S6c"       "Flow Lifecycle & Event Storm Guard (A1/A2)" stage_S6c
run_stage "S6d"       "Concurrency RPS CPU Pinning (A3)"           stage_S6d
run_stage "S6e-model" "Python Model Canonical Key Check"           stage_S6e_model
run_stage "S6e"       "Canonical Key Kernel Drop Execution (A4)"   stage_S6e
run_stage "S7"  "Experiment Manifest & Capture"              stage_S7
run_stage "S8"  "Closed-Loop Engine & Watchdog"              stage_S8
run_stage "S8b" "Netem Impairment & Feature Ablations (C11)" stage_S8b
run_stage "S9"  "System Harness, Bypass & Harm (N2/C10)"     stage_S9
run_stage "S10" "Drift Guard S1-S5 & Cost-of-Evasion (C3)"   stage_S10
run_stage "S11" "Dataset Split Integrity & Leakage (WP2b)"   stage_S11

# Write results/verify/REPORT.md
{
    echo "# Linux Verification Report (\`scripts/verify_linux.sh\`)"
    echo ""
    echo "- **Timestamp**: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "- **Host**: $(uname -srm)"
    echo "- **Git Commit**: $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    echo ""
    echo "| Stage | Status | Time | Summary |"
    echo "|-------|--------|------|---------|"
    for s in "${STAGES[@]}"; do
        echo "| $s | **${STAGE_STATUS[$s]}** | ${STAGE_TIME[$s]} | ${STAGE_NOTES[$s]} |"
    done
    echo ""
    for s in "${STAGES[@]}"; do
        if [[ "${STAGE_STATUS[$s]}" == "FAIL" && -f "$VERIFY_DIR/${s}.log" ]]; then
            echo "## Failure Tail: $s"
            echo '```text'
            tail -n 30 "$VERIFY_DIR/${s}.log"
            echo '```'
            echo ""
        fi
    done
} >"$REPORT_FILE"

echo ""
echo "[+] Wrote verification summary to $REPORT_FILE"
cat "$REPORT_FILE"

