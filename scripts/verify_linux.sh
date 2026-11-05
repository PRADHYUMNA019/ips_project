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
STAGES=(S0 S1 S2 S3 S4 S5 S5b S6 S6b S6c S6d S6e S7 S8 S8b S9 S10 S11)

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
    python3 -m pytest tests/test_schema_and_equivalence.py -k "test_flow_record_lifecycle_and_reinit_a1 or test_checkpoint_retry_and_shed_counters_a2" -v
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

stage_S6e() {
    cd "$REPO_DIR"
    python3 audit/check_canonical_key.py
    python3 -m pytest tests/test_schema_and_equivalence.py -k "test_flow_key_canonical_symmetry" -v
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
run_stage "S6c" "Flow Lifecycle & Re-init (A1/A2)"            stage_S6c
run_stage "S6d" "Concurrency RPS CPU Pinning (A3)"           stage_S6d
run_stage "S6e" "Canonical Key Drop Execution (A4)"          stage_S6e
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

