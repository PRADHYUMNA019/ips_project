#!/usr/bin/env bash
# scripts/check_env.sh — Verify system dependencies and readiness for the IPS demo
set -uo pipefail

echo "=========================================================="
echo "   IPS Project: Pre-Flight Environment & Readiness Check  "
echo "=========================================================="

PASS=0
FAIL=0

check_cmd() {
    local cmd=$1
    local pkg=$2
    if command -v "$cmd" >/dev/null 2>&1; then
        echo -e "[PASS] Command '$cmd' is installed ($(command -v "$cmd"))"
        PASS=$((PASS + 1))
    else
        echo -e "[FAIL] Command '$cmd' is MISSING! Install via: sudo apt install -y $pkg"
        FAIL=$((FAIL + 1))
    fi
}

echo -e "\n--- [1] Core Tooling & Utilities ---"
check_cmd "clang" "clang llvm"
check_cmd "bpftool" "linux-tools-common linux-tools-\$(uname -r)"
check_cmd "jq" "jq"
check_cmd "iperf3" "iperf3"
check_cmd "tcpdump" "tcpdump"
check_cmd "openssl" "openssl"
check_cmd "ip" "iproute2"

echo -e "\n--- [2] Python Dependencies ---"
python3 -c "import bcc" >/dev/null 2>&1 && echo "[PASS] Python BCC (bpfcc) is installed" && PASS=$((PASS + 1)) || { echo "[FAIL] Python BCC is missing! Install via: sudo apt install -y python3-bpfcc"; FAIL=$((FAIL + 1)); }
python3 -c "import yaml" >/dev/null 2>&1 && echo "[PASS] PyYAML is installed" && PASS=$((PASS + 1)) || echo "[WARN] PyYAML is not installed (engine will use built-in defaults). Optional: pip install pyyaml"

echo -e "\n--- [3] Kernel & eBPF Capabilities ---"
KERNEL=$(uname -r)
echo "[INFO] Running Linux Kernel: $KERNEL"
if [[ $(id -u) -eq 0 ]]; then
    echo "[PASS] Running with root/sudo privileges"
    PASS=$((PASS + 1))
else
    echo "[WARN] Not running as root. Testbed and eBPF commands will require 'sudo'"
fi

echo -e "\n=========================================================="
if [ "$FAIL" -eq 0 ]; then
    echo "  [SUCCESS] All critical dependencies are satisfied!"
    echo "  You are ready for the Saturday presentation demo."
else
    echo "  [WARNING] $FAIL critical dependencies are missing!"
    echo "  Please install the missing packages before presenting."
fi
echo "=========================================================="
