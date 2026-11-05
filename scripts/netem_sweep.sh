#!/usr/bin/env bash
# scripts/netem_sweep.sh — Network-Impairment Sweep on Gateway Interface (C11 / N11).
#
# Injects controlled WAN/Wi-Fi impairments on v-lan-gw inside the gw namespace using tc netem:
#   tc qdisc replace dev v-lan-gw root netem delay <d>ms <j>ms loss <l>% reorder <r>%
# across a grid of delay (5-50 ms), jitter (0-20 ms), loss (0-2%), and reordering (0-5%).
#
# Usage:
#   sudo bash scripts/netem_sweep.sh [--dry-run] [--dev v-lan-gw]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
DRY_RUN=0
DEV="v-lan-gw"
NS="gw"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --dev) DEV="$2"; shift 2 ;;
        *) shift ;;
    esac
done

cleanup_qdisc() {
    if [[ "$DRY_RUN" -eq 0 ]]; then
        ip netns exec "$NS" tc qdisc del dev "$DEV" root 2>/dev/null || true
    fi
}
trap cleanup_qdisc EXIT INT TERM

# Grid profiles: name delay_ms jitter_ms loss_pct reorder_pct
PROFILES=(
    "clean 0 0 0 0"
    "mild_wifi 5 2 0.1 0.5"
    "mod_jitter 15 10 0.5 1.0"
    "high_jitter 30 20 1.0 2.0"
    "severe_wan 50 20 2.0 5.0"
)

echo "[*] Starting C11 netem impairment sweep on ${NS}:${DEV} (dry_run=${DRY_RUN})"
for prof in "${PROFILES[@]}"; do
    read -r pname d_ms j_ms l_pct r_pct <<< "$prof"
    if [[ "$d_ms" == "0" ]]; then
        CMD="ip netns exec $NS tc qdisc del dev $DEV root || true"
    else
        CMD="ip netns exec $NS tc qdisc replace dev $DEV root netem delay ${d_ms}ms ${j_ms}ms loss ${l_pct}% reorder ${r_pct}% 50%"
    fi
    echo "[+] Profile=${pname}: ${CMD}"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        eval "$CMD"
    fi
done

echo "[+] Running offline/simulated feature impairment & ablation analysis (ips/eval/impairment.py)..."
python3 "$REPO_DIR/ips/eval/impairment.py" --smoke
echo "[+] C11 netem sweep complete."
