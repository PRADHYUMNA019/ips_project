#!/usr/bin/env bash
# datasets/download_kitsune.sh — Download SSL Renegotiation slice of Kitsune Network Attack Dataset.
#
# NOTE: Kitsune pcaps have packets truncated to 200 bytes (snaplen=200), so payload length
# MUST be read from IP/TCP headers (ip.len - ip.hl*4 - tcp.off*4), never len(tcp.data).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="$SCRIPT_DIR/raw/kitsune"
mkdir -p "$DEST_DIR"

URL="${KITSUNE_URL:-https://archive.ics.uci.edu/static/public/516/kitsune+network+attack+dataset.zip}"

echo "================================================================================"
echo "  Kitsune Network Attack Dataset (UCI Machine Learning Repository 516)"
echo "  Target: SSL Renegotiation (TLS attack) & SSDP Flood (UDP); others plaintext"
echo "  Destination: $DEST_DIR"
echo "  NOTE: Check size before downloading full UCI archive (UNVERIFIED sub-file URL)."
echo "================================================================================"

if [[ "${1:-}" != "--yes" ]]; then
    read -r -p "Proceed with downloading Kitsune archive to $DEST_DIR? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Download cancelled by user."
        exit 0
    fi
fi

curl -fL -o "$DEST_DIR/kitsune_dataset.zip" "$URL" || {
    echo "WARNING: Download failed; check UCI repository ID 516 URL." >&2
}
echo "[OK] Kitsune download script completed."
