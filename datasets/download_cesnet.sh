#!/usr/bin/env bash
# datasets/download_cesnet.sh — Download CESNET-TLS-Year22 metadata and weekly samples (Zenodo 10608607).
#
# NOTE: Exact file names on Zenodo record 10608607 (e.g. stats-dataset.json, weekly archives)
# are marked UNVERIFIED – check on the Zenodo page before downloading large weekly files.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="$SCRIPT_DIR/raw/cesnet"
mkdir -p "$DEST_DIR"

ZENODO_BASE="${ZENODO_BASE:-https://zenodo.org/records/10608607/files}"

echo "================================================================================"
echo "  CESNET-TLS-Year22 Downloader (Zenodo 10.5281/zenodo.10608607)"
echo "  Role: OFFLINE real benign TLS (first 30 payload packets, no pcaps, no attacks)"
echo "  Destination: $DEST_DIR"
echo "  NOTE: Check file sizes on Zenodo 10608607 first (UNVERIFIED file list)."
echo "================================================================================"

if [[ "${1:-}" != "--yes" ]]; then
    read -r -p "Proceed with fetching stats-dataset.json from Zenodo 10608607? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Download cancelled by user."
        exit 0
    fi
fi

echo "[CESNET] Fetching stats-dataset.json ..."
curl -fL -o "$DEST_DIR/stats-dataset.json" "${ZENODO_BASE}/stats-dataset.json" || {
    echo "WARNING: Could not fetch stats-dataset.json automatically; check Zenodo 10608607 in browser." >&2
}
echo "[OK] CESNET directory ready in $DEST_DIR"
