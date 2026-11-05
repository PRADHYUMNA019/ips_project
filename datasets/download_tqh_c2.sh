#!/usr/bin/env bash
# datasets/download_tqh_c2.sh — Download TQH-C2 Testbed D (Merlin HTTP/2-over-TLS C2).
#
# Reference: Zenodo record for TQH-C2 v1.2.0 (check exact Zenodo record URL before running:
# UNVERIFIED URL PATTERN — verify record ID on Zenodo page if 21523144/1523144 redirects).
#
# Why Testbed D only:
#   - Testbed D (TQH-C2_pcap_D_merlin_h2.zip, ~1.8 GB): Merlin C2 over HTTP/2-over-TLS (encrypted).
#   - Testbed A (33.4 GB): Sliver over TLS, omitted due to size.
#   - Testbed B: QUIC (not TLS/TCP).
#   - Testbed C: Plain HTTP with AES body (NOT TLS on the wire — excluded per encrypted scope).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$SCRIPT_DIR/raw/tqh_c2"
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"

# UNVERIFIED – check on the Zenodo page if Zenodo record path changes
ZENODO_BASE="${ZENODO_BASE:-https://zenodo.org/records/21523144/files}"

FILES=(
    "SHA256SUMS_v120.txt"
    "README_v120.md"
    "TQH-C2_labels_D.zip"
    "TQH-C2_features_D.zip"
    "TQH-C2_pcap_D_merlin_h2.zip"
)

echo "=================================================================="
echo "TQH-C2 Testbed D Downloader (Merlin over HTTP/2-over-TLS)"
echo "Target directory: $TARGET_DIR"
echo "Estimated download size: ~1.8 GB (TQH-C2_pcap_D_merlin_h2.zip)"
echo "NOTE: Zenodo URL ($ZENODO_BASE) is UNVERIFIED – check on the Zenodo page."
echo "=================================================================="

if [[ "${1:-}" != "--yes" ]]; then
    read -r -p "Proceed with download (~1.8 GB)? [y/N] " resp
    if [[ ! "$resp" =~ ^[Yy]$ ]]; then
        echo "Aborted by user."
        exit 0
    fi
fi

for f in "${FILES[@]}"; do
    echo "[*] Downloading $f ..."
    curl -fL -O "${ZENODO_BASE}/${f}" || {
        echo "ERROR: Failed to download ${ZENODO_BASE}/${f}." >&2
        echo "Please verify the Zenodo record URL on the TQH-C2 Zenodo page and set ZENODO_BASE." >&2
        exit 1
    }
done

echo "[*] Verifying SHA-256 checksums against SHA256SUMS_v120.txt..."
sha256sum -c --ignore-missing SHA256SUMS_v120.txt

echo "[+] TQH-C2 Testbed D download and SHA-256 check complete in $TARGET_DIR"
