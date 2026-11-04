#!/usr/bin/env bash
# datasets/download_tqh_c2.sh — Download TQH-C2 encrypted C2 dataset (Zenodo 21523144)
set -euo pipefail

DEST_DIR="$(cd "$(dirname "$0")/raw/tqh_c2" && pwd)"
mkdir -p "$DEST_DIR"

SIZE_ESTIMATE="~379 MB (Testbed C archive)"
URL="https://zenodo.org/records/21523144/files/testbed_c.tar.gz"

echo "================================================================================"
echo "  TQH-C2 Dataset Downloader (Zenodo Record 21523144, CC-BY 4.0)"
echo "  Contents: Sliver over TLS, Merlin over HTTP/3, Mythic pcaps and JA4 labels"
echo "  Estimated download size: $SIZE_ESTIMATE"
echo "  Destination: $DEST_DIR"
echo "================================================================================"

if [ -t 0 ]; then
    read -r -p "Do you want to proceed with downloading $SIZE_ESTIMATE? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Download cancelled by user."
        exit 0
    fi
fi

echo "[TQH-C2] Downloading testbed_c.tar.gz ..."
curl -L -o "$DEST_DIR/testbed_c.tar.gz" "$URL"
echo "[TQH-C2] Extracting archive ..."
tar -xzf "$DEST_DIR/testbed_c.tar.gz" -C "$DEST_DIR"
echo "[OK] TQH-C2 ready in $DEST_DIR"
