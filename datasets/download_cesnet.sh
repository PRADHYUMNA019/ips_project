#!/usr/bin/env bash
# datasets/download_cesnet.sh — Download sampled week of CESNET-TLS-Year22 (Zenodo 10608607)
set -euo pipefail

DEST_DIR="$(cd "$(dirname "$0")/raw/cesnet" && pwd)"
mkdir -p "$DEST_DIR"

SIZE_ESTIMATE="~250 MB (Sampled week parquet)"
URL="https://zenodo.org/records/10608607/files/week_01_sample.parquet"

echo "================================================================================"
echo "  CESNET-TLS-Year22 Downloader (Zenodo 10.5281/zenodo.10608607)"
echo "  Contents: Benign backbone TLS flow vectors (first 30 packets, sizes, IATs)"
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

echo "[CESNET] Downloading week_01_sample.parquet ..."
curl -L -o "$DEST_DIR/week_01_sample.parquet" "$URL"
echo "[OK] CESNET sample ready in $DEST_DIR"
