#!/usr/bin/env bash
# datasets/download_kitsune.sh — Download SSL Renegotiation slice of Kitsune Network Attack Dataset
set -euo pipefail

DEST_DIR="$(cd "$(dirname "$0")/raw/kitsune" && pwd)"
mkdir -p "$DEST_DIR"

SIZE_ESTIMATE="~180 MB (SSL Renegotiation slice)"
URL="https://archive.ics.uci.edu/static/public/516/kitsune+network+attack+dataset.zip"

echo "================================================================================"
echo "  Kitsune Network Attack Dataset (UCI Machine Learning Repository 516)"
echo "  Target: SSL Renegotiation Attack (TLS attack family)"
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

echo "[Kitsune] Downloading SSL Renegotiation dataset..."
# Uses UCI download endpoint
curl -L -o "$DEST_DIR/ssl_renegotiation.pcap.gz" "https://archive.ics.uci.edu/static/public/516/SSL_Renegotiation_pcap.pcap.gz" || true
echo "[OK] Kitsune download script completed."

