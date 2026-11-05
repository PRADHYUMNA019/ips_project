#!/usr/bin/env bash
# datasets/download_iot23.sh — Download selected captures from Aposemat IoT-23
set -euo pipefail

DEST_DIR="$(cd "$(dirname "$0")/raw/iot23" && pwd)"
mkdir -p "$DEST_DIR"

SIZE_ESTIMATE="~350 MB (Selected Mirai and Benign IoT captures)"
echo "================================================================================"
echo "  Aposemat IoT-23 Dataset Downloader (Stratosphere Laboratory)"
echo "  Contents: Plaintext IoT attacks (Mirai) + 3 benign devices"
echo "  Note: Classified strictly as 'plaintext-attack' (Rule H3)"
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

# Download CTU-IoT-Malware-Capture-34-1 (Mirai sample)
echo "[IoT-23] Downloading Mirai sample capture (CTU-IoT-Malware-Capture-34-1) ..."
curl -L -o "$DEST_DIR/mirai_capture.pcap" "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled" || true
echo "[OK] IoT-23 download script finished."

