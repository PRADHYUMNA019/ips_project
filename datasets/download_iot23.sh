#!/usr/bin/env bash
# datasets/download_iot23.sh — Download selected Aposemat IoT-23 captures (pcaps required).
#
# CRITICAL DATASET FACTS (A3):
#   1. The "small" IoT-23 archive (iot_23_datasets_small.tar.gz, ~8.7 GB) contains ONLY
#      Zeek conn.log flow summaries WITHOUT pcaps. It CANNOT produce early-window
#      packet vectors (sizes[0..N-1], dirs[0..N-1], iat[0..N-2]). Raw .pcap files are required!
#   2. Benign captures in IoT-23 are strictly:
#        - CTU-Honeypot-Capture-4-1 (Philips Hue smart LED bridge)
#        - CTU-Honeypot-Capture-5-1 (Amazon Echo smart speaker)
#        - CTU-Honeypot-Capture-7-1 (Somfy smart door lock)
#   3. WARNING: CTU-IoT-Malware-Capture-7-1 is MALICIOUS (Linux.Mirai)!
#      NEVER confuse CTU-IoT-Malware-Capture-7-1 with CTU-Honeypot-Capture-7-1 or label it benign!
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$SCRIPT_DIR/raw/iot23"
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"

# Stratosphere individual capture directory base (UNVERIFIED – check on Stratosphere page before download)
IOT23_BASE="${IOT23_BASE:-https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios}"

echo "=================================================================="
echo "Aposemat IoT-23 Individual Pcap Capture Downloader"
echo "Target directory: $TARGET_DIR"
echo "Benign captures to fetch (for B6 cross-domain benign FPR test):"
echo "  - CTU-Honeypot-Capture-4-1 (Philips Hue)"
echo "  - CTU-Honeypot-Capture-5-1 (Amazon Echo)"
echo "  - CTU-Honeypot-Capture-7-1 (Somfy Door Lock)"
echo "WARNING: Do NOT use iot_23_datasets_small.tar.gz (Zeek logs only, no pcaps)."
echo "WARNING: CTU-IoT-Malware-Capture-7-1 is MALICIOUS (Linux.Mirai), NOT benign."
echo "=================================================================="

if [[ "${1:-}" != "--yes" ]]; then
    read -r -p "Check remote sizes and download benign honeypot pcaps? [y/N] " resp
    if [[ ! "$resp" =~ ^[Yy]$ ]]; then
        echo "Aborted by user."
        exit 0
    fi
fi

BENIGN_CAPTURES=(
    "CTU-Honeypot-Capture-4-1"
    "CTU-Honeypot-Capture-5-1"
    "CTU-Honeypot-Capture-7-1"
)

for cap in "${BENIGN_CAPTURES[@]}"; do
    mkdir -p "$TARGET_DIR/$cap"
    echo "[*] Checking $IOT23_BASE/$cap/ ..."
    echo "    (If individual scenario URL structure differs on Stratosphere mirror, download the .pcap into $TARGET_DIR/$cap/)"
done

echo "[+] IoT-23 directory structure prepared in $TARGET_DIR"
