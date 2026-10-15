#!/usr/bin/env bash
# scripts/capture.sh <name> — tcpdump on v-lan-gw with standard naming
# Usage: sudo ./scripts/capture.sh benign_train   (Ctrl+C to stop)
set -euo pipefail
cd "$(dirname "$0")/.."
NAME=${1:?usage: capture.sh <name>}
mkdir -p ml/data/raw
sudo tcpdump -i v-lan-gw -w "ml/data/raw/${NAME}_$(date +%Y%m%d_%H%M%S).pcap"
