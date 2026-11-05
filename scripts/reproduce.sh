#!/usr/bin/env bash
# scripts/reproduce.sh — Regenerate docs/RESULTS.md from real experimental outputs (WP9).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

python3 "$REPO_DIR/ips/eval/reproduce.py"

