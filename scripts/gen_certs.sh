#!/usr/bin/env bash
# scripts/gen_certs.sh — Generate self-signed TLS certificates for the testbed.
# Idempotent: skips generation if certs already exist.
# Run from repo root or any directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/../traffic/certs"

mkdir -p "$CERTS_DIR"

if [ -f "$CERTS_DIR/server.crt" ] && [ -f "$CERTS_DIR/server.key" ]; then
    echo "[gen_certs] Certificates already exist in $CERTS_DIR — skipping."
    exit 0
fi

echo "[gen_certs] Generating self-signed certificate ..."
openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.crt" \
    -days 365 -nodes \
    -subj "/CN=ips-testbed" \
    2>/dev/null

echo "[gen_certs] Created: $CERTS_DIR/server.{crt,key}"

