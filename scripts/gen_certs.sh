#!/usr/bin/env bash
# scripts/gen_certs.sh — Generate self-signed TLS certificates for the testbed.
# Idempotent: skips generation if certs already exist.
# Matches traffic/tls_server.py certificate generation logic.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/../traffic/certs"

mkdir -p "$CERTS_DIR"

if [ -f "$CERTS_DIR/server.crt" ] && [ -f "$CERTS_DIR/server.key" ]; then
    echo "[gen_certs] Certificates already exist in $CERTS_DIR — skipping."
    exit 0
fi

echo "[gen_certs] Generating self-signed certificate with SAN=IP:10.0.2.10 ..."
openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.crt" \
    -days 365 -nodes \
    -subj "/CN=10.0.2.10" \
    -addext "subjectAltName = IP:10.0.2.10,IP:127.0.0.1,DNS:localhost" \
    2>/dev/null || \
openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.crt" \
    -days 365 -nodes \
    -subj "/CN=10.0.2.10" \
    2>/dev/null

echo "[gen_certs] Created: $CERTS_DIR/server.{crt,key}"
