#!/usr/bin/env python3
"""
traffic/services/https_server.py — HTTPS server for IoT camera uploads & exfiltration target.

Runs in netns 'srv' on port 443 (or custom port) with TLS 1.2/1.3.
"""
import os
import ssl
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CERTS_DIR = os.path.join(REPO_DIR, "traffic", "certs")
CERT_FILE = os.path.join(CERTS_DIR, "server.crt")
KEY_FILE = os.path.join(CERTS_DIR, "server.key")


class EdgeHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Edge HTTPS Gateway OK\n")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        # Read payload
        body = self.rfile.read(content_length) if content_length > 0 else b""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "received", "bytes": ' + str(len(body)).encode() + b'}\n')

    def log_message(self, format, *args):
        # Quiet logging
        pass


def run_https_server(host="0.0.0.0", port=443):
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        # Auto generate certs if needed
        from traffic.tls_server import ensure_certs
        ensure_certs()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    server = HTTPServer((host, port), EdgeHTTPHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"[HTTPS] Serving on https://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 443
    run_https_server(port=port)
