#!/usr/bin/env python3
"""
traffic/tls_server.py — TLS echo server (port 8883).
Run in the server namespace:
  sudo ip netns exec srv python3 traffic/tls_server.py
"""
import ssl
import socket
import threading
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("TLS-Server")

import os
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
CERT = os.path.join(CERTS_DIR, "server.crt")
KEY  = os.path.join(CERTS_DIR, "server.key")
HOST, PORT = "0.0.0.0", 8883

def ensure_certs():
    if not os.path.exists(CERTS_DIR):
        os.makedirs(CERTS_DIR, exist_ok=True)
    if not os.path.exists(CERT) or not os.path.exists(KEY):
        logger.info(f"Generating self-signed certificate in {CERTS_DIR}...")
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY, "-out", CERT, "-days", "365",
            "-nodes", "-subj", "/CN=10.0.2.10"
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("Certificate generated successfully.")


def handle_client(conn, addr):
    logger.info(f"connection from {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data[:64])   # small echo, like an ACK
    except Exception as e:
        logger.debug(f"{addr} disconnected: {e}")
    finally:
        conn.close()


def main():
    ensure_certs()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(50)
    tls = ctx.wrap_socket(sock, server_side=True)
    logger.info(f"TLS server listening on {HOST}:{PORT}")
    while True:
        conn, addr = tls.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
