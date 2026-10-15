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

CERT = "/home/vboxuser/ips-project/traffic/certs/server.crt"
KEY  = "/home/vboxuser/ips-project/traffic/certs/server.key"
HOST, PORT = "0.0.0.0", 8883


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
