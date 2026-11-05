#!/usr/bin/env python3
"""
traffic/attacks/a4_exfiltration.py — A4: TLS Exfiltration attack.

Transmits large payloads in high-volume chunks (800-1460 B) upstream over TLS
simulating sensitive sensor / configuration / credential data theft.
"""
import ssl
import socket
import time
import random
import argparse
import os
import sys

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)
from traffic.manifest import ManifestWriter


def run_a4_exfil(target_ip="10.0.2.10", target_port=8883,
                 chunk_size=1400, duration_s=20.0,
                 manifest_path="results/manifest.csv", run_id="run_exp"):
    print(f"[A4 EXFILTRATION] Uploading high-volume TLS payloads to {target_ip}:{target_port} for {duration_s}s")
    writer = ManifestWriter(manifest_path, run_id=run_id)
    start_ts = time.time()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    bytes_sent = 0
    chunks = 0

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        tls = ctx.wrap_socket(s, server_hostname=target_ip)
        tls.connect((target_ip, target_port))

        while time.time() - start_ts < duration_s:
            # Vary chunk size slightly (1200 - 1460)
            sz = random.randint(chunk_size - 100, chunk_size + 60)
            payload = bytes(random.getrandbits(8) for _ in range(sz))
            tls.sendall(payload)
            bytes_sent += len(payload)
            chunks += 1
            time.sleep(random.uniform(0.01, 0.05))

        tls.close()
    except Exception as e:
        print(f"[A4 EXFIL ERROR] Socket exception: {e}")

    end_ts = time.time()
    writer.record_episode(
        family="A4_exfil",
        src_ip="10.0.1.4",
        dst_ip=target_ip,
        dst_port=target_port,
        start_ts=start_ts,
        end_ts=end_ts,
        params={"chunks": chunks, "bytes_sent": bytes_sent, "duration_s": duration_s},
    )
    print(f"[A4 EXFILTRATION] Completed. Exfiltrated {bytes_sent:,} bytes in {chunks} chunks.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="10.0.2.10")
    parser.add_argument("--port", type=int, default=8883)
    parser.add_argument("--chunk-size", type=int, default=1400)
    parser.add_argument("--duration", type=float, default=20.0)
    parser.add_argument("--manifest", default="results/manifest.csv")
    parser.add_argument("--run-id", default="run_a4")
    args = parser.parse_args()

    run_a4_exfil(args.target, args.port, args.chunk_size, args.duration, args.manifest, args.run_id)

