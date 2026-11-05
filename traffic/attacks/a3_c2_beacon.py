#!/usr/bin/env python3
"""
traffic/attacks/a3_c2_beacon.py — A3: Realistic C2 beaconing over TLS.

Simulates Sliver / Mythic / CobaltStrike C2 beacons with configurable:
  - Intervals: {1, 5, 15, 30, 60} seconds
  - Jitter: {0, 15, 30} percent
  - Modes: persistent keep-alive vs reconnect-per-beacon
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


def run_a3_c2_beacon(target_ip="10.0.2.10", target_port=8883,
                     interval_s=5.0, jitter_pct=0.30, duration_s=60.0,
                     mode="persistent", manifest_path="results/manifest.csv",
                     run_id="run_exp"):
    print(f"[A3 C2 BEACON] Starting TLS C2: interval={interval_s}s, jitter={jitter_pct*100}%, mode={mode}, duration={duration_s}s")
    writer = ManifestWriter(manifest_path, run_id=run_id)
    start_ts = time.time()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    beacons_sent = 0
    seq = 0

    def create_tls_conn():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        t = ctx.wrap_socket(s, server_hostname=target_ip)
        t.connect((target_ip, target_port))
        return t

    tls_sock = None
    if mode == "persistent":
        try:
            tls_sock = create_tls_conn()
        except Exception as e:
            print(f"[A3 ERROR] Initial TLS connect failed: {e}")

    while time.time() - start_ts < duration_s:
        seq += 1
        msg = f"c2_cmd_heartbeat_seq_{seq:04d}".encode()
        try:
            if mode == "reconnect":
                conn = create_tls_conn()
                conn.sendall(msg)
                try:
                    conn.recv(64)
                except Exception:
                    pass
                conn.close()
                beacons_sent += 1
            else:
                if tls_sock is None:
                    tls_sock = create_tls_conn()
                tls_sock.sendall(msg)
                try:
                    tls_sock.recv(64)
                except Exception:
                    pass
                beacons_sent += 1
        except Exception as e:
            if mode == "persistent" and tls_sock:
                try:
                    tls_sock.close()
                except Exception:
                    pass
                tls_sock = None

        # Apply jittered sleep
        jitter = random.uniform(-jitter_pct, jitter_pct) * interval_s
        sleep_time = max(0.05, interval_s + jitter)
        time.sleep(sleep_time)

    if tls_sock:
        try:
            tls_sock.close()
        except Exception:
            pass

    end_ts = time.time()
    writer.record_episode(
        family="A3_c2",
        src_ip="10.0.1.4",
        dst_ip=target_ip,
        dst_port=target_port,
        start_ts=start_ts,
        end_ts=end_ts,
        params={
            "interval_s": interval_s,
            "jitter_pct": jitter_pct,
            "mode": mode,
            "beacons_sent": beacons_sent,
        },
    )
    print(f"[A3 C2 BEACON] Finished episode. {beacons_sent} beacons transmitted.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="10.0.2.10")
    parser.add_argument("--port", type=int, default=8883)
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--jitter", type=float, default=0.30)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--mode", choices=["persistent", "reconnect"], default="persistent")
    parser.add_argument("--manifest", default="results/manifest.csv")
    parser.add_argument("--run-id", default="run_a3")
    args = parser.parse_args()

    run_a3_c2_beacon(
        target_ip=args.target,
        target_port=args.port,
        interval_s=args.interval,
        jitter_pct=args.jitter,
        duration_s=args.duration,
        mode=args.mode,
        manifest_path=args.manifest,
        run_id=args.run_id,
    )

