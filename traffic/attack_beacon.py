#!/usr/bin/env python3
"""
traffic/attack_beacon.py — A3: periodic C2 beaconing over TLS.
Usage: sudo ip netns exec attacker python3 traffic/attack_beacon.py [interval_ms] [duration_s]
Defaults: 20 ms interval for 120 s.
"""
import ssl
import socket
import sys
import time

INTERVAL_MS = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
DURATION_S  = float(sys.argv[2]) if len(sys.argv) > 2 else 120.0
SERVER      = ("10.0.2.10", 8883)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

raw = socket.create_connection(SERVER, timeout=5)
tls = ctx.wrap_socket(raw, server_hostname=SERVER[0])
print(f"[beacon] connected to {SERVER}, interval={INTERVAL_MS} ms")

start, n = time.time(), 0
while time.time() - start < DURATION_S:
    tls.sendall(f"beacon-{n}".encode())
    n += 1
    time.sleep(INTERVAL_MS / 1000.0)

tls.close()
print(f"[beacon] sent {n} beacons, done")
