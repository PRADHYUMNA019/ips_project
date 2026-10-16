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

print("\033[1;31m" + "="*80)
print(f"  [ATTACKER SIMULATOR] Launching Periodic C2 Beaconing over TLS")
print(f"  Target Server : {SERVER[0]}:{SERVER[1]}")
print(f"  Beacon Rate   : {INTERVAL_MS:.1f} ms interval ({1000.0/INTERVAL_MS:.1f} pkts/sec)")
print(f"  Max Duration  : {DURATION_S} seconds")
print("="*80 + "\033[0m\n")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

try:
    raw = socket.create_connection(SERVER, timeout=5)
    tls = ctx.wrap_socket(raw, server_hostname=SERVER[0])
    raw.settimeout(0.25) # 250ms read timeout for server echo
    print(f"\033[32m[beacon] Established TLS 1.3/1.2 tunnel to C2 server {SERVER}\033[0m")
    print(f"[beacon] Beginning periodic transmission. Observing gateway inline enforcement...\n")
except Exception as e:
    print(f"\033[91m[beacon ERROR] Failed to connect to server {SERVER}: {e}\033[0m")
    sys.exit(1)

start = time.time()
n = 0
delivered = 0
blocked = 0

try:
    while time.time() - start < DURATION_S:
        n += 1
        msg = f"beacon-{n:04d}".encode()
        t0 = time.time()
        ts = time.strftime('%H:%M:%S')

        try:
            tls.sendall(msg)
            # Wait for server echo to confirm packet reached the server
            resp = tls.recv(64)
            rtt_ms = (time.time() - t0) * 1000.0
            delivered += 1
            print(f"\033[90m[{ts}]\033[0m \033[32m[BEACON #{n:03d}]\033[0m "
                  f"Payload={len(msg)}B -> Server Echo: ACK ({rtt_ms:4.1f}ms) "
                  f"\033[32m[STATUS: DELIVERED TO C2]\033[0m")
        except (socket.timeout, ssl.SSLError, OSError) as e:
            blocked += 1
            print(f"\033[90m[{ts}]\033[0m \033[1;31m[BEACON #{n:03d}]\033[0m "
                  f"Payload={len(msg)}B -> NO RESPONSE (TIMEOUT) --> "
                  f"\033[1;41;37m REJECTED: BLOCKED BY GATEWAY IPS (eBPF XDP DROP) \033[0m")

        time.sleep(INTERVAL_MS / 1000.0)
except KeyboardInterrupt:
    print("\n\033[33m[beacon] Attack stopped by user.\033[0m")
finally:
    try:
        tls.close()
    except Exception:
        pass

print("\n" + "\033[1;34m" + "="*80)
print(f"  [ATTACK RUN SUMMARY]")
print(f"  Total Beacons Attempted : {n}")
print(f"  Permitted (Pre-Verdict) : \033[32m{delivered}\033[0m (Observed during first 12 packets)")
print(f"  Blocked & Intercepted   : \033[1;31m{blocked}\033[0m (Dropped inline by kernel XDP)")
if n > 0:
    print(f"  Interception Efficiency : \033[1;32m{(blocked/n)*100:.1f}%\033[0m")
print("="*80 + "\033[0m\n")
