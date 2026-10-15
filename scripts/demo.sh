#!/usr/bin/env bash
# scripts/demo.sh — full 30% demo, stages 1-4 automatic.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results/logs

echo "=== [1/6] Testbed: topology up ==="
sudo ./scripts/topology.sh teardown >/dev/null 2>&1 || true
sudo ./scripts/topology.sh create
sudo ip netns exec iot1 ping -c 2 10.0.2.10 | tail -1

echo "=== [2/6] TLS server (encrypted traffic) ==="
sudo ip netns exec srv nohup python3 traffic/tls_server.py > results/logs/server.log 2>&1 &
sleep 1

echo "=== [3/6] Benign IoT telemetry (7 devices, 5 classes, TLS) ==="
sudo ip netns exec iot1 nohup python3 traffic/benign_iot_generator.py 300 > results/logs/benign.log 2>&1 &
sleep 2

echo "=== [4/6] Kernel-only inline enforcement (xdp_v1 + drop_map) ==="
sudo ./scripts/xdp.sh attach
echo "-- attacker CAN reach server before block:"
sudo ip netns exec attacker ping -c 2 10.0.2.10 | tail -1
sudo ./scripts/block_ip.sh block 10.0.1.4
echo "-- attacker blocked IN KERNEL (expect 100% loss):"
sudo ip netns exec attacker ping -c 2 10.0.2.10 | tail -1 || true
echo "-- benign unaffected:"
sudo ip netns exec iot1 ping -c 2 10.0.2.10 | tail -1
sudo ./scripts/block_ip.sh unblock 10.0.1.4
sudo ./scripts/xdp.sh detach

echo ""
echo "=== [5/6] Now open TWO more terminals: ==="
echo "  T2:  cd ~/ips-project && sudo python3 engine/ringbuf_engine.py"
echo "  T3:  sleep 15 && sudo ip netns exec attacker python3 traffic/attack_beacon.py 20 60"
echo ""
echo "=== [6/6] After the demo: baseline measurements ==="
echo "  sudo ./scripts/baseline.sh plain 3"
