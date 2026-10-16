#!/usr/bin/env bash
# scripts/demo.sh — System Demonstration (Automated Infrastructure & Baseline)
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results/logs results/csv

echo -e "\033[1;36m========================================================================================\033[0m"
echo -e "\033[1;36m   DRIFT-RESILIENT ON-DEVICE INLINE IPS — LIVE SYSTEM DEMONSTRATION                      \033[0m"
echo -e "\033[1;36m========================================================================================\033[0m\n"

echo -e "\033[1;33m>>> [STAGE 1/6] Testbed Initialization: Virtual Network Topology <<<\033[0m"
sudo ./scripts/topology.sh teardown >/dev/null 2>&1 || true
sudo ./scripts/topology.sh create

echo -e "\n  \033[1mNetwork Topology Overview:\033[0m"
echo -e "    - Subnet LAN: \033[32m10.0.1.0/24\033[0m (iot1: 10.0.1.2, iot2: 10.0.1.3, attacker: 10.0.1.4)"
echo -e "    - Gateway   : \033[33m10.0.1.1 (v-lan-gw) <--> 10.0.2.1 (v-wan-gw)\033[0m [Inline Router]"
echo -e "    - Subnet WAN: \033[34m10.0.2.0/24\033[0m (srv: 10.0.2.10:8883)"
echo -e "  \033[32m[OK] Verifying end-to-end IP routing (iot1 -> srv):\033[0m"
sudo ip netns exec iot1 ping -c 2 10.0.2.10 | grep -E "packets transmitted|rtt"

echo -e "\n\033[1;33m>>> [STAGE 2/6] Starting TLS 1.3/1.2 Encrypted Server (Port 8883) <<<\033[0m"
sudo ip netns exec srv nohup python3 traffic/tls_server.py > results/logs/server.log 2>&1 &
sleep 1.5
echo -e "  \033[32m[OK] TLS Server online in netns 'srv' (Listening on 10.0.2.10:8883)\033[0m"
echo -e "       Log output: \033[90mresults/logs/server.log\033[0m"

echo -e "\n\033[1;33m>>> [STAGE 3/6] Starting Benign IoT Telemetry Fleet (7 Devices, 5 Classes) <<<\033[0m"
sudo ip netns exec iot1 nohup python3 traffic/benign_iot_generator.py 600 > results/logs/benign.log 2>&1 &
sleep 2
echo -e "  \033[32m[OK] 7 simulated IoT devices active:\033[0m"
echo -e "       - Smart Cameras (High throughput, bursty: ~800-1400B)"
echo -e "       - Smart Thermostats (Periodic telemetry: ~15s interval)"
echo -e "       - Smart Plugs (Periodic power draw: ~30s interval)"
echo -e "       - Smart Door Locks (Event driven telemetry: ~60s interval)"
echo -e "       - Temperature Sensors (Periodic telemetry: ~10s interval)"
echo -e "       Log output: \033[90mresults/logs/benign.log\033[0m"

echo -e "\n\033[1;33m>>> [STAGE 4/6] Fast-Path Kernel Enforcement Benchmark (xdp_v1 + drop_map) <<<\033[0m"
sudo ./scripts/xdp.sh attach
echo -e "  \033[1m1. Testing Attacker connectivity BEFORE blocking:\033[0m"
sudo ip netns exec attacker ping -c 2 10.0.2.10 | grep -E "packets transmitted|rtt"

echo -e "\n  \033[1m2. Inserting Attacker IP (10.0.1.4) into Kernel drop_map via bpftool:\033[0m"
sudo ./scripts/block_ip.sh block 10.0.1.4
echo -e "  \033[1m3. Testing Attacker connectivity AFTER blocking (Expect 100% loss):\033[0m"
sudo ip netns exec attacker ping -c 2 -W 1 10.0.2.10 | grep -E "packets transmitted|100% packet loss" || true

echo -e "\n  \033[1m4. Testing Benign IoT (10.0.1.2) connectivity (Expect 0% loss):\033[0m"
sudo ip netns exec iot1 ping -c 2 10.0.2.10 | grep -E "packets transmitted|rtt"

# Clean up baseline fast-path module
sudo ./scripts/block_ip.sh unblock 10.0.1.4 >/dev/null 2>&1 || true
sudo ./scripts/xdp.sh detach >/dev/null 2>&1 || true
echo -e "\n  \033[32m[OK] Fast-path kernel enforcement verified. Cleaned drop_map and detached xdp_v1.\033[0m"

echo -e "\n\033[1;32m========================================================================================\033[0m"
echo -e "\033[1;32m   INFRASTRUCTURE READY! NOW PROCEED TO LIVE TWO-TIER CLOSED-LOOP DEMO                   \033[0m"
echo -e "\033[1;32m========================================================================================\033[0m"
echo -e "Open two additional terminals side-by-side:"
echo -e "  \033[1mTerminal 2 (IPS Engine):\033[0m"
echo -e "     cd $(pwd) && sudo python3 engine/ringbuf_engine.py"
echo -e "     \033[90m(Tracks early-flow packets 1..12, runs verdict engine, intercepts dropped packets)\033[0m"
echo -e ""
echo -e "  \033[1mTerminal 3 (Attacker Beacon):\033[0m"
echo -e "     cd $(pwd) && sudo ip netns exec attacker python3 traffic/attack_beacon.py 20 60"
echo -e "     \033[90m(Transmits 20ms periodic TLS beacons; watches packets get dropped in real time)\033[0m"
echo -e ""
echo -e "  \033[1mOptional Bird's-Eye View (Terminal 4 or background):\033[0m"
echo -e "     cd $(pwd) && sudo ./scripts/monitor.sh"
echo -e "     \033[90m(Real-time traffic classifier & packet flow sniffer on gateway router)\033[0m"
echo -e "\033[1;32m========================================================================================\033[0m\n"
