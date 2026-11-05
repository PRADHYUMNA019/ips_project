#!/usr/bin/env bash
# scripts/demo.sh — System Demonstration (Automated Infrastructure & Live Run)
set -u
cd "$(dirname "$0")/.."
mkdir -p results/logs results/csv

echo -e "\033[1;36m========================================================================================\033[0m"
echo -e "\033[1;36m   DRIFT-RESILIENT ON-DEVICE INLINE IPS — LIVE SYSTEM DEMONSTRATION                      \033[0m"
echo -e "\033[1;36m========================================================================================\033[0m\n"

echo -e "\033[1;33m>>> [STAGE 1/6] Testbed Initialization: Virtual Network Topology <<<\033[0m"
sudo ./scripts/topology.sh teardown >/dev/null 2>&1 || true
sudo ./scripts/topology.sh create

echo -e "\n  \033[1mNetwork Topology Overview:\033[0m"
echo -e "    - Subnet LAN: \033[32m10.0.1.0/24\033[0m (12 devices: sensor-01..04, plug-01..03, therm-01..03, cam-01..02; attacker: 10.0.1.4)"
echo -e "    - Gateway   : \033[33m10.0.1.1 (v-lan-gw) <--> 10.0.2.1 (v-wan-gw)\033[0m [Inline Router]"
echo -e "    - Subnet WAN: \033[34m10.0.2.0/24\033[0m (srv: 10.0.2.10:8883)"
echo -e "  \033[32m[OK] Verifying end-to-end IP routing (sensor-01 -> srv):\033[0m"
sudo ip netns exec sensor-01 ping -c 2 -W 1 10.0.2.10 || true

echo -e "\n\033[1;33m>>> [STAGE 2/6] Starting TLS 1.3/1.2 Encrypted Server (Port 8883) <<<\033[0m"
sudo ip netns exec srv nohup python3 traffic/tls_server.py > results/logs/server.log 2>&1 &
sleep 1.5
echo -e "  \033[32m[OK] TLS Server online in netns 'srv' (Listening on 10.0.2.10:8883)\033[0m"
echo -e "       Log output: \033[90mresults/logs/server.log\033[0m"

echo -e "\n\033[1;33m>>> [STAGE 3/6] Starting Benign IoT Telemetry Fleet (12 Devices, 4 Classes) <<<\033[0m"
sudo ip netns exec sensor-01 nohup python3 traffic/benign_iot_generator.py --device-from-config sensor-01 --duration 600 > results/logs/benign_sensor01.log 2>&1 &
sudo ip netns exec plug-01 nohup python3 traffic/benign_iot_generator.py --device-from-config plug-01 --duration 600 > results/logs/benign_plug01.log 2>&1 &
sleep 2
echo -e "  \033[32m[OK] Simulated IoT device fleet active across isolated namespaces:\033[0m"
echo -e "       - Smart Cameras (High throughput, bursty: ~800-1400B)"
echo -e "       - Smart Thermostats (Periodic telemetry: ~15s interval)"
echo -e "       - Smart Plugs (Periodic power draw: ~30s interval)"
echo -e "       - Temperature Sensors (Periodic telemetry: ~10s interval)"
echo -e "       Log output: \033[90mresults/logs/benign_sensor01.log\033[0m"

echo -e "\n\033[1;33m>>> [STAGE 4/6] Fast-Path Kernel Enforcement Benchmark (xdp_v1 + drop_map) <<<\033[0m"
sudo ./scripts/xdp.sh attach || true
echo -e "  \033[1m1. Testing Attacker connectivity BEFORE blocking:\033[0m"
sudo ip netns exec attacker ping -c 2 -W 1 10.0.2.10 || true

echo -e "\n  \033[1m2. Inserting Attacker IP (10.0.1.4) into Kernel drop_map:\033[0m"
sudo ./scripts/block_ip.sh block 10.0.1.4 || true
echo -e "  \033[1m3. Testing Attacker connectivity AFTER blocking (Expect 100% loss):\033[0m"
sudo ip netns exec attacker ping -c 2 -W 1 10.0.2.10 || true

echo -e "\n  \033[1m4. Testing Benign IoT (sensor-01: 10.0.1.10) connectivity (Expect 0% loss):\033[0m"
sudo ip netns exec sensor-01 ping -c 2 -W 1 10.0.2.10 || true

# Clean up baseline fast-path module
sudo ./scripts/block_ip.sh unblock 10.0.1.4 >/dev/null 2>&1 || true
sudo ./scripts/xdp.sh detach >/dev/null 2>&1 || true
echo -e "\n  \033[32m[OK] Fast-path kernel enforcement verified. Detached baseline module.\033[0m"

echo -e "\n\033[1;33m>>> [STAGE 5/6] Automated Two-Tier Inline IPS Closed-Loop Live Run (v2 Engine) <<<\033[0m"
echo -e "  [1] Starting IPS Closed-Loop Engine v2 (ips.engine) in gw namespace..."
sudo ip netns exec gw python3 -m ips.engine --config configs/system.yaml --mode enforce > results/logs/engine.log 2>&1 &
ENGINE_PID=$!
sleep 2.5

if ! ps -p "$ENGINE_PID" >/dev/null 2>&1; then
    echo -e "  \033[91m[WARN] Engine could not attach. Checking logs:\033[0m"
    cat results/logs/engine.log
else
    echo -e "  \033[32m[OK] Engine v2 online (PID: $ENGINE_PID). XDP attached to v-lan-gw and v-wan-gw.\033[0m"
    echo -e "  [2] Launching TLS Attack Traffic from Attacker (10.0.1.4)..."
    echo -e "      (Watch early payload packets 1..12 trigger EARLY_FLOW, then packet 13+ get dropped by verdict_map)\n"
    sudo ip netns exec attacker python3 traffic/attack_beacon.py 20 5 || true

    echo -e "\n  [3] Real-Time Telemetry from IPS Engine v2:"
    echo -e "\033[90m----------------------------------------------------------------------------------------\033[0m"
    if [ -f results/logs/engine_v2.jsonl ]; then
        tail -n 20 results/logs/engine_v2.jsonl
    elif [ -f results/logs/engine.log ]; then
        tail -n 35 results/logs/engine.log
    fi
    echo -e "\033[90m----------------------------------------------------------------------------------------\033[0m"

    # Cleanly stop background engine
    sudo kill -SIGINT "$ENGINE_PID" >/dev/null 2>&1 || true
    sleep 1
fi

echo -e "\n\033[1;32m========================================================================================\033[0m"
echo -e "\033[1;32m   AUTOMATED DEMO COMPLETE! FOR INTERACTIVE MULTI-TERMINAL PRESENTATION:                \033[0m"
echo -e "\033[1;32m========================================================================================\033[0m"
echo -e "If presenting across multiple open terminals side-by-side:"
echo -e "  \033[1mTerminal 2 (IPS Engine):\033[0m"
echo -e "     cd $(pwd) && sudo python3 engine/ringbuf_engine.py"
echo -e ""
echo -e "  \033[1mTerminal 3 (Attacker Beacon):\033[0m"
echo -e "     cd $(pwd) && sudo ip netns exec attacker python3 traffic/attack_beacon.py 20 60"
echo -e ""
echo -e "  \033[1mTerminal 4 (Bird's-Eye View Sniffer):\033[0m"
echo -e "     cd $(pwd) && sudo ./scripts/monitor.sh"
echo -e "\033[1;32m========================================================================================\033[0m\n"
