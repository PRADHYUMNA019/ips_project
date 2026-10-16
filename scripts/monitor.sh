#!/usr/bin/env bash
# scripts/monitor.sh — Real-time Bird's-Eye-View Network Traffic Monitor on Gateway (v-lan-gw)
set -euo pipefail

IFACE="v-lan-gw"

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo -e "\033[91m[ERROR] Interface '$IFACE' not found. Please start topology first: sudo ./scripts/topology.sh create\033[0m"
    exit 1
fi

echo -e "\033[1;36m========================================================================================\033[0m"
echo -e "\033[1;36m    GATEWAY BIRD'S-EYE VIEW: REAL-TIME PACKET FLOW MONITOR (Interface: $IFACE)         \033[0m"
echo -e "\033[1;36m========================================================================================\033[0m"
echo -e "\033[1mNetwork Map:\033[0m"
echo -e "  - Benign Devices : \033[32m10.0.1.2 (iot1)\033[0m, \033[32m10.0.1.3 (iot2)\033[0m"
echo -e "  - Attacker Device: \033[31m10.0.1.4 (attacker - periodic C2 beaconing)\033[0m"
echo -e "  - Gateway Router : \033[33m10.0.1.1 (v-lan-gw) <--> 10.0.2.1 (v-wan-gw)\033[0m"
echo -e "  - WAN Server     : \033[34m10.0.2.10:8883 (srv - TLS Echo Service)\033[0m"
echo -e "\033[1;36m----------------------------------------------------------------------------------------\033[0m"
printf "%-10s %-23s %-4s %-23s %-6s %-7s %s\n" "[TIME]" "[SOURCE]" "DIR" "[DESTINATION]" "[PROTO]" "[LEN]" "[DATA FLOW IDENTIFICATION]"
echo -e "\033[1;36m----------------------------------------------------------------------------------------\033[0m"

# Sniff packets on gateway interface and format each packet live
sudo tcpdump -l -n -nn -i "$IFACE" -t 2>/dev/null | python3 -u -c '
import sys, re, time

for line in sys.stdin:
    line = line.strip()
    # Match IP packets: IP 10.0.1.4.54320 > 10.0.2.10.8883: Flags [P.], length 16
    m = re.search(r"IP ([\d\.]+)\.([\w]+) > ([\d\.]+)\.([\w]+): (.*)length (\d+)", line)
    ts = time.strftime("%H:%M:%S")
    if m:
        s_ip, s_port, d_ip, d_port, flags, length = m.groups()
        src = f"{s_ip}:{s_port}"
        dst = f"{d_ip}:{d_port}"
        
        # Determine classification
        if "10.0.1.4" in (s_ip, d_ip):
            tag = "\033[1;31m[MALICIOUS: C2 BEACON]\033[0m"
        elif "10.0.1.2" in (s_ip, d_ip) or "10.0.1.3" in (s_ip, d_ip):
            tag = "\033[1;32m[BENIGN IoT TELEMETRY]\033[0m"
        else:
            tag = "\033[33m[GATEWAY ROUTED]\033[0m"
            
        proto = "TCP" if "Flags" in line else "UDP"
        print(f"\033[90m{ts}\033[0m   {src:<23} \033[36m->\033[0m   {dst:<23} {proto:<6} {length:<7}B {tag}")
    elif "ICMP" in line:
        m2 = re.search(r"IP ([\d\.]+) > ([\d\.]+): ICMP", line)
        if m2:
            s_ip, d_ip = m2.groups()
            tag = "\033[1;36m[ICMP DIAGNOSTIC PING]\033[0m"
            print(f"\033[90m{ts}\033[0m   {s_ip:<23} \033[36m->\033[0m   {d_ip:<23} ICMP   64B     {tag}")
'
