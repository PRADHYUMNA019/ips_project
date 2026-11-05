# Action Items for the User (Linux Environment Required)

This document tracks all operations that cannot be performed in the current development environment (Windows / non-root) and must be executed by the user on a Linux system or VM.

---

## 1. Linux VM Environment Verification
1. Boot an Ubuntu 22.04 or 24.04 environment (minimum 2 vCPU, 4 GB RAM recommended).
2. Install system packages from `requirements-linux.txt`:
   ```bash
   sudo apt-get update && sudo apt-get install -y \
       clang llvm libbpf-dev linux-tools-common linux-tools-generic \
       bpfcc-tools python3-bpfcc iproute2 iperf3 hping3 \
       mosquitto mosquitto-clients nginx tcpdump tshark jq openssl make
   sudo apt-get install -y linux-headers-$(uname -r)
   ```
3. Run the complete automated verification harness:
   ```bash
   sudo bash scripts/verify_linux.sh
   ```
   Check `results/verify/REPORT.md` and review any failing stages.

---

## 2. Public Dataset Downloads (V3 - Data Dependent)
*Note: Scripts will ask for user confirmation before initiating downloads > 100 MB.*

1. **TQH-C2 (Zenodo 21523144)**:
   - Target archive: Testbed C (~379 MB) or Testbed D (~1.8 GB).
   - Run: `bash datasets/download_tqh_c2.sh`
   - Purpose: Primary held-out evaluation for encrypted TLS C2 beaconing.
2. **CESNET-TLS-Year22**:
   - Run: `bash datasets/download_cesnet.sh` (downloads sampled subset).
   - Purpose: Natural long-term benign drift evaluation.
3. **Kitsune (SSL Renegotiation & SSDP)**:
   - Run: `bash datasets/download_kitsune.sh`.

---

## 3. Real Testbed Data Collection Sessions
To generate real non-synthetic testbed features:
```bash
# Collect training baseline (~5,000 flows):
sudo bash scripts/collect.sh train 5000

# Collect EVT calibration baseline (~3,000 flows):
sudo bash scripts/collect.sh calibration 3000

# Collect validation split:
sudo bash scripts/collect.sh validation 2000

# Collect held-out benign test split:
sudo bash scripts/collect.sh test_benign 3000
```

---

## 4. Hardware Gateway Validation (Post-60% Roadmap)
- Flash OpenWrt or Raspberry Pi OS onto a Raspberry Pi 4 / 5.
- Deploy `ebpf/ips_engine.c` and measure true hardware NIC native XDP performance.

