# Linux Virtual Machine Quickstart Guide (`docs/VM_QUICKSTART.md`)

This guide is for Windows users who want to run the full Linux kernel verification suite (`scripts/verify_linux.sh`) and live network testbed.

---

## 1. Prerequisites & VM Specifications

- **Hypervisor**: [VirtualBox](https://www.virtualbox.org/) (free), [VMware Workstation Player](https://www.vmware.com/), or WSL2 with systemd enabled.
- **Operating System**: **Ubuntu 24.04 LTS** (Server or Desktop x86_64).
- **Resource Allocation**:
  - **vCPUs**: $\ge 4$ cores (needed for concurrent packet generation, services, and multi-core XDP tests).
  - **RAM**: $\ge 8$ GB (BCC runtime JIT compilation and PyTorch model loading require sufficient memory).
  - **Disk**: $\ge 30$ GB free space.

---

## 2. Step 1: Clone Repository

Open a terminal inside your Ubuntu VM and clone the project:

```bash
git clone -b wp0-fix-30pct https://github.com/PRADHYUMNA019/ips_project.git
cd ips_project
```

---

## 3. Step 2: Install System Dependencies (One-Liner)

Install the Linux kernel headers, BCC eBPF toolchain, clang, and Python dependencies:

```bash
sudo apt update && sudo apt install -y \
    linux-headers-$(uname -r) \
    bpfcc-tools python3-bpfcc libbpf-dev clang llvm \
    python3-pip python3-dev python3-venv \
    net-tools iproute2 bridge-utils tcpdump \
    ethtool iperf3 curl mosquitto mosquitto-clients \
    && sudo pip3 install --break-system-packages -r requirements.txt
```

---

## 4. Step 3: Run Full Linux Verification Suite

Execute the automated verification harness:

```bash
sudo bash scripts/verify_linux.sh
```

To run a single verification stage (e.g. S4 XDP attach or S6 equivalence):

```bash
sudo bash scripts/verify_linux.sh S4
sudo bash scripts/verify_linux.sh S6
```

---

## 5. Expected Output & Results

- **Expected Runtime**: ~5–10 minutes for the full 18-stage run (`S0..S11`).
- **Output Report**: Written automatically to `results/verify/REPORT.md`.
- **Log Files**: Individual stage logs are saved under `results/verify/stage_*.log`.
