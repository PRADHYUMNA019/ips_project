# Linux Virtual Machine Quickstart Guide (`docs/VM_QUICKSTART.md`)

This guide is for Windows users who want to run the full Linux kernel verification suite (`scripts/verify_linux.sh`) and live network testbed (`Prompt 7`).

---

## 1. Prerequisites & VM Specifications

- **Hypervisor**: [VirtualBox](https://www.virtualbox.org/) (free), [VMware Workstation Player](https://www.vmware.com/), or KVM/QEMU.
  - **Important**: **No WSL2** — WSL2 is unsupported for XDP attachment, custom kernel headers, and full network-namespace `veth` testing. Use a full Linux VM.
- **Operating System**: **Ubuntu 22.04 LTS or Ubuntu 24.04 LTS** (Server or Desktop `x86_64`), **Linux kernel $\ge 5.15$**.
- **Resource Allocation**:
  - **vCPUs**: $\ge 4$ cores (needed for concurrent packet generation, TLS services, and multi-core XDP tests).
  - **RAM**: $\ge 6$ GB ($\ge 8$ GB recommended for BCC runtime Clang JIT compilation and PyTorch/ONNX training).
  - **Disk**: $\ge 100$ GB free space (for kernel headers, BCC/LLVM toolchain, Python venv, and testbed/public pcaps).

---

## 2. Step 1: Clone Repository

Open a terminal inside your Ubuntu VM and clone the project:

```bash
git clone -b p10-complete https://github.com/PRADHYUMNA019/ips_project.git
cd ips_project
```

---

## 3. Step 2: Install System Dependencies

Install the Linux kernel headers, BCC eBPF toolchain, Clang/LLVM, and Python virtual environment packages:

```bash
sudo apt update && sudo apt install -y \
    linux-headers-$(uname -r) \
    bpfcc-tools python3-bpfcc libbpf-dev clang llvm \
    python3-pip python3-dev python3-venv \
    net-tools iproute2 bridge-utils tcpdump \
    ethtool iperf3 curl mosquitto mosquitto-clients
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-linux.txt
```

---

## 4. Step 3: Run Full Linux Verification Suite

Execute the automated verification harness:

```bash
sudo env "PATH=$VIRTUAL_ENV/bin:$PATH" bash scripts/verify_linux.sh
```

To run a single verification stage (e.g. `S4` XDP attach or `S6` equivalence):

```bash
sudo env "PATH=$VIRTUAL_ENV/bin:$PATH" bash scripts/verify_linux.sh S4
sudo env "PATH=$VIRTUAL_ENV/bin:$PATH" bash scripts/verify_linux.sh S6
```

---

## 5. Expected Output & Results

- **Expected Runtime**: ~5–10 minutes for the full stage run (`S0..S11`).
- **Output Report**: Written automatically to `results/verify/REPORT.md`.
- **Log Files**: Individual stage logs are saved under `results/verify/`.
