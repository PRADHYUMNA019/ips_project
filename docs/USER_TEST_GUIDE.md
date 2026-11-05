# User Test & Reproduction Guide (`docs/USER_TEST_GUIDE.md`)

This guide walks you through verifying the entire codebase and generating all real experimental numbers for the 60% paper inside an Ubuntu Linux VM. Every command below is copy-pasteable.

---

## 1. VM Setup (Ubuntu 22.04 / 24.04 LTS, Kernel >= 5.15)

Allocate at least **2 vCPUs, 4 GB RAM, and 25 GB disk** to your Ubuntu VM.

### 1.1 Install System & Kernel Dependencies
```bash
sudo apt update
sudo apt install -y \
    git make curl wget jq bc \
    iproute2 iptables tcpdump openssl \
    clang llvm libelf-dev linux-headers-$(uname -r) \
    python3 python3-pip python3-venv python3-bpfcc bpfcc-tools \
    mosquitto mosquitto-clients nginx hping3 iperf3
```

### 1.2 Clone the Repository & Checkout Branch
```bash
git clone https://github.com/PRADHYUMNA019/ips_project.git
cd ips_project
git checkout wp0-fix-30pct
```

### 1.3 Install Python Packages
> **Note**: Because `python3-bpfcc` is installed as a system package in `/usr/lib/python3/dist-packages`, either install Python requirements with `--break-system-packages` (Ubuntu 24.04) or create a virtualenv with `--system-site-packages` so `sudo python3` can see both `bcc` and `onnxruntime`.

```bash
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 2. Running the Automated Verification (`scripts/verify_linux.sh`)

Run the 11-stage automated verification script first. It tests your Linux environment (`S0`), unit tests (`S1`), 14-namespace topology (`S2`), TLS services (`S3`), bidirectional XDP v2 attachment (`S4`), per-5-tuple verdict cache and TTL expiration (`S5`), 50-flow kernel-vs-offline equivalence (`S6`), experiment manifests (`S7`), closed-loop watchdog (`S8`), system harness (`S9`), and drift guard scenarios (`S10`).

```bash
sudo env "PATH=$VIRTUAL_ENV/bin:$PATH" bash scripts/verify_linux.sh
```

- **Where to check the summary**:
  ```bash
  cat results/verify/REPORT.md
  ```
- **What `PASS` looks like**: Every stage `S0` through `S10` shows `**PASS**` in the Markdown table.
- **How to re-run a single failed stage** (for example, `S4` or `S6`):
  ```bash
  sudo env "PATH=$VIRTUAL_ENV/bin:$PATH" bash scripts/verify_linux.sh S4
  sudo env "PATH=$VIRTUAL_ENV/bin:$PATH" bash scripts/verify_linux.sh S6
  ```
- **If a stage fails**: Paste `results/verify/REPORT.md` and the specific `results/verify/S<N>.log` back into the chat so the exact line can be fixed.

---

## 3. Producing Real 60% Paper Results (Ordered Pipeline)

Smoke tests in `results/smoke/` are strictly for verifying code paths (`Rule B0`). To produce real experimental data and populate `docs/RESULTS.md`, run the following steps in order:

### Step 3.1: Generate TLS Certificates & Create the 14-Namespace Testbed
```bash
bash scripts/gen_certs.sh
sudo bash scripts/topology.sh create
```

### Step 3.2: Collect Multi-Session Benign Captures (Sessions 1, 2, 3)
Use `--time-scale 10` to accelerate collection while preserving distinct inter-arrival distributions across the 4 device classes (`sensor`, `plug`, `thermostat`, `camera`):
```bash
sudo env "PATH=$VIRTUAL_ENV/bin:$PATH" bash scripts/collect.sh --session benign_s1 --duration 300 --time-scale 10
sudo env "PATH=$VIRTUAL_ENV/bin:$PATH" bash scripts/collect.sh --session benign_s2 --duration 300 --time-scale 10
sudo env "PATH=$VIRTUAL_ENV/bin:$PATH" bash scripts/collect.sh --session benign_s3 --duration 300 --time-scale 10
```

### Step 3.3: Collect Attack Captures (Families A1–A5)
```bash
sudo env "PATH=$VIRTUAL_ENV/bin:$PATH" bash scripts/run_experiment.sh configs/experiments/demo_scenario.yaml
```

### Step 3.4: Extract Canonical Early-Flow Features (`N=12`) from Pcaps
```bash
make features
```

### Step 3.5: Train Models, Fit EVT Thresholds, and Quantize to ONNX INT8
```bash
python3 ips/models/train.py \
    --data results/raw/benign_s1_flows.csv \
    --out-dir models \
    --epochs 30
```

### Step 3.6: Run Offline Evaluation (LOFO Zero-Day Split, N-Sweep, Calibration Curve)
```bash
python3 ips/models/eval_offline.py \
    --test-data results/raw/combined_test_flows.csv \
    --card models/model_card.json \
    --out-dir results/offline
```

### Step 3.7: Run Live Kernel-vs-Offline Feature Equivalence Test (N6)
```bash
sudo env "PATH=$VIRTUAL_ENV/bin:$PATH" bash scripts/equivalence_test.sh
cat results/equivalence/report.md
```

### Step 3.8: Run System Evaluation & Fast-Path Bypass Ablation (N2)
```bash
sudo env "PATH=$VIRTUAL_ENV/bin:$PATH" python3 ips/eval/harness.py --out-dir results/system
```

### Step 3.9: Run Concept Drift & Poisoning-Aware Guard Evaluation (N1 + N4)
```bash
python3 ips/drift/scenarios.py --out-dir results/offline
```

### Step 3.10: Compile `docs/RESULTS.md` (`make reproduce`)
```bash
make reproduce
cat docs/RESULTS.md
```

---

## 4. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `RTNETLINK answers: File exists` | Previous namespace or bridge still exists | Run `sudo bash scripts/topology.sh teardown` then `create` again (`topology.sh` is idempotent) |
| `ModuleNotFoundError: No module named 'bcc'` inside virtualenv | Virtualenv was created without `--system-site-packages` | Recreate venv with `python3 -m venv --system-site-packages .venv` and reinstall `requirements.txt` |
| `bpf_attach_xdp` fails on `v-lan-gw` | Kernel veth driver requires generic/SKB XDP flags | Handled automatically: `BCCKernelBackend` falls back to `BPF.XDP_FLAGS_SKB_MODE` and logs `xdp_mode=generic-skb` |
| `llvm/clang header not found` when compiling `ebpf/ips_engine.c` | Missing kernel headers for running kernel | Run `sudo apt install -y linux-headers-$(uname -r) libelf-dev clang llvm` |
| `SSL: CERTIFICATE_VERIFY_FAILED` | Certs missing or generated without SAN `IP:10.0.2.10` | Run `rm -rf traffic/certs/* && bash scripts/gen_certs.sh` |
| `Address already in use` on port `8443` or `8883` | Stale background server in `srv` namespace | Run `sudo ip netns pids srv \| xargs -r sudo kill -9` |

---

## 5. Expected Runtime Table

| Step | Command | Expected Wall-Clock Time |
|------|---------|--------------------------|
| Automated 11-Stage Verification (`S0–S10`) | `sudo bash scripts/verify_linux.sh` | ~2–3 minutes |
| Benign Sessions 1–3 (`--time-scale 10`) | `scripts/collect.sh` (x3) | ~15 minutes |
| Attack Scenarios A1–A5 | `scripts/run_experiment.sh` | ~10 minutes |
| Feature Extraction + Model Training + INT8 | `make features && make train` | ~2 minutes |
| Offline Evaluation + N-Sweep + Calibration | `python3 ips/models/eval_offline.py` | ~2 minutes |
| Kernel-vs-Offline Equivalence Test | `sudo bash scripts/equivalence_test.sh` | ~30 seconds |
| System & Drift Evaluations + `make reproduce` | `harness.py` + `scenarios.py` + `make reproduce` | ~3 minutes |
| **Total End-to-End Pipeline** | **All steps above** | **~35 minutes** |

