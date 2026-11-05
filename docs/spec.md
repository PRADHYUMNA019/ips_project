# System Specification: Drift-Resilient On-Device Inline IPS

## 1. Scope & Protocol Boundaries
- **In-Scope**:
  - Transport Layer Security (TLS 1.2 and TLS 1.3) encapsulated over TCP IPv4.
  - Edge IoT / smart-system gateway inline traffic inspection and filtering.
  - Volumetric UDP flooding (handled as a tier-0 stateless or rate-based flow anomaly).
- **Explicitly Out-of-Scope**:
  - QUIC / HTTP/3 (UDP-based encrypted transport) — flagged as future work.
  - Encrypted Client Hello (ECH) metadata decoding — payload-independent features remain agnostic, but TLS record type parsing relies on standard headers.
  - IPv6 routing and inspection — only IPv4 32-bit addresses are tracked in fast-path flow tables.
  - Deep packet inspection (DPI) of decrypted application payload — design is strictly payload-independent.

---

## 2. Target Platform & Hardware Resource Profiles
The system targets gateway-class embedded hardware acting as an inline network bridge or router between LAN and WAN:

| Profile | Target Hardware Analogue | Emulated Resource Limit (User Space Engine) |
|---|---|---|
| **Profile S (Small)** | Low-end MIPS/ARM router (e.g. MT7621, Pi Zero 2W) | 25–30% of 1 CPU core, 256 MB RAM (`MemoryMax=256M`, `CPUQuota=30%`) |
| **Profile M (Medium)** | Mid-tier residential gateway (e.g. Raspberry Pi 4) | 50% of 1 CPU core, 512 MB RAM (`MemoryMax=512M`, `CPUQuota=50%`) |
| **Profile L (Large)** | Enterprise/industrial IoT edge gateway (x86_64 edge box) | 100% of 2 vCPUs, 1024 MB RAM (`MemoryMax=1G`, `CPUQuota=200%`) |

*Note (H4/H5)*: In this phase, hardware limits are enforced on the user-space Python engine using systemd cgroups (`systemd-run`). The eBPF/XDP fast path executes in kernel context and is not throttled by cgroups.

---

## 3. Threat Model & Attack Taxonomy

### Adversary Model
- The attacker seeks to compromise or control devices behind the gateway, exfiltrate data, or disrupt services.
- The attacker knows the system relies on early-packet timing and size statistics (white-box awareness).
- The attacker can manipulate timing (jitter, beacon interval expansion) and payload sizes (padding, chunk splitting).
- **Poisoning Capability**: The attacker may gradually alter traffic parameters over hours or days ("boiling-frog" attack) attempting to force the drift adaptation logic to accept malicious traffic as normal baseline.

### Attack Families
- **A1 — Volumetric Flood (TLS Handshake / SYN Flood)**:
  High packet rate aimed at exhausting connection states on port 8883/443. Addressed by tier-0 token-bucket rate limiter.
- **A2 — Slow-Rate DoS (TLS Slowloris)**:
  Exhausts server thread pools by opening many connections and transmitting tiny byte fragments (1–8 B) every 5–15 seconds.
- **A3 — C2 Beaconing over TLS**:
  Periodic communications with C2 infrastructure. Evaluation sweeps intervals {1, 5, 15, 30, 60} seconds with 0–30% jitter.
- **A4 — TLS Exfiltration**:
  Unusually large upstream payloads (800–1460 B) sent persistently or in bursts to external servers.
- **A5 — Credential Brute Force (MQTT-over-TLS)**:
  Repeated short connections with rapid authentication failures and reconnections.

---

## 4. Zero-Day Definition & Leave-One-Family-Out (LOFO) Protocol
- **Strict Definition**: A "Zero-Day" attack is an attack family that is **never used** during:
  1. Feature selection or normalization parameter calculation.
  2. Baseline model training.
  3. EVT extreme-value threshold calibration.
  4. Hyperparameter tuning (e.g. choice of $N$, autoencoder depth, latent dimension).
- **Evaluation Protocol**:
  - **Development (DEV) Families**: A1, A2, A5 (used for threshold validation and canary drift checks).
  - **Held-Out (Test) Families**: A3 (TLS C2 Beaconing) and A4 (Exfiltration) are evaluated once at final benchmark.

---

## 5. Fail-Open Architecture Policy
- **Policy**: In the event of system saturation, resource exhaustion, or ring buffer overflow, the IPS **must fail open**.
- While a flow is accumulating its first $N$ payload packets, intermediate packets are forwarded (`XDP_PASS`).
- If the user-space watchdog detects engine lag > 500 ms or ring buffer drops > 100/s, it sets `cfg.shed = 1`, causing XDP to bypass feature emission and pass all non-dropped traffic without disruption.

---

## 6. Evaluation Unit & Session Splits

The fundamental unit of evaluation is the **bidirectional flow**, evaluated at verdict time (packet $N$).

### Data Partitioning by Session (No Cross-Contamination)
| Split | Purpose | Data Source | Composition |
|---|---|---|---|
| **Session 1 (Train)** | Train baseline Autoencoder / IF | Testbed captures / Public benign | 100% Benign IoT fleet |
| **Session 2 (Calibration)** | Fit GPD tail threshold via EVT | Separate testbed capture | 100% Benign IoT fleet ($\ge 3,000$ flows) |
| **Session 3 (Validation)** | Tune architecture & early window $N$ | Separate capture session | Benign + DEV attack families (A1, A2, A5) |
| **Session 4 (Test-Benign)** | Measure operational False Positive Rate | Held-out benign session | 100% Benign IoT fleet |
| **Session 5 (Test-ZeroDay)**| Final TPR and zero-day detection evaluation | Held-out attack capture | Held-out families (A3, A4, TQH-C2) |

---

## 7. Metrics & Formal Definitions
1. **AUROC & AUPRC**: Calculated over flow reconstruction errors across benign test and attack flows.
2. **True Positive Rate at Target FPR**: $\text{TPR} @ \text{FPR} = 10^{-2}$ and $\text{TPR} @ \text{FPR} = 10^{-3}$.
3. **Attack Packet Leakage Rate ($L$)**:
   $$L = \frac{\text{Attack packets exiting gateway egress}}{\text{Total attack packets transmitted}}$$
4. **Time-to-Verdict**:
   - Packets: Exact number of payload packets observed before verdict map insertion ($N$).
   - Latency: Elapsed wall-clock time from flow SYN to verdict insertion.
5. **System Overhead**:
   - In-line packet forwarding latency percentiles: $p_{50}, p_{95}, p_{99}$ ($\mu$s).
   - Throughput (iperf3 Mbps).
   - Gateway CPU utilization (%) and RSS memory (MB).

<!-- SPLIT_TABLE_START -->
### Session-Disjoint Split Table (`ips/data/build_splits.py`)

| Split Role | Flow Count | Allowed Families | Integrity Check |
|------------|------------|------------------|-----------------|
| `train` | NOT RUN (needs real data) | Benign only (`is_attack == 0`) | Session-disjoint, no attack-window flows |
| `calibration` | NOT RUN (needs real data) | Benign only (`is_attack == 0`) | EVT / Conformal threshold fit (`min_calibration_flows=3000`) |
| `validation` | NOT RUN (needs real data) | Benign + DEV families (`A1, A2, A5`) | Held-out zero-day families (`A3_c2, A4_exfil`) strictly excluded |
| `test` | NOT RUN (needs real data) | Benign test session + Held-out families (`A3_c2, A4_exfil`) | Evaluated once per LOFO fold |
<!-- SPLIT_TABLE_END -->
