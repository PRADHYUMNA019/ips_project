# Paper Outline & Claim-to-Evidence Map (`docs/PAPER_OUTLINE.md`)

**Working Title**: *Drift-Resilient On-Device Inline Intrusion Prevention for Encrypted Traffic in Resource-Constrained Smart Systems Against Zero-Day Attacks*

---

## 1. Section-by-Section Paper Outline

### Abstract
- Problem: Encrypted IoT gateway traffic prevents payload inspection, while unsupervised zero-day anomaly detectors suffer from (a) uncalibrated false positive rates in inline blocking mode, (b) per-packet user-space bottleneck, and (c) vulnerability to adversarial threshold-inflation poisoning during concept drift adaptation.
- Contributions: (N1) Poisoning-Aware Drift Guard (`G1–G4` + bounded step + rollback), (N2) Two-Tier XDP Verdict Cache with Bidirectional Early-Flow Bypass, (N3) EVT Peaks-Over-Threshold FPR Calibration with KS selection, (N4) Two-Timescale Slow-C2 Host-Pair Periodicity Tracker, (N5) INT8 Quantized Autoencoder, (N6) Verified Kernel-vs-Offline Feature Equivalence.

### §1. Introduction
- Tension between inline prevention (must act within $N$ packets without MITM decryption) and unsupervised anomaly detection (false positives sever legitimate IoT telemetry).
- Why naive online adaptation (plain ADWIN recalibration/retraining) fails under "boiling frog" adversarial poisoning.
- Summary of contributions and reproducible artifacts.

### §2. Threat Model & Operational Assumptions (`docs/spec.md`)
- Protected assets: 12 IoT devices across 4 classes (`sensor` $\times 4$, `plug` $\times 3$, `thermostat` $\times 3$, `camera` $\times 2$) behind an inline Linux gateway.
- Adversary capabilities: compromises 1 device (Scenario S3) or a coordinated subset $k$ of devices (Scenario S4); launches 5 attack families (`A1_flood`, `A2_slowloris`, `A3_c2`, `A4_exfil`, `A5_bruteforce`) over TLS 1.2/1.3 without gateway keys.
- Zero-day definition: strict **Leave-One-Attack-Family-Out (LOFO)** protocol where models are trained on benign data only, hyperparameters are tuned on DEV families (`A1`, `A2`, `A5`), and held-out families (`A3_c2`, `A4_exfil`) are evaluated strictly once (Honesty Rule H2).

### §3. System Architecture & Kernel-Userspace Co-Design (`docs/ARCHITECTURE.md`)
- Bidirectional XDP attachment on `v-lan-gw` and `v-wan-gw` (`ebpf/ips_engine.c`) deriving packet direction from `ingress_ifindex` (F3).
- Canonical 5-tuple `verdict_map` (`BPF_MAP_TYPE_LRU_HASH`) with `BYPASS` and `DROP` actions and monotonic `bpf_ktime_get_ns()` TTL expiration (F4, F5, N2).
- Tier-0 per-source SYN token bucket guard (explicitly rule-based, not ML) and 1 Hz user-space Watchdog / Load Shedder (`cfg.shed`).
- Single-source-of-truth schema generation (`ips/engine/schema.py`) and Kernel-vs-Offline Feature Equivalence (`ips/eval/equivalence.py`, N6).

### §4. Unsupervised Detection, EVT Calibration & Poisoning-Aware Drift Guard
- **Early-Flow Feature Representation (`ips/features.py`)**: $3N+8$ normalized metadata vector over the first $N$ payload-bearing packets; shortcut-learning guard excluding IPs and ports.
- **EVT Threshold Calibration (`ips/models/evt.py`, N3)**: GPD Peaks-Over-Threshold fit on benign calibration scores with KS goodness-of-fit selection of $u \in [0.90, 0.97]$ and exact Clopper-Pearson confidence intervals.
- **Poisoning-Aware Drift Guard (`ips/drift/guard.py`, N1)**:
  - Stream detection via `ADWIN` and `PageHinkley`.
  - Check **G1** (Persistence across $k$ windows), **G2** (Cross-device consistency $\ge \lceil \rho \cdot \text{class\_size} \rceil$ for class size $\ge 3$), **G3** (Non-periodicity via CV & FFT spectral ratio), **G4** (Quarantine buffer + shadow validation against frozen ANCHOR benign set and frozen CANARY DEV-attack set), **Bounded Step** ($\gamma$), and **Automatic Rollback**.
- **Two-Timescale Slow-C2 Tracker (`ips/drift/periodicity.py`, N4)**: Host-pair connection-start periodicity analysis catching slow reconnecting C2 beacons (`30s–3600s` interval).

### §5. Experimental Evaluation & Ablations
- **Table 1 (Model & LOFO Zero-Day Comparison)**: `ips/models/eval_offline.py` $\to$ `eval_models.csv`, `eval_families_lofo.csv` (reporting PR-AUC, ROC-AUC, TPR at $\text{FPR} \in \{10^{-3}, 10^{-2}\}$ with Clopper-Pearson CIs, and `time_to_verdict_ms`).
- **Figure 1 (Early-Window $N$ Sweep)**: `eval_n_sweep.csv` over $N \in \{4, 6, 8, 12, 16, 24\}$ showing detection accuracy vs decision latency and pre-verdict leaked packets.
- **Figure 2 (EVT Calibration Curve)**: `calibration_curve.csv` & `calibration_curve.png` comparing GPD POT against $3\sigma$ and empirical quantile.
- **Table 2 (INT8 Quantization & Model Footprint)**: `quantization_table.csv` (FP32 vs INT8 model size KB, p50/p95/p99 latency $\mu\text{s}$, and accuracy preservation).
- **Table 3 (Kernel-vs-Offline Feature Equivalence)**: `ips/eval/equivalence.py` $\to$ `results/equivalence/report.md`.
- **Table 4 (System Overhead, Attack-Packet Leakage & Fast-Path Bypass Ablation)**: `ips/eval/harness.py` comparing `plain_forwarding`, `noop_xdp`, `full_ips` (`bypass: on` vs `bypass: off`).
- **Table 5 & Figures 3–5 (Concept Drift & Poisoning Scenarios S1–S5 + Guard Ablations)**: `ips/drift/scenarios.py` $\to$ `drift_metrics.csv`, `s1_benign_drift.png`, `s3_boiling_frog.png`, `s4_coordinated_poisoning.png`.

### §6. Limitations & Threats to Validity (`docs/LIMITATIONS.md`)
### §7. Related Work (`docs/related_work_todo.md`)
### §8. Conclusion

---

## 2. One-Page "Claims We Can and Cannot Make" Table

| Topic | Claim We **CAN** Defensibly Make | Claim We **CANNOT** Make (and Why) | Supporting Code / Table |
|-------|----------------------------------|------------------------------------|-------------------------|
| **Zero-Day Scope** | The autoencoder detects unseen attack families (`A3_c2`, `A4_exfil`) under a strict Leave-One-Attack-Family-Out (LOFO) protocol without using attack labels during training or threshold calibration. | We **cannot** claim universal detection of arbitrary real-world zero-days (e.g., application-layer logic exploits inside a single benign-sized TLS record). | `ips/models/train.py`, `ips/models/eval_offline.py` (`eval_families_lofo.csv`) |
| **Encrypted Traffic Inspection** | The IPS operates strictly on TLS flow metadata (payload sizes, directions, IATs) without TLS termination, MITM certificates, or payload decryption. | We **cannot** claim resistance to full traffic morphing (constant-rate padding to fixed MTU with Poisson scheduling) when flow volumes match benign profiles. | `ebpf/ips_engine.c`, `ips/features.py`, `docs/LIMITATIONS.md` |
| **Inline Prevention & Pre-Verdict Leakage** | Once the verdict is issued after $N$ payload packets, `verdict_map` drops 100% of subsequent packets on that 5-tuple in XDP while leaving other flows on the same IP unaffected. | We **cannot** claim zero packet leakage: the first $N$ payload packets (plus TCP handshake) of a new flow must cross the gateway to form the early-flow vector. | `ebpf/ips_engine.c`, `ips/eval/harness.py` (`pre_verdict_leaked_pkts`) |
| **Poisoning-Aware Drift Guard (N1)** | Against single-device "boiling frog" poisoning (S3), `G1–G4` reject threshold inflation and preserve attack TPR, whereas unguarded ADWIN adapts and loses attack TPR. | We **cannot** claim G2 stops coordinated compromise of $\ge \lceil \rho \cdot \text{class\_size} \rceil$ devices (Scenario S4) or works on classes with $<3$ devices (`camera`); in S4, G2 is bypassed and defense relies on G4 canary checks and bounded step $\gamma$. | `ips/drift/guard.py`, `ips/drift/scenarios.py` (`S3`, `S4`, `test_drift_guard.py`) |
| **Two-Timescale C2 Detection (N4)** | Combining Tier-1 early-flow anomaly scoring with Tier-2 host-pair inter-connection periodicity (`SlowC2Tracker`) catches both fast in-flow floods and slow reconnecting C2 beacons (`30s–120s`). | We **cannot** claim single-flow first-$N$ packet features alone detect slow C2 beacons that send 1 message per connection every 60 seconds. | `ips/drift/periodicity.py` (`SlowC2Tracker`), `ips/drift/scenarios.py` (`S5`) |
| **Resource-Constrained Edge Target** | The user-space inference model is a $<20\text{ KB}$ INT8 ONNX autoencoder with sub-millisecond CPU inference and bounded LRU BPF maps (`4096` entries). | At the 60% milestone, we **cannot** claim measured hardware numbers on a physical Raspberry Pi or hard cgroup-throttled VM until the remaining 40% hardware experiments are run. | `ips/models/quantize.py`, `ebpf/ips_engine.c`, `docs/LIMITATIONS.md` |
| **XDP Attachment Mode** | On Linux `veth` pairs, XDP runs in generic/SKB mode (or native driver mode where supported by the NIC/veth kernel version), which is logged explicitly in telemetry (`xdp_mode`). | We **cannot** claim NIC hardware-offload or physical driver-mode Gbps line-rate throughput from virtual `veth` namespace benchmarks. | `ips/engine/engine.py` (`BCCKernelBackend`), `docs/LIMITATIONS.md` |

