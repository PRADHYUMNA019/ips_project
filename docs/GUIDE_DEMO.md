# Guide Review Walkthrough Script (`docs/GUIDE_DEMO.md`)

> **Target Duration**: 7–10 minutes (Windows laptop, branch `p9-fixes`, no Linux VM required for this review).
> **Honesty Banner**: Everything demonstrated live today is `UNIT TEST`, `SYNTHETIC SMOKE (pipeline demonstration only)`, or offline `REAL PUBLIC DATA` audit/diagnostic. **No Linux/kernel/real-testbed result exists yet.**

---

## 1. Problem & Research Gap (3 Sentences — ~45 seconds)
1. Smart-home and IoT gateways carry encrypted traffic (TLS 1.2/1.3, MQTT-TLS, HTTPS) where traditional deep-packet inspection is blind without breaking encryption, while waiting until flow completion cannot prevent ongoing attacks inline.
2. Existing early-flow anomaly detectors face three unresolved gaps: (i) a fixed window $N$ forces a rigid trade-off between early attack-packet leakage and accuracy on short vs. persistent flows, (ii) unguarded online drift adaptation can be slowly poisoned ("boiling frog") by an attacker, and (iii) single-flow detectors struggle against slow, periodic C2 beacons.
3. Our prototype addresses these via a two-tier eBPF/XDP + INT8 autoencoder architecture featuring progressive multi-checkpoint verdicts (`[4, 8, 16]` with "early drop, late bypass"), a 4-gate poisoning-aware drift guard (`G1–G4` + bounded step + rollback), and a Tier-2 host-pair slow-C2 periodicity tracker.

---

## 2. Architecture Walkthrough (~1.5 minutes)
Open [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) or the exported PNG/SVG diagrams in [`demo/figures/diagrams/`](../demo/figures/diagrams/):
- **Diagram 1 (`01_two_tier_overview.png`)**: Kernel XDP fast path (`ebpf/ips_engine.c`, `SCHEMA_VERSION 4`) does $O(1)$ `verdict_map` enforcement/bypass, Tier-0 SYN rate limiting, and payload-only feature collection (`flow_idle_s = 120 s`); user space runs `FEATURE_SCHEMA_VERSION = 2` (`log_iat / 7.0` in `[0, 1.5]`) + masked INT8 autoencoders + drift guard.
- **Diagram 2 (`02_checkpoint_sequence.png`)**: Attacks drop at packet 4 (`VERDICT_DROP`, sticky until TTL); benign flows receive `VERDICT_BYPASS` at packet 16 so remaining packets stay in the kernel.
- **Diagram 3 (`03_drift_guard_flow.png`)**: Persistence (`G1`), cross-device class quorum (`G2`, fails closed for `< 3` devices), non-periodicity (`G3`), and shadow validation against frozen benign ANCHOR + DEV-attack CANARY (`G4`), with honest failure mode `S4`.
- **Diagram 4 (`04_splits_and_leakage.png`)**: Session-level splits, benign-only train/calib, DEV families (`A1, A2, A5`) separated from held-out zero-days (`A3, A4`), and offline-only public datasets.

---

## 3. Live Command Demonstration (~1.5 minutes)
Run the single-command PowerShell demo runner from any directory:
```powershell
powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1
```
Point out the three PASS lines in the summary table:
1. **Unit Test Suite (`pytest -q`)**: **`73 passed, 0 failed`** (`UNIT TEST`).
2. **Claims & Title Audit (`audit/check_claims.py`)**: **`0 forbidden phrases`**, `3/3` identical canonical titles (`UNIT TEST`).
3. **End-to-End Smoke Pipeline (`demo/run_smoke_pipeline.py`)**: exercises split assertions, `[4, 8, 16]` training + INT8 quantization, EVT/conformal/3σ thresholds, `MockBPFBackend` (`attack_exfil_1 -> DROP` at `pkt=4`, `benign_sensor_1 -> BYPASS` at `pkt=16`, watchdog shed/recover), drift `S1–S5`, and C3 evasion curve — verified **10/10 artefacts byte-for-byte identical** across repeated runs (`demo/evidence/smoke/smoke_pipeline_summary.json`).

---

## 4. Watermarked Smoke Figures (~1 minute)
Show the 5 figures under [`demo/figures/smoke/`](../demo/figures/smoke/) and point to the red watermark **"SYNTHETIC SMOKE DATA — NOT A RESULT"**:
- `fig_a_roc_pr_per_checkpoint.png` — ROC/PR curves per checkpoint (`k=4, 8, 16`) on flows reaching each checkpoint.
- `fig_b_detection_vs_packets_leaked.png` — Progressive `[4, 8, 16]` vs. fixed single-checkpoint leakage Pareto.
- `fig_c_calibration_target_vs_achieved_fpr.png` — EVT vs. split-conformal (with $1/(n+1)$ sample floor) vs. mean+3σ.
- `fig_d_drift_s1_s5_fpr_over_time.png` — S1–S2 Clean Benign FPR (Static spikes; Guarded adapts), S3–S4 Held-Out Attack TPR (Unguarded ADWIN gets poisoned; Guarded preserves TPR), and S5 Concurrent Slow-C2 TPR (Tier-2 fires at window 7 after 8 beacons).
- `fig_e_cost_of_evasion_curve.png` — Query-bounded ($Q=200$) white-box adaptive attacker utility vs. detection curve.

---

## 5. Real Public Dataset Audit: TQH-C2 D & IoT-23 Benign (~1.5 minutes)
Open [`docs/DATASET_AUDIT.md`](DATASET_AUDIT.md), [`demo/evidence/real/tqh_c2_audit.csv`](../demo/evidence/real/tqh_c2_audit.csv), and [`demo/evidence/real/iot23_benign_audit.csv`](../demo/evidence/real/iot23_benign_audit.csv) (`REAL PUBLIC DATA`):
- **TQH-C2 Testbed D (Zenodo `21523144`, CC-BY-4.0, SHA-256 verified, 11,528 rows: 9,564 benign / 1,964 `malicious_c2`)**:
  - Real Merlin HTTP/2-over-TLS C2 flows have median **33 total packets** and **31.02 s** duration: **100.0% / 98.1% / 97.7%** are **estimated** to reach `k=4 / 8 / 16` payload packets (**upper bound**: `total_pkts - 3`; TLS handshakes consume more).
  - Tier-2 `SlowC2Tracker` (`min_connections=8, CV<=0.35`) flags **71/71** C2 host pairs reaching ≥8 connections (`15/15` at 30 s, `26/26` at 300 s, `0/15` reaching 8 connections at 1,800–3,600 s within 1–2 h) alongside **`0/157` (`0.00%`) real benign host pairs flagged** (`min CV = 0.388`; reporting `"15/15 flagged"` without the benign host-pair false-positive baseline is meaningless).
  - **Schema limitation**: `TQH-C2_features_D.zip` has Zeek flow summaries only; per-packet `3N+8` evaluation requires the 1.82 GB raw pcap in Prompt 7.
- **Aposemat IoT-23 Benign Pcaps (8 pcaps, 513 MB streamed via `dpkt` with `flow_idle_s = 120 s`, `1,447` flows)**:
  - `4-1` Hue (`353` flows, `0.28%` TLS), `5-1` Echo (`844` flows, `16.23%` TLS), `7-1` Somfy (`250` flows, `3.60%` TLS).
  - **Motivates progressive early exit**: only **6.01%** of these (mostly UDP — **72.7%** post-split; `69.0%` pre-split) flows reach `k=16`, whereas **30.20%** reach `k=4` (`100.0%` on Somfy at median `18.49 ms`).

---

## 6. Exploratory Real IoT-23 Domain-Shift Diagnostic (~45 seconds)
Open [`docs/EXPLORATORY_P8.md`](EXPLORATORY_P8.md) (`REAL PUBLIC DATA — DOMAIN-SHIFT DIAGNOSTIC, NOT A DETECTION RESULT`):
- **Caveats**: benign-only cross-device transfer (not attack detection), fixed capture split (seeds `{42, 43, 44}` vary model initialisation only), and **69.0%–72.7% UDP** flows.
- **Before vs. After (`Echo -> Hue calib -> Somfy test`, `FPR@EVT0.05`)**: `0.948 / 0.945 / 0.945` (`p8-demo`) → **`0.156 / 0.175 / 0.204`** after `/ 7.0` IAT scaling + `120 s` flow-idle split (`FPR@EVT0.01`: `0.0053 / 0.0053 / 0.1840`), while `Echo -> Somfy calib -> Hue test` rose from `0.003–0.006` to **`0.035–0.095`** (`KS = 0.83–0.84`), likely due to cross-device protocol/direction differences (`dir_1..3`, `std_log_iat`).

---

## 7. Slide: Known Issues Found by Independent Review & How They Were Fixed (`Prompt 9`)

> Showing that an adversarial review caught real defects — and that we fixed them with red→green tests and reported even metrics that worsened — demonstrates scientific and engineering maturity:

| Review Finding (`p8-demo`) | Root Cause Identified | Fix & Verification (`p9-fixes`) | Before → After (Honest Report) |
|---|---|---|---|
| **1. Smoke ROC below diagonal (`AUROC = 0.3213`) & `benign_sensor_1` false `DROP`** | `epochs=8` (32 updates) left decoder `log_iat` stuck at `~2.7` (closer to fast attacks than slow benign); `score_onnx_model` lacked `build_valid_mask_matrix`; smoke `A3_c2` overlapped benign; `IPSEngine` ignored `cfg['engine']['model_card']` & inverted `ckpt_thresholds` check | Masked `score_onnx_model`, adaptive batch/epochs (`50`), asymmetric C2 burst in `synth.py`, fixed `IPSEngine` `model_card` + `_loaded_threshold`; 2 red→green tests | Smoke INT8 AUROC: `0.3213 → 1.0000` *(SMOKE ONLY)*; `benign_sensor_1`: `DROP (2.53) → BYPASS (0.0006)` |
| **2. Unnormalised per-packet `log_iat` (`[0, ~7.5]`)** | `ips/features.py` scaled `mean_log_iat / 7.0` but left per-packet `log_iat_i` raw (`~30×` MSE dominance) | Scaled `log_iat_i / 7.0` clipped to `[0, 1.5]` (`FEATURE_SCHEMA_VERSION = 2`); added range/balance test + mutant `M17` (`18/18 KILLED`) | `Hue->Somfy` `k=4` FPR@0.05: `0.9476 → 0.0572` (`k=8,16`: `0.62–0.67`); `Somfy->Hue` rose `0.006 → 0.081` *(reported honestly)* |
| **3. Offline extractor lacked `flow_idle_s = 120 s` split (`ttv_p95` in hours)** | `pcap_to_flows.py` glued UDP/NTP/SSDP 5-tuples hours apart into single flows & reset on SYN retransmits | Added `ebpf/ips_engine.c` idle (`120 s`) + `FIN/RST + SYN` rules to `pcap_to_flows.py` & `equivalence.py`; 5-case pcap test | IoT-23 flows `1,254 → 1,447`; Somfy `ttv_k8_p95`: **`4.39e7 ms` (12.2 h) → `54,767 ms` (54.8 s)**; Hue `ttv_k4_p95`: **`8.68e6 ms` → `212 ms`** |
| **4. Overstated public-data wording & missing tracker FP baseline** | Missing benign host-pair CV rate next to `"15/15 C2 flagged"`; `total_pkts - 3` stated without upper-bound caveat | Added `demo/audit_tqh_c2_real.py` measuring benign host pairs; calibrated wording across 5 docs | TQH-C2 `CV<=0.35` (`>=8` conns): **`71/71` C2 pairs vs. `0/157` (`0.00%`) benign pairs** (`min CV = 0.388`) |
| **5. Figure D flat-zero panels (`S3–S5`) & missing diagram PNG/SVGs** | S3–S5 plotted Clean Benign FPR (`0.0`) instead of poisoning/C2 impact | Plotted Held-Out Attack TPR on S3–S4 (Unguarded ADWIN vs. Guarded) & Concurrent C2 TPR on S5; exported 4 PNG+SVG diagrams | Informative 5-panel Figure D + 8 diagram files in `demo/figures/diagrams/` |

---

## 8. Honest Status & Plan to 80% / 100% (~1 minute)
Open [`demo/evidence/CLAIMS_VS_EVIDENCE.md`](../demo/evidence/CLAIMS_VS_EVIDENCE.md) and state plainly what is **NOT DONE**:
- **NOT done yet**: `ebpf/ips_engine.c` has never been compiled or run on Linux; no real TLS testbed traffic has been collected; no real inline latency/leakage/harm measurements exist; literature review (`docs/related_work_todo.md`) is unverified; paper title (`"On-Device"` vs. emulated gateway) is `TITLE_DECISION_PENDING`.
- **Plan (dates to confirm with guide)**:
  - `[DATE_1]`: Provision Ubuntu 24.04 VM (≥4 vCPU, ≥8 GB RAM, ≥120 GB disk on `D:`/cloud), run Prompt 7 Phases 0–1 (kernel compile, BCC attach, acceptance checks `a–l`).
  - `[DATE_2]`: Prompt 7 Phases 2–3 (download TQH-C2 D 1.8 GB pcap + CESNET subset; pre-register `EXPERIMENT_PLAN.md`; collect real multi-session TLS testbed data).
  - `[DATE_3]`: Prompt 7 Phases 4–7 (real offline, inline closed-loop ≥10 reps, drift/evasion with ≥5 inline-validated points, final figures & draft paper sections → **80% milestone**).
  - `[DATE_4]`: Remaining 20% (literature review verification, guide-requested ablations, optional physical Raspberry Pi / OpenWrt deployment, camera-ready paper polish).

---

## 9. Likely Guide Questions & Honest Answers

1. **Why use a synthetic/emulated testbed at all instead of only public datasets?**
   - You cannot drop packets inline from a recorded pcap or CSV. Measuring real attack-packet leakage, time-to-verdict, verdict-cache bypass speedup, and operational harm (benign sessions severed) requires live TLS flows passing through a live XDP gateway. Public datasets (TQH-C2 D, IoT-23, CESNET) complement the testbed offline for real-world C2, IoT hardware benign shift, and long-term TLS drift.
2. **Why emulate resource limits via cgroups instead of measuring on a Raspberry Pi now?**
   - We do not yet have physical edge hardware provisioned for the 60%–80% phase. Every document carries a Scope Note stating we measure an emulated resource-constrained gateway (Linux namespaces + cgroup CPU/RAM profiles S/M/L on user space; generic XDP unconstrained) and flags `"On-Device"` as `TITLE_DECISION_PENDING`.
3. **What is actually novel, and how will you prove it?**
   - Four focused claims (`C1–C4`): progressive `[4, 8, 16]` XDP early-drop/late-bypass with flow-level $\alpha$-spending (`C1`), poisoning-aware 4-gate drift guard with honest `S4` boundary (`C2`), two-tier detection + white-box $Q=200$ cost-of-evasion curve (`C3`), and cross-domain + operational-harm + split-conformal-vs-EVT evaluation (`C4`). Novelty is **not yet claimed established** until tested on real Linux/testbed/public data in Prompt 7.
4. **What happens if early-window detection fails on slow C2 beacons?**
   - Our real TQH-C2 D audit showed two regimes: Merlin HTTP/2-over-TLS connections carry ~33 total packets in ~31 s (`97.7%–100%` are **estimated** as an upper bound `total_pkts - 3` to reach checkpoints 4/8/16; TLS handshakes consume more), whereas ultra-slow 1-packet or mimicry beacons that evade Tier-1 are handed to Tier-2 `SlowC2Tracker` (`71/71` C2 pairs ≥8 conns flagged vs `0/157` benign host pairs flagged on Testbed D, while `0/15` C2 pairs reach 8 connections within 1–2 h at 1,800–3,600 s intervals).
5. **Why are public datasets used offline only (no pcap replay through the gateway)?**
   - Replaying recorded public pcaps breaks closed-loop TCP/TLS state (retransmissions, congestion control, TLS handshakes cannot react to an inline `XDP_DROP`). Public datasets are therefore strictly offline-only (`Rule H5`).
6. **What does the remaining 20% (after Prompt 7's 80% milestone) cover?**
   - Full verified literature review & citations, guide-requested ablations, optional physical embedded hardware validation (Raspberry Pi / OpenWrt router) + libbpf/CO-RE migration, additional public datasets, and camera-ready paper formatting.
