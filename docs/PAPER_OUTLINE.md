# Paper Outline & Claim-to-Evidence Map (`docs/PAPER_OUTLINE.md`)

**Working Title**: *Drift-Resilient On-Device Inline Intrusion Prevention for Encrypted Traffic in Resource-Constrained Smart Systems Against Zero-Day Attacks*

> **Scope note (evaluation):** All measurements are obtained on an emulated resource-constrained gateway (Linux network namespaces on a laptop/VM; user-space engine limited by cgroups; XDP in generic mode, unconstrained). No physical embedded device was measured. Title wording is pending guide approval (TITLE_DECISION_PENDING).

---

## 1. Strictly Four Claimed Paper Contributions (`C1–C4`)

> **Contribution Discipline (Prompt 3 Part C)**: The paper claims **strictly 4 primary contributions (`C1, C2, C3, C4`)** in §1 and proves them deeply. Supporting methodological and engineering rigour (`C9` Split-Conformal vs EVT, `C10` Operational-Harm Metrics, `C11` Netem Impairment Robustness, `C12` Training-Set Contamination & Trimmed Loss, `N5` INT8 Quantization, `N6` Kernel-to-Offline Equivalence) are placed in §5 as evaluation/ablation subsections — never inflated into a 12-bullet contribution list.

1. **Claim C1 — Progressive Multi-Checkpoint XDP Inference + Per-5-Tuple Verdict Caching (`C1/N7 + N2`)**:
   - Instead of waiting for a single fixed window $N$, the XDP fast path (`ebpf/ips_engine.c`) emits `EARLY_FLOW` events at progressive checkpoints $N_1 < N_2 < \dots < N_K$ (`checkpoints: [4, 8, 16]`), paired with an **"early drop, late bypass"** verdict policy and a flow-level false-positive budget $\alpha = \sum_k \alpha_k$ (`equal` and `front_loaded` spending). Obvious volumetric/exfiltration attacks are dropped at packet 4 (`VERDICT_DROP`), subtle attacks are caught at packet 8 or 16, and benign long flows receive kernel fast-path bypass (`VERDICT_BYPASS`) at packet 16.
2. **Claim C2 — Poisoning-Aware Drift Guard (`G1–G4` + Bounded Step + Rollback, `N1`) with Honest Failure Mode (`S4`)**:
   - Online threshold adaptation (`ADWIN` / `PageHinkley`) is protected against "boiling frog" adversarial threshold inflation via four compositional checks: **G1** (tail-kurtosis & persistence), **G2** (cross-device quorum $\ge \lceil \rho \cdot \text{class\_size} \rceil$ for classes with $\ge 3$ devices), **G3** (non-periodicity via CV & FFT spectral peak ratio), and **G4** (shadow validation against a frozen trusted benign **ANCHOR** set and a frozen DEV-attack **CANARY** set), plus bounded step $\gamma$ and automatic post-update rollback. Includes the honest failure mode **S4** where coordinated multi-device compromise bypasses G2 and is contained by G4 and bounded step.
3. **Claim C3 — Two-Tier Detection + White-Box Adaptive-Attacker Cost-of-Evasion Curve (`N4 + C3/N8`)**:
   - Combines Tier-1 per-flow progressive checkpoints with a Tier-2 host-pair inter-connection periodicity tracker (`SlowC2Tracker`, `N4`) and evaluates the combined defense against a **white-box, query-bounded adaptive attacker** ($Q=200$ queries via random search + coordinate hill-climbing) optimizing over traffic parameters subject to attack-utility floors (exfiltration goodput $\ge R\text{ KB/s}$, C2 beacon latency $\le T\text{ s}$).
4. **Claim C4 — Cross-Domain Benign Generalisation (`Testbed <-> IoT-23`, `B6`) + Rigorous Tail & Operational-Harm Evaluation (`C9 + C10 + C11 + C12 + N6`)**:
   - Evaluates zero-retuning domain transfer between our TLS testbed and real IoT hardware captures (`CTU-IoT-23` Hue, Echo, Somfy benign pcaps) in both forward and reverse directions, supported by verified kernel-to-offline feature equivalence (`N6`), split-conformal vs EVT tail calibration (`C9`), operational-harm translation (`C10`), network-impairment robustness (`C11`), and training-set contamination resilience (`C12`).

---

## 2. Section-by-Section Paper Outline

### §1. Introduction
- Tension between inline prevention on encrypted IoT traffic (must act within early packets without TLS MITM) and unsupervised zero-day anomaly detection (false positives sever legitimate IoT telemetry).
- Why single-window early-flow detectors face an latency-vs-accuracy dilemma (`C1`) and why unguarded online drift adaptation fails under adversarial poisoning (`C2`).
- Statement of the **4 primary contributions (`C1–C4`)**.

### §2. Threat Model & Operational Assumptions (`docs/spec.md`)
- Protected topology: 12 IoT devices across 4 classes (`sensor` $\times 4$, `plug` $\times 3$, `thermostat` $\times 3$, `camera` $\times 2$) behind an inline Linux XDP gateway.
- Adversary capabilities: launches 5 encrypted attack families (`A1_flood`, `A2_slowloris`, `A3_c2`, `A4_exfil`, `A5_bruteforce`), performs white-box query-bounded parameter search ($Q=200$, `C3`), or compromises 1 device (`S3`) or $k$ coordinated devices (`S4`) to poison drift adaptation.
- Strict **Leave-One-Attack-Family-Out (LOFO)** zero-day protocol (`ips/data/build_splits.py`): benign-only training/calibration, DEV families (`A1, A2, A5`) for tuning/canary, held-out zero-day families (`A3_c2, A4_exfil`) evaluated strictly once.

### §3. System Architecture: Progressive XDP Fast Path & Verdict Cache (`C1`, `docs/ARCHITECTURE.md`)
- Bidirectional XDP attachment on `v-lan-gw` and `v-wan-gw` (`ebpf/ips_engine.c`, `SCHEMA_VERSION 3`).
- Progressive checkpoint ring-buffer emission (`emitted_mask`, `checkpoint_idx` at $N \in \{4, 8, 16\}$) and **"early drop, late bypass"** state machine in `ips/engine/engine.py`.
- Flow-level FPR budget allocation ($\alpha = \sum_k \alpha_k$: equal vs front-loaded $\alpha_k \propto 2^{-k}$) and empirical union-bound correlation measurement.
- Tier-0 per-source SYN token bucket guard (explicitly rule-based, not ML) and 1 Hz user-space Watchdog / Load Shedder (`cfg.shed`).

### §4. Poisoning-Aware Drift Guard & Two-Tier Evasion Defense (`C2, C3`)
- Canonical `3N+8` early-flow feature representation (`ips/features.py`) and shortcut-learning guard.
- **Poisoning-Aware Drift Guard (`ips/drift/guard.py`, `C2`)**: `G1`–`G4`, bounded step $\gamma$, post-update health rollback, and `S4` coordinated failure analysis.
- **Two-Timescale Slow-C2 Tracker (`ips/drift/periodicity.py`, `N4`)** and **White-Box Cost-of-Evasion Formulation (`ips/drift/evasion_cost.py`, `C3`)**.

### §5. Experimental Evaluation, Cross-Domain Transfer & Methodological Ablations (`C4`)
- **§5.1 Zero-Day LOFO Detection & Progressive Checkpoint Pareto (`C1`)**: `eval_models.csv`, `eval_families_lofo.csv`, `progressive_pareto.csv`, `eval_n_sweep.csv` ($\ge 3$ seeds with 95% CIs).
- **§5.2 Inline Enforcement, Fast-Path Bypass & Operational-Harm Metrics (`C1, C10/N10`)**: `ips/eval/harness.py` reporting attack-packet leakage alongside expected dropped benign flows per device-day, fleet-day, and recovery time.
- **§5.3 Concept Drift (`S1–S5`), CESNET Multi-Week Natural Drift (`B5`), & Adaptive Cost-of-Evasion Curve (`C2, C3`)**: `drift_metrics.csv`, `cesnet_natural_drift.csv` (using `G1/G3/G4` + EVT only; `G2` disabled), and `evasion_cost_curve.csv` / `evasion_cost_curve.png`.
- **§5.4 Cross-Domain Benign Generalisation (`Testbed <-> IoT-23`, `C4 / B6`)**: `ips/eval/cross_domain.py` forward and reverse transfer without retuning.
- **§5.5 Split-Conformal vs EVT Tail Calibration (`C9/N9`)**: `ips/models/evt.py` & `calibration_curve.csv` across $\alpha \in \{10^{-1}, 10^{-2}, 10^{-3}, 10^{-4}\}$, marking the finite-sample conformal floor $\alpha = 1/(n+1)$.
- **§5.6 Network-Impairment Robustness (`C11/N11`)**: `scripts/netem_sweep.sh` & `ips/eval/impairment.py` across delay/jitter/loss/reordering with `full_features`, `no_iat_features`, and `no_size_features` ablations.
- **§5.7 Training-Set Contamination & Trimmed-Loss Mitigation (`C12/N12`)**: `ips/eval/contamination.py` mixing $c \in \{0\%, 0.5\%, 1\%, 2\%, 5\%\}$ DEV-family attacks into training data.
- **§5.8 Kernel-vs-Offline Feature Equivalence (`N6`) & INT8 Quantization (`N5`)**: `ips/eval/equivalence.py` (per-checkpoint exact size/dir match) and `quantization_table.csv`.

### §6. Limitations & Threats to Validity (`docs/LIMITATIONS.md`)
### §7. Related Work (`docs/related_work_todo.md`)

---

## 8. Claim-to-Experiment Matrix (`C1–C4` & Supporting Studies)

| Claim ID | Claim Summary | Exact Script(s) | Exact Table / Figure | Dataset(s) Used | Current Status |
|----------|---------------|-----------------|----------------------|-----------------|----------------|
| **C1** | Progressive multi-checkpoint XDP inference (`[4, 8, 16]`) + "early drop, late bypass" verdict caching reduces time-to-drop and user-space load while bounding flow-level FPR | `ebpf/ips_engine.c`, `ips/engine/engine.py`, `ips/models/train.py`, `ips/models/eval_offline.py`, `ips/eval/harness.py` | `progressive_pareto.csv`, `eval_n_sweep.csv`, `system_ablation_smoke.csv` (`system_eval.csv`) | TLS Testbed (`S1–S4` splits) | `SMOKE-ONLY` (V1 verified; real testbed capture `NOT TESTED`) |
| **C2** | Poisoning-aware drift guard (`G1–G4` + bounded step + rollback) adapts to benign drift (`S1, S2`, CESNET) while rejecting single-device (`S3`) and containing coordinated (`S4`) poisoning | `ips/drift/guard.py`, `ips/drift/scenarios.py` | `drift_metrics.csv`, `cesnet_natural_drift.csv`, `figures/s1_benign_drift.png`, `s3_boiling_frog.png`, `s4_coordinated_poisoning.png` | TLS Testbed (`S1–S5`) + CESNET-TLS-Year22 (`B5`, `G2` disabled) | `SMOKE-ONLY` (V1 verified; real CESNET/testbed `NOT TESTED`) |
| **C3** | Two-tier detection (`[4, 8, 16]` + `SlowC2Tracker`) raises the white-box query-bounded ($Q=200$) adaptive attacker's cost of evasion across exfiltration and C2 utility floors | `ips/drift/periodicity.py`, `ips/drift/evasion_cost.py` | `evasion_cost_curve.csv`, `figures/evasion_cost_curve.png` | TLS Testbed + TQH-C2 Testbed D (`merlin_h2`) | `SMOKE-ONLY` (V1 verified; real TQH-C2 D `NOT TESTED`) |
| **C4** | Cross-domain benign generalisation (`Testbed <-> IoT-23` Hue/Echo/Somfy) and methodological rigour (`C9` Conformal vs EVT, `C10` Operational Harm, `C11` Netem, `C12` Contamination, `N6` Equivalence) | `ips/eval/cross_domain.py`, `ips/models/evt.py`, `ips/eval/harness.py`, `ips/eval/impairment.py`, `ips/eval/contamination.py`, `ips/eval/equivalence.py` | `cross_domain_iot23.csv`, `calibration_curve.csv`, `netem_impairment.csv`, `contamination_study.csv`, `results/equivalence/report.md` | TLS Testbed + IoT-23 Benign (`4-1, 5-1, 7-1`) + Kitsune | `SMOKE-ONLY` (V1 verified; real pcaps `NOT TESTED`) |
