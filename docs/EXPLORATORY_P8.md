# Exploratory Real-Data Experiment (`docs/EXPLORATORY_P8.md`)

> **Evidence Type**: `REAL PUBLIC DATA — EXPLORATORY ONLY (NOT PART OF PRE-REGISTERED STUDY, NOT A PAPER CLAIM)`
> **Rule R1 / R2 / R3 Notice**: This experiment runs strictly on Windows using real Aposemat IoT-23 benign hardware captures (`4-1`, `5-1`, `7-1`). **No Linux/kernel/real-testbed result exists yet.**

---

## 1. Pre-Stated Experiment Plan (Written BEFORE Running)

### 1.1 Why TQH-C2 D Per-Packet Autoencoder Evaluation Is Skipped (Prompt 8 §4.3)
- As verified in [`docs/DATASET_AUDIT.md`](DATASET_AUDIT.md), `TQH-C2_features_D.zip` (`features_D/testbed_D.parquet`, 11,528 rows × 27 columns) and `TQH-C2_labels_D.zip` contain **Zeek flow-level summary aggregates only** (`orig_pkts`, `resp_pkts`, `orig_bytes`, `resp_bytes`, `duration`, `ja4`, `interval_s`, `jitter_pct`, `label_raw`, `y`).
- They do **not** contain per-packet early-window sequences (`size_0..N-1`, `dir_0..N-1`, `iat_0..N-2`).
- Downloading the 1.82 GB raw pcap (`TQH-C2_pcap_D_merlin_h2.zip`) is explicitly deferred to Prompt 7 on the Linux VM (§3.5).
- Per **Prompt 8 §4.3**, we **skip TQH-C2 D per-packet autoencoder TPR scoring** rather than fabricating synthetic packet sequences from flow totals.

### 1.2 Real Cross-Device Benign Transfer Exploratory Test (Aposemat IoT-23 Hardware Captures)
Because all three real IoT-23 benign captures (`CTU-Honeypot-Capture-4-1` Philips Hue, `5-1` Amazon Echo, `7-1` Somfy Door Lock) were successfully downloaded and parsed into genuine `3N+8` per-packet vectors via `ips/offline/pcap_to_flows.py`, we run an exploratory **cross-device benign generalisation** check:
- **Protocol (strictly capture-isolated; no tuning on held-out capture)**:
  - **Config A (`Echo -> Somfy calib -> Hue test`)**: Train per-checkpoint autoencoders (`k in {4, 8, 16}`, masked MSE loss, 15 epochs, `torch.set_num_threads(4)`) strictly on `CTU-Honeypot-Capture-5-1` (Amazon Echo, 761 flows). Calibrate EVT (POT GPD), split-conformal, and mean+3σ thresholds at target `alpha = 0.05` and `alpha = 0.01` strictly on `CTU-Honeypot-Capture-7-1` (Somfy Door Lock, 140 flows). Evaluate **ONCE** on held-out `CTU-Honeypot-Capture-4-1` (Philips Hue, 353 flows).
  - **Config B (`Echo -> Hue calib -> Somfy test`)**: Train strictly on `5-1` (Amazon Echo, 761 flows), calibrate strictly on `4-1` (Philips Hue, 353 flows), evaluate **ONCE** on held-out `7-1` (Somfy Door Lock, 140 flows).
  - **Seeds**: `{42, 43, 44}` (report mean and std/spread across seeds).
- **Expectation Stated Up Front**: This is a **cross-device domain shift** test (smart speaker → door lock → LED bridge, with different protocol ratios: Hue is 99.7% non-TLS UDP/TCP, Echo is 15.9% TLS, Somfy is 12.1% TLS). A **large domain shift and elevated cross-device FPR are expected** and will be reported honestly as measured, alongside two-sample KS statistics and the top-3 shifting features by mean per-feature squared error difference.

---

## 2. Measured Exploratory Results (`demo/evidence/real/exploratory_results.csv`)

Executed once via `python demo/run_exploratory_p8.py` across seeds `{42, 43, 44}` (`torch.set_num_threads(4)`). **TQH-C2 D TPR is SKIPPED per §4.3** (no per-packet sequences in `TQH-C2_features_D.zip`).

| Config (Real IoT-23 Benign Captures) | `k` | FPR @ EVT `α=0.05` (mean ± std) | FPR @ EVT `α=0.01` (mean) | FPR @ Conformal `α=0.05` | FPR @ Mean+3σ | KS Stat (Cal vs Test) | Top-3 Shifting Features (Test − Cal MSE) |
|---|---:|---:|---:|---:|---:|---:|---|
| `Echo(5-1) -> Hue(4-1) calib -> Somfy(7-1) test` | 4 | `0.9476 ± 0.0165` | `0.7928` | `0.9476` | `0.7691` | `0.9283` | `log_iat_1 (+10.91); log_iat_0 (+3.92); size_3 (+0.35)` |
| `Echo(5-1) -> Hue(4-1) calib -> Somfy(7-1) test` | 8 | `0.9452 ± 0.0109` | `0.6476` | `0.9452` | `0.6429` | `0.9212` | `log_iat_1 (+8.20); log_iat_0 (+5.65); log_iat_3 (+4.63)` |
| `Echo(5-1) -> Hue(4-1) calib -> Somfy(7-1) test` | 16 | `0.9452 ± 0.0148` | `0.4429` | `0.9452` | `0.4429` | `0.9207` | `log_iat_1 (+10.11); log_iat_0 (+5.41); log_iat_3 (+4.14)` |
| `Echo(5-1) -> Somfy(7-1) calib -> Hue(4-1) test` | 4 | `0.0057 ± 0.0029` | `0.0057` | `0.0057` | `0.0038` | `0.9283` | `log_iat_1 (-10.91); log_iat_0 (-3.92); size_3 (-0.35)` |
| `Echo(5-1) -> Somfy(7-1) calib -> Hue(4-1) test` | 8 | `0.0028 ± 0.0029` | `0.0009` | `0.0028` | `0.0028` | `0.9212` | `log_iat_1 (-8.20); log_iat_0 (-5.65); log_iat_3 (-4.63)` |
| `Echo(5-1) -> Somfy(7-1) calib -> Hue(4-1) test` | 16 | `0.0038 ± 0.0033` | `0.0019` | `0.0038` | `0.0028` | `0.9207` | `log_iat_1 (-10.11); log_iat_0 (-5.41); log_iat_3 (-4.14)` |

---

## 3. Honest Reading: What Worked, What Failed, and Diagnostic Insight
1. **What worked**: The full streaming `dpkt` → `recompute_early_matrix_for_k` → masked `EarlyFlowAutoencoder` → EVT/conformal/3σ pipeline executed end-to-end on three real IoT hardware captures with tight seed stability (`std <= 0.0165`).
2. **What failed (severe cross-device shift)**: Calibrating thresholds on Philips Hue (`4-1`) and applying them without retuning to Somfy Door Lock (`7-1`) produced **94.5%–94.8% false positives** at target `α=0.05` (`KS = 0.921–0.928`, `p < 1e-100`). Conversely, Somfy-calibrated thresholds yielded `0.28%–0.57%` FPR on Hue only because Somfy's higher score distribution set a conservative ceiling above Hue's simpler short flows — the score distributions remain almost disjoint (`KS > 0.92`).
3. **Root cause exposed by per-feature diagnostics**: In `ips/features.py`, `log_iat_i = log10(1 + iat_us)` takes values in `[0, ~7]`, whereas `size_i` and `dir_i` lie in `[0, 1]`. Consequently, squared reconstruction errors on `log_iat_0, log_iat_1, log_iat_3` (`±4` to `±10.9`) dominate total MSE across heterogeneous devices with different packet counts and cadence. This is a concrete, real-data-driven finding to address in Prompt 7 (per-device-class models/calibration and feature-group normalization ablation).
4. **Status reminder**: Exploratory only — not a paper claim and no attack TPR was measured because TQH-C2 D per-packet pcaps were excluded per §3.5 / §4.3.
