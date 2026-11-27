# Exploratory Real-Data Domain-Shift Diagnostic (`docs/EXPLORATORY_P8.md`)

> **Evidence Type**: `REAL PUBLIC DATA — EXPLORATORY ONLY (DOMAIN-SHIFT DIAGNOSTIC, NOT A DETECTION RESULT, NOT A PAPER CLAIM)`
> **Rule R1 / R2 / R3 Notice**: Executed on Windows using real Aposemat IoT-23 benign hardware captures (`4-1`, `5-1`, `7-1`). **No Linux/kernel/real-testbed result exists yet.**

---

## 1. Pre-Stated Protocol & Methodological Caveats

1. **TQH-C2 D per-packet autoencoder TPR is SKIPPED (§4.3)**: `TQH-C2_features_D.zip` (`features_D/testbed_D.parquet`, 11,528 rows × 27 columns) contains Zeek flow-level summaries only (no per-packet `size/dir/iat` arrays). Downloading the 1.82 GB raw pcap (`TQH-C2_pcap_D_merlin_h2.zip`) is deferred to Prompt 7 on Linux.
2. **Cross-device benign setup (NOT attack detection)**: Every flow in `4-1` (Philips Hue), `5-1` (Amazon Echo), and `7-1` (Somfy Door Lock) is **benign**. This diagnostic measures cross-device false-positive sensitivity under domain shift, **not** attack detection TPR/AUROC.
3. **What seeds `{42, 43, 44}` vary**: The three seeds vary **only** model weight initialisation and the internal 85/15 early-stopping shuffle within the training capture (`5-1` Echo); the capture assignment (`train=5-1`, `calib=4-1 or 7-1`, `test=7-1 or 4-1`) is **fixed** (`n=1` device split per direction).
4. **Protocol composition**: Across the three benign IoT-23 captures, **69.0%** of flows before the idle-timeout split (**72.7%** = `1,052 / 1,447` after the `120 s` idle split) are **UDP** (DNS/NTP/SSDP/mDNS) and only **10.2%–11.1%** carry TLS (`4-1` Hue is `99.7%` non-TLS). Do **not** tune further on these captures.

---

## 2. Three-Stage Progression: Baseline (`p8-demo`) vs. Post-Item-2 (`log_iat / 7.0`) vs. Post-Item-3 (`+ flow_idle_s = 120 s`)

- **Baseline (`p8-demo`, `FEATURE_SCHEMA_VERSION = 1`, no idle split, `1,254` flows)**: [`demo/evidence/real/exploratory_results_before_iat_norm.csv`](../demo/evidence/real/exploratory_results_before_iat_norm.csv)
- **Post-Item-2 (`FEATURE_SCHEMA_VERSION = 2` `log_iat / 7.0`, no idle split, `1,254` flows)**: [`demo/evidence/real/exploratory_results_after_iat_norm.csv`](../demo/evidence/real/exploratory_results_after_iat_norm.csv)
- **Post-Item-3 (`FEATURE_SCHEMA_VERSION = 2` + `flow_idle_s = 120 s` kernel-parity split, `1,447` flows)**: [`demo/evidence/real/exploratory_results.csv`](../demo/evidence/real/exploratory_results.csv)

| Config (Fixed Capture Split) | `k` | **Baseline (`p8-demo`)** FPR@EVT`0.05` | **Post-Item-2 (`log_iat/7`)** FPR@EVT`0.05` | **Post-Item-3 (`+120s` idle)** FPR@EVT`0.05` | **Post-Item-3** FPR@EVT`0.01` | **Post-Item-3** KS Stat | **Post-Item-3** Top-3 Shifting Features |
|---|---:|---:|---:|---:|---:|---:|---|
| `Echo(5-1) -> Hue(4-1) cal -> Somfy(7-1) test` | 4 | `0.9476 ± 0.0165` | `0.0572 ± 0.0757` | **`0.1560 ± 0.2702`** | **`0.0053`** | `0.8309` | `log_iat_0 (+0.26); std_log_iat (+0.23); valid_len (+0.20)` |
| `Echo(5-1) -> Hue(4-1) cal -> Somfy(7-1) test` | 8 | `0.9452 ± 0.0109` | `0.6214 ± 0.4023` | **`0.1747 ± 0.2471`** | **`0.0053`** | `0.8433` | `log_iat_2 (+0.43); dir_1 (+0.27); log_iat_0 (+0.25)` |
| `Echo(5-1) -> Hue(4-1) cal -> Somfy(7-1) test` | 16 | `0.9452 ± 0.0148` | `0.6738 ± 0.4784` | **`0.2040 ± 0.2506`** | **`0.1840`** | `0.8423` | `dir_2 (+0.29); dir_3 (+0.28); log_iat_2 (+0.27)` |
| `Echo(5-1) -> Somfy(7-1) cal -> Hue(4-1) test` | 4 | `0.0057 ± 0.0029` | `0.0812 ± 0.0618` | **`0.0718 ± 0.0567`** *(worse vs p8)* | **`0.0482`** | `0.8309` | `log_iat_0 (-0.26); std_log_iat (-0.23); valid_len (-0.20)` |
| `Echo(5-1) -> Somfy(7-1) cal -> Hue(4-1) test` | 8 | `0.0028 ± 0.0029` | `0.0227 ± 0.0049` | **`0.0953 ± 0.0654`** *(worse vs p8)* | **`0.0142`** | `0.8433` | `log_iat_2 (-0.43); dir_1 (-0.27); log_iat_0 (-0.25)` |
| `Echo(5-1) -> Somfy(7-1) cal -> Hue(4-1) test` | 16 | `0.0038 ± 0.0033` | `0.0142 ± 0.0000` | **`0.0349 ± 0.0322`** *(higher vs p8, <0.05)* | **`0.0057`** | `0.8423` | `dir_2 (-0.29); dir_3 (-0.28); log_iat_2 (-0.27)` |

---

## 3. Plain-Language Diagnostic Reading

1. **Combined effect of IAT normalisation + `120 s` flow-idle split**:
   - On `Echo -> Hue calib -> Somfy test`, `FPR@EVT0.05` dropped substantially from **`0.948 / 0.945 / 0.945`** (`p8-demo`) to **`0.156 / 0.175 / 0.204`** (`FPR@EVT0.01`: `0.793 / 0.648 / 0.443` → **`0.0053 / 0.0053 / 0.1840`**), because both bugs — raw `log_iat` scale dominance (`±10.9`) and multi-hour glued UDP flows on Somfy (`140 → 250` flows) — had artificially inflated Somfy reconstruction errors.
2. **What got worse or remains elevated (reported honestly)**:
   - On `Echo -> Somfy calib -> Hue test`, `FPR@EVT0.05` **increased** from `0.0057 / 0.0028 / 0.0038` (`p8-demo`) to **`0.0718 / 0.0953 / 0.0349`**, because removing Somfy's multi-hour glued IAT spikes lowered Somfy's calibration ceiling.
   - Across both directions, `FPR@EVT0.05` (`0.07–0.20`) still exceeds the nominal `0.05` target with wide initialisation variance (`±0.25` on `Hue -> Somfy`) and large score-distribution separation (`KS = 0.83–0.84`). This is consistent with genuine protocol/cadence domain shift across distinct IoT device types (`72.7%` UDP overall; Hue `99.7%` non-TLS) and motivates per-device-class calibration (`N5`) rather than global cross-device thresholds.
