# Exploratory Real-Data Domain-Shift Diagnostic (`docs/EXPLORATORY_P8.md`)

> **Evidence Type**: `REAL PUBLIC DATA — EXPLORATORY ONLY (DOMAIN-SHIFT DIAGNOSTIC, NOT A DETECTION RESULT, NOT A PAPER CLAIM)`
> **Rule R1 / R2 / R3 Notice**: Executed on Windows using real Aposemat IoT-23 benign hardware captures (`4-1`, `5-1`, `7-1`). **No Linux/kernel/real-testbed result exists yet.**

---

## 1. Pre-Stated Protocol & Methodological Caveats

1. **TQH-C2 D per-packet autoencoder TPR is SKIPPED (§4.3)**: `TQH-C2_features_D.zip` (`features_D/testbed_D.parquet`, 11,528 rows × 27 columns) contains Zeek flow-level summaries only (no per-packet `size/dir/iat` arrays). Downloading the 1.82 GB raw pcap (`TQH-C2_pcap_D_merlin_h2.zip`) is deferred to Prompt 7 on Linux.
2. **Cross-device benign setup (NOT attack detection)**: Every flow in `4-1` (Philips Hue), `5-1` (Amazon Echo), and `7-1` (Somfy Door Lock) is **benign**. This diagnostic measures cross-device false-positive sensitivity under domain shift, **not** attack detection TPR/AUROC.
3. **What seeds `{42, 43, 44}` vary**: The three seeds vary **only** model weight initialisation and the internal 85/15 early-stopping shuffle within the training capture (`5-1` Echo); the capture assignment (`train=5-1`, `calib=4-1 or 7-1`, `test=7-1 or 4-1`) is **fixed** (`n=1` device split per direction).
4. **Protocol composition**: Across the three benign IoT-23 captures, **69.0% of extracted flows are UDP** (DNS/NTP/SSDP/mDNS) and only **11.1%** carry TLS (`4-1` Hue is `99.7%` non-TLS). Do **not** tune further on these captures.

---

## 2. Side-by-Side Before vs. After Per-Packet `log_iat` Normalisation (Prompt 9 Item 2d)

- **Before (`FEATURE_SCHEMA_VERSION = 1`)**: [`demo/evidence/real/exploratory_results_before_iat_norm.csv`](../demo/evidence/real/exploratory_results_before_iat_norm.csv) — raw `log10(1 + iat_us)` in `[0, ~7.5]`.
- **After (`FEATURE_SCHEMA_VERSION = 2`)**: `min(1.5, log10(1 + iat_us) / 7.0)` in `[0, 1.5]`, same protocol & seeds `{42, 43, 44}` (no flow-idle split yet; see Item 3 section when added).

| Config (Fixed Capture Split) | `k` | **Before** FPR@EVT`0.05` (mean ± std) | **After** FPR@EVT`0.05` (mean ± std) | **Before** FPR@EVT`0.01` | **After** FPR@EVT`0.01` | **Before -> After** KS Stat | **After** Top-3 Shifting Features (Test − Cal MSE) |
|---|---:|---:|---:|---:|---:|---:|---|
| `Echo(5-1) -> Hue(4-1) cal -> Somfy(7-1) test` | 4 | `0.9476 ± 0.0165` | **`0.0572 ± 0.0757`** | `0.7928` | **`0.0024`** | `0.9283 -> 0.8128` | `dir_1 (+0.38); std_log_iat (+0.25); log_iat_0 (+0.25)` |
| `Echo(5-1) -> Hue(4-1) cal -> Somfy(7-1) test` | 8 | `0.9452 ± 0.0109` | **`0.6214 ± 0.4023`** | `0.6476` | **`0.0262`** | `0.9212 -> 0.8222` | `log_iat_2 (+0.34); log_iat_0 (+0.34); std_log_iat (+0.33)` |
| `Echo(5-1) -> Hue(4-1) cal -> Somfy(7-1) test` | 16 | `0.9452 ± 0.0148` | **`0.6738 ± 0.4784`** | `0.4429` | **`0.0429`** | `0.9207 -> 0.8908` | `std_log_iat (+0.31); log_iat_0 (+0.30); dir_2 (+0.24)` |
| `Echo(5-1) -> Somfy(7-1) cal -> Hue(4-1) test` | 4 | `0.0057 ± 0.0029` | **`0.0812 ± 0.0618`** *(worse)* | `0.0057` | **`0.0595`** *(worse)* | `0.9283 -> 0.8128` | `dir_1 (-0.38); std_log_iat (-0.25); log_iat_0 (-0.25)` |
| `Echo(5-1) -> Somfy(7-1) cal -> Hue(4-1) test` | 8 | `0.0028 ± 0.0029` | **`0.0227 ± 0.0049`** *(higher, closer to 0.05)* | `0.0009` | **`0.0095`** | `0.9212 -> 0.8222` | `log_iat_2 (-0.34); log_iat_0 (-0.34); std_log_iat (-0.33)` |
| `Echo(5-1) -> Somfy(7-1) cal -> Hue(4-1) test` | 16 | `0.0038 ± 0.0033` | **`0.0142 ± 0.0000`** *(higher, < 0.05)* | `0.0019` | **`0.0038`** | `0.9207 -> 0.8908` | `std_log_iat (-0.31); log_iat_0 (-0.30); dir_2 (-0.24)` |

---

## 3. Plain-Language Verdict on Whether Cross-Device FPR Improved

- **Partial improvement, not a silver bullet**:
  1. **What improved**: Scaling per-packet `log_iat` by `/ 7.0` eliminated the `~30×` squared-error dominance (`±10.9` dropped to `±0.38`). On `Echo -> Hue calib -> Somfy test`, `k=4` `FPR@EVT0.05` dropped sharply from **`0.9476` to `0.0572`**, and `FPR@EVT0.01` dropped across all checkpoints (`0.7928 / 0.6476 / 0.4429` -> **`0.0024 / 0.0262 / 0.0429`**).
  2. **What remained poor or got worse**: At `k=8` and `k=16` (`α=0.05`), `Echo -> Hue calib -> Somfy test` FPR improved only modestly (`0.9452 -> 0.6214` and `0.6738`) with wide initialisation spread across the 3 seeds (`0.12` to `0.95`), and `KS` stayed high (`0.81–0.89`). In the reverse direction (`Echo -> Somfy calib -> Hue test`), `FPR@EVT0.05` **increased** from `0.0057 -> 0.0812` at `k=4` (`0.0028 -> 0.0227` at `k=8`, `0.0038 -> 0.0142` at `k=16`) once Somfy's threshold ceiling was no longer artificially inflated by unscaled `log_iat` errors.
  3. **Diagnostic takeaway**: Raw `log_iat` dominance exacerbated the Prompt-8 numbers, **and** genuine cross-device traffic heterogeneity (`dir_1..3` direction patterns, `std_log_iat`, UDP vs TCP mix) still prevents zero-shot threshold transfer across unrelated IoT hardware classes — motivating per-device-class calibration (N5) rather than global cross-device thresholds.
