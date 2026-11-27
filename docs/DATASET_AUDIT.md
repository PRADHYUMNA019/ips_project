# Real Public Dataset Audit (`docs/DATASET_AUDIT.md`)

> **Evidence Type**: `REAL PUBLIC DATA` (offline audit only; Rule H5 — no public data replayed through the gateway).
> **Scope Notice (R2)**: These numbers come strictly from real public datasets downloaded to `D:\ips_data\`. **No Linux/kernel/real-testbed result exists yet.**

---

## 1. TQH-C2 Testbed D (`Merlin HTTP/2-over-TLS`, Zenodo `21523144`, CC-BY-4.0)

### 1.1 Verification & Schema Audit (`datasets/download_tqh_c2_win.py`)
- **Zenodo Record Verified**: `21523144` (`TQH-C2 v1.2.0`, licence `CC-BY-4.0`). Note: record `19365445` is an unrelated FAERS paper; newer v1.2.5 is at `23905375`.
- **Downloaded Files (SHA-256 Verified against `SHA256SUMS_v120.txt`)**:
  - `TQH-C2_features_D.zip`: `1,222,048` bytes (`sha256=5f1c6c26329f2d68079514b3cfc926931f4fcfe34284862b2681bf213d11a412`) — **PASS**
  - `TQH-C2_labels_D.zip`: `791,480` bytes (`sha256=b91e9ebe36a94cf8ffc5b4209a2670443e1e0b45b0215147f20487f60f1777e6`) — **PASS**
  - `README_v120.md`: `17,614` bytes (`sha256=aa0dd75211670ca87b17d0097a39f52bca0aa849deb494600b20843f182f23f5`) — **PASS**
  - `TQH-C2_pcap_D_merlin_h2.zip` (`1,823,494,055` bytes) was **NOT** downloaded in Prompt 8 (deferred to Prompt 7 on Linux VM).
- **Real Schema Discovery (`features_D/testbed_D.parquet`)**:
  - **11,528 rows × 27 columns** (Zeek-style flow summaries: `ts, uid, orig_h, resp_h, duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts, orig_p, resp_p, proto, conn_state, history, orig_ip_bytes, resp_ip_bytes, missed_bytes, ja4, ja4s, ja4h, profile, encryption_profile, interval_s, jitter_pct, capture_id, label_raw, y`).
  - **Labels**: `9,564` benign (`y=0`, 82.96%) and `1,964` `malicious_c2` (`y=1`, 17.04%).
  - **Protocols**: `9,972` TCP (86.50%), `1,082` UDP (9.39%), `474` ICMP (4.11%). Top destination ports: `443` (`9,090`), `8443` (`1,922`).
  - **Granularity Limitation (Honest Finding)**: `TQH-C2_features_D.zip` provides flow-level aggregates (`orig_pkts`, `resp_pkts`, `duration`, `ja4`), **not** per-packet early-window arrays (`size_0..N-1`, `dir_0..N-1`, `iat_0..N-2`). Therefore, evaluating the `3N+8` per-packet early-flow autoencoder on TQH-C2 D requires parsing `TQH-C2_pcap_D_merlin_h2.zip` (Prompt 7 on Linux VM).

### 1.2 Beacon Interval, Jitter, Checkpoint Reachability & Slow-C2 Tracker Audit (`demo/evidence/real/tqh_c2_audit.csv`)

Because `TQH-C2_features_D.zip` reports total flow packets (`orig_pkts + resp_pkts`), we estimate payload-bearing packets conservatively as `est_payload_pkts = max(1, total_pkts - 3)` when `total_bytes > 0` (subtracting 3 handshake/teardown packets):

| `interval_s` | `jitter_pct` | C2 Flows | Benign Flows | C2 Total Pkts (p50) | C2 Est. Pay >= 4 | C2 Est. Pay >= 8 | C2 Est. Pay >= 16 | C2 Duration p50 (s) | Host Pairs >= 8 Conns | Median Inter-Conn (s) | Median Pair CV | Pairs Flagged (`CV <= 0.35`) |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 30 | 0 | 554 | 676 | 32.0 | 100.0% | 97.47% | 97.29% | 31.02 | 15 | 30.03 | 0.0481 | 15 / 15 |
| 30 | 30 | 482 | 687 | 32.0 | 100.0% | 96.89% | 96.89% | 31.02 | 15 | 35.08 | 0.0872 | 15 / 15 |
| 30 | 70 | 411 | 656 | 32.0 | 100.0% | 97.81% | 96.35% | 31.02 | 15 | 39.58 | 0.1571 | 15 / 15 |
| 300 | 0 | 134 | 550 | 33.0 | 100.0% | 100.00% | 100.00% | 31.03 | 15 | 300.05 | 0.0001 | 15 / 15 |
| 300 | 30 | 115 | 547 | 33.0 | 100.0% | 100.00% | 99.13% | 31.03 | 10 | 342.94 | 0.0669 | 10 / 10 |
| 300 | 70 | 99 | 564 | 33.0 | 100.0% | 100.00% | 100.00% | 31.03 | 1 | 345.57 | 0.1173 | 1 / 1 |
| 1800 | 0 | 36 | 811 | 34.0 | 100.0% | 100.00% | 100.00% | 31.03 | 0 | — | — | 0 / 0 |
| 1800 | 30 | 35 | 800 | 34.0 | 100.0% | 100.00% | 100.00% | 31.04 | 0 | — | — | 0 / 0 |
| 1800 | 70 | 27 | 799 | 35.0 | 100.0% | 100.00% | 100.00% | 31.05 | 0 | — | — | 0 / 0 |
| 3600 | 0 | 24 | 1151 | 50.5 | 100.0% | 100.00% | 100.00% | 31.05 | 0 | — | — | 0 / 0 |
| 3600 | 30 | 24 | 1152 | 50.5 | 100.0% | 100.00% | 100.00% | 31.06 | 0 | — | — | 0 / 0 |
| 3600 | 70 | 23 | 1171 | 61.0 | 100.0% | 100.00% | 100.00% | 31.07 | 0 | — | — | 0 / 0 |

### 1.3 Plain-Language Implications for Our Architecture
1. **Implication for Tier-1 Early-Window Detector (`checkpoints = [4, 8, 16]`)**: Contrary to naive assumptions that slow C2 beacons only send 1–2 packets per connection, real Merlin HTTP/2-over-TLS C2 establishes a full TLS 1.3 + HTTP/2 session per check-in (median 33 total packets, median flow duration **31.02 s**, well inside `flow_idle_s = 120 s`). Across all 1,964 C2 flows, **100.0%** reach an estimated ≥ 4 payload packets, **98.1%** reach ≥ 8, and **97.7%** reach ≥ 16. Thus, **a single C2 check-in connection DOES reach all three early checkpoints within ~31 s**.
2. **Implication for Tier-2 Slow-C2 Periodicity Tracker (`SlowC2Tracker`, `min_connections = 8`, `CV <= 0.35`)**:
   - For 30 s beacons (even at 70% jitter!), **15/15** victim host pairs reach ≥ 8 connections during the capture cell and **100% (15/15)** are flagged (`median CV = 0.048–0.157 <= 0.35`).
   - For 300 s beacons, 8 connections require ~40 minutes; 15/15 (`j=0%`), 10/15 (`j=30%`), and 1/15 (`j=70%`) reach 8 connections within the cell duration (all that do are flagged).
   - For **1,800 s (30 min)** and **3,600 s (1 hour)** beacons, **0/15** host pairs reach 8 connections within a ~1–2 hour capture window (8 × 3,600 s = 8 hours!). Therefore, **Tier-2 periodicity tracking alone is blind to ultra-slow beacons over short windows** and requires multi-hour/multi-day state retention, making Tier-1 per-flow early-window inspection essential for first-connection detection.

---

## 2. Aposemat IoT-23 Benign Honeypot Supplement (Real Pcaps, Streaming `dpkt` Audit)

### 2.1 Downloads & Streaming Extraction (`datasets/download_iot23_win.py`, `demo/audit_iot23_real.py`)
- **Downloaded Captures (Strict Benign-Only Guard A3 — `CTU-IoT-Malware-Capture-7-1` Excluded)**:
  - `CTU-Honeypot-Capture-4-1` (Philips Hue): `2018-10-25-14-06-32-192.168.1.132.pcap.xz` (0.36 MB compressed → `4.38 MB` decompressed `.pcap`)
  - `CTU-Honeypot-Capture-5-1` (Amazon Echo): `2018-09-21-capture.pcap` (`363.71 MB`)
  - `CTU-Honeypot-Capture-7-1` (Somfy Door Lock): 6 pcaps (`Somfy-01..06`, `144.88 MB` total)
  - Total on `D:\ips_data\iot23`: **512.97 MB** (well below the 3 GB cap; raw pcaps excluded from git).
- **Extractor**: Streamed through `ips/offline/pcap_to_flows.py` (`dpkt`, `early_n=16`, LAN CIDRs `192.168.0.0/16, 10.0.0.0/8`).

### 2.2 Real IoT-23 Benign Flow & Checkpoint Reachability Table (`demo/evidence/real/iot23_benign_audit.csv`)

| Capture | Device | Pcaps (MB) | Total Flows | TLS Flows (%) | TCP / UDP | Payload Pkts (p50 / p90) | Reach `k=4` | Reach `k=8` | Reach `k=16` | TTV `k=4` p50 (ms) | TTV `k=8` p50 (ms) | TTV `k=16` p50 (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `CTU-Honeypot-Capture-4-1` | Philips Hue | 1 (4.38) | 353 | 1 (0.28%) | 57 / 296 | 2.0 / 3.0 | 8.22% (29) | 0.85% (3) | 0.57% (2) | 61.97 | 58,960.50 | 474,820.51 |
| `CTU-Honeypot-Capture-5-1` | Amazon Echo | 1 (363.71) | 761 | 121 (15.90%) | 315 / 446 | 2.0 / 12.0 | 15.11% (115) | 13.40% (102) | 8.41% (64) | 117.54 | 286.36 | 972.72 |
| `CTU-Honeypot-Capture-7-1` | Somfy Door Lock | 6 (144.88) | 140 | 17 (12.14%) | 17 / 123 | 4.0 / 16.0 | 94.29% (132) | 15.71% (22) | 11.43% (16) | 30.24 | 10,392.60 | 21,771.36 |
| **Combined (All 3 Benign)** | **3 Real IoT Devices** | **8 (512.97)** | **1,254** | **139 (11.08%)** | **389 / 865** | — | **22.01% (276)** | **10.13% (127)** | **6.54% (82)** | — | — | — |

### 2.3 Honest Reading of IoT-23 Benign Audit
1. **Most real IoT-23 benign flows are very short UDP/DNS/NTP/control exchanges**: Across all 1,254 flows, 69.0% (865/1,254) are UDP and only 11.08% (139/1,254) carry TLS (`4-1` Hue has only 1 TLS flow; `5-1` Echo has 121; `7-1` Somfy has 17).
2. **Checkpoint reachability strongly validates progressive early exit (C1)**: Only **6.54%** of flows reach `k=16` payload packets, whereas **22.01%** reach `k=4` (including **94.29%** of Somfy flows at median `30.24 ms`). On slow persistent IoT connections (`4-1` Hue, `7-1` Somfy), waiting for `k=16` takes `21.8 s` to `474.8 s` median — confirming why `k=4` and `k=8` progressive checkpoints are necessary.
3. **Sample-size caution**: With only 1,254 total benign flows across the 3 captures (and only 82 reaching `k=16`), IoT-23 alone cannot support distribution-free split-conformal calibration at `alpha = 1e-3` (which requires `n >= 1,000` calibration flows reaching `k`). This directly justifies collecting our own larger multi-session TLS testbed dataset in Prompt 7.
