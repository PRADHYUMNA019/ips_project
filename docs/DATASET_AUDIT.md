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

### 1.2 Beacon Interval, Jitter, Upper-Bound Checkpoint Reachability & Slow-C2 Tracker Audit (`demo/evidence/real/tqh_c2_audit.csv`)

Because `TQH-C2_features_D.zip` reports flow-level packet totals (`orig_pkts + resp_pkts`) rather than per-packet payload lengths, `est_payload_pkts = max(1, total_pkts - 3)` (for `total_bytes > 0`) is strictly an **upper bound** (a 3-way TCP handshake consumes 3 packets, whereas TLS 1.3 + HTTP/2 SETTINGS/ACK frames consume additional non-application or zero-payload packets). Next to the C2 host pairs, we also measure the **exact same `CV <= 0.35` rule (`min_connections = 8`) on real BENIGN (`y = 0`) `(orig_h, resp_h, resp_p)` host pairs** within each capture (`demo/audit_tqh_c2_real.py`):

| `interval_s` | `jitter_pct` | C2 / Benign Flows | C2 Total Pkts (p50) | C2 Est. Pay `>= 4 / 8 / 16` *(Upper Bound)* | C2 Pairs `>=8` | C2 Med. CV | C2 Flagged (`CV<=0.35`) | **Benign Pairs `>=8`** | **Benign Med. CV (Min)** | **Benign Flagged (`CV<=0.35`)** |
|---:|---:|---|---:|---|---:|---:|---:|---:|---|---:|
| 30 | 0 | 554 / 676 | 32.0 | 100.0 / 97.5 / 97.3% | 15 | 0.0496 | 15 / 15 | 5 | 0.6834 (0.3957) | **0 / 5** |
| 30 | 30 | 482 / 687 | 32.0 | 100.0 / 96.9 / 96.9% | 15 | 0.0872 | 15 / 15 | 7 | 0.8599 (0.6559) | **0 / 7** |
| 30 | 70 | 411 / 656 | 32.0 | 100.0 / 97.8 / 96.4% | 15 | 0.1571 | 15 / 15 | 7 | 0.8041 (0.5801) | **0 / 7** |
| 300 | 0 | 134 / 550 | 33.0 | 100.0 / 100.0 / 100.0% | 15 | 0.0001 | 15 / 15 | 4 | 0.6424 (0.6162) | **0 / 4** |
| 300 | 30 | 115 / 547 | 33.0 | 100.0 / 100.0 / 99.1% | 10 | 0.0669 | 10 / 10 | 3 | 0.6861 (0.4679) | **0 / 3** |
| 300 | 70 | 99 / 564 | 33.0 | 100.0 / 100.0 / 100.0% | 1 | 0.1173 | 1 / 1 | 5 | 0.7002 (0.5281) | **0 / 5** |
| 1800 | 0 | 36 / 811 | 34.0 | 100.0 / 100.0 / 100.0% | 0 | — | 0 / 0 | 15 | 0.7383 (0.4139) | **0 / 15** |
| 1800 | 30 | 35 / 800 | 34.0 | 100.0 / 100.0 / 100.0% | 0 | — | 0 / 0 | 10 | 0.6615 (0.4552) | **0 / 10** |
| 1800 | 70 | 27 / 799 | 35.0 | 100.0 / 100.0 / 100.0% | 0 | — | 0 / 0 | 13 | 0.7237 (0.4703) | **0 / 13** |
| 3600 | 0 | 24 / 1,151 | 50.5 | 100.0 / 100.0 / 100.0% | 0 | — | 0 / 0 | 19 | 0.9561 (0.5400) | **0 / 19** |
| 3600 | 30 | 24 / 1,152 | 50.5 | 100.0 / 100.0 / 100.0% | 0 | — | 0 / 0 | 31 | 0.9313 (0.5711) | **0 / 31** |
| 3600 | 70 | 23 / 1,171 | 61.0 | 100.0 / 100.0 / 100.0% | 0 | — | 0 / 0 | 38 | 0.8441 (0.3879) | **0 / 38** |
| **Totals** | — | **1,964 / 9,564** | — | **100.0 / 98.1 / 97.7%** | **71** | — | **71 / 71** | **157** | — | **0 / 157 (0.00%)** |

### 1.3 Plain-Language Implications for Our Architecture
1. **Implication for Tier-1 Early-Window Detector (`checkpoints = [4, 8, 16]`)**: Real Merlin HTTP/2-over-TLS C2 establishes a full TLS 1.3 + HTTP/2 session per check-in (median 33 total packets, median flow duration **31.02 s**, inside `flow_idle_s = 120 s`). Across all 1,964 C2 flows, **100.0% / 98.1% / 97.7% are ESTIMATED to reach `k = 4 / 8 / 16` payload packets (upper bound: payload packets estimated as `total_pkts - 3`; TLS handshakes and pure ACKs consume more, so exact payload-packet reachability must be verified on the 1.82 GB raw pcap in Prompt 7)**.
2. **Implication for Tier-2 Slow-C2 Periodicity Tracker (`SlowC2Tracker`, `min_connections = 8`, `CV <= 0.35`) & Why Benign Baseline Matters**:
   - Reporting *"15/15 C2 pairs flagged"* (`71/71` across all cells with `>= 8` connections) is **meaningless without the false-positive rate on benign host pairs** — a trivial rule like `CV <= 10` would also flag `15/15` C2 pairs while flagging every benign host pair.
   - Across all **9,564 real benign background flows** in Testbed D, **157 `(orig_h, resp_h, resp_p)` benign host pairs** accumulate `>= 8` connections, with median CVs in **`0.642–0.956`** (minimum CV = `0.3879`), and **`0 / 157` (`0.00%`, 95% Clopper-Pearson upper bound `[0.00%, 2.32%]`)** are flagged by either `CV <= 0.35` or the full `SlowC2Tracker` (`CV <= 0.35` or spectral peak). Caveat: Testbed D's benign background simulates aperiodic user/enterprise browsing; fixed-timer IoT cron/NTP/heartbeat services on real home networks could exhibit `CV <= 0.35` and must be evaluated on our IoT testbed in Prompt 7.
   - For **1,800 s (30 min)** and **3,600 s (1 hour)** beacons, **0/15** C2 host pairs reach 8 connections within a ~1–2 hour capture window (8 × 3,600 s = 8 hours). Thus Tier-2 periodicity tracking alone is blind to ultra-slow beacons over short windows.

---

## 2. Aposemat IoT-23 Benign Honeypot Supplement (Real Pcaps, Streaming `dpkt` Audit)

### 2.1 Downloads & Streaming Extraction (`datasets/download_iot23_win.py`, `demo/audit_iot23_real.py`)
- **Downloaded Captures (Strict Benign-Only Guard A3 — `CTU-IoT-Malware-Capture-7-1` Excluded)**:
  - `CTU-Honeypot-Capture-4-1` (Philips Hue): `2018-10-25-14-06-32-192.168.1.132.pcap.xz` (0.36 MB compressed → `4.38 MB` decompressed `.pcap`)
  - `CTU-Honeypot-Capture-5-1` (Amazon Echo): `2018-09-21-capture.pcap` (`363.71 MB`)
  - `CTU-Honeypot-Capture-7-1` (Somfy Door Lock): 6 pcaps (`Somfy-01..06`, `144.88 MB` total)
  - Total on `D:\ips_data\iot23`: **512.97 MB** (well below the 3 GB cap; raw pcaps excluded from git).
- **Extractor**: Streamed through `ips/offline/pcap_to_flows.py` (`dpkt`, `early_n=16`, `flow_idle_s=120.0` from `configs/system.yaml`, LAN CIDRs `192.168.0.0/16, 10.0.0.0/8`).

### 2.2 Real IoT-23 Benign Flow & Checkpoint Reachability Table (`demo/evidence/real/iot23_benign_audit.csv`, After `flow_idle_s = 120 s` Split — Prompt 9 Item 3)

| Capture | Device | Pcaps (MB) | Total Flows | TLS Flows (%) | TCP / UDP | Payload Pkts (p50 / p90) | Reach `k=4` | Reach `k=8` | Reach `k=16` | TTV `k=4` p50 / p95 (ms) | TTV `k=8` p50 / p95 (ms) | TTV `k=16` p50 / p95 (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `CTU-Honeypot-Capture-4-1` | Philips Hue | 1 (4.38) | 353 | 1 (0.28%) | 55 / 298 | 2.0 / 3.0 | 7.65% (27) | 0.85% (3) | 0.57% (2) | 61.72 / **212.11** | 58,960.48 / 330,295.65 | 474,820.47 / 803,476.69 |
| `CTU-Honeypot-Capture-5-1` | Amazon Echo | 1 (363.71) | 844 | 137 (16.23%) | 331 / 513 | 2.0 / 11.7 | 18.96% (160) | 12.44% (105) | 7.58% (64) | 141.71 / 39,619.03 | 288.86 / 62,659.86 | 1,034.80 / **44,414.28** |
| `CTU-Honeypot-Capture-7-1` | Somfy Door Lock | 6 (144.88) | 250 | 9 (3.60%) | 9 / 241 | 4.0 / 8.0 | 100.00% (250) | 13.20% (33) | 8.40% (21) | 18.49 / 356.84 | 7,577.70 / **54,766.80** | 22,418.98 / **135,028.14** |
| **Combined (All 3 Benign)** | **3 Real IoT Devices** | **8 (512.97)** | **1,447** | **147 (10.16%)** | **395 / 1,052** | — | **30.20% (437)** | **9.74% (141)** | **6.01% (87)** | — | — | — |

### 2.3 Old vs. New Comparison (Before vs. After `flow_idle_s = 120 s` Kernel-Parity Split)

Preserved pre-fix baseline: [`demo/evidence/real/iot23_benign_audit_before_idle_split.csv`](../demo/evidence/real/iot23_benign_audit_before_idle_split.csv).

| Capture | Flows (Old → New) | Reach `k=4 / 8 / 16` (Old → New) | TTV `k=4` p95 ms (Old → New) | TTV `k=8` p95 ms (Old → New) | TTV `k=16` p95 ms (Old → New) |
|---|---|---|---|---|---|
| `4-1` Hue | `353 → 353` | `8.22 / 0.85 / 0.57%` → **`7.65 / 0.85 / 0.57%`** | `8,679,347.33` (2.41 h) → **`212.11`** | `330,295.77` → `330,295.65` | `803,476.72` → `803,476.69` |
| `5-1` Echo | `761 → 844` | `15.11 / 13.40 / 8.41%` → **`18.96 / 12.44 / 7.58%`** | `50,133.58` → **`39,619.03`** | `91,853.70` → **`62,659.86`** | `190,149.59` → **`44,414.28`** |
| `7-1` Somfy | `140 → 250` | `94.29 / 15.71 / 11.43%` → **`100.0 / 13.20 / 8.40%`** | `121.24` → `356.84` | `43,901,593.91` (12.19 h) → **`54,766.80`** | `10,979,012.70` (3.05 h) → **`135,028.14`** |
| **Combined** | **`1,254 → 1,447`** | **`22.01 / 10.13 / 6.54%`** → **`30.20 / 9.74 / 6.01%`** | — | — | — |

**Plain-language explanation of what changed**:
- Previously, `ips/offline/pcap_to_flows.py` lacked the kernel's `120 s` idle-timeout split (`ebpf/ips_engine.c` line 362). Because UDP protocols (NTP, SSDP, mDNS, DNS — **72.7% of extracted flows**) have no `FIN/RST` flags and frequently reuse the same `(src_ip, sport, dst_ip, dport, UDP)` 5-tuple hours apart, the old extractor glued separate periodic UDP exchanges hours apart into a single "flow", producing bogus multi-hour `ttv_p95` values (`8.68×10^6 ms = 2.41 h` on Hue `k=4`; `4.39×10^7 ms = 12.19 h` on Somfy `k=8`).
- Enforcing `flow_idle_s = 120 s` (and ignoring pure SYN retransmits while splitting on new SYNs after `FIN/RST` or payload) splits those idle-reused 5-tuples (`1,254 → 1,447` flows), collapsing Somfy `ttv_k8_p95` from **12.2 hours to 54.8 s** and Hue `ttv_k4_p95` from **2.41 hours to 212 ms**. Note that active flows whose consecutive packet gaps remain `<= 120 s` (e.g., the 2 persistent Hue connections sending keepalives every ~30–60 s) legitimately span `> 120 s` total time (`474.8 s` to reach 16 packets) without idling out.

### 2.4 Honest Reading of IoT-23 Benign Audit
1. **Most real IoT-23 benign flows are very short UDP/DNS/NTP/control exchanges**: Across all 1,447 flows, **72.70% (1,052/1,447) are UDP** (`69.0%` before idle split) and only **10.16% (147/1,447)** carry TLS (`4-1` Hue has 1 TLS flow; `5-1` Echo has 137; `7-1` Somfy has 9).
2. **Checkpoint reachability motivates progressive early exit**: Only **6.01%** of these (mostly UDP) flows reach `k=16` payload packets, whereas **30.20%** reach `k=4` (including **100.0%** of Somfy flows at median `18.49 ms`). On slow persistent IoT connections (`4-1` Hue, `7-1` Somfy), waiting for `k=16` takes `22.4 s` to `474.8 s` median — motivating why `k=4` and `k=8` progressive checkpoints are included alongside `k=16`.
3. **Sample-size caution**: With only 1,447 total benign flows across the 3 captures (and only 87 reaching `k=16`), IoT-23 alone cannot support distribution-free split-conformal calibration at `alpha = 1e-3` (which requires `n >= 1,000` calibration flows reaching `k`). This directly justifies collecting our own larger multi-session TLS testbed dataset in Prompt 7.
