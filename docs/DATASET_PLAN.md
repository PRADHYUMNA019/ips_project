# Dataset Usage Plan & Split Governance (`docs/DATASET_PLAN.md`)

> **Binding Rules (WP2b / B1–B6)**:
> 1. All public datasets are **OFFLINE-only** (B5). No public pcaps are replayed through the gateway.
> 2. Splits are strictly by **SESSION** (one capture session = one indivisible unit; never split flows from the same session across train/calibration/validation/test).
> 3. Plaintext datasets support ONLY the claim *"flow-header/timing features do not inspect payload"*, NEVER *"encrypted attack detection"*.

---

## 1. Per-Dataset Roles, Splits, and Claims

| Dataset | Role | Allowed Splits | Forbidden Uses | Download Size | Paper Tables / Figures Fed | Honest Claim Supported |
|---------|------|----------------|----------------|---------------|----------------------------|------------------------|
| **1. Own Linux Testbed (Primary)** | Primary encrypted TLS 1.2/1.3 benchmark (MQTT-TLS 8883 via `mosquitto`, HTTPS 443 via `https_server.py`; 12 devices in 4 classes + `attacker`) | `benign_s1` (train), `benign_s2` (calib), `benign_s3` (val/test), attack runs `A1..A5` (DEV: `A1,A2,A5`; Held-out zero-day: `A3_c2,A4_exfil`) | Never mix flows from the same session across splits; never include benign flows captured during an attack window in benign train/calib/val; never tune on `A3_c2` or `A4_exfil` | Generated locally (~50–200 MB per session) | Table 1 (Models & LOFO), Fig 1 (Checkpoint/N Pareto), Fig 2 (EVT/Conformal Calibration), Table 2 (INT8), Table 3 (Equivalence), Table 4 (System/Harm/Bypass), Table 5 & Figs 3–5 (Drift S1–S5 & Evasion Curve) | End-to-end encrypted inline IPS detection, prevention, fast-path bypass, and poisoning-aware drift guard |
| **2. CESNET-TLS-Year22** (Zenodo 10608607) | Offline real-world benign TLS traffic (first 30 payload packets per flow; no pcaps, no attacks; backbone web TLS, not IoT) | Weekly units (`week_k` = 1 session unit): early weeks for train/calib, later weeks for long-term benign drift & large-sample calibration (`alpha = 1e-3, 1e-4`) | **Cannot** test G2 cross-device consistency (hashed client IPs, no device identities); cannot evaluate attack TPR (no attack labels) | Check `stats-dataset.json` and weekly parquet sizes on Zenodo 10608607 before download | Fig 2b (Large-sample EVT vs Conformal vs 3-sigma calibration at `1e-3` and `1e-4`), Table 5b (Natural multi-week benign drift with G1/G3/G4) | Long-term real TLS benign FPR stability and extreme-tail EVT calibration on real TLS traffic |
| **3. TQH-C2 (Testbed D ONLY)** (Zenodo record 21523144) | Offline held-out TLS C2 attack benchmark (Merlin over HTTP/2-over-TLS; intervals `30–3600 s`, jitter `0–70%`) | `test-zeroday` ONLY (grouped by `(interval, jitter)` cell) | Forbidden in train, calibration, or hyperparameter validation; do **not** use Testbed A (33.4 GB), B (QUIC), or C (plain HTTP with AES body, NOT TLS) | Verified: `TQH-C2_pcap_D_merlin_h2.zip` (1.8 GB), `TQH-C2_features_D.zip` (1.2 MB), `TQH-C2_labels_D.zip` (0.8 MB) | Table 1b (Held-out TQH-C2 D detection vs beacon interval; Tier-1 early-flow vs Tier-2 `SlowC2Tracker`) | Real TLS C2 detection and honest demonstration that long-interval C2 (`>=30s`) requires the Tier-2 host-pair periodicity tracker (N4) |
| **4. Aposemat IoT-23** | Offline cross-domain benign generalization test (B6) + optional malware captures | `cross-domain-test` (one capture = one session unit: `CTU-Honeypot-Capture-4-1` Hue, `5-1` Echo, `7-1` Somfy) | **Never** label `CTU-IoT-Malware-Capture-7-1` (Linux.Mirai) as benign! **Never** use the "small" 8.7 GB archive (Zeek `conn.log` only, no pcaps). Never retune thresholds on IoT-23 after measuring cross-domain FPR. | Check per-capture `.pcap` sizes before download (full archive >20 GB; small 8.7 GB archive lacks pcaps) | Table 6 (Cross-Domain Benign Shift: FPR, KS stat, AUROC, top shifting features) | Cross-domain transferability and honest measurement of domain shift between simulated testbed profiles and real IoT hardware |
| **5. Kitsune Network Attack Dataset** (UCI 516) | Optional secondary offline attack evaluation (`SSL Renegotiation` = TLS attack; `SSDP Flood` = UDP; others plaintext) | `test-optional` | Do not claim "encrypted attack detection" on the 8 plaintext Kitsune attacks; do not use `len(tcp.data)` (packets truncated to 200B snaplen) | Check UCI 516 per-file size before download | Appendix / Supporting Table (Truncated-pcap header extraction & SSL Renegotiation detection) | Payload-header feature extraction (`ip.len - ip.hl*4 - tcp.off*4`) works on 200B-truncated pcaps |

---

## 2. Datasets Explicitly NOT Used at 60%

- **CIC-Darknet2020 / ISCXVPN2016**: Traffic classification datasets (VPN/Tor vs non-VPN) with no intrusion/attack labels; at most usable as hard-negative benign traffic.
- **UNSW-NB15 / NSL-KDD**: Legacy tabular datasets lacking per-packet early-flow sequences (`sizes[0..N-1]`, `iat[0..N-2]`).
- **CIC-IDS2018 (220 GB) / CIC-IoT-2023 / Edge-IIoTset / TON_IoT**: Deferred to post-60% scope due to size and predominantly plaintext IoT attack mix.

---

## 3. Verified vs Unverified Facts Checklist

### Verified Facts
- **TQH-C2 v1.2.0 Testbed D**: `TQH-C2_pcap_D_merlin_h2.zip` (1.8 GB, Merlin HTTP/2-over-TLS), `TQH-C2_features_D.zip` (1.2 MB), `TQH-C2_labels_D.zip` (0.8 MB), `SHA256SUMS_v120.txt`. Testbed C is plain HTTP with AES payload (not TLS).
- **IoT-23 Benign vs Malicious IDs**: `CTU-Honeypot-Capture-4-1` (Philips Hue), `CTU-Honeypot-Capture-5-1` (Amazon Echo), and `CTU-Honeypot-Capture-7-1` (Somfy door lock) are the 3 benign captures; `CTU-IoT-Malware-Capture-7-1` is malicious (`Linux.Mirai`). The 8.7 GB "small" archive has Zeek logs only (no pcaps).
- **Kitsune Snaplen**: Packets in Kitsune pcaps are truncated at 200 bytes; IP/TCP header lengths preserve true payload size.

### Unverified Facts (Must Check on Download)
- Exact column names and IPT time units (seconds vs milliseconds vs microseconds) inside CESNET-TLS-Year22 parquet/CSV files (`UNVERIFIED SCHEMA` warning in `datasets/adapters/cesnet_adapter.py`).
- Exact flow counts per weekly CESNET file (read `stats-dataset.json` after download; never state flow counts from memory).
- Exact Zenodo download URL path if record `21523144` redirects.

