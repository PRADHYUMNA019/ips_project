# Dataset Registry & Integration Documentation

This directory houses download scripts, adapters, and schemas for datasets utilized in the project.

In strict compliance with **Honesty Rule H3**, all datasets are categorized by their ground-truth traffic nature:
- `real-testbed`: Captured from our live encrypted network namespace testbed.
- `real-public`: External peer-reviewed or open-source scientific captures.
- `semi-synthetic`: Resampled or parametric early-flow vectors (clearly labelled).

---

## Dataset Portfolio & Usage Matrix

| Dataset | Nature | Size | Primary Usage | Prohibited Usage (DO NOT USE FOR) |
|---|---|---|---|---|
| **real-testbed** | Real TLS 1.2/1.3 | Variable (~100 MB–1 GB) | Closed-loop inline IPS evaluation, leakage measurement, drift scenarios. | Do not claim "physical hardware" until Pi deployment. |
| **TQH-C2 (2026)** | Real TLS C2 | 379 MB (Testbed C), 1.8 GB (Testbed D) | Held-out "zero-day" TLS C2 evaluation (Sliver, Merlin, Mythic). | Do not use for training or threshold calibration. |
| **CESNET-TLS-Year22** | Real backbone TLS | Parquet (~500 MB sample) | Long-term natural benign drift and EVT calibration curves. | Cannot replay through XDP (no pcaps; feature vectors only). |
| **Kitsune (UCI 516)** | Real mixed traffic | 17.7 GB total (use SSL sub-pcap) | SSL Renegotiation attack (TLS) & SSDP Flood (UDP). | Note: 200B truncation; do not use for DPI claims. |
| **IoT-23 (Stratosphere)** | Real IoT malware | ~21 GB | Non-TLS plaintext attacks (Mirai, DoS, port scans). | **NEVER** cite as "encrypted attack" data. |
| **ISCX-VPN2016** | Real OpenVPN/TLS | ~28 GB | Hard benign negatives under encryption. | Contains no attacks; do not use for attack detection. |
| **CIC-Darknet2020** | Encrypted Tor/VPN | ~15 GB | Hard benign negatives / traffic classification. | Traffic classification only, not intrusion detection. |

---

## Automated Download Scripts
All download scripts verify file size and prompt for user confirmation before initiating downloads:
- `datasets/download_tqh_c2.sh`: Downloads TQH-C2 testbed archive from Zenodo.
- `datasets/download_cesnet.sh`: Downloads a sampled week of CESNET-TLS-Year22 parquet data.
- `datasets/download_kitsune.sh`: Downloads SSL Renegotiation and SSDP flood pcap slices.
- `datasets/download_iot23.sh`: Downloads selected IoT-23 Mirai and benign captures.

---

## Unified Feature Schema
All adapters convert raw dataset flows into the unified early-flow schema defined in `ips/features.py`:
- `early_n`: Number of payload-bearing packets ($N \in \{4, 6, 8, 12, 16, 24\}$).
- `sizes`: Vector of $N$ TCP/UDP payload byte lengths (Ethernet/IP headers excluded).
- `dirs`: Vector of $N$ directional flags ($0 = \text{client}\to\text{server}, 1 = \text{server}\to\text{client}$).
- `iat_ms`: Inter-packet arrival times between consecutive payload packets (ms).
- Metadata: `{source, label_family, is_attack, encrypted, session_id, split_hint}`.
