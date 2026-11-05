# Data Card & Schema Provenance (`docs/DATA_CARD.md`)

## 1. Canonical Feature & Metadata Schema

Every flow table produced by `ips/offline/pcap_to_flows.py` or `datasets/adapters/*.py` shares a single canonical schema:

1. **Flow-Key & Provenance Metadata Columns** (strictly excluded from model inputs by `ips.features.split_metadata_and_features` and `assert_no_forbidden_features`):
   - `src_ip`, `dst_ip`, `sport`, `dport`, `proto`
   - `start_ts`, `end_ts`, `instance`
   - `session_id`, `source`, `label_family`, `is_attack`, `encrypted`, `domain`
2. **Model Feature Columns (`3N + 8` floats produced by `ips.features.build_early_vector`)**:
   - `size_0 .. size_{N-1}`: L4 payload bytes normalized by `1500.0` (computed from IP/TCP/UDP header lengths, resilient to truncated pcaps)
   - `dir_0 .. dir_{N-1}`: direction (`0` = initiator/LAN->WAN, `1` = responder/WAN->LAN)
   - `log_iat_0 .. log_iat_{N-2}`: `log10(1 + iat_us)` between consecutive payload-bearing packets
   - 9 aggregates: `bytes_up`, `bytes_down`, `pkts_up`, `pkts_down`, `frac_upstream`, `mean_log_iat`, `std_log_iat`, `first_payload_size`, `valid_len`

---

## 2. External Dataset Schema Verification Status (A7)

- **CESNET-TLS-Year22 (`datasets/adapters/cesnet_adapter.py`)**:
  - Column names (`PPI_PKT_LENGTHS`, `PPI_PKT_DIRECTIONS`, `PPI_PKT_TIMES` / `sizes`, `dirs`, `iats`) and inter-packet time units (seconds vs milliseconds) are marked **`UNVERIFIED SCHEMA`** until inspected against a downloaded CESNET parquet/csv file. Adapter emits a runtime warning printing actual columns found.
- **TQH-C2 Testbed D (`datasets/adapters/tqh_adapter.py`)**:
  - Raw pcaps (`TQH-C2_pcap_D_merlin_h2.zip`) are parsed directly by `ips/offline/pcap_to_flows.py` (verified header layout). Pre-extracted CSV columns in `TQH-C2_features_D.zip` are marked **`UNVERIFIED SCHEMA`** and emit a runtime warning if used directly.
- **Kitsune (`datasets/adapters/kitsune_adapter.py`)**:
  - Raw pcaps are parsed via `ips/offline/pcap_to_flows.py` using IP/TCP header lengths (handling Kitsune's 200-byte packet truncation). Pre-extracted CSV columns are marked **`UNVERIFIED SCHEMA`**.
- **Aposemat IoT-23 (`datasets/adapters/iot23_adapter.py`)**:
  - Raw pcaps from `CTU-Honeypot-Capture-4-1` (Hue), `CTU-Honeypot-Capture-5-1` (Echo), and `CTU-Honeypot-Capture-7-1` (Somfy) are parsed via `ips/offline/pcap_to_flows.py`. Never use `CTU-IoT-Malware-Capture-7-1` (Linux.Mirai) as benign.
