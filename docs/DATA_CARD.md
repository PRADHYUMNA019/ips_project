# Dataset Provenance & Protocol Audit Card

> Last updated: 2026-11-04 13:06:52 via `datasets/audit_pcap.py`

| File | SHA-256 (Prefix) | Size (MB) | Packets | Flows | TLS Flows | TLS Share (%) | Plaintext (%) | Top Ports |
|---|---|---|---|---|---|---|---|---|
| (No pcap files audited yet) | - | - | - | - | - | - | - | - |

### Audit Rules & Verification Criteria
- **TLS Verification**: Confirms payload bytes `0x16 0x03 0x01..0x04` at start of first application packet.
- **Honesty Rule H3**: Datasets lacking verified TLS record headers are classified as `plaintext-attack` or `plaintext-benign`, never as 'encrypted attacks'.
- **Held-Out Criteria**: Datasets designated as zero-day evaluations are held strictly in held-out test splits.