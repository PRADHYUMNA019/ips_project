# Datasets & Offline Benchmarks (`datasets/README.md`)

## 1. Dataset Roles & Honest Scope

| Dataset | Role | Protocol / Encryption | Key Facts & Warnings |
|---------|------|-----------------------|----------------------|
| **Own Testbed (Primary)** | Primary source for all headline inline IPS, LOFO zero-day, fast-path bypass, and drift guard results | Real TLS 1.2 / 1.3 (`mosquitto` 8883 MQTT-TLS, `https_server.py` 8443 HTTPS) | 12 IoT devices across 4 classes + `attacker` (`10.0.1.4`) + `srv` (`10.0.2.10`) |
| **CESNET-TLS-Year22** | Offline real benign TLS for long-term benign drift, FPR-over-time, and large-sample EVT/conformal calibration | TLS (first 30 payload packets per flow; no pcaps, no attacks) | Backbone web TLS (not IoT); hashed client IPs (cannot test G2 cross-device consistency). Units of IPT must be verified against real file (`UNVERIFIED SCHEMA`). |
| **TQH-C2 (Testbed D only)** | Offline held-out TLS C2 family (`TQH-C2_pcap_D_merlin_h2.zip`, ~1.8 GB) | Merlin C2 over HTTP/2-over-TLS | Beacon intervals `30s–3600s` with `0–70%` jitter. Do NOT use Testbed A (33.4 GB), B (QUIC), or C (plain HTTP with AES body, NOT TLS). |
| **Aposemat IoT-23** | Offline cross-domain benign FPR test (B6) + optional malware captures | Mostly plaintext IoT | Benign captures are **ONLY** `CTU-Honeypot-Capture-4-1` (Hue), `CTU-Honeypot-Capture-5-1` (Echo), `CTU-Honeypot-Capture-7-1` (Somfy). **WARNING**: `CTU-IoT-Malware-Capture-7-1` is **MALICIOUS** (`Linux.Mirai`)! Also do NOT use the "small" 8.7 GB archive (Zeek logs only, no pcaps). |
| **Kitsune** | Optional offline evaluation (`SSL Renegotiation` = TLS attack; `SSDP Flood` = UDP) | Mixed (1 TLS attack, 8 plaintext) | Packets in Kitsune pcaps are truncated to 200 bytes (`snaplen=200`); `ips/offline/pcap_to_flows.py` reads payload length from IP/TCP headers (`ip.len - ip.hl*4 - tcp.off*4`). |

> **Rule B5**: All public datasets are **OFFLINE-only**. Do not replay public pcaps through the gateway.
