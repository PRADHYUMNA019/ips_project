# Related Work Candidates

> **IMPORTANT NOTICE (Rule H8)**: All entries below are flagged as:
> `UNVERIFIED — human must check`
> Authors and students must retrieve the original papers, verify exact publication venues, read methodology details, and check citation strings before including any claim or citation in the final paper manuscript.

---

## 1. Early-Packet & Payload-Independent Anomaly Detection
- **Kitsune (Mirai Detection via Autoencoders)**
  - *Reference*: Mirsky et al., "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection", NDSS 2018.
  - *Status*: `UNVERIFIED — human must check`
  - *Relevance*: Pioneer in using ensembles of small autoencoders with incremental feature extraction over packet statistics. Differences to verify: Kitsune operated offline or as an out-of-band sniffer, without inline eBPF/XDP drop mechanics or poisoning-aware drift adaptation.

- **Whisper (Frequency-Domain Packet Analysis)**
  - *Reference*: "Whisper: Real-time ML-based Encrypted Traffic Analysis at Edge", IEEE INFOCOM / ACM CCS candidate.
  - *Status*: `UNVERIFIED — human must check`
  - *Relevance*: Analyzes frequency-domain representations of packet sequences for encrypted traffic classification without inspecting payloads.

- **NetBeacon**
  - *Reference*: C2 beaconing detection over encrypted channels via inter-arrival timing periodicity.
  - *Status*: `UNVERIFIED — human must check`
  - *Relevance*: Provides baseline mathematical formulations for detecting periodic command-and-control beaconing in enterprise and IoT networks.

---

## 2. eBPF / XDP High-Performance Network Security
- **eBPF-based IDS / IPS Implementations**
  - *Reference*: Scholz et al., "Performance Analysis of eBPF-based Network Monitoring and Filtering", ACM SIGCOMM Workshop / IEEE NetSoft.
  - *Status*: `UNVERIFIED — human must check`
  - *Relevance*: Examines XDP driver vs generic mode packet dropping overhead and memory limits (512-byte stack, BPF array/hash maps).

- **DMLITE (Distributed Micro-IPS)**
  - *Reference*: Lightweight micro-firewall and packet filtering for constrained edge nodes.
  - *Status*: `UNVERIFIED — human must check`
  - *Relevance*: Evaluates memory footprint on small IoT gateways.

---

## 3. Adversarial Drift & Model Poisoning in Network Anomaly Detection
- **MalMoE (Mixture of Experts for Malware Detection)**
  - *Reference*: arXiv:2602.10157 (Recent preprint on multi-expert adaptation under evasion).
  - *Status*: `UNVERIFIED — human must check`
  - *Relevance*: Addresses concept drift and evasion in encrypted malware detection pipelines.

- **Poisoning and Evasion Attacks on Online Network Anomaly Detectors**
  - *Reference*: Kloft and Laskov, "Online Anomaly Detection under Adversarial Impact", AISTATS / JMLR.
  - *Status*: `UNVERIFIED — human must check`
  - *Relevance*: Mathematical foundation of "boiling-frog" attacks against online adaptive learning algorithms.

