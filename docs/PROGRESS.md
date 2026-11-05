# Progress Tracker (`docs/PROGRESS.md`)

> Last updated: Part A (A1–A8 corrections complete; next: Part B / WP2b dataset splits & cross-domain)
> Platform detected: Windows (`platform.system() == "Windows"`, win32, Python 3.12.3)

## Verification Classes
- **V1 – Ran here:** Pure-Python logic, feature extraction, ML models, EVT calibration, ONNX INT8 quantization, kernel-userspace schema & equivalence verifier, mocked closed-loop engine & watchdog, drift guard & scenarios S1–S5, and pytest unit tests. Executed and verified on host.
- **V2 – Linux-only:** Topology (`ip netns`/veth/bridges), XDP/eBPF kernel programs (`ebpf/ips_engine.c`), BCC loader, `tcpdump` capture, services (`mosquitto`/`nginx`), attack injectors, live system measurements. Statically verified; marked `CODE WRITTEN, NOT RUN (Linux required)`.
- **V3 – Data-dependent:** Experiments and tables requiring real testbed pcap captures or public datasets. Marked `NOT RUN (needs real data)`.

## 60% Checklist

| # | Item | WP | Status | Evidence |
|---|------|----|--------|----------|
| 1 | Repaired generator, per-device IPs, no committed secrets, truthful README | WP0 / WP0b | PARTIAL (V1 DONE, V2 code written) | V1: `pytest tests/test_generator.py tests/test_topology_parse.py` (7 passed); V2: `scripts/topology.sh` rewritten for 12 devices / 14 namespaces, `CODE WRITTEN, NOT RUN (Linux required)` |
| 2 | `docs/spec.md`, `docs/LIMITATIONS.md`, `docs/related_work_todo.md`, `docs/TODO_USER.md` | WP1 | ✅ DONE (V1) | All 4 specification and honesty documents authored and verified; `ips/smoke/synth.py` created (Rule B0) |
| 3 | `docs/DATA_CARD.md`, adapters, audit scripts | WP2 | PARTIAL (V1 DONE, V3 needs real data) | V1: `pytest tests/test_dataset_adapters.py` (6 passed); `datasets/audit_pcap.py`, `docs/DATA_CARD.md`, adapters (CESNET, TQH, Kitsune), download scripts; V3: `NOT RUN (needs real data)` |
| 4 | Labelled TLS testbed captures with manifest, services, attacks A1–A5 | WP3 | PARTIAL (V1 DONE, V2 code written) | V1: `pytest tests/test_manifest.py` (1 passed); services (HTTPS/MQTT), attacks A1–A5, `scripts/run_experiment.sh`, `scripts/collect.sh`; V2: `CODE WRITTEN, NOT RUN (Linux required)` |
| 5 | Shared feature implementation (`ips/features.py`), shortcut guard | WP4 | ✅ DONE (V1) | V1: `pytest tests/test_features.py` (4 passed); dimension `3N+8` verified, shortcut guard enforced, golden pcap fixture matches; `ips/offline/pcap_to_flows.py` |
| 6 | Offline detection (IF/AE/Kitsune-style), EVT calibration, INT8 quantization | WP5 | PARTIAL (V1 DONE, V3 needs real data) | V1: `pytest tests/test_models.py` (7 passed); AE/Kitsune-style/IF/per-class trained & quantized (FP32/INT8) on smoke data; EVT GPD POT + KS fit & Clopper-Pearson curve verified; V3: `NOT RUN (needs real data)` |
| 7 | Kernel v2 (`ebpf/ips_engine.c`), verdict cache, LRU state, tier-0 guard | WP6 | PARTIAL (V1 DONE, V2 code written) | V1: `pytest tests/test_schema_and_equivalence.py` (5 passed); `ips/engine/schema.py`, `ebpf/ips_engine.c`, `ips/eval/equivalence.py`, `scripts/xdp_selftest.sh`, `scripts/equivalence_test.sh`; V2: `CODE WRITTEN, NOT RUN (Linux required)` |
| 8 | Closed loop v2 (`ips/engine`), watchdog, measurement harness | WP7 | PARTIAL (V1 DONE, V2 code written) | V1: `pytest tests/test_engine_closed_loop.py` (5 passed); `ips/engine/engine.py`, `ips/eval/harness.py`, `scripts/demo.sh`; V2: live XDP closed-loop `CODE WRITTEN, NOT RUN (Linux required)` |
| 9 | Drift guard (ADWIN, G1–G4 checks, scenarios S1–S5) | WP8 | PARTIAL (V1 DONE, V3 needs real data) | V1: `pytest tests/test_drift_guard.py` (3 passed); `ips/drift/periodicity.py`, `ips/drift/guard.py`, `ips/drift/scenarios.py`; S1–S5 & ablations verified on smoke streams; V3: `NOT RUN (needs real data)` |
| 10 | `make reproduce`, `docs/RESULTS.md`, `scripts/verify_linux.sh`, `docs/USER_TEST_GUIDE.md`, `docs/PAPER_OUTLINE.md`, `docs/ARCHITECTURE.md` | WP9 / Part C | PARTIAL (V1 DONE, V2/V3 pending Linux VM run) | V1: `pytest tests/test_reproduce.py` (2 passed); all 40 V1 unit tests pass; `scripts/verify_linux.sh`, `docs/USER_TEST_GUIDE.md`, `docs/RESULTS.md`, `docs/PAPER_OUTLINE.md`, `docs/ARCHITECTURE.md` complete |

## V1 Unit Test Summary (Executed on Host)
- `tests/test_generator.py`: 5 passed
- `tests/test_topology_parse.py`: 2 passed
- `tests/test_dataset_adapters.py`: 6 passed
- `tests/test_manifest.py`: 1 passed
- `tests/test_features.py`: 4 passed
- `tests/test_models.py`: 7 passed
- `tests/test_schema_and_equivalence.py`: 5 passed
- `tests/test_engine_closed_loop.py`: 5 passed
- `tests/test_drift_guard.py`: 3 passed
- `tests/test_reproduce.py`: 2 passed
- **Total V1 Unit Tests**: **40 passed, 0 failed**

## Not Run Here (V2 Linux Required / V3 Real Data Required)
- `sudo bash scripts/verify_linux.sh` (Stages S0, S2–S4, S6 require Linux root + network namespaces + BCC)
- `scripts/collect.sh` & `scripts/run_experiment.sh` (live TLS testbed pcap collection)
- Public dataset downloads (`datasets/download_{cesnet,tqh_c2,kitsune,iot23}.sh`)

## Remaining 40% (Post-60% Scope)
- Gateway VM with hard cgroup CPU/RAM limits
- Raspberry Pi 4/5 hardware validation
- libbpf / CO-RE precompiled bytecode loader
- Extended public datasets (full CIC-IDS2018 220GB, full CIC-IoT-2023)
- Full paper prose and camera-ready formatting
