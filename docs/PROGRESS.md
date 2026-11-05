# Progress Tracker (`docs/PROGRESS.md`)

> Last updated: P0–P5 complete (Part A corrections A1–A8, Part B WP2b dataset plan/splits/label-joins/cross-domain, Part C/D WP5–WP9 progressive checkpoints `[4,8,16]`, split-conformal/EVT calibration, C10 operational harm, C11 netem impairment, C12 contamination study, C3 white-box cost-of-evasion curve, B5 CESNET drift mode, and Part E verification harness `S0..S11`)
> Platform detected: Windows (`platform.system() == "Windows"`, win32, Python 3.12.3)

## Verification Classes
- **V1 – Ran here:** Pure-Python logic, feature extraction, ML models, EVT calibration, ONNX INT8 quantization, kernel-userspace schema & equivalence verifier, mocked closed-loop engine & watchdog, drift guard & scenarios S1–S5, dataset adapters, session split builder & label joiners, cross-domain generalisation evaluator, and pytest unit tests. Executed and verified on host.
- **V2 – Linux-only:** Topology (`ip netns`/veth/bridges), XDP/eBPF kernel programs (`ebpf/ips_engine.c`), BCC loader, `tcpdump` capture, services (`mosquitto`/`https_server.py`), attack injectors, live system measurements. Statically verified; marked `CODE WRITTEN, NOT RUN (Linux required)`.
- **V3 – Data-dependent:** Experiments and tables requiring real testbed pcap captures or public datasets. Marked `NOT RUN (needs real data)`.

## 60% Checklist

| # | Item | WP | Status | Evidence |
|---|------|----|--------|----------|
| 1 | Repaired generator, per-device IPs, no committed secrets, truthful README | WP0 / WP0b / A1, A5 | PARTIAL (V1 DONE, V2 code written) | V1: `pytest tests/test_generator.py tests/test_topology_parse.py tests/test_shell_permissions.py` (8 passed); MQTT/HTTPS real-protocol traffic + per-class TLS; V2: `scripts/topology.sh` rewritten for 12 devices / 14 namespaces, `CODE WRITTEN, NOT RUN (Linux required)` |
| 2 | `docs/spec.md`, `docs/LIMITATIONS.md`, `docs/related_work_todo.md`, `docs/TODO_USER.md` | WP1 | ✅ DONE (V1) | All 4 specification and honesty documents authored and verified; `ips/smoke/synth.py` created (Rule B0, deterministic RNG A8) |
| 3 | `docs/DATA_CARD.md`, `docs/DATASET_PLAN.md`, adapters, splits, label joins, cross-domain eval | WP2 / WP2b / A2, A3, A7 | PARTIAL (V1 DONE, V3 needs real data) | V1: `pytest tests/test_dataset_adapters.py tests/test_splits_and_joins.py` (10 passed); `docs/DATASET_PLAN.md`, `ips/data/build_splits.py` (assertions a-d), `ips/data/label_join.py`, `ips/eval/cross_domain.py`, adapters (CESNET, TQH, Kitsune, IoT-23); V3: `NOT RUN (needs real data)` |
| 4 | Labelled TLS testbed captures with manifest, services, attacks A1–A5 | WP3 / A6 | PARTIAL (V1 DONE, V2 code written) | V1: `pytest tests/test_manifest.py` (1 passed); services (HTTPS/MQTT), attacks A1–A5, `scripts/run_experiment.sh`, `scripts/collect.sh` (process-group teardown & YAML parsing); V2: `CODE WRITTEN, NOT RUN (Linux required)` |
| 5 | Shared feature implementation (`ips/features.py`), shortcut guard, truncated & reused-tuple pcap parsing | WP4 / A4 | ✅ DONE (V1) | V1: `pytest tests/test_features.py` (6 passed); dimension `3N+8` verified, shortcut guard enforced, IP/TCP header payload length & TCP instance splitting verified |
| 6 | Offline detection (IF/AE/Kitsune-style), progressive checkpoints (`[4,8,16]`), Split-Conformal & EVT calibration, contamination study, INT8 quantization | WP5 / C1, C9, C12 | PARTIAL (V1 DONE, V3 needs real data) | V1: `pytest tests/test_models.py` (9 passed); per-checkpoint AE `[4,8,16]`, Split-Conformal (`alpha >= 1/(n+1)`), EVT POT/GPD, C12 contamination & trimmed-loss (`ips/eval/contamination.py`), multi-seed LOFO; V3: `NOT RUN (needs real data)` |
| 7 | Kernel v2 (`ebpf/ips_engine.c`), progressive checkpoint emission (`[4,8,16]`), verdict cache, LRU state, tier-0 guard | WP6 / C1, N6 | PARTIAL (V1 DONE, V2 code written) | V1: `pytest tests/test_schema_and_equivalence.py` (6 passed); `ips/engine/schema.py` (`SCHEMA_VERSION 3`), `ebpf/ips_engine.c` (`emitted_mask`, `checkpoint_idx`), per-checkpoint `ips/eval/equivalence.py`; V2: `CODE WRITTEN, NOT RUN (Linux required)` |
| 8 | Closed loop v2 (`ips/engine`), progressive verdicts, watchdog, C10 operational harm, C11 netem impairment | WP7 / C1, C10, C11 | PARTIAL (V1 DONE, V2 code written) | V1: `pytest tests/test_engine_closed_loop.py` (7 passed); `ips/engine/engine.py` (early drop/late bypass), `ips/eval/harness.py` (C10 operational harm), `scripts/netem_sweep.sh`, `ips/eval/impairment.py` (C11 feature ablations); V2: `CODE WRITTEN, NOT RUN (Linux required)` |
| 9 | Drift guard (ADWIN, G1–G4 checks, scenarios S1–S5, C3 cost-of-evasion curve, B5 CESNET drift) | WP8 / C3, B5 | PARTIAL (V1 DONE, V3 needs real data) | V1: `pytest tests/test_drift_guard.py` (4 passed); `ips/drift/periodicity.py`, `ips/drift/guard.py`, `ips/drift/scenarios.py`, `ips/drift/evasion_cost.py` (C3 Q=200 adaptive curve & B5 CESNET no-G2 mode); V3: `NOT RUN (needs real data)` |
| 10 | `make reproduce`, `docs/RESULTS.md`, `scripts/verify_linux.sh`, `docs/USER_TEST_GUIDE.md`, `docs/PAPER_OUTLINE.md`, `docs/ARCHITECTURE.md` | WP9 / Part E | PARTIAL (V1 DONE, V2/V3 pending Linux VM run) | V1: `pytest tests/test_reproduce.py` (3 passed); all 54 V1 unit tests pass; `scripts/verify_linux.sh` (15 stages `S0..S11`), `docs/USER_TEST_GUIDE.md`, `docs/RESULTS.md`, `docs/PAPER_OUTLINE.md`, `docs/ARCHITECTURE.md` complete |

## V1 Unit Test Summary (Executed on Host)
- `tests/test_generator.py`: 5 passed
- `tests/test_topology_parse.py`: 2 passed
- `tests/test_shell_permissions.py`: 1 passed
- `tests/test_dataset_adapters.py`: 7 passed
- `tests/test_splits_and_joins.py`: 3 passed
- `tests/test_manifest.py`: 1 passed
- `tests/test_features.py`: 6 passed
- `tests/test_models.py`: 9 passed
- `tests/test_schema_and_equivalence.py`: 6 passed
- `tests/test_engine_closed_loop.py`: 7 passed
- `tests/test_drift_guard.py`: 4 passed
- `tests/test_reproduce.py`: 3 passed
- **Total V1 Unit Tests**: **54 passed, 0 failed**

## Not Run Here (V2 Linux Required / V3 Real Data Required)
- `sudo bash scripts/verify_linux.sh` (Stages S0, S2–S4, S6, S6b require Linux root + network namespaces + BCC + `tc netem`)
- `scripts/collect.sh` & `scripts/run_experiment.sh` (live TLS testbed pcap collection)
- Public dataset downloads (`datasets/download_{cesnet,tqh_c2,kitsune,iot23}.sh`)

## Remaining 40% (Post-60% Scope)
- Gateway VM with hard cgroup CPU/RAM limits
- Raspberry Pi 4/5 hardware validation
- libbpf / CO-RE precompiled bytecode loader
- Extended public datasets (full CIC-IDS2018 220GB, full CIC-IoT-2023)
- Full paper prose and camera-ready formatting
