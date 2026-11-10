# Progress Tracker (`docs/PROGRESS.md`)

> Last updated: P0–P5 complete (Part A corrections A1–A8, Part B WP2b dataset plan/splits/label-joins/cross-domain, Part C/D WP5–WP9 progressive checkpoints `[4,8,16]`, split-conformal/EVT calibration, C10 operational harm, C11 netem impairment, C12 contamination study, C3 white-box cost-of-evasion curve, B5 CESNET drift mode, and Part E verification harness `S0..S11`)
> Platform detected: Windows (`platform.system() == "Windows"`, win32, Python 3.12.3)

## Verification Classes
- **V1 – Ran here:** Pure-Python logic, feature extraction, ML models, EVT calibration, ONNX INT8 quantization, kernel-userspace schema & equivalence verifier, mocked closed-loop engine & watchdog, drift guard & scenarios S1–S5, dataset adapters, session split builder & label joiners, cross-domain generalisation evaluator, and pytest unit tests. Executed and verified on host.
- **V2 – Linux-only:** Topology (`ip netns`/veth/bridges), XDP/eBPF kernel programs (`ebpf/ips_engine.c`), BCC loader, `tcpdump` capture, services (`mosquitto`/`https_server.py`), attack injectors, live system measurements. Marked `CODE WRITTEN, NOT COMPILED, NOT RUN (V2)`.
- **V3 – Data-dependent:** Experiments and tables requiring real testbed pcap captures or public datasets. Marked `NOT RUN (needs real data)`.

## 60% Checklist

| # | Item | WP | Status | Evidence |
|---|------|----|--------|----------|
| 1 | Repaired generator, per-device IPs, no committed secrets, truthful README | WP0 / WP0b / A1, A5 | PARTIAL (V1 model PASS; V2 `CODE WRITTEN, NOT COMPILED, NOT RUN (V2)`) | V1: `pytest tests/test_generator.py tests/test_topology_parse.py tests/test_shell_permissions.py` (10 passed); MQTT/HTTPS real-protocol traffic + per-class TLS; V2: `scripts/topology.sh` rewritten for 12 devices (`10.0.1.10–10.0.1.41`) / 14 namespaces, `CODE WRITTEN, NOT COMPILED, NOT RUN (V2)` |
| 2 | `docs/spec.md`, `docs/LIMITATIONS.md`, `docs/related_work_todo.md`, `docs/TODO_USER.md` | WP1 | ✅ DONE (V1) | All 4 specification and honesty documents authored and verified; `ips/smoke/synth.py` created (Rule B0, deterministic RNG A8); scope notes attached to prevent hardware overstatement |
| 3 | `docs/DATA_CARD.md`, `docs/DATASET_PLAN.md`, adapters, splits, label joins, cross-domain eval | WP2 / WP2b / A2, A3, A7, B7 | PARTIAL (V1 DONE, V3 `NOT RUN (needs real data)`) | V1: `pytest tests/test_dataset_adapters.py tests/test_splits_and_joins.py tests/test_cross_eval.py` (10 passed); `docs/DATASET_PLAN.md`, `ips/data/build_splits.py` (assertions a-d), `ips/data/label_join.py`, `ips/eval/cross_domain.py` (with target leakage sentinel & train-only scaler fit), adapters (CESNET, TQH, Kitsune, IoT-23); V3: `NOT RUN (needs real data)` |
| 4 | Labelled TLS testbed captures with manifest, services, attacks A1–A5 | WP3 / A6 | PARTIAL (V1 model PASS; V2 `CODE WRITTEN, NOT COMPILED, NOT RUN (V2)`) | V1: `pytest tests/test_manifest.py` (1 passed); services (HTTPS/MQTT), attacks A1–A5, `scripts/run_experiment.sh`, `scripts/collect.sh` (process-group teardown & YAML parsing); V2: `CODE WRITTEN, NOT COMPILED, NOT RUN (V2)` |
| 5 | Shared feature implementation (`ips/features.py`), shortcut guard, direction asymmetry, truncated & reused-tuple pcap parsing | WP4 / A4, B3 | ✅ DONE (V1) | V1: `pytest tests/test_features.py` (7 passed); dimension `3N+8` verified, shortcut guard enforced, direction asymmetry (`frac_upstream`) verified (M2 killed), IP/TCP header payload length & TCP instance splitting verified |
| 6 | Offline detection (IF/AE/Kitsune-style), progressive checkpoints (`[4,8,16]`), masked short-flow MSE, Split-Conformal & EVT calibration, contamination study, INT8 quantization | WP5 / C1, C9, C12, B4, B5, B6 | PARTIAL (V1 DONE, V3 `NOT RUN (needs real data)`) | V1: `pytest tests/test_models.py` (12 passed); per-checkpoint AE `[4,8,16]`, masked loss/score over `< valid_len` (`test_short_flow_masked_padding_invariance_c1`), Split-Conformal exact order statistic test (M8 killed), EVT POT/GPD known-answer test (B6), C12 contamination & trimmed-loss; V3: `NOT RUN (needs real data)` |
| 7 | Kernel v2 (`ebpf/ips_engine.c`), progressive checkpoint emission (`[4,8,16]`), connection reuse re-init, safe submit + `emitted_mask` set, verdict cache, LRU state, tier-0 guard | WP6 / C1, N6, A1, A2, A3, A4 | PARTIAL (V1 model PASS; V2 `CODE WRITTEN, NOT COMPILED, NOT RUN (V2)`) | V1: `pytest tests/test_schema_and_equivalence.py tests/test_kernel_source_invariants.py` (10 passed); `ips/engine/schema.py` (`SCHEMA_VERSION 4`), `ebpf/ips_engine.c` (`emitted_mask` set after `ringbuf_submit`, `checkpoint_idx`, FIN/RST/idle reinit, retry counter), stages `S6c-S6e` in `scripts/verify_linux.sh`; V2: `CODE WRITTEN, NOT COMPILED, NOT RUN (V2)` |
| 8 | Closed loop v2 (`ips/engine`), progressive verdicts, sticky drop, safe ringbuf parser, watchdog, C10 operational harm, C11 netem impairment | WP7 / C1, C10, C11, B1, B2, B8, C2 | PARTIAL (V1 model PASS; V2 `CODE WRITTEN, NOT COMPILED, NOT RUN (V2)`) | V1: `pytest tests/test_engine_closed_loop.py` (11 passed); safe ringbuf parser (B1 / DEF-04), confusion matrix test (B2 / M15 killed), sticky DROP verdict (C2), wire-to-engine leakage reconciliation (B8), watchdog fail-open shedding; V2: `CODE WRITTEN, NOT COMPILED, NOT RUN (V2)` |
| 9 | Drift guard (ADWIN, G1–G4 checks, scenarios S1–S5, C3 cost-of-evasion curve, B5 CESNET drift) | WP8 / C3, B5, C1d, C1e | PARTIAL (V1 DONE, V3 `NOT RUN (needs real data)`) | V1: `pytest tests/test_drift_guard.py` (5 passed); `ips/drift/periodicity.py`, `ips/drift/guard.py` (G2 small-class fail-closed limitation, quorum & periodicity checks), `ips/drift/scenarios.py` (DEV-only canary), `ips/drift/evasion_cost.py`; V3: `NOT RUN (needs real data)` |
| 10 | `make reproduce`, `docs/RESULTS.md`, `scripts/verify_linux.sh`, `docs/USER_TEST_GUIDE.md`, `docs/PAPER_OUTLINE.md`, `docs/ARCHITECTURE.md` | WP9 / Part E | PARTIAL (V1 DONE, V2/V3 `CODE WRITTEN, NOT COMPILED, NOT RUN (V2)`) | V1: `pytest tests/test_reproduce.py` (2 passed); all 68 V1 unit tests pass; `scripts/verify_linux.sh` (19 stages `S0..S11`), `docs/USER_TEST_GUIDE.md`, `docs/RESULTS.md`, `docs/PAPER_OUTLINE.md`, `docs/ARCHITECTURE.md` complete |

## V1 Unit Test Summary (Executed on Host)
- `tests/test_cross_eval.py`: 1 passed
- `tests/test_dataset_adapters.py`: 6 passed
- `tests/test_drift_guard.py`: 5 passed
- `tests/test_engine_closed_loop.py`: 11 passed
- `tests/test_features.py`: 7 passed
- `tests/test_generator.py`: 5 passed
- `tests/test_kernel_source_invariants.py`: 1 passed
- `tests/test_manifest.py`: 1 passed
- `tests/test_models.py`: 12 passed
- `tests/test_reproduce.py`: 2 passed
- `tests/test_schema_and_equivalence.py`: 9 passed
- `tests/test_shell_permissions.py`: 2 passed
- `tests/test_splits_and_joins.py`: 3 passed
- `tests/test_topology_parse.py`: 3 passed
- **Total V1 Unit Tests**: **68 passed, 0 failed**

## Not Run Here (V2 Linux Required / V3 Real Data Required)
- `sudo bash scripts/verify_linux.sh` (Stages S0, S2–S4, S6, S6b, S6c require Linux root + network namespaces + BCC + `tc netem`)
- `scripts/collect.sh` & `scripts/run_experiment.sh` (live TLS testbed pcap collection)
- Public dataset downloads (`datasets/download_{cesnet,tqh_c2,kitsune,iot23}.sh`)

## Remaining 40% (Post-60% Scope)
- Physical embedded gateway deployment (e.g. Raspberry Pi 4/5 or OpenWrt hardware router)
- Libbpf / CO-RE precompiled bytecode loader
- Extended public datasets (full CIC-IDS2018 220GB, full CIC-IoT-2023)
- Full paper prose and camera-ready formatting
