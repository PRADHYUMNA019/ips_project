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
- `tests/test_dataset_adapters.py`: 7 passed
- `tests/test_drift_guard.py`: 5 passed
- `tests/test_engine_closed_loop.py`: 12 passed
- `tests/test_features.py`: 9 passed
- `tests/test_generator.py`: 5 passed
- `tests/test_kernel_source_invariants.py`: 1 passed
- `tests/test_manifest.py`: 1 passed
- `tests/test_models.py`: 13 passed
- `tests/test_reproduce.py`: 2 passed
- `tests/test_schema_and_equivalence.py`: 10 passed
- `tests/test_shell_permissions.py`: 2 passed
- `tests/test_splits_and_joins.py`: 3 passed
- `tests/test_topology_parse.py`: 3 passed
- **Total V1 Unit Tests**: **74 passed, 0 failed, 0 warnings** (`18/18` adversarial mutants KILLED)

## Not Run Here (V2 Linux Required / V3 Real Data Required)
- `sudo bash scripts/verify_linux.sh` (Stages S0, S2–S4, S6, S6b, S6c require Linux root + network namespaces + BCC + `tc netem`)
- `scripts/collect.sh` & `scripts/run_experiment.sh` (live TLS testbed pcap collection)
- Public dataset downloads (`datasets/download_{cesnet,tqh_c2,kitsune,iot23}.sh`)

## Remaining 40% (Post-60% Scope)
- Physical embedded gateway deployment (e.g. Raspberry Pi 4/5 or OpenWrt hardware router)
- Libbpf / CO-RE precompiled bytecode loader
- Extended public datasets (full CIC-IDS2018 220GB, full CIC-IoT-2023)
- Full paper prose and camera-ready formatting

---

## Prompt 8 — Windows-Only Guide-Review Evidence Pack (branch `p8-demo`)
> **Honesty Reminder (R1/R2)**: All Prompt 8 runs are on Windows (`UNIT TEST`, `SYNTHETIC SMOKE`, or `REAL PUBLIC DATA` offline). **No Linux/kernel/real-testbed result exists yet.**

- **P8.1 (UNIT TEST evidence) — DONE**: Removed untracked `BLOCKERS.md`; branched `p8-demo` from `wp0-fix-30pct` (`3b3050f`). Ran `pytest -q` (**68 passed, 0 failed, 0 skipped**), `compileall -q .` (rc=0), `audit/check_claims.py` (0 forbidden phrases, 3/3 titles consistent), `audit/mutation_runner.py` (**17/17 KILLED, 0 survived, 0 invalid**). Saved timestamped logs under `demo/evidence/logs/` and created `demo/run_demo.ps1`.
- **P8.2 (SYNTHETIC SMOKE pipeline + watermarked figures) — DONE**: Created `demo/run_smoke_pipeline.py` running smoke generation → split integrity assertions → `3N+8` features → per-checkpoint `[4, 8, 16]` training & INT8 export → EVT/conformal/3σ calibration → offline eval → `MockBPFBackend` closed loop (sticky DROP + watchdog shed/recover) → drift S1–S5 → C3 evasion curve. Ran twice with fixed seed 42: **10/10 deterministic artefacts byte-for-byte IDENTICAL**. Generated 5 colour-blind-safe watermarked figures + captions under `demo/figures/smoke/`. Verified `demo/run_demo.ps1` from external directory `C:\Users\Dell` (**PASS, 71.1s**).
- **P8.3 (REAL PUBLIC DATA: TQH-C2 Testbed D + IoT-23 Benign) — DONE**: Verified Zenodo `21523144` (`TQH-C2 v1.2.0`, CC-BY-4.0); wrote `datasets/download_tqh_c2_win.py` & downloaded small files (`features_D`, `labels_D`, `README_v120`, `SHA256SUMS_v120`, all 3 SHA-256 **PASS**) to `D:\ips_data\tqh_c2`. Verified 27 Parquet columns in `datasets/adapters/tqh_adapter.py` + added 6-row CC-BY-4.0 fixture test (`tests/test_dataset_adapters.py`: 7 passed). Audited all `11,528` TQH-C2 D rows (`9,564` benign, `1,964` `malicious_c2`; `100.0%/98.1%/97.7%` reach est. `k=4/8/16`; median dur `31.02s`). Downloaded all 3 real IoT-23 benign captures (`4-1` Hue, `5-1` Echo, `7-1` Somfy; `512.97 MB` on `D:\ips_data\iot23`) and streamed through `ips/offline/pcap_to_flows.py` (`1,254` flows, `11.08%` TLS, `22.01%/10.13%/6.54%` reaching `k=4/8/16`). Wrote `docs/DATASET_AUDIT.md`, `demo/evidence/real/tqh_c2_audit.csv`, and `demo/evidence/real/iot23_benign_audit.csv`.
- **P8.4 (EXPLORATORY REAL DATA: IoT-23 cross-device benign transfer; TQH-C2 TPR skipped per §4.3) — DONE (PARTIAL BY DESIGN)**: Pre-stated plan in `docs/EXPLORATORY_P8.md` before running `demo/run_exploratory_p8.py` (seeds 42, 43, 44). Measured severe asymmetric cross-device shift (`KS = 0.921–0.928`, driven by `log_iat_1/0/3`): `Echo->Hue_cal->Somfy_test` FPR@0.05 = `0.945–0.948`; `Echo->Somfy_cal->Hue_test` FPR@0.05 = `0.003–0.006`. TQH-C2 D per-packet autoencoder TPR skipped per §4.3 because `TQH-C2_features_D.zip` contains flow-level Zeek summaries only (1.82 GB pcap excluded per §3.5). Wrote `demo/evidence/real/exploratory_results.csv`.
- **P8.5 (Diagrams, Claims vs. Evidence, Guide Script & Index) — DONE**: Added 4 Mermaid diagrams to `docs/ARCHITECTURE.md` (two-tier overview, checkpoint 4/8/16 sequence, drift guard G1–G4, split governance; `mmdc` not installed so source + render commands documented). Wrote `demo/evidence/CLAIMS_VS_EVIDENCE.md` (strictly matching `docs/PAPER_OUTLINE.md` statuses), `docs/GUIDE_DEMO.md` (7–10 min walkthrough + 6 Q&As), and `demo/evidence/INDEX.md`. Final `pytest -q` (69 passed) and `audit/check_claims.py` (0 violations) PASS.

---

## Prompt 9 — Independent-Review Defect Fixes & Re-Verification (branch `p9-fixes`)
> **Honesty Reminder (R1/R2)**: All Prompt 9 fixes and measurements ran on Windows (`UNIT TEST`, `SYNTHETIC SMOKE`, or offline `REAL PUBLIC DATA`). **No Linux/kernel/real-testbed result exists yet.**

- **P9.1 (Fix smoke ROC inversion & mock closed-loop false DROP) — DONE**: Diagnosed inverted smoke ROC (`0.3213`): `epochs=8` (32 updates) left decoder `log_iat` stuck at `~2.7` under unscaled `log_iat`, `score_onnx_model` lacked `build_valid_mask_matrix`, smoke `A3_c2` overlapped benign, and `IPSEngine._load_model_and_thresholds` ignored `config['engine']['model_card']` while bypassing `ckpt_thresholds`. Fixed with red→green unit tests (`test_toy_gaussian_cluster_all_checkpoints_and_length_comparability_p9_1d`, `test_engine_loads_configured_model_card_and_benign_reaches_bypass_p9_1e`), regenerated Figures A–E (`offline_int8_auroc`: `0.3213 -> 1.0000` *SMOKE ONLY*; `benign_sensor_1`: `DROP -> BYPASS`), determinism `10/10 IDENTICAL`.
- **P9.2 (Normalise per-packet `log_iat` by `/ 7.0`, `FEATURE_SCHEMA_VERSION = 2`) — DONE**: Scaled `log_iat_i = min(1.5, log10(1 + iat_us) / 7.0)` across `ips/features.py` and updated `recompute_early_matrix_for_k`, `eval_offline.py`, `impairment.py`, `engine.py`, and golden fixtures. Added `test_feature_group_ranges_and_no_iat_dominance_p9_2c` and mutant `M17` (**18/18 mutants KILLED**). Preserved `exploratory_results_before_iat_norm.csv` and re-ran `demo/run_exploratory_p8.py` once.
- **P9.3 (Add kernel-matching `flow_idle_s = 120 s` & `FIN/RST + SYN` split rules to offline extractor) — DONE**: Updated `ips/offline/pcap_to_flows.py` and `ips/eval/equivalence.py` to match `ebpf/ips_engine.c` (`flow_idle_s` read from `configs/system.yaml`, overridable; pure SYN retransmits do not reset; active flows >120 s with <=120 s gaps do not reset). Verified via 5-case pcap test `test_offline_extractor_idle_timeout_and_syn_lifecycle_p9_3b`. Re-ran `demo/audit_iot23_real.py` (`1,254 -> 1,447` flows; Somfy `ttv_k8_p95`: `4.39e7 ms -> 54,766.8 ms`; Hue `ttv_k4_p95`: `8.68e6 ms -> 212.1 ms`) and single post-split `demo/run_exploratory_p8.py` (`Echo->Hue->Somfy` FPR@0.05: `0.945–0.948 -> 0.156–0.204`; `Echo->Somfy->Hue` rose `0.003–0.006 -> 0.035–0.095`).
- **P9.4 (Calibrate public-data claims & measure real benign host-pair CV baseline) — DONE**: Added `demo/audit_tqh_c2_real.py` computing `CV <= 0.35` (`>=8` conns) on real TQH-C2 D benign host pairs: **`0 / 157` (`0.00%`) benign host pairs flagged** (`min CV = 0.3879`) vs **`71 / 71` C2 host pairs flagged**. Replaced overstated wording across `docs/DATASET_AUDIT.md`, `demo/evidence/CLAIMS_VS_EVIDENCE.md`, `docs/GUIDE_DEMO.md`, `docs/PAPER_OUTLINE.md`, and `docs/EXPLORATORY_P8.md`.
- **P9.5 (Informative Figure D panels, PNG/SVG architecture diagrams, updated guide script & final gate) — DONE**: Replaced flat-zero Figure D panels `S3–S5` with Held-Out Attack TPR (`S3, S4` comparing Static, Unguarded ADWIN, and Guarded `G1–G4`) and Concurrent Slow-C2 TPR (`S5`), rendered 4 PNG + 4 SVG diagrams into `demo/figures/diagrams/` via `demo/render_architecture_diagrams.py`, added the review-fixes slide section to `docs/GUIDE_DEMO.md`, and passed `pytest -q` (`73 passed`), `audit/check_claims.py` (`0` violations), `audit/mutation_runner.py` (`18/18 KILLED`), smoke determinism (`10/10 IDENTICAL`), and `demo/run_demo.ps1` (`PASS`).
