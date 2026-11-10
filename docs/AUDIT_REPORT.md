# Adversarial Audit Report: WP0 → WP9

> **Auditor Role**: Hostile Independent Code Reviewer & Research Methodology Auditor  
> **Audited Repository**: `https://github.com/PRADHYUMNA019/ips_project` (`branch: wp0-fix-30pct`)  
> **Host Platform**: Windows 11 (`win32`, Python 3.12.3)  
> **Specification Baseline**: Master Prompt (Rules H1–H8, Architecture §3), Prompt 2 (V1–V3 verification), Prompt 3 (P0–P5 upgrades), Prompt 4 (Hostile Audit Protocol)  
> **Evaluation Mode**: Emulated Gateway (Linux network namespaces / software bridges) — **Zero physical hardware validation**

---

## 1. Executive Verdict

**The project as built is technically substantive but cannot support its published title or primary edge-deployment claims.**
While the pure-Python pipelines (53 passing V1 unit tests, canonical feature extraction, split-conformal and EVT calibration, multi-checkpoint progressive models, and the G1–G4 poisoning-aware drift guard) are rigorously implemented and pass offline tests, **the title's claim of "On-Device" prevention is contradicted by the decision to evaluate exclusively via laptop/VM network namespace emulation.**
No Raspberry Pi or physical IoT hardware measurements were conducted; all cgroup limits apply solely to the Python user-space engine while the kernel XDP program executes unconstrained in host kernel context in generic SKB mode.
Furthermore, all active inline packet dropping and real-time latency claims remain **UNVERIFIABLE HERE** pending execution on Linux with root and BCC.
Critical architectural defects exist in the kernel fast path: multi-core generic XDP races update flow states non-atomically, TCP FIN/RST packets fail to evict connection records, and runtime ring-buffer events lack schema version enforcement.
**The single worst problem is the title and claims disconnect: the repository claims "On-Device Inline Intrusion Prevention for Encrypted Traffic in Resource-Constrained Smart Systems", but presents only laptop-emulated software bridge measurements and synthetic smoke metrics.**

---

## 2. Scorecard Table

| Package | Verdict | Confidence | Defects (B / M / m) | One-Line Summary Reason |
|---|---|---|---|---|
| **WP0** | `PARTIAL` | High | 0 / 1 / 1 | Generator `wait` bug fixed and certs untracked, but namespace topology and traffic generation require Linux root. |
| **WP0b** | `CORRECT (static)` | High | 0 / 0 / 1 | Connection profiles (`persistent`/`reconnect`) and time scaling verified in unit tests; IP docs had minor discrepancy. |
| **WP1** | `CORRECT (static)` | High | 0 / 0 / 1 | `docs/spec.md` and `docs/LIMITATIONS.md` define protocol boundaries and zero-day LOFO protocol; hardware profiles need emulation disclaimer. |
| **WP2** | `PARTIAL` | High | 0 / 1 / 0 | Adapters and audit script output canonical schema, but public dataset downloads and schema verification remain unrun on real captures. |
| **WP2b** | `PARTIAL` | High | 0 / 0 / 0 | Session split builder strictly enforces zero session overlap and LOFO family exclusion; cross-domain script tested on synthetic inputs. |
| **WP3** | `PARTIAL` | High | 0 / 1 / 1 | Attacks A1–A5 and real MQTT/HTTPS services implemented; live multi-namespace execution and pcap capture unverified on host. |
| **WP4** | `CORRECT (executed)` | High | 0 / 0 / 1 | Canonical `3N+8` features, shortcut-learning guard, and truncated-packet IP header length extraction verified in unit tests. |
| **WP5** | `PARTIAL` | High | 0 / 0 / 0 | Progressive checkpoints `[4, 8, 16]`, EVT POT/GPD tail fitting, split-conformal calibration, and contamination study implemented; real tables empty. |
| **WP6** | `UNVERIFIABLE HERE` | High | 0 / 2 / 0 | Kernel struct layout matches ctypes (224 B) and canonical key matches, but multi-CPU concurrency races and FIN/RST state leaks exist. |
| **WP7** | `PARTIAL` | High | 0 / 1 / 1 | User-space engine progressive verdicts, watchdog load shedding, and operational harm metrics verified in Python; live XDP unverified. |
| **WP8** | `PARTIAL` | High | 0 / 0 / 0 | G1–G4 drift guard, slow-C2 periodicity detector, and Q=200 white-box adaptive evasion curve unit-tested; real CESNET drift pending data. |
| **WP9** | `PARTIAL` | High | 0 / 0 / 1 | Verification harness (15 stages `S0..S11`), test guide, and paper outline complete; all results tables are smoke-only. |
| **Cross-Cutting**| `PARTIAL` | High | 0 / 1 / 2 | 53 unit tests pass; mutation M2 survived; title contains unsupported "On-Device" claim; earlier progress text claimed 54 tests. |

*Defect count format: Blocker (B) / Major (M) / Minor (m)*

---

## 3. Defect Register

### [DEF-01] Title and Scope Contradiction: "On-Device" Claim Without Edge Hardware
- **Severity**: `MAJOR`
- **Work Package**: WP1 / WP9 / Cross-cutting
- **Location**: `README.md:1`, `docs/spec.md:1`, `docs/PAPER_OUTLINE.md:3`
- **What is wrong**: The title explicitly claims *"On-Device Inline Intrusion Prevention for Encrypted Traffic in Resource-Constrained Smart Systems"*. In reality, the user decided to evaluate exclusively via laptop emulation using Linux network namespaces and software bridges. No Raspberry Pi, OpenWrt, or physical embedded hardware was measured.
- **How verified**: Static review of experimental scripts (`scripts/topology.sh`, `scripts/run_experiment.sh`) and confirmation of laptop emulation decision.
- **Impact on claims**: Reviewers will immediately reject the paper if titled "On-Device" while reporting results obtained exclusively on an x86 laptop using virtual ethernet pairs.
- **Proposed fix**: Rename title to: *"Drift-Resilient Inline Intrusion Prevention for Encrypted IoT Traffic on an Emulated Resource-Constrained Gateway Against Zero-Day Attacks"*.

### [DEF-02] Concurrency Race Condition in eBPF Fast Path Across CPU Cores
- **Severity**: `MAJOR`
- **Work Package**: WP6
- **Location**: `ebpf/ips_engine.c:381-398`
- **What is wrong**: In generic XDP over virtual ethernet (`veth`) pairs, bidirectional packets of a single flow entering `v-lan-gw` (client→server) and `v-wan-gw` (server→client) can be scheduled on different CPU cores. The updates to `flow_record` fields (`rec->valid_len++`, `rec->total_pkts++`, `rec->sizes[idx] = ...`, `rec->iat_ns[idx-1] = ...`) use non-atomic reads and writes without BPF spinlocks.
- **How verified**: Code inspection of `ebpf/ips_engine.c` lines 381–398.
- **Impact on results**: Under multi-core packet arrival, lost updates can corrupt early-flow size and IAT feature vectors, causing anomalous classification of benign flows. Furthermore, this concurrency limitation is omitted from `docs/LIMITATIONS.md`.
- **Proposed fix**: Document this concurrency boundary explicitly in `docs/LIMITATIONS.md` Section 1, or introduce BPF spinlocks (`bpf_spin_lock`) on the `flow_record` struct for kernel >= 5.1.

### [DEF-03] TCP FIN/RST Packets Do Not Evict Connection State in eBPF Map
- **Severity**: `MAJOR`
- **Work Package**: WP6
- **Location**: `ebpf/ips_engine.c:381-385`
- **What is wrong**: When a TCP connection terminates via FIN or RST, `ebpf/ips_engine.c` merely records `rec->flags_seen |= tcp_flags;`. It does NOT delete the entry from `flow_state`. If a client reuses the same 5-tuple before the LRU hash naturally evicts the entry, the new connection finds the old record with `rec->valid_len >= EARLY_N` and emits zero events, completely blinding the IPS to the new connection. In contrast, `ips/offline/pcap_to_flows.py:199-205` properly finalizes flows on FIN/RST or new SYN.
- **How verified**: Code comparison between `ebpf/ips_engine.c:381` and `ips/offline/pcap_to_flows.py:199`.
- **Impact on results**: Discrepancy between offline feature extraction and live kernel execution during connection churn or 5-tuple reuse.
- **Proposed fix**: On `tcp->fin` or `tcp->rst`, mark the flow closed or delete it from `flow_state`, and on `tcp->syn && !tcp->ack`, reset `valid_len = 0` and `emitted_mask = 0`.

### [DEF-04] Runtime Ring-Buffer Event Schema Version is Not Validated
- **Severity**: `MAJOR`
- **Work Package**: WP6 / WP7
- **Location**: `ips/engine/engine.py:584-593`, `ips/engine/schema.py:318-337`
- **What is wrong**: While `ebpf/ips_engine.c` embeds `SCHEMA_VERSION 3` and Python serializes `schema_version` into JSON, the event handler in `engine.py:585` casts incoming ring buffer bytes to `ctypes.POINTER(EarlyFlowEvent)` without asserting that `ev_struct.schema_version == SCHEMA_VERSION`. Mismatched kernel programs or outdated structures will be parsed silently, leading to corrupted feature arrays.
- **How verified**: Code inspection of `ips/engine/engine.py:584-593`.
- **Impact on results**: Silent memory corruption or wrong feature extraction if kernel and user-space binaries diverge.
- **Proposed fix**: In `_ringbuf_cb`, add `if ev_struct.schema_version != SCHEMA_VERSION: raise RuntimeError(...)`.

### [DEF-05] `evaluate_run_metrics()` in `ips/eval/harness.py` Has Zero Unit Test Coverage
- **Severity**: `MAJOR`
- **Work Package**: WP7 / Test Quality
- **Location**: `ips/eval/harness.py:175-225`
- **What is wrong**: The primary run evaluation function `evaluate_run_metrics()`—which computes TPR, FPR, precision, F1, and confusion matrices for the measurement harness—is never called by any unit test in `tests/test_engine_closed_loop.py` or elsewhere. Mutation M15 (corrupting the FPR denominator to `fp / (tp + fn)`) survived undetected.
- **How verified**: Mutation testing runner execution (`audit/mutation_results.md`).
- **Impact on results**: Critical evaluation metrics could harbor calculation bugs without failing the test suite.
- **Proposed fix**: Add a dedicated unit test in `tests/test_engine_closed_loop.py` verifying `evaluate_run_metrics()` on a known confusion matrix.

### [DEF-06] Weak Direction Assertion in Feature Extraction Golden Fixture Test
- **Severity**: `MINOR`
- **Work Package**: WP4 / Test Quality
- **Location**: `tests/test_features.py:65-95`
- **What is wrong**: Mutation M2 (flipping the upstream byte accumulation rule to `if dirs[i] == 1: bytes_up += sz`) survived all unit tests in `tests/test_features.py`. The golden fixture test checked size sequences and vector length but failed to assert exact asymmetric values for `bytes_up`, `bytes_down`, and `frac_upstream`.
- **How verified**: Mutation testing runner execution (`audit/mutation_results.md`).
- **Impact on results**: A bug in direction handling could silently slip through feature extraction tests.
- **Proposed fix**: In `tests/test_features.py`, add explicit assertions checking `vec[feat_names.index("bytes_up")]` and `vec[feat_names.index("bytes_down")]` against hand-calculated values.

### [DEF-07] Untested Split-Conformal Quantile Threshold Index
- **Severity**: `MINOR`
- **Work Package**: WP5 / Test Quality
- **Location**: `tests/test_models.py:170-190`
- **What is wrong**: Mutation M8 (off-by-one in the split-conformal order statistic index `k_1idx = ceil((n+1)(1-alpha)) + 1`) survived `test_split_conformal_regime_and_alpha_budget`. The test only asserted that `res["valid_regime"]` was True and `min_supported_alpha == 0.01`, but never asserted the exact quantile score value returned.
- **How verified**: Mutation testing runner execution (`audit/mutation_results.md`).
- **Impact on results**: An off-by-one index in conformal calibration would not be caught by unit tests.
- **Proposed fix**: Assert `res["threshold"] == pytest.approx(scores[k_1idx - 1])` in `test_split_conformal_regime_and_alpha_budget`.

### [DEF-08] Inaccurate Unit Test Count in Progress Documentation
- **Severity**: `MINOR`
- **Work Package**: WP0 / Documentation
- **Location**: `docs/PROGRESS.md:37`
- **What is wrong**: `docs/PROGRESS.md` line 37 claimed: *"Total V1 Unit Tests: 54 passed, 0 failed"*, citing `tests/test_reproduce.py: 3 passed`. In reality, `tests/test_reproduce.py` contains exactly 2 test functions (`test_reproduce_rejects_smoke_data` and `test_generate_results_md_truthful_when_no_real_data`). The actual total collected and executed by pytest is 53 tests.
- **How verified**: `python -m pytest --collect-only -q` reports: *"53 tests collected"*.
- **Impact on results**: Minor documentation honesty discrepancy.
- **Proposed fix**: Update `docs/PROGRESS.md` line 37 to reflect 53 tests passed.

### [DEF-09] Discrepancy in Device IP Documentation vs Configuration
- **Severity**: `MINOR`
- **Work Package**: WP0 / WP1 / Documentation
- **Location**: `docs/PROGRESS.md:15`, `configs/devices.yaml:15-90`
- **What is wrong**: `docs/PROGRESS.md` stated device IPs were allocated in range `10.0.1.11–10.0.1.22` with attacker at `10.0.1.100`. In `configs/devices.yaml` and `scripts/topology.sh`, device IPs are `10.0.1.10–10.0.1.41` (e.g. sensor-01 is 10.0.1.10, plug-01 is 10.0.1.20, therm-01 is 10.0.1.30, cam-01 is 10.0.1.40), attacker is `10.0.1.4`, and server is `10.0.2.10`.
- **How verified**: Execution of `audit/check_netns_refs.py`.
- **Impact on claims**: Documentation mismatch; scripts and configs agree with each other, but progress notes had conflicting IP strings.
- **Proposed fix**: Update `docs/PROGRESS.md` line 15 to reflect exact IP assignments.

---

## 4. Claim Ledger and Alignment Analysis

### 4.1 Title Terms Alignment

| Term in Working Title | Implemented Code | Test / Experiment | Audit Verdict | Empirical Reality & Grounding |
|---|---|---|---|---|
| **Drift-Resilient** | `ips/drift/guard.py`, `ips/drift/periodicity.py`, `ips/drift/scenarios.py` | `tests/test_drift_guard.py` (4 tests) | `SMOKE-ONLY` | Guard logic (G1–G4, bounded step, rollback) is fully implemented and tested on synthetic streams. Natural multi-week drift on CESNET (`B5`) is code-complete but pending real download. |
| **On-Device** | None | None | **CONTRADICTED** | **Not supported.** Evaluated solely via laptop network namespaces and Linux veth bridges. Resource constraints apply only to user-space Python via cgroups. Zero embedded hardware tested. |
| **Inline** | `ebpf/ips_engine.c:317-332` | `scripts/xdp_selftest.sh`, `tests/test_engine_closed_loop.py` | `UNVERIFIABLE HERE` | Kernel fast path implements `XDP_DROP` in `verdict_map`. Mocked unit tests verify packet dropping, but live kernel enforcement requires Linux root + BCC. |
| **Intrusion Prevention** | `ebpf/ips_engine.c`, `ips/engine/engine.py` | `tests/test_engine_closed_loop.py` | `PARTIAL` | Active prevention implemented; drops flows based on autoencoder reconstruction error. Evaluated only against synthetic smoke attacks on host. |
| **Encrypted Traffic** | `ips/features.py`, `traffic/benign_iot_generator.py` | `tests/test_dataset_adapters.py:test_tls_handshake_detector` | `SUPPORTED (testbed & offline)` | Strictly payload-independent features (sizes, directions, IATs). Testbed uses real TLS 1.2/1.3. Evaluation on real public TLS C2 (`TQH-C2`) awaits pcap download. |
| **Resource-Constrained** | `configs/system.yaml` (profiles S, M, L) | `ips/eval/harness.py` | `PARTIAL` | Profiles defined for `systemd-run` cgroups on user-space engine. eBPF/XDP kernel execution is unconstrained. |
| **Smart Systems** | `traffic/benign_iot_generator.py`, `configs/devices.yaml` | `tests/test_generator.py` (5 tests) | `SUPPORTED (simulated)` | 12 simulated IoT devices across 4 classes (sensor, plug, thermostat, camera) running real MQTT-over-TLS (8883) and HTTPS POST uploads. |
| **Zero-Day Attacks** | `ips/data/build_splits.py`, `ips/eval/cross_domain.py` | `tests/test_splits_and_joins.py` | `SUPPORTED (methodology)` | Strict LOFO protocol: A3 (C2) and A4 (exfiltration) strictly held out from training, calibration, and tuning. Empirical numbers currently smoke-only. |

### 4.2 Research Gap Alignment
1. **Architectural Gap**: *Combining measured on-device footprint, active inline prevention, and payload-independent encrypted inspection.*  
   - *Status*: **Partially Closed in Code, Open in Measurement.** The two-tier architecture (`ebpf/ips_engine.c` fast path + `ips/engine/` slow path) and payload-independent features are built. However, active packet dropping and CPU/memory footprint have only been measured under Python mock simulation, not on physical gateway hardware.
2. **Functional Gap**: *Treating drift adaptation and zero-day detection jointly without permitting slow poisoning.*  
   - *Status*: **Closed in Code, Smoke-Only in Evaluation.** The poisoning-aware drift guard (G1 persistence, G2 quorum, G3 non-periodicity, G4 quarantine + anchor/canary validation) successfully prevents single-device boiling frog (S3) while allowing benign drift (S1) in synthetic tests. It honestly reports that coordinated class-wide poisoning (S4) defeats G2 when $\ge 60\%$ of devices are compromised.
3. **Contextual Gap**: *Encrypted IoT traffic where payloads are completely opaque.*  
   - *Status*: **Closed.** The system strictly uses IP header lengths, directions, and inter-arrival times, with an automated shortcut-learning guard prohibiting port and IP address features.

### 4.3 Contributions C1–C4 Ledger

| Claim ID | Paper Claim Description | Implementation File | Verification Test | Experiment Script | Current Status |
|---|---|---|---|---|---|
| **C1 (N7)** | Progressive multi-checkpoint early exit (`[4, 8, 16]`) improves TPR vs bytes-leaked Pareto frontier | `ebpf/ips_engine.c:401`, `ips/engine/engine.py:418`, `ips/models/train.py` | `test_multi_checkpoint_equivalence`, `test_progressive_checkpoints_early_drop_late_bypass` | `ips/models/eval_offline.py` | `SMOKE-ONLY` |
| **C2 (N3)** | Poisoning-aware drift guard adapts to benign drift while resisting boiling-frog poisoning | `ips/drift/guard.py`, `ips/drift/scenarios.py` | `tests/test_drift_guard.py` (4 tests) | `ips/drift/scenarios.py` | `SMOKE-ONLY` |
| **C3 (N8)** | Two-tier progressive + slow-C2 defense raises white-box adaptive attacker's cost-of-evasion floor | `ips/drift/evasion_cost.py` | `test_cost_of_evasion_and_cesnet_drift_c3_b5` | `ips/drift/evasion_cost.py` | `SMOKE-ONLY` |
| **C4 (N2+N6)**| Two-tier eBPF fast path + Tier-0 flood guard + watchdog bounds latency and loss under flood | `ebpf/ips_engine.c:334`, `ips/engine/watchdog.py`, `ips/eval/harness.py` | `test_watchdog_load_shedding_and_cooldown_recovery` | `scripts/verify_linux.sh` (S6, S9) | `UNVERIFIABLE HERE` / `SMOKE-ONLY` |

---

## 5. Test Quality and Tautology Findings

### 5.1 Mutation Testing Summary
As detailed in Section 3 and `audit/mutation_results.md`, 17 deliberate code mutations were tested against the test suite:
- **14 Mutations Killed (82.4%)**: The test suite effectively catches feature scaling changes, shortcut guard removal, split session leakage, attack flows in calibration, EVT formula sign flips, G2/G3 guard bypasses, observe mode violations, topology parser bugs, verdict TTL expiry bypasses, ctypes offset desync, and inverted CV formulas.
- **3 Mutations Survived (17.6%)**:
  1. **M2**: Flipping direction convention (`bytes_up` vs `bytes_down`) in `ips/features.py:103` survived `tests/test_features.py`.
  2. **M8**: Off-by-one in split-conformal quantile index in `ips/models/evt.py:67` survived `tests/test_models.py`.
  3. **M15**: Corrupting the FPR denominator in `ips/eval/harness.py:195` survived `tests/test_engine_closed_loop.py` because `evaluate_run_metrics()` is never tested.

### 5.2 Tautology Check (Expected Values Computed by Code Under Test)
- **Tautological Test Detected**: `tests/test_models.py::test_train_and_eval_pipeline_smoke`
  - *Finding*: This test executes `train_pipeline()` on synthetic smoke data and asserts that output CSV files exist and `metrics["source"] == "synthetic-smoke"`. It does not compare accuracy, loss, or thresholds against an independently calculated ground truth. It proves only that the pipeline runs to completion without crashing.
- **Tautological Test Detected**: `tests/test_engine_closed_loop.py::test_attack_leakage_and_bootstrap_ci` (Line 147–150)
  - *Finding*: `assert lo <= mean_v <= hi` asserts that the bootstrap confidence interval contains the sample mean, which is true by definition for symmetric bootstrap percentiles on small monotonic lists. It does not test the quantitative correctness of the confidence bounds.
- **Non-Tautological, Independently Verified Tests**:
  - `tests/test_models.py::test_clopper_pearson_rule_of_three`: Explicitly checks Clopper-Pearson bound against the analytic rule of three ($3/3000 = 0.001$).
  - `audit/check_canonical_key.py`: Tests 10 boundary cases across C, Python, and offline code against pre-calculated network-byte-order vs host-order expectations.
  - `tests/test_features.py::test_shortcut_guard`: Strictly verifies that forbidden feature names raise `ValueError`.

---

## 6. Unverified Linux-Only Items & Verification Protocol

The following items cannot run on Windows and require a Linux virtual machine (Ubuntu 22.04 or 24.04 with kernel >= 5.15 and `python3-bpfcc`):

| Component / Stage | VM Verification Command | Expected PASS Output | Expected FAIL Symptom |
|---|---|---|---|
| **S0: Kernel & BCC Environment** | `bash scripts/verify_linux.sh` (Stage S0) | `[PASS] Stage 0: Linux kernel, BCC, and toolchain sanity check` | `BCC not found` or kernel header compile error |
| **S2: Topology Creation** | `sudo ./scripts/topology.sh create` | `Created 15 network namespaces; br-lan and br-wan active` | `parse_devices` returns 0 devices; namespace collision |
| **S3: TLS Services Startup** | `ip netns exec srv netstat -tlpn` | Listening on `10.0.2.10:8883` (mosquitto) and `10.0.2.10:8443` | `Connection refused` or SSL certificate error |
| **S4: Testbed Traffic Flow** | `ip netns exec sensor-01 ping -c 1 10.0.2.10` | `1 packets transmitted, 1 received, 0% packet loss` | Network unreachable; bridge routing broken |
| **S6: eBPF Fast Path Attachment** | `sudo ./scripts/xdp_selftest.sh` | `[PASS] XDP selftest: both ports attached, verdict DROP enforced` | Clang compilation failure; verifier rejection |
| **S6b: Struct Size & ABI Match** | `bash scripts/check_struct_sizes.sh` | `PASS: C struct sizes and Python ctypes struct sizes match identically` | `FAIL: Struct size mismatch detected` |
| **S8b: Network Impairment Sweep** | `sudo bash scripts/netem_sweep.sh` | `Netem sweep complete: delay, jitter, loss tables generated` | `tc: command not found` or missing netem kernel module |
| **S9: Watchdog Load Shedding** | `sudo python3 -m ips.eval.harness --flood-test` | `Watchdog engaged: shed=1 under flood, recovered to shed=0` | Kernel packet drop; engine crash; watchdog freeze |

---

## 7. Seed List Status

| # | Seed Finding | Status | Evidence in Working Tree |
|---|---|---|---|
| 1 | `topology.sh` created zero namespaces (trimmed-line parser bug) | **CODE WRITTEN, NOT COMPILED, NOT RUN (V2)**; V1 parser PASS | `scripts/topology.sh:41` uses `${line#"${line%%[![:space:]]*}"}`. V1 regex/list check verified by `tests/test_topology_parse.py`; Linux netns creation not run here. |
| 2 | `demo.sh`, `baseline.sh`, `monitor.sh` referenced removed `iot1`/`iot2` | **CODE WRITTEN, NOT COMPILED, NOT RUN (V2)**; V1 grep PASS | `audit/check_netns_refs.py` confirms 0 references to `iot1`/`iot2` across all shell scripts; live scripts require Linux. |
| 3 | Shell scripts were mode 100644 (not executable) | **FIXED (V1)** | All 21 shell scripts are mode `100755` in git index. Verified by `tests/test_shell_permissions.py`. |
| 4 | `download_tqh_c2.sh` exited at once (`cd` before `mkdir`) | **CODE WRITTEN, NOT RUN (V2/V3)** | `datasets/download_tqh_c2.sh:17` runs `mkdir -p raw/tqh_c2` before `cd`. Live download not run here. |
| 5 | `pcap_to_flows.py` dropped flow key, overwrote 5-tuples, used captured bytes | **FIXED (V1)** | `ips/offline/pcap_to_flows.py` computes payload from IP header, tracks instances on FIN/RST/new-SYN, preserves metadata. |
| 6 | MQTT/mosquitto never started; fleet used raw TLS echo; cameras no HTTPS | **CODE WRITTEN, NOT COMPILED, NOT RUN (V2)**; V1 client PASS | `traffic/benign_iot_generator.py` uses `paho-mqtt` on 8883 and HTTPS POST on 8443; services launched by `collect.sh` (Linux V2 not run here). |
| 7 | `run_experiment.sh` ignored YAML, killed sudo instead of child process | **CODE WRITTEN, NOT COMPILED, NOT RUN (V2)** | `scripts/run_experiment.sh` parses scenario phases, uses `setsid` and `kill -TERM -- -$PGID` (Linux V2 not run here). |
| 8 | Adapters used guessed column names and secondary schema | **FIXED (V1)** | Unified `3N+8` feature schema + `METADATA_COLUMNS` across all adapters with `UNVERIFIED SCHEMA` warnings. |
| 9 | `PROGRESS.md` showed false ✅ for WP2/WP4 and MQTT | **FIXED (V1)** | Statuses downgraded to `PARTIAL (V1 model PASS; V2 CODE WRITTEN, NOT COMPILED, NOT RUN (V2))`. |
| 10 | Smoke CSV committed; smoke generator unseeded | **FIXED (V1)** | `ips/smoke/synth.py` uses deterministic RNG seed (42); `results/smoke/` added to `.gitignore`. |
| 11 | Downloaded dataset note labelled Mirai capture as benign | **FIXED (V1)** | `datasets/adapters/iot23_adapter.py:46-55` explicitly raises `ValueError` if `CTU-IoT-Malware-Capture-7-1` is loaded as benign. |

---

## 8. Prioritised Fix Plan

1. **[FIX-01] Title & Claim Realignment (Effort: S)**
   - *Target*: `README.md`, `docs/spec.md`, `docs/PAPER_OUTLINE.md`
   - *Action*: Remove "On-Device" from paper title; replace with "on an Emulated Resource-Constrained Gateway".
2. **[FIX-02] Document Multi-Core Concurrency Limitation (Effort: S)**
   - *Target*: `docs/LIMITATIONS.md`
   - *Action*: Add Section 1.3 explaining non-atomic flow state updates in generic XDP across virtual interfaces.
3. **[FIX-03] Enforce Schema Version Validation on Ring Buffer Events (Effort: S)**
   - *Target*: `ips/engine/engine.py:585`
   - *Action*: Add runtime check: `if ev_struct.schema_version != SCHEMA_VERSION: raise RuntimeError(...)`.
4. **[FIX-04] Add Unit Test for `evaluate_run_metrics()` (Effort: S)**
   - *Target*: `tests/test_engine_closed_loop.py`
   - *Action*: Add test function verifying TPR, FPR, precision, and F1 calculations against a fixed 2x2 confusion matrix.
5. **[FIX-05] Tighten Golden Fixture Direction Assertions (Effort: S)**
   - *Target*: `tests/test_features.py`
   - *Action*: Assert exact asymmetric values for `bytes_up` and `bytes_down` to ensure mutation M2 is killed.
6. **[FIX-06] Tighten Split-Conformal Quantile Assertion (Effort: S)**
   - *Target*: `tests/test_models.py`
   - *Action*: Assert exact threshold value `res["threshold"] == sorted_scores[k_1idx - 1]` to ensure mutation M8 is killed.
7. **[FIX-07] Handle TCP FIN/RST Flow State Eviction in Kernel (Effort: M)**
   - *Target*: `ebpf/ips_engine.c`
   - *Action*: Reset flow state or delete record upon connection termination to avoid 5-tuple collision blinding.
8. **[FIX-08] Run End-to-End Real Traffic Verification in Linux VM (Effort: L)**
   - *Target*: Linux VM environment
   - *Action*: Execute `sudo bash scripts/verify_linux.sh` and `sudo bash scripts/collect.sh` to obtain real traffic numbers.

---

## 9. Wording Corrections (Laptop Simulation Decision)

In adherence to Section 1 of Prompt 4, the following occurrences of forbidden or overclaimed hardware phrasing must be updated:

| File | Line | Current Wording | Required Honest Replacement |
|---|---|---|---|
| `README.md` | 1 | `# Drift-Resilient On-Device Inline Intrusion Prevention...` | `# Drift-Resilient Inline Intrusion Prevention for Encrypted IoT Traffic on an Emulated Resource-Constrained Gateway...` |
| `README.md` | 42 | `- Raspberry Pi / real device validation (remaining 40%)` | `- Physical embedded hardware validation (e.g. Raspberry Pi / OpenWrt router) (remaining 40%)` |
| `docs/spec.md` | 1 | `# System Specification: Drift-Resilient On-Device Inline IPS` | `# System Specification: Drift-Resilient Inline IPS on an Emulated Resource-Constrained Gateway` |
| `docs/spec.md` | 22 | `Mid-tier residential gateway (e.g. Raspberry Pi 4)` | `Mid-tier residential gateway analogue (cgroup emulation: 50% CPU, 512MB RAM)` |
| `docs/PAPER_OUTLINE.md` | 3 | `**Working Title**: *Drift-Resilient On-Device Inline...*` | `**Working Title**: *Drift-Resilient Inline Intrusion Prevention for Encrypted IoT Traffic on an Emulated Resource-Constrained Gateway...*` |
| `traffic/attack_beacon.py` | 79 | `print(f"  Interception Efficiency : ...")` | `print(f"  Connection Timeout Rate (Not Verified Inline Drop) : ...")` |
| `docs/PROGRESS.md` | 15 | `12 distinct IoT namespaces 10.0.1.11–10.0.1.22, attacker 10.0.1.100` | `12 distinct IoT namespaces 10.0.1.10–10.0.1.41, attacker 10.0.1.4` |
| `docs/PROGRESS.md` | 37 | `Total V1 Unit Tests: 54 passed, 0 failed` | `Total V1 Unit Tests: 53 passed, 0 failed` |

---

## 10. Remediation Status (Prompt 5 & Prompt 6 Implementation)

All findings from the adversarial audit (`54b5f81`) and Prompt 5/6 inspections have been addressed on branch `wp0-fix-30pct`. Note: C kernel code (`ebpf/ips_engine.c`) and Linux testbed scripts were NOT compiled and NOT executed in this session (no C compiler or Linux root/BCC on Windows host).

| Defect / Item ID | Category | Status | Commit | Proving Test / Verification Artefact | Summary of Fix & Verification |
|---|---|---|---|---|---|
| **DEF-01** | Scope Realignment | **FIXED (V1)** | `c47fafb`, Current | `audit/check_claims.py` (0 forbidden phrases, exact title consistency) | Exact paper title restored across `README.md`, `docs/spec.md`, and `docs/PAPER_OUTLINE.md` per R4 with prominent Scope note; defined Profiles S & M cgroup envelopes. |
| **DEF-02** | Kernel Concurrency | **CODE WRITTEN, NOT COMPILED, NOT RUN (V2); LIMITATION** | `42e4c0a`, `c47fafb` | Stage `S6d` in `scripts/verify_linux.sh`, `docs/LIMITATIONS.md` §6 | Disclosed non-atomic flow record update across generic XDP veth interfaces on multi-CPU systems; added RPS single-CPU pinning stage `S6d` to Linux harness. |
| **DEF-03** | Flow Lifecycle Reset | **CODE WRITTEN, NOT COMPILED, NOT RUN (V2); V1 model PASS** | `42e4c0a` | `tests/test_schema_and_equivalence.py::test_flow_record_lifecycle_and_reinit_a1` | Added `last_seen_ns`, `FLOW_IDLE_NS` (120s), and TCP FIN/RST reset in `ebpf/ips_engine.c` (uncompiled V2) and Python `MockBPFBackend` (V1 PASS). |
| **DEF-04** | Ringbuf Parser Panic | **FIXED (V1)** | `3a4206f` | `tests/test_engine_closed_loop.py::test_ringbuf_malformed_event_and_schema_mismatch_b1` | Added ctypes buffer length check, `SCHEMA_VERSION 4` validation, and fail-open load shedding after 10 corrupt events in `ips/engine/engine.py`. |
| **DEF-05** | Decision Metrics Untested | **FIXED (V1)** | `3a4206f` | `tests/test_engine_closed_loop.py::test_confusion_matrix_and_decision_metrics_b2` | Added unit test with fixed 2x2 confusion matrix (TP=10, FP=2, FN=3, TN=85; TPR=10/13, FPR=2/87, F1=0.8000) and zero-division guards. Killed mutation M15. |
| **DEF-06** | Direction Feature Untested | **FIXED (V1)** | `3a4206f` | `tests/test_features.py::test_direction_asymmetry_and_frac_upstream_b3` | Added test with asymmetric packet counts (500 up / 1500 down -> `frac_upstream=0.25`, reverse yields 0.75). Killed mutation M2. |
| **DEF-07** | Conformal Quantile Untested | **FIXED (V1)** | `3a4206f` | `tests/test_models.py::test_split_conformal_regime_and_alpha_budget` | Added finite-sample exact order statistic test for $n=99, \alpha=0.1$ (`order_stat_idx=90`, `threshold=0.90`). Killed mutation M8. |
| **DEF-08** | Progress & Subnet Inconsistency | **FIXED (V1)** | `c47fafb`, Current | `tests/test_shell_permissions.py`, `docs/PROGRESS.md` | Corrected unit test count to exact 68 passed, updated IP ranges to `10.0.1.10–10.0.1.41`, and realigned honest V1/V2/V3 status tracking. |
| **A1** | Flow Record Eviction | **CODE WRITTEN, NOT COMPILED, NOT RUN (V2); V1 model PASS** | `42e4c0a` | `tests/test_schema_and_equivalence.py::test_flow_record_lifecycle_and_reinit_a1` | `ebpf/ips_engine.c` flow lifecycle reset on FIN/RST or elapsed idle timeout > 120s (C not compiled here; V1 Python model PASS). |
| **A2** | Ringbuf Checkpoint Drop & `emitted_mask` | **CODE WRITTEN, NOT COMPILED, NOT RUN (V2); V1 model + source-guard PASS** | `42e4c0a`, Current | `tests/test_kernel_source_invariants.py`, `test_40_packet_flow_exact_3_checkpoints_no_event_storm_1c` | Restored `rec->emitted_mask |= (__u8)(1U << ckpt_hit);` after `ringbuf_submit` in `ebpf/ips_engine.c` (uncompiled V2); V1 source-text invariant and 40-pkt C-mirror model PASS. |
| **A3** | Multi-CPU Flow Race | **CODE WRITTEN, NOT COMPILED, NOT RUN (V2); LIMITATION** | `42e4c0a`, `c47fafb` | Stage `S6d` in `scripts/verify_linux.sh`, `docs/LIMITATIONS.md` §6 | Disclosed generic XDP limitation; added single-CPU RPS validation stage to `verify_linux.sh`. |
| **A4** | Canonical Key Kernel Drop | **CODE WRITTEN, NOT COMPILED, NOT RUN (V2); V1 model PASS** | `42e4c0a`, Current | Stage `S6e` (V2 kernel) & `S6e-model` (Python model) in `scripts/verify_linux.sh` | Implemented real kernel `verdict_map` drop & `pkts_dropped_verdict` counter assertion in `stage_S6e` (V2 not run); renamed Python check to `S6e-model`. |
| **A5** | Per-Class Protocol & TLS Services | **CODE WRITTEN, NOT COMPILED, NOT RUN (V2); V1 config PASS** | `42e4c0a` | `tests/test_shell_permissions.py::test_per_class_protocols_and_tls_contexts` | Per-class MQTT/HTTPS generators verified in V1; live `mosquitto`/`https_server.py` in `collect.sh` require Linux V2. |
| **B1** | Ringbuffer Event Parser Panic | **FIXED (V1)** | `3a4206f` | `tests/test_engine_closed_loop.py::test_ringbuf_malformed_event_and_schema_mismatch_b1` | Implemented bounds validation, schema mismatch counter, and fail-open engine shedding. |
| **B2** | Decision Metric Unit Tests | **FIXED (V1)** | `3a4206f` | `tests/test_engine_closed_loop.py::test_confusion_matrix_and_decision_metrics_b2` | Non-tautological test on fixed 2x2 confusion matrix; killed mutation M15. |
| **B3** | Direction Asymmetry Unit Tests | **FIXED (V1)** | `3a4206f` | `tests/test_features.py::test_direction_asymmetry_and_frac_upstream_b3` | Asymmetric upstream/downstream packet size and count assertions; killed mutation M2. |
| **B4** | Conformal Quantile Exactness | **FIXED (V1)** | `3a4206f` | `tests/test_models.py::test_split_conformal_regime_and_alpha_budget` | Verified finite-sample order statistic indexing; killed mutation M8. |
| **B5** | Autoencoder Separability & CI | **FIXED (V1)** | `3a4206f` | `tests/test_models.py::test_autoencoder_separates_synthetic_clusters`, `test_attack_leakage_and_bootstrap_ci` | AUROC $\ge 0.90$ on synthetic clusters; non-zero width and sample-size shrinkage in bootstrap CI. |
| **B6** | EVT Known-Answer Exponential Tail | **FIXED (V1)** | `3a4206f` | `tests/test_models.py::test_evt_known_answer_exponential_tail_b6` | Exponential(1) samples fitted with POT GPD, threshold verified against analytical $-\ln(10^{-3})$ within 1.18% error. |
| **B7** | Cross-Domain Leakage Isolation | **FIXED (V1)** | Current | `tests/test_cross_eval.py::test_iot23_tqh_c2_cross_domain_train_eval_isolation` | Tests real `ips/eval/cross_domain.py::evaluate_cross_domain_pair` on IoT-23/TQH-C2 stand-in with sentinel hook and train-only scaler statistics check. |
| **B8** | Wire Egress Pcap Reconciliation | **FIXED (V1)** | `3a4206f` | `tests/test_engine_closed_loop.py::test_leakage_reconciliation_against_egress_pcap_b8` | Reconciles engine decisions against wire-captured pcap packets, detecting wire vs engine miscounting. |
| **C1** | Masked Loss/Score over `< valid_len` | **FIXED (V1)** | `82c1950`, Current | `tests/test_models.py::test_short_flow_masked_padding_invariance_c1` | Implemented `build_valid_mask_matrix` in `ips/features.py`, `ips/models/autoencoder.py`, `ips/models/train.py`, and `ips/engine/engine.py`; short-flow score invariant to padding values. |
| **C2** | Non-Sticky Drop Verdict Bug | **FIXED (V1)** | `82c1950` | `tests/test_engine_closed_loop.py::test_sticky_drop_verdict_c2` | Invariant `DROP_STICKY`: early checkpoint DROP can never be overwritten by a subsequent BYPASS. |
| **C3** | Hardware Claims Repository Grep | **FIXED (V1)** | `82c1950`, `c47fafb`, Current | `audit/check_claims.py` (0 forbidden phrases, 0 title mismatches) | Complete inventory of 53 occurrences, replaced with cgroup emulation and explicit future-work designations; canonical title enforced across 3 docs. |
| **E1** | Full Test Suite & Linters | **VERIFIED (V1)** | Current | `python -m pytest -q` (68 passed), `test_shell_permissions.py` | Complete V1 test suite passing, zero python syntax errors. |
| **E2** | Mutation Testing Suite | **VERIFIED (V1)** | Current | `audit/mutation_results.md` (17/17 KILLED, 0 survived, 17/17 target found: yes) | Enforced single-occurrence target check, disk-diff assertion, and global baseline run; disclosed 8 invalid earlier mutants in `54b5f81`. |
| **E3** | Hardware & Title Claims Assertion | **VERIFIED (V1)** | Current | `audit/check_claims.py` (0 forbidden phrases, 0 title mismatches) | Verified zero unhedged hardware claims and identical canonical title across `README.md`, `docs/spec.md`, and `docs/PAPER_OUTLINE.md`. |
