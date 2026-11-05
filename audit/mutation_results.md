# Adversarial Mutation Testing Audit (`audit/mutation_results.md`)

This audit applied 17 deliberate mutations (M1–M16) across critical code paths in `ips/` and `scripts/` to evaluate test suite sensitivity and detect weak or tautological assertions.

## Summary

- **Total Mutations Evaluated**: 17
- **KILLED (Caught by Tests)**: 14 (82.4%)
- **SURVIVED (Tests Weak or Missing)**: 3 (17.6%)
- **Baseline Test Suite Status**: 53 passed, 0 failed

---

## Detailed Mutation Results

| ID | Mutated File | Description | Result | Failing Test / Exception | Analysis & Weakness Identification |
|---|---|---|---|---|---|
| **M1** | `ips/offline/pcap_to_flows.py:234` | Count zero-payload packets (e.g. pure SYN/ACK) in early window (`payload_len >= 0`) | **KILLED** | `tests/test_features.py::test_pcap_to_flows_golden_fixture` | Caught: golden fixture asserts exact packet payload size sequence. |
| **M2** | `ips/features.py:103` | Flip direction convention (`if dirs[i] == 1: bytes_up += sz`) | **SURVIVED** | *None (All 6 tests in test_features.py passed)* | **WEAK TEST**: `test_pcap_to_flows_golden_fixture` checks sizes and vector length but does not assert asymmetric upstream vs downstream aggregate byte counts (`bytes_up`, `bytes_down`). |
| **M3** | `ips/features.py:79` | Change payload normalization constant (`/1500.0` -> `/1400.0`) | **KILLED** | `tests/test_features.py::test_pcap_to_flows_golden_fixture` | Caught: normalized float32 features differed from golden array. |
| **M4** | `ips/features.py:138` | Remove / neutralise forbidden-column shortcut guard | **KILLED** | `tests/test_features.py::test_shortcut_guard` | Caught: `test_shortcut_guard` specifically asserts `pytest.raises(ValueError)`. |
| **M5** | `ips/data/build_splits.py:62` | Disable session overlap assertion across splits | **KILLED** | `tests/test_splits_and_joins.py::test_split_integrity_assertions_a_b_c_d` | Caught: test passes identical session to train & cal, expecting ValueError. |
| **M6** | `ips/data/build_splits.py:73` | Allow attack flows into calibration split | **KILLED** | `tests/test_splits_and_joins.py::test_split_integrity_assertions_a_b_c_d` | Caught: test asserts ValueError when attack flows are present in calibration. |
| **M7** | `ips/models/evt.py:250` | Swap sign in EVT Generalized Pareto threshold (`t = u - (sigma/xi)*term`) | **KILLED** | `tests/test_models.py::test_evt_gpd_fitting_and_threshold` | Caught: asserts `res["threshold"] > res["u"]`. |
| **M8** | `ips/models/evt.py:67` | Off-by-one in split-conformal quantile index (`k_1idx = ... + 1`) | **SURVIVED** | *None (All 9 tests in test_models.py passed)* | **WEAK TEST**: `test_split_conformal_regime_and_alpha_budget` verifies `valid_regime` boolean and `min_supported_alpha` bound, but never asserts the exact conformal quantile threshold value returned. |
| **M9** | `ips/data/label_join.py:46` | Shift time window comparison in manifest label join | **KILLED** | `tests/test_splits_and_joins.py::test_label_join_manifest_and_engine_events` | Caught: attack-window boolean flag mismatch on joined flows. |
| **M10** | `ips/drift/guard.py:208` | Disable guard check G2 (force cross-device quorum to always pass) | **KILLED** | `tests/test_drift_guard.py::test_g2_small_class_limitation_and_rollback` | Caught: asserts `status == "REJECTED_G2_UNAVAILABLE_SMALL_CLASS"` on fleet size 2. |
| **M10b**| `ips/drift/guard.py:228` | Disable guard check G3 (force non-periodicity to always pass) | **KILLED** | `tests/test_drift_guard.py::test_periodicity_and_slow_c2_tracker` | Caught: asserts periodic C2 stream trips G3 guard. |
| **M11** | `ips/engine/engine.py:467` | Make `observe` mode write verdicts to BPF map (`mode in ("enforce", "observe")`) | **KILLED** | `tests/test_engine_closed_loop.py::test_observe_vs_enforce_and_explainability` | Caught: asserts `len(backend.verdict_map) == 0` in observe mode. |
| **M12** | `scripts/topology.sh:41` | Reintroduce trimmed-line parser bug in `parse_devices` | **KILLED** | `tests/test_topology_parse.py::test_topology_sh_list` | Caught: parser returns 0 devices instead of 12 devices. |
| **M13** | `ips/engine/engine.py:96` | Ignore TTL expiry in verdict cache logic (stale entries never expire) | **KILLED** | `tests/test_engine_closed_loop.py::test_enforce_per_flow_drop_and_ttl_expiry` | Caught: asserts expired verdict returns `VERDICT_NONE` and is deleted. |
| **M14** | `ips/engine/schema.py:221` | Change `checkpoint_idx` type from uint8 to uint32 in ctypes struct | **KILLED** | `tests/test_schema_and_equivalence.py::test_early_flow_event_roundtrip` | Caught: ctypes struct size and memory offset mismatch. |
| **M15** | `ips/eval/harness.py:195` | Corrupt FPR denominator in `evaluate_run_metrics` (`fp / (tp + fn)`) | **SURVIVED** | *None (All 7 tests in test_engine_closed_loop.py passed)* | **UNTESTED FUNCTION**: `evaluate_run_metrics()` in `ips/eval/harness.py` is never called by any unit test in `tests/`. Unit tests only exercise `compute_operational_harm_metrics()`, `compute_attack_leakage()`, and `compute_bootstrap_ci()`. |
| **M16** | `ips/drift/periodicity.py:53` | Invert Coefficient of Variation calculation (`mean / stdev`) | **KILLED** | `tests/test_drift_guard.py::test_periodicity_and_slow_c2_tracker` | Caught: CV threshold trips on synthetic jittered periodic series. |
