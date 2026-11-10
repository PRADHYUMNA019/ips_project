# Mutation Testing Audit Results (`audit/mutation_results.md`)

**Summary**: Total: 17 | **KILLED**: 17 | **SURVIVED**: 0 | **BASELINE FAILS**: 0 | **INVALID**: 0

> **Historical Honesty Note (Prompt 6 §6)**: In commit `54b5f81` (Prompt 4 audit), **8 of the 17 mutants** (`M6, M7, M8, M9, M10, M10b, M15, M16`) had target strings that did not match the source files and were therefore invalid until `audit/mutation_runner.py` was updated with exact single-occurrence assertions and disk-diff verification.

| ID | File | Description | target found: yes/no | Result | Output / Failure Line | Test that Should Catch |
|---|---|---|---|---|---|---|
| M1 | `ips/offline/pcap_to_flows.py` | Count zero-payload packets (e.g. pure SYN/ACK) in early-flow window | yes | KILLED | `1 failed, 1 passed in 1.33s` | `tests/test_features.py::test_reused_5tuple_flow_instances_and_metadata` |
| M2 | `ips/features.py` | Flip direction convention (0 = client->server from LAN side) | yes | KILLED | `1 failed, 1 passed in 1.04s` | `tests/test_features.py::test_direction_asymmetry_and_frac_upstream_b3` |
| M3 | `ips/features.py` | Change normalization constant (/1500.0 -> /1400.0) | yes | KILLED | `1 failed in 1.02s` | `tests/test_features.py::test_pcap_to_flows_golden_fixture` |
| M4 | `ips/features.py` | Remove / neutralise forbidden-column shortcut guard | yes | KILLED | `1 failed in 1.32s` | `tests/test_features.py::test_shortcut_guard` |
| M5 | `ips/data/build_splits.py` | Disable assertion that sessions appear in only one split | yes | KILLED | `1 failed in 5.16s` | `tests/test_splits_and_joins.py::test_split_integrity_assertions_a_b_c_d` |
| M6 | `ips/data/build_splits.py` | Allow attack flows into calibration split | yes | KILLED | `1 failed in 6.88s` | `tests/test_splits_and_joins.py::test_split_integrity_assertions_a_b_c_d` |
| M7 | `ips/models/evt.py` | Swap sign in EVT Generalized Pareto threshold formula | yes | KILLED | `1 failed in 3.87s` | `tests/test_models.py::test_evt_gpd_fitting_and_threshold` |
| M8 | `ips/models/evt.py` | Off-by-one in split-conformal quantile index | yes | KILLED | `1 failed in 4.34s` | `tests/test_models.py::test_split_conformal_regime_and_alpha_budget` |
| M9 | `ips/data/label_join.py` | Shift time window comparison in manifest label join | yes | KILLED | `1 failed in 5.43s` | `tests/test_splits_and_joins.py::test_label_join_manifest_and_engine_events` |
| M10 | `ips/drift/guard.py` | Disable guard check G2 (force cross-device quorum to always pass) | yes | KILLED | `1 failed in 3.41s` | `tests/test_drift_guard.py::test_g2_quorum_and_g3_periodicity_checks` |
| M10b | `ips/drift/guard.py` | Disable guard check G3 (force non-periodicity to always pass) | yes | KILLED | `1 failed in 3.12s` | `tests/test_drift_guard.py::test_g2_quorum_and_g3_periodicity_checks` |
| M11 | `ips/engine/engine.py` | Make observe mode write verdicts to BPF map (violates observe contract) | yes | KILLED | `1 failed in 4.45s` | `tests/test_engine_closed_loop.py::test_observe_vs_enforce_and_explainability` |
| M12 | `scripts/topology.sh` | Reintroduce trimmed-line bug in topology.sh parse_devices | yes | KILLED | `1 failed in 0.11s` | `tests/test_topology_parse.py::test_topology_sh_source_syntax_and_trimming` |
| M13 | `ips/engine/engine.py` | Ignore TTL expiry in verdict cache logic (stale entries never expire) | yes | KILLED | `1 failed in 4.56s` | `tests/test_engine_closed_loop.py::test_enforce_per_flow_drop_and_ttl_expiry` |
| M14 | `ips/engine/schema.py` | Change checkpoint_idx type from uint8 to uint32 in ctypes struct | yes | KILLED | `1 failed, 1 passed in 1.03s` | `tests/test_schema_and_equivalence.py::test_c_header_and_ctypes_sync_across_early_n` |
| M15 | `ips/eval/harness.py` | Corrupt FPR denominator (fp/(tp+fn) instead of fp/(fp+tn)) | yes | KILLED | `1 failed, 1 passed in 8.43s` | `tests/test_engine_closed_loop.py::test_confusion_matrix_and_decision_metrics_b2` |
| M16 | `ips/drift/periodicity.py` | Invert Coefficient of Variation calculation (mean/std instead of std/mean) | yes | KILLED | `1 failed in 3.20s` | `tests/test_drift_guard.py::test_periodicity_and_slow_c2_tracker` |
