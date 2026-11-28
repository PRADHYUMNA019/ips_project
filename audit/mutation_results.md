# Mutation Testing Audit Results (`audit/mutation_results.md`)

**Summary**: Total: 28 | **KILLED**: 28 | **SURVIVED**: 0 | **BASELINE FAILS**: 0 | **INVALID**: 0

> **Historical Honesty Note (Prompt 6 §6)**: In commit `54b5f81` (Prompt 4 audit), **8 of the 17 mutants** (`M6, M7, M8, M9, M10, M10b, M15, M16`) had target strings that did not match the source files and were therefore invalid until `audit/mutation_runner.py` was updated with exact single-occurrence assertions and disk-diff verification.

| ID | File | Description | target found: yes/no | Result | Output / Failure Line | Test that Should Catch |
|---|---|---|---|---|---|---|
| M1 | `ips/offline/pcap_to_flows.py` | Count zero-payload packets (e.g. pure SYN/ACK) in early-flow window | yes | KILLED | `1 failed, 1 passed in 1.27s` | `tests/test_features.py::test_reused_5tuple_flow_instances_and_metadata` |
| M2 | `ips/features.py` | Flip direction convention (0 = client->server from LAN side) | yes | KILLED | `1 failed, 1 passed in 1.24s` | `tests/test_features.py::test_direction_asymmetry_and_frac_upstream_b3` |
| M3 | `ips/features.py` | Change normalization constant (/1500.0 -> /1400.0) | yes | KILLED | `1 failed in 1.40s` | `tests/test_features.py::test_pcap_to_flows_golden_fixture` |
| M4 | `ips/features.py` | Remove / neutralise forbidden-column shortcut guard | yes | KILLED | `1 failed in 1.16s` | `tests/test_features.py::test_shortcut_guard` |
| M5 | `ips/data/build_splits.py` | Disable assertion that sessions appear in only one split | yes | KILLED | `1 failed in 4.63s` | `tests/test_splits_and_joins.py::test_split_integrity_assertions_a_b_c_d` |
| M6 | `ips/data/build_splits.py` | Allow attack flows into calibration split | yes | KILLED | `1 failed in 5.83s` | `tests/test_splits_and_joins.py::test_split_integrity_assertions_a_b_c_d` |
| M7 | `ips/models/evt.py` | Swap sign in EVT Generalized Pareto threshold formula | yes | KILLED | `1 failed in 4.46s` | `tests/test_models.py::test_evt_gpd_fitting_and_threshold` |
| M8 | `ips/models/evt.py` | Off-by-one in split-conformal quantile index | yes | KILLED | `1 failed in 3.91s` | `tests/test_models.py::test_split_conformal_regime_and_alpha_budget` |
| M9 | `ips/data/label_join.py` | Shift time window comparison in manifest label join | yes | KILLED | `1 failed in 5.76s` | `tests/test_splits_and_joins.py::test_label_join_manifest_and_engine_events` |
| M10 | `ips/drift/guard.py` | Disable guard check G2 (force cross-device quorum to always pass) | yes | KILLED | `1 failed in 3.25s` | `tests/test_drift_guard.py::test_g2_quorum_and_g3_periodicity_checks` |
| M10b | `ips/drift/guard.py` | Disable guard check G3 (force non-periodicity to always pass) | yes | KILLED | `1 failed in 5.80s` | `tests/test_drift_guard.py::test_g2_quorum_and_g3_periodicity_checks` |
| M11 | `ips/engine/engine.py` | Make observe mode write verdicts to BPF map (violates observe contract) | yes | KILLED | `1 failed in 4.05s` | `tests/test_engine_closed_loop.py::test_observe_vs_enforce_and_explainability` |
| M12 | `scripts/topology.sh` | Reintroduce trimmed-line bug in topology.sh parse_devices | yes | KILLED | `1 failed in 0.41s` | `tests/test_topology_parse.py::test_topology_sh_source_syntax_and_trimming` |
| M13 | `ips/engine/engine.py` | Ignore TTL expiry in verdict cache logic (stale entries never expire) | yes | KILLED | `1 failed in 4.10s` | `tests/test_engine_closed_loop.py::test_enforce_per_flow_drop_and_ttl_expiry` |
| M14 | `ips/engine/schema.py` | Change checkpoint_idx type from uint8 to uint32 in ctypes struct | yes | KILLED | `1 failed, 1 passed in 1.29s` | `tests/test_schema_and_equivalence.py::test_c_header_and_ctypes_sync_across_early_n` |
| M15 | `ips/eval/harness.py` | Corrupt FPR denominator (fp/(tp+fn) instead of fp/(fp+tn)) | yes | KILLED | `1 failed, 1 passed in 7.06s` | `tests/test_engine_closed_loop.py::test_confusion_matrix_and_decision_metrics_b2` |
| M16 | `ips/drift/periodicity.py` | Invert Coefficient of Variation calculation (mean/std instead of std/mean) | yes | KILLED | `1 failed in 3.29s` | `tests/test_drift_guard.py::test_periodicity_and_slow_c2_tracker` |
| M17 | `ips/features.py` | Remove per-packet log-IAT /7.0 normalisation and [0, 1.5] clip | yes | KILLED | `1 failed in 1.34s` | `tests/test_features.py::test_feature_group_ranges_and_no_iat_dominance_p9_2c` |
| M18 | `ips/engine/schema.py` | Desynchronize SCHEMA_VERSION in C header generator vs ebpf/generated_constants.h | yes | KILLED | `1 failed in 3.45s` | `tests/test_bugfixes_p10.py::test_bug06_generated_constants_header_and_c_struct_parser_sync` |
| M19 | `ips/engine/schema.py` | Break canonical bidirectional FlowKey symmetry (A->B != B->A) | yes | KILLED | `1 failed in 2.70s` | `tests/test_prop_flow_key.py::test_prop_flow_key_symmetry_stability_and_c_byte_equivalence` |
| M20 | `ips/features.py` | Reintroduce silent all-ones mask fallback on invalid feature dimensions | yes | KILLED | `1 failed in 3.69s` | `tests/test_bugfixes_p10.py::test_bug01_build_valid_mask_raises_on_invalid_and_masks_zero_len` |
| M21 | `ips/features.py` | Remove [0, 1.5] scaling/clipping on aggregate mean_log_iat | yes | KILLED | `1 failed in 2.76s` | `tests/test_prop_features.py::test_prop_feature_vector_bounds_finiteness_and_mask` |
| M22 | `ips/offline/pcap_to_flows.py` | Remove kernel-matching flow_idle_s timeout rule in pcap_to_flows | yes | KILLED | `1 failed in 1.39s` | `tests/test_features.py::test_offline_extractor_idle_timeout_and_syn_lifecycle_p9_3b` |
| M23 | `ips/offline/pcap_to_flows.py` | Disable non-initial IPv4 fragment guard in pcap_to_flows | yes | KILLED | `1 failed in 7.29s` | `tests/test_bugfixes_p10.py::test_bug07_pcap_fragment_guard_and_packet_conservation` |
| M24 | `ips/engine/engine.py` | Corrupt drop_ttl_ns sign/unit in IPSEngine | yes | KILLED | `1 failed, 1 passed in 10.11s` | `tests/test_prop_engine_mock.py::test_prop_engine_invariants_under_random_streams` |
| M25 | `ips/engine/engine.py` | Disable flow_map_max LRU eviction in MockBPFBackend | yes | KILLED | `1 failed in 6.99s` | `tests/test_prop_engine_mock.py::test_prop_engine_invariants_under_random_streams` |
| M26 | `ips/drift/guard.py` | Violate bounded-step threshold update invariant in PoisoningAwareDriftGuard | yes | KILLED | `1 failed in 6.35s` | `tests/test_prop_drift_guard.py::test_prop_drift_guard_bounded_step_and_exact_rollback` |
| M27 | `ips/models/evt.py` | Invert order-statistic index in split-conformal quantile (violating alpha monotonicity) | yes | KILLED | `1 failed in 11.75s` | `tests/test_prop_thresholds.py::test_prop_evt_finiteness_conformal_monotonicity_and_3sigma` |
