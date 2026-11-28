# Known Issues & Bug Registry (`docs/KNOWN_ISSUES.md`)

> Maintained per Prompt 10 §1.5 & Rule R4. Every bug discovered during static analysis, consistency auditing, and property/fuzz testing is logged below with its severity, root cause, RED→GREEN regression test, and resolution status.

---

## 1. Fixed Bugs (Prompt 10 Phase 1 — RED → GREEN Verified)

| ID | Severity | File : Line | Root Cause | Fix Commit | Regression Test (`RED -> GREEN`) | Status |
|---|---|---|---|---|---|---|
| **BUG-01** | **High** | `ips/features.py:197-230`, `ips/eval/impairment.py:158-166` | `build_valid_mask_matrix` silently returned all-ones when feature dimension `!= 3N+8` or `valid_len` was invalid (`<0`, `>1`, `NaN`), failed to mask `vlen=0` empty vectors, and mis-masked the 29-column `no_size_features` ablation (`(29-8)%3 == 0` -> falsely inferred `early_n=7`). | `P10.1` | `tests/test_bugfixes_p10.py::test_bug01_build_valid_mask_raises_on_invalid_and_masks_zero_len` | **FIXED (V1)** |
| **BUG-02** | **Medium** | `ips/engine/engine.py:68-169` | `MockBPFBackend` used unbounded Python `dict`s for `flow_state` and `verdict_map` (ignoring `flow_map_max` / `verdict_map_max`) and omitted the Tier-0 per-source TCP SYN token bucket (`check_tier0_syn`). | `P10.1` | `tests/test_bugfixes_p10.py::test_bug02_mock_backend_lru_capacity_and_tier0_syn_bucket`, `tests/test_prop_engine_mock.py` | **FIXED (V1)** |
| **BUG-03** | **Medium** | `ips/smoke/synth.py:31-37, 189` | Hardcoded `DEVICE_IPS` (`10.0.1.11..14`, `thermostat-01`, `camera-01`) mismatched `configs/devices.yaml` (`10.0.1.10..13`, `therm-01`, `cam-01`), breaking per-class IP lookup in `IPSEngine`, and `generate_smoke_dataset` silently ignored `out_parquet`. | `P10.1` | `tests/test_bugfixes_p10.py::test_bug03_synth_matches_devices_yaml_and_writes_parquet` | **FIXED (V1)** |
| **BUG-04** | **Medium** | `ips/engine/engine.py:424-427, 500` | Nested `except Exception: pass` blocks in `_load_model_and_thresholds` hid corrupt `model_card.json` / ONNX load failures, and `_handle_schema_mismatch` discarded its `reason` string without logging. | `P10.1` | `tests/test_bugfixes_p10.py::test_bug04_engine_logs_corrupt_card_and_schema_mismatch_reason` | **FIXED (V1)** |
| **BUG-05** | **Medium** | `datasets/download_tqh_c2_win.py:50-66` | `download_resumable` passed unchecked URLs directly to `urllib.request.urlopen` (`Bandit B310`), permitting `file://` local file reads or plaintext `http://`. | `P10.1` | `tests/test_bugfixes_p10.py::test_bug05_downloader_rejects_non_https_schemes` | **FIXED (V1)** |
| **BUG-06** | **Medium** | `ebpf/ips_engine.c:21-76`, `ips/engine/schema.py` | Duplicate hand-maintained C `#define` constants in `ebpf/ips_engine.c` risked drift from `configs/system.yaml` during standalone C builds, and struct offsets were not checked by an automated C struct parser. | `P10.1` | `tests/test_bugfixes_p10.py::test_bug06_generated_constants_header_and_c_struct_parser_sync` | **FIXED (V1)** |
| **BUG-07** | **High** | `ebpf/ips_engine.c:200`, `ips/offline/pcap_to_flows.py:168-270` | Non-initial IPv4 fragments (`frag_off & 0x1FFF != 0`) carry no TCP/UDP header, yet both C fast path and offline pcap parser attempted L4 header parsing on fragment payload bytes; offline parser also lacked packet-conservation accounting. | `P10.1` | `tests/test_bugfixes_p10.py::test_bug07_pcap_fragment_guard_and_packet_conservation`, `tests/test_prop_pcap_to_flows.py` | **FIXED (V1; C fix V2-static)** |
| **BUG-08** | **Low** | `ips/models/train.py:345-352`, `docs/USER_TEST_GUIDE.md:95` | `USER_TEST_GUIDE.md` passed `--out-dir models` to `ips/models/train.py`, which lacked a `--model-dir` / `--out-dir` CLI argument. | `P10.1` | `tests/test_bugfixes_p10.py::test_bug08_train_cli_model_dir_and_seed_determinism` | **FIXED (V1)** |
| **BUG-09** | **Low** | `docs/USER_TEST_GUIDE.md:136`, `docs/VM_QUICKSTART.md:9` | `USER_TEST_GUIDE.md` passed `--out` instead of `--out-dir` to `ips.eval.cross_domain`, and `VM_QUICKSTART.md` listed WSL2 (unsupported for XDP) and undersized 30 GB disk. | `P10.1` | `audit/check_claims.py` | **FIXED (V1)** |
| **BUG-10** | **Medium** | `ips/eval/reproduce.py:77-156` | `generate_results_md` called `DataFrame.to_markdown(index=False)` when real CSVs existed, crashing with `ImportError: Missing optional dependency 'tabulate'` because `tabulate` was not in `requirements.txt`. Added pure-Python GFM fallback `_df_to_markdown`. | `P10.1` | `tests/test_coverage_core_p10.py::test_reproduce_b0_guard_and_populated_tables` | **FIXED (V1)** |

---

## 2. Previously Fixed Historical Regressions (Prompts 5, 6, 9 — Preserved for Traceability)

- **DEF-03 (`A1`)**: 5-tuple reuse & 120 s idle flow-state reset (`ebpf/ips_engine.c`, `ips/offline/pcap_to_flows.py`).
- **Prompt-6 Blocker**: `rec->emitted_mask |= (1U << ckpt_hit)` restored strictly after `events.ringbuf_submit(ev, 0)`.
- **P9.1**: Smoke ROC inversion (`score_onnx_model` unmasked padding + EVT calibrated on FP32 instead of INT8 ONNX).

---

## 3. Open Platform / Scope Issues (Cannot Be Resolved on Windows Without Linux Kernel / Hardware)

| ID | Severity | Scope | Description & Honest Status |
|---|---|---|---|
| **OPEN-V2-01** | **Blocker for Inline Claims** | `ebpf/ips_engine.c`, `BCCKernelBackend` | **Kernel program never loaded or executed on a Linux kernel yet (`V2`)**. Static C compilation, verifier-invariant AST checks, and CI compile jobs do NOT prove runtime verifier acceptance or live packet drop/bypass behavior until Prompt 7 runs inside an Ubuntu 22.04/24.04 VM. |
| **OPEN-V2-02** | **Architectural Limit** | `ebpf/ips_engine.c` (`flow_state`) | Multi-CPU race on bidirectional flows under Generic XDP if LAN and WAN packets of the same 5-tuple execute simultaneously on different vCPUs without RSS/RPS CPU steering (`docs/LIMITATIONS.md` §6). |
| **OPEN-V3-01** | **Scope Limit** | Hardware / Title (`TITLE_DECISION_PENDING`) | No physical resource-constrained IoT gateway (e.g., Raspberry Pi / OpenWrt router) has been measured; resource profiles are cgroup-emulated on x86_64 VM (Prompt 7) and formula-estimated in `docs/RESOURCE_MODEL.md`. |
