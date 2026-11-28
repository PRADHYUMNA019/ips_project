# Cross-Layer Consistency Audit (`docs/CONSISTENCY_AUDIT.md`)

> **Artefact Label**: `STATIC ANALYSIS + UNIT TEST (V1)`
> **Automated Verifiers**: `audit/check_claims.py`, `ips/engine/c_struct_parser.py`, `tests/test_bugfixes_p10.py`, `tests/test_schema_and_equivalence.py`.

---

## 1. Cross-Layer Consistency Audit Table

| Item | Locations Compared | Result Before Fix | Fix / Verification |
|---|---|---|---|
| **Shared C/Python Constants** (`SCHEMA_VERSION=4`, `checkpoints=[4,8,16]`, `NUM_CHECKPOINTS=3`, `EARLY_N=16`, `FLOW_MAP_MAX=4096`, `VERDICT_MAP_MAX=4096`, `FLOW_IDLE_NS=120s`, `TIER0_*`, `VERDICT_*`) | `configs/system.yaml` ↔ `ips/engine/schema.py` ↔ `ebpf/ips_engine.c` | **MISMATCH RISK (`BUG-06`)**: `ebpf/ips_engine.c` duplicated 14 `#ifndef ... #define` blocks by hand instead of including a generated header. | Added `write_generated_c_header()` generating `ebpf/generated_constants.h` and `#include "generated_constants.h"` in `ebpf/ips_engine.c`. Tested by `test_bug06` + `audit/check_claims.py` + mutant `M18`. |
| **Kernel ↔ User Struct Layout (`sizeof`, field offsets, 8B alignment, endianness)** | `ebpf/ips_engine.c` (`flow_key`, `verdict_entry`, `cfg_entry`, `stats_entry`, `early_flow_event`) ↔ `ips/engine/schema.py` (`ctypes.Structure`) | Previously checked against manual offset tuples only. | Built `ips/engine/c_struct_parser.py` to parse `ebpf/ips_engine.c` C structs + preprocessor `#if` padding and verify exact `sizeof` (`16, 16, 16, 72, 224` B at `N=16`), every field offset, and 8-byte alignment of all `u64` fields. **100% MATCH**. |
| **Device Fleet Registry (`device_id`, IPv4, `class`)** | `configs/devices.yaml` ↔ `ips/smoke/synth.py` ↔ `ips/engine/engine.py::_load_device_registry` ↔ `scripts/topology.sh` | **MISMATCH (`BUG-03`)**: `synth.py` used `10.0.1.11..14`, `thermostat-01`, `camera-01` while `devices.yaml` had `10.0.1.10..13`, `therm-01`, `cam-01`. | Refactored `ips/smoke/synth.py` to load canonical `device_id`, `ip`, and `class` directly from `configs/devices.yaml`. Verified by `test_bug03`. |
| **Feature Dimension & Masking (`3N + 8`, `FEATURE_SCHEMA_VERSION = 2`)** | `ips/features.py` ↔ `ips/models/autoencoder.py` ↔ `ips/models/quantize.py` ↔ `ips/eval/impairment.py` ↔ `docs/DATA_CARD.md` | **BUG (`BUG-01`) + STALE DOC**: `build_valid_mask_matrix` silently returned ones on invalid input and mis-masked 29-col `no_size_features` ablation; `DATA_CARD.md` listed unscaled `log10(1 + iat_us)`. | `build_valid_mask_matrix` now raises `ValueError` on invalid dims/`valid_len` and masks `vlen=0`; `EarlyFlowAutoencoder(apply_flow_mask=...)` disables flow masking on ablated sub-matrices; `DATA_CARD.md` updated to `/ 7.0` clipped to `[0, 1.5]`. |
| **IPv4 Fragmentation & Flow Idle Lifecycle (`flow_idle_s = 120`)** | `ebpf/ips_engine.c` ↔ `ips/offline/pcap_to_flows.py` ↔ `ips/eval/equivalence.py` ↔ `ips/engine/engine.py` | **BUG (`BUG-07`)**: Neither `ebpf/ips_engine.c` nor `pcap_to_flows.py` guarded against non-initial IPv4 fragments (`frag_off & 0x1FFF`), risking L4 port misparse. | Added `frag_off` / `ip.offset` fragment guards to both `ebpf/ips_engine.c` and `ips/offline/pcap_to_flows.py` + packet conservation counters (`df.attrs["packet_stats"]`). Verified by `test_bug07` and `tests/test_prop_pcap_to_flows.py`. |
| **Mock vs C Map Capacity & Tier-0 Token Bucket** | `ebpf/ips_engine.c` (`BPF_TABLE("lru_hash", ...)` + `check_tier0_syn`) ↔ `ips/engine/engine.py::MockBPFBackend` | **MISMATCH (`BUG-02`)**: `MockBPFBackend` had unbounded dicts and lacked `check_tier0_syn`. | Added `OrderedDict` LRU eviction (`flow_map_max`, `verdict_map_max`, `tier0_map_max`) and `check_tier0_syn` to `MockBPFBackend`. Verified by `test_bug02` & `tests/test_prop_engine_mock.py`. |
| **Docs vs CLI Flags & VM Specs (No WSL2)** | `docs/VM_QUICKSTART.md`, `docs/USER_TEST_GUIDE.md`, `docs/LIMITATIONS.md` ↔ `ips/models/train.py`, `ips/eval/cross_domain.py`, `configs/system.yaml` | **MISMATCHES (`BUG-08`, `BUG-09`, WSL2)**: `VM_QUICKSTART.md` recommended WSL2 and 30 GB disk; `USER_TEST_GUIDE.md` used `--out-dir` on `train.py` (missing flag) and `--out` on `cross_domain.py` (`--out-dir`); `LIMITATIONS.md` said `default N=12`. | Removed WSL2 and updated VM specs (`Ubuntu 22.04/24.04`, `>=100 GB` disk, `>=6 GB` RAM, `>=4` vCPUs, `kernel >=5.15`, no WSL2); added `--model-dir`/`--out-dir` to `train.py`; fixed `USER_TEST_GUIDE.md` & `LIMITATIONS.md`; enforced in `audit/check_claims.py`. |
| **Seeds & Byte-Identical Determinism** | `ips/smoke/synth.py`, `ips/models/train.py`, `ips/drift/evasion_cost.py`, `demo/run_smoke_pipeline.py` | Verified on smoke pipeline (`10/10` files identical); added fast unit test. | Verified via `test_bug08_train_cli_model_dir_and_seed_determinism` and `demo/run_smoke_pipeline.py --check-determinism`. |
| **Error Handling** | `ips/engine/engine.py`, `ips/features.py`, `datasets/download_tqh_c2_win.py` | Silent `except Exception: pass` in `engine.py` (`BUG-04`), unchecked URL scheme (`BUG-05`). | Replaced with structured `logger.warning` + `load_warnings`/`schema_mismatch_reasons` lists and HTTPS URL validation. |

---

## 2. Config Keys Audit (`configs/system.yaml` & `configs/devices.yaml`)

| Config Key | Value in YAML | Read By | Status |
|---|---|---|---|
| `system.checkpoints` | `[4, 8, 16]` | `ips/engine/schema.py`, `ips/engine/engine.py` | Active |
| `system.early_n` | `16` | `schema.py`, `engine.py`, `harness.py` | Active |
| `system.alpha_spending` | `equal` | `schema.py`, `engine.py` | Active |
| `system.flow_map_max` | `4096` | `schema.py` -> `FLOW_MAP_MAX`, `engine.py` | Active |
| `system.verdict_map_max` | `4096` | `schema.py` -> `VERDICT_MAP_MAX`, `engine.py` | Active |
| `system.bypass_ttl_s` | `300` | `engine.py` (`bypass_ttl_ns = bypass_ttl_s * 1e9`) | Active |
| `system.drop_ttl_s` | `60` | `engine.py`, `harness.py` | Active |
| `system.flow_idle_s` | `120` | `schema.py` -> `FLOW_IDLE_NS`, `pcap_to_flows.py`, `equivalence.py` | Active |
| `system.target_fpr` | `0.001` | `train.py`, `evt.py` | Active |
| `system.mode` | `observe` | `engine.py` | Active |
| `system.bypass` | `on` (`True`) | `engine.py` | Active |
| `system.guard` | `off` | Documented operational switch for online drift guard (`GuardConfig`); offline replay uses `ips/drift/scenarios.py` | Documented (online daemon hook pending Prompt 7) |
| `system.model_path` | `models/autoencoder_int8.onnx` | `engine.py` | Active |
| `system.devices_path` | `configs/devices.yaml` | `engine.py`, `synth.py`, `topology.sh`, `benign_iot_generator.py` | Active |
| `engine.auto_block_mean_iat_ms` | `50.0` | Legacy 30% stub `engine/ringbuf_engine.py` ONLY | Legacy 30% baseline key (kept for backward compatibility) |
| `engine.watchdog.*` | `100`, `10000`, `500`, `30` | `ips/engine/engine.py` (`step_watchdog`) | Active |
| `engine.tier0.*` | `true`, `50`, `50`, `100`, `30` | `schema.py` -> `TIER0_*`, `engine.py` (`BCCKernelBackend`, `MockBPFBackend`) | Active (`tier0.max_new_flows_per_s` aliases `bucket_refill_rate`) |

---

## 3. Units & Naming Convention Table

| Quantity | Canonical Unit | Where Used | Conversion Rule |
|---|---|---|---|
| Kernel / Mock timestamps & TTLs | **Nanoseconds (`ns`, `uint64`)** | `ebpf/ips_engine.c` (`first_ts_ns`, `last_ts_ns`, `iat_ns`, `expiry_ns`, `FLOW_IDLE_NS`), `ips/engine/engine.py` | `ns = s * 1_000_000_000` (`1e9`); `ms = ns / 1e6` |
| Pcap frame timestamps & config durations | **Seconds (`s`, `float` / `int`)** | `configs/system.yaml` (`*_ttl_s`, `flow_idle_s`, `cooldown_s`), `dpkt` reader `ts`, `SlowC2Tracker` | `iat_ms = (ts_i - ts_{i-1}) * 1000.0` |
| Feature-extractor input IATs & engine latency | **Milliseconds (`ms`, `float`)** | `build_early_vector(..., iat_ms_list)`, `time_to_verdict_ms`, `inference_ms`, `max_engine_lag_ms` | Converted internally to `us = ms * 1000.0` |
| Normalized log-IAT feature (`FEATURE_SCHEMA_VERSION=2`) | **Dimensionless in `[0.0, 1.5]`** | `ips/features.py` (`log_iat_i`, `mean_log_iat`) | `min(1.5, log10(1.0 + iat_us) / 7.0)` (`10 s = 10^7 us -> 1.0`) |
| ONNX microbenchmark & equivalence IAT error | **Microseconds (`us`, `float`)** | `ips/models/quantize.py` (`p50_us`), `ips/eval/equivalence.py` (`iat_diff_p99_us`) | `us = s * 1e6 = ns / 1000.0` |
| Packet payload size (`sizes[i]`) | **Bytes (`B`, `uint16`) -> `[0.0, 1.0]`** | L4 payload bytes from IP/TCP/UDP headers (`ebpf/ips_engine.c`, `pcap_to_flows.py`) | `min(1500.0, bytes) / 1500.0` |
