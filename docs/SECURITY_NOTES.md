# Security, Dead-Code & Complexity Review (`docs/SECURITY_NOTES.md`)

> **Artefact Label**: `STATIC ANALYSIS (V1 — ran on Windows 11, Python 3.12.3)`
> **Raw Logs**: `demo/evidence/logs/p10_bandit_initial.log`, `demo/evidence/logs/p10_bandit_final.log`, `demo/evidence/logs/p10_pip_audit.log`, `demo/evidence/logs/p10_radon_cc.log`, `demo/evidence/logs/p10_radon_mi.log`.

---

## 1. Bandit Security Scan (`bandit -r ips datasets demo`)

### Summary
- **High-Severity Findings**: **`0`**
- **Medium-Severity Findings**: `7` initial -> **`6` benign/justified (`0` exploitable)** after fixing `B310` (`BUG-05`).
- **Low-Severity Findings**: `35` initial -> **`26`** after replacing silent `try/except/pass` blocks with structured logging.

### Every Medium & Low Finding Reviewed

| Rule | Count | Locations | Verdict & Action |
|---|---:|---|---|
| **`B310`** (`urllib.urlopen`) | `1 -> FIXED` | `datasets/download_tqh_c2_win.py:66` | **FIXED (`BUG-05`)**: Previously allowed `file://` or custom schemes (`test_bug05` demonstrated local file copy). Added strict `urllib.parse.urlparse(url).scheme == "https"` + non-empty `netloc` validation raising `ValueError` before constructing `Request`. |
| **`B104`** (`hardcoded_bind_all_interfaces`) | `4` (Medium) | `datasets/adapters/cesnet_adapter.py:93-94`, `ips/data/label_join.py:81,83` | **FALSE POSITIVE (Justified)**: `"0.0.0.0"` is used purely as a fallback string value in dictionary/DataFrame metadata columns (`row.get("src_ip", "0.0.0.0")`) when an offline dataset omits IP addresses. No network socket binds to `0.0.0.0` in `ips/` or `datasets/`. |
| **`B301` / `B403`** (`pickle.load` / `import pickle`) | `2` Med, `2` Low | `ips/models/train.py:21`, `ips/models/eval_offline.py:312,329` | **JUSTIFIED (Trusted Local Artifact Boundary)**: `pickle` serializes/deserializes locally trained scikit-learn `IsolationForest` and `KitsuneStyleEnsemble` baseline objects referenced by `models/model_card.json` on the researcher's own disk. Online user-space inference (`ips/engine/engine.py`) uses **ONNX Runtime (`autoencoder_int8.onnx`)**, never `pickle`. Do not load untrusted third-party `.pkl` files. |
| **`B404` / `B603` / `B607`** (`subprocess`) | `9` (Low) | `datasets/download_iot23_win.py:20,36,43,50`, `ips/eval/reproduce.py:13,23` | **JUSTIFIED**: All `subprocess` calls pass argument lists (`shell=False`), never interpolate untrusted shell strings, and invoke either `["git", "rev-parse", "--short", "HEAD"]` or `["curl.exe", ...]` against fixed Stratosphere HTTPS dataset URLs. |
| **`B311`** (`random` PRNG) | `10` (Low) | `ips/smoke/synth.py` | **JUSTIFIED**: Standard `random` is intentionally seeded (`random.seed(seed)`) for deterministic synthetic smoke-data generation, never for cryptographic keys, tokens, or TLS nonces. |
| **`B110` / `B112`** (`try/except/pass` or `continue`) | `0` silent `pass` in `ips/` | `datasets/audit_pcap.py:113`, `ips/eval/equivalence.py:133`, `ips/models/evt.py:193`, `ips/offline/pcap_to_flows.py:298` | **FIXED / JUSTIFIED**: All silent `except Exception: pass` blocks in `engine.py`, `pcap_to_flows.py`, `evasion_cost.py`, and `eval_offline.py` were replaced with `logger.warning(...)` or `ValueError` handling (`BUG-04`). Remaining `try/except/continue` loops in pcap frame iteration count `skipped_counts["corrupt_frame"]` (`BUG-07`) or skip degenerate GPD candidate quantiles during POT grid search. |
| **`B101`** (`assert_used`) | `3` (Low) | `demo/run_smoke_pipeline.py:428`, `ips/drift/evasion_cost.py:159,227` | **JUSTIFIED**: Used only in offline/demo scripts for internal loop postcondition narrowing (`mypy`), never as an external security or input validation gate. |

---

## 2. Dependency Vulnerability Audit (`pip-audit`)

- Command run: `python -m pip_audit` (raw log: `demo/evidence/logs/p10_pip_audit.log`).
- Observation: Because Python `3.12.3` on this Windows machine uses the global user/system `site-packages`, `pip-audit` scans **all** globally installed packages on the laptop (including unrelated web/GUI packages not imported by `ips_project`, such as `werkzeug`, `flask`, `pillow`, `tornado`).
- Project-direct runtime dependencies (`numpy`, `scipy`, `scikit-learn`, `pandas`, `pyarrow`, `onnx`, `onnxruntime`, `dpkt`, `PyYAML`, `river`, `psutil`, `matplotlib`) have no High/Critical RCE in our offline/local execution path (`torch==2.15.0+cpu` is a local CPU wheel skipped by PyPI index lookup).
- Isolation remedy (Phase 3): Clean virtual environments (`python -m venv .venv`) + `requirements.txt` / `constraints.txt` install **only** the minimal pinned dependencies needed by `ips_project`, eliminating unrelated global packages.

---

## 3. Dead-Code Scan (`vulture ips datasets demo --min-confidence 80`)

- Initial findings (`6`):
  1. `demo/run_smoke_pipeline.py:29` unused import `tempfile` -> **Removed**.
  2. `ips/drift/guard.py:23` unused import `field` -> **Removed**.
  3. `ips/drift/scenarios.py:38` unused re-import `generate_adaptive_boiling_frog_sequence` -> **Removed** (function itself in `evasion_cost.py` is tested in `tests/test_drift_guard.py`).
  4. `ips/engine/engine.py:500` unused parameter `reason` in `_handle_schema_mismatch` -> **Fixed (`BUG-04`)**: now logged and appended to `self.schema_mismatch_reasons`.
  5. `ips/engine/engine.py:681` unused callback arg `ctx` in `_ringbuf_cb` -> **Renamed to `_ctx`** (required BCC C-callback signature `(ctx, data, size)`).
  6. `ips/smoke/synth.py:189` unused parameter `out_parquet` in `generate_smoke_dataset` -> **Fixed (`BUG-03`)**: now writes `df.to_parquet(out_parquet, index=False)` when supplied.
- Final `vulture ips datasets demo --min-confidence 80` output: **`0` findings**.

---

## 4. Cyclomatic Complexity & Maintainability (`radon cc -s -a ips` & `radon mi ips`)

- **Maintainability Index (`radon mi ips`)**: Every single module in `ips/` achieves **Grade `A`**.
- **Top-10 Most Complex Functions Reviewed**:
  1. `ips/smoke/synth.py::generate_flow_vector` — simplified from **`F (54)` -> `B (8)`** by extracting `_sample_benign_sequence` and `_sample_attack_sequence`; covered by `test_bug03` & smoke pipeline tests.
  2. `ips/models/eval_offline.py::run_offline_evaluation` (`E (40)`) — orchestrator writing 5 CSVs + plots; covered by `test_train_and_eval_pipeline_runs_only`.
  3. `ips/offline/pcap_to_flows.py::extract_flows_from_pcap` (`E`) — streaming TCP/UDP/VLAN/fragment state machine; covered by golden fixture, idle/SYN lifecycle tests, `test_bug07`, and Hypothesis fuzz suite `tests/test_prop_pcap_to_flows.py`.
  4. `ips/eval/equivalence.py::compare_flows` (`E (33)`) — per-checkpoint equivalence matcher; covered by `test_equivalence_verifier_pass_and_mismatch` and `test_multi_checkpoint_equivalence`.
  5. `ips/drift/guard.py::PoisoningAwareDriftGuard.evaluate_window` (`E (32)`) — sequential G1–G4 + bounded-step gate; covered by `tests/test_drift_guard.py` and `tests/test_prop_drift_guard.py`.
  6. `ips/eval/contamination.py::run_contamination_study` (`E (32)`) — covered by `test_contamination_study_and_trimmed_loss`.
  7. `ips/data/build_splits.py::verify_split_integrity` (`D (27)`) — B2a–d leakage gate; covered by `test_split_integrity_assertions_a_b_c_d` and mutants `M5, M6`.
  8. `ips/drift/scenarios.py::generate_scenario_windows` (`D (28)`) — S1–S5 generator; covered by `test_drift_guard.py`.
  9. `ips/engine/engine.py::MockBPFBackend.simulate_packet` (`D`) — C fast-path mirror; covered by `test_schema_and_equivalence.py`, `test_bug02`, and `tests/test_prop_engine_mock.py`.
  10. `ips/engine/engine.py::IPSEngine._load_model_and_thresholds` (`D`) — covered by `test_engine_loads_configured_model_card_and_benign_reaches_bypass_p9_1e` and `test_bug04`.
