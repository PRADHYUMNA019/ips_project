# Commands Run & Observed Outputs (`demo/evidence/COMMANDS.md`)

> **Rule R8**: Every claim in the Prompt 8 Guide-Review Evidence Pack is backed by an exact command actually executed in this Windows session and its verbatim output lines.
> **Scope**: Windows-only (`UNIT TEST`, `SYNTHETIC SMOKE`, `REAL PUBLIC DATA`). **No Linux/kernel/real-testbed result exists yet.**

---

## Phase 1 — Unit Tests, Syntax Check, Claims Audit & Mutation Testing (`UNIT TEST`)

- **Cleanup & branch creation**:
  - Command: `Remove-Item -Force BLOCKERS.md; git checkout -- tests/test_kernel_source_invariants.py; git checkout -b p8-demo`
  - Output: `Switched to a new branch 'p8-demo'` (base commit `3b3050f`)
- **Disk check (R6)**:
  - Command: `python -c "import os, shutil; print('C free GB:', round(shutil.disk_usage('C:/').free/1024**3,2)); print('D exists:', os.path.exists('D:/'), 'D free GB:', round(shutil.disk_usage('D:/').free/1024**3,2))"`
  - Output: `C free GB: 21.46` / `D exists: True D free GB: 286.4`
- **Unit tests (`demo/evidence/logs/pytest.log`)**:
  - Command: `python -m pytest -q`
  - Output: `68 passed, 18 warnings in 70.67s (0:01:10)` (exit code `0`)
- **Python syntax check (`demo/evidence/logs/compileall.log`)**:
  - Command: `python -m compileall -q .`
  - Output: `(no errors, exit code 0)`
- **Claims & title consistency audit (`demo/evidence/logs/check_claims.log`)**:
  - Command: `python audit/check_claims.py`
  - Output: `1. Explicit Forbidden Phrases Found: 0` / `3. Title Consistency Check (Rule R4): 3/3 match` (exit code `0`)
- **Adversarial mutation runner (`demo/evidence/logs/mutation_runner.log`)**:
  - Command: `python audit/mutation_runner.py`
  - Output: `Total: 17 | KILLED: 17 | SURVIVED: 0 | BASELINE FAILS: 0 | INVALID: 0` (exit code `0`)

---

## Phase 2 — End-to-End Synthetic Smoke Pipeline & Watermarked Figures (`SYNTHETIC SMOKE`)

- **End-to-end smoke pipeline + determinism check**:
  - Command: `python demo/run_smoke_pipeline.py --check-determinism`
  - Output: `[DETERMINISM CHECK] 10/10 deterministic artefacts byte-for-byte IDENTICAL.` / `[+] Wrote smoke pipeline summary to demo/evidence/smoke/smoke_pipeline_summary.json`
- **PowerShell demo runner from external working directory (`C:\Users\Dell`)**:
  - Command: `Push-Location C:\Users\Dell; powershell -ExecutionPolicy Bypass -File C:\Users\Dell\finalyr_project\demo\run_demo.ps1`
  - Output: `FINAL DEMO SUMMARY (Total: 71.1s)` / `OVERALL: PASS (UNIT TEST + SYNTHETIC SMOKE ONLY — No Linux/kernel/real-testbed result)` (exit code `0`)

---

## Phase 3 — Real Public Data Downloads, Adapter Verification & Dataset Audit (`REAL PUBLIC DATA`)

- **Zenodo API verification for TQH-C2 (record `21523144`)**:
  - Command: `python -c "... urllib.request.urlopen('https://zenodo.org/api/records/21523144') ..."`
  - Output: `title: TQH-C2: An Encrypted Command-and-Control Traffic Dataset Across Protocols and Encryption Layers` / `license: {'id': 'cc-by-4.0'}` / `TQH-C2_features_D.zip 1222048` / `TQH-C2_labels_D.zip 791480`
- **TQH-C2 Testbed D small-file download & SHA-256 verification**:
  - Command: `python datasets/download_tqh_c2_win.py`
  - Output: `[PASS] README_v120.md` / `[PASS] TQH-C2_features_D.zip` / `[PASS] TQH-C2_labels_D.zip` (all 3 SHA-256 matched `SHA256SUMS_v120.txt` in `D:\ips_data\tqh_c2`)
- **TQH-C2 Testbed D real Parquet audit & CC-BY-4.0 fixture test**:
  - Command: `python -m pytest tests/test_dataset_adapters.py -v`
  - Output: `7 passed in 1.05s` (including `test_tqh_verified_parquet_summary_fixture` with 0 `UNVERIFIED SCHEMA` warnings)
  - Audit summary (`demo/evidence/real/tqh_c2_audit.csv`): `11,528` total rows (`9,564` benign, `1,964` `malicious_c2`), `100.0% / 98.1% / 97.7%` of C2 flows reach estimated ≥ 4 / 8 / 16 payload packets (median duration `31.02 s`).
- **IoT-23 benign honeypot downloads (`CTU-Honeypot-Capture-4-1`, `5-1`, `7-1`)**:
  - Command: `python datasets/download_iot23_win.py` (via Windows Schannel `curl.exe` into `D:\ips_data\iot23`)
  - Output: 8 pcaps totaling `512.97 MB` (`4-1`: 4.38 MB decompressed, `5-1`: 363.71 MB, `7-1`: 144.88 MB across `Somfy-01..06`).
- **IoT-23 benign streaming `dpkt` pcap audit (`demo/evidence/real/iot23_benign_audit.csv`)**:
  - Command: `python demo/audit_iot23_real.py`
  - Output: `1,254` total flows (`4-1`: 353, `5-1`: 761, `7-1`: 140), `139` TLS (`11.08%`), reaching checkpoints `k=4/8/16`: `22.01% / 10.13% / 6.54%`.

---

## Phase 4 — Exploratory Real Cross-Device Benign Experiment (`REAL PUBLIC DATA — EXPLORATORY`)

- **IoT-23 cross-device benign transfer (`demo/evidence/real/exploratory_results.csv`, seeds 42, 43, 44)**:
  - Command: `python demo/run_exploratory_p8.py`
  - Output: `Echo->Hue_cal->Somfy_test`: FPR@0.05 = `0.9452–0.9476` (`KS = 0.921–0.928`, top shift `log_iat_1 +8.2..+10.9`); `Echo->Somfy_cal->Hue_test`: FPR@0.05 = `0.0028–0.0057` (`KS = 0.921–0.928`). TQH-C2 D TPR explicitly skipped per §4.3 (no per-packet sequences in `TQH-C2_features_D.zip`).

---

## Phase 5 — Final Claims Audit & Unit Test Gate (`UNIT TEST`)

- **Final claims & title consistency check**:
  - Command: `python audit/check_claims.py`
  - Output: `1. Explicit Forbidden Phrases Found: 0` / `3. Title Consistency Check (Rule R4): 3/3 match` (exit code `0`)
- **Final unit test verification (after all P8 edits)**:
  - Command: `python -m pytest -q`
  - Output: `69 passed, 18 warnings` (exit code `0`)
