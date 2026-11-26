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
