# Guide-Review Evidence Pack Index (`demo/evidence/INDEX.md`)

> **Branch**: `p8-demo` (branched from `wp0-fix-30pct`, never merged to `main`).
> **Honesty Statement (R1/R2)**: Every artefact below is tagged with its exact evidence type (`UNIT TEST`, `SYNTHETIC SMOKE`, `REAL PUBLIC DATA`, or `DOCUMENTATION`). **No Linux/kernel/real-testbed result exists yet.**

| Artefact Path | Evidence Type | Description | Regeneration Command |
|---|---|---|---|
| [`demo/run_demo.ps1`](../run_demo.ps1) | `UNIT TEST` + `SYNTHETIC SMOKE` | One-command Windows guide-review demo runner (runs from any directory, ~71 s) | `powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1` |
| [`demo/evidence/logs/pytest.log`](logs/pytest.log) | `UNIT TEST` | Timestamped raw output of full pytest suite (`68 passed` at P8.1; `69 passed` after P8.3) | `python -m pytest -q` |
| [`demo/evidence/logs/compileall.log`](logs/compileall.log) | `UNIT TEST` | Timestamped Python bytecode syntax check across repository (`rc=0`) | `python -m compileall -q .` |
| [`demo/evidence/logs/check_claims.log`](logs/check_claims.log) | `UNIT TEST` | Timestamped forbidden-wording & 3-doc title consistency audit (`0` violations) | `python audit/check_claims.py` |
| [`demo/evidence/logs/mutation_runner.log`](logs/mutation_runner.log) | `UNIT TEST` | Timestamped adversarial mutation suite (`17/17 KILLED, 0 survived, 0 invalid`) | `python audit/mutation_runner.py` |
| [`audit/mutation_results.md`](../../audit/mutation_results.md) | `UNIT TEST` | Markdown summary table of all 17 mutants (`target found: yes`, historical note on 8 invalid in `54b5f81`) | `python audit/mutation_runner.py` |
| [`demo/evidence/COMMANDS.md`](COMMANDS.md) | `UNIT TEST` / `REAL PUBLIC DATA` / `SYNTHETIC SMOKE` | Verbatim log of every command executed in Prompt 8 with observed output lines | Updated as commands run |
| [`demo/evidence/smoke/smoke_pipeline_summary.json`](smoke/smoke_pipeline_summary.json) | `SYNTHETIC SMOKE` | End-to-end smoke pipeline summary + byte-for-byte determinism check (`10/10 IDENTICAL`) | `python demo/run_smoke_pipeline.py --check-determinism` |
| [`demo/figures/smoke/fig_a_roc_pr_per_checkpoint.png`](../figures/smoke/fig_a_roc_pr_per_checkpoint.png) | `SYNTHETIC SMOKE` | Watermarked ROC & PR curves per checkpoint `k=4, 8, 16` (+ `.caption.txt`) | `python demo/run_smoke_pipeline.py --check-determinism` |
| [`demo/figures/smoke/fig_b_detection_vs_packets_leaked.png`](../figures/smoke/fig_b_detection_vs_packets_leaked.png) | `SYNTHETIC SMOKE` | Watermarked progressive `[4,8,16]` vs. fixed checkpoint leakage Pareto (+ `.caption.txt`) | `python demo/run_smoke_pipeline.py --check-determinism` |
| [`demo/figures/smoke/fig_c_calibration_target_vs_achieved_fpr.png`](../figures/smoke/fig_c_calibration_target_vs_achieved_fpr.png) | `SYNTHETIC SMOKE` | Watermarked EVT vs. split-conformal vs. mean+3σ calibration curve (+ `.caption.txt`) | `python demo/run_smoke_pipeline.py --check-determinism` |
| [`demo/figures/smoke/fig_d_drift_s1_s5_fpr_over_time.png`](../figures/smoke/fig_d_drift_s1_s5_fpr_over_time.png) | `SYNTHETIC SMOKE` | Watermarked static vs. guarded (`G1–G4`) FPR across drift scenarios `S1–S5` (+ `.caption.txt`) | `python demo/run_smoke_pipeline.py --check-determinism` |
| [`demo/figures/smoke/fig_e_cost_of_evasion_curve.png`](../figures/smoke/fig_e_cost_of_evasion_curve.png) | `SYNTHETIC SMOKE` | Watermarked white-box $Q=200$ cost-of-evasion curve for A4 exfil & A3 C2 (+ `.caption.txt`) | `python demo/run_smoke_pipeline.py --check-determinism` |
| [`demo/evidence/real/tqh_c2_audit.csv`](real/tqh_c2_audit.csv) | `REAL PUBLIC DATA` | Real TQH-C2 Testbed D audit across all 12 `(interval, jitter)` cells (`11,528` rows; Zenodo `21523144`) | `python datasets/download_tqh_c2_win.py` + audit script |
| [`demo/evidence/real/iot23_benign_audit.csv`](real/iot23_benign_audit.csv) | `REAL PUBLIC DATA` | Real Aposemat IoT-23 benign pcap audit (`4-1` Hue, `5-1` Echo, `7-1` Somfy; `1,254` flows) | `python datasets/download_iot23_win.py && python demo/audit_iot23_real.py` |
| [`docs/DATASET_AUDIT.md`](../../docs/DATASET_AUDIT.md) | `REAL PUBLIC DATA` | Full narrative audit of TQH-C2 D and IoT-23 benign with architectural implications | Generated from `tqh_c2_audit.csv` & `iot23_benign_audit.csv` |
| [`tests/fixtures/tqh_c2_d_sample.json`](../../tests/fixtures/tqh_c2_d_sample.json) | `REAL PUBLIC DATA` (`UNIT TEST`) | 6-row CC-BY-4.0 real TQH-C2 D fixture verifying `datasets/adapters/tqh_adapter.py` | `python -m pytest tests/test_dataset_adapters.py -v` |
| [`demo/evidence/real/exploratory_results.csv`](real/exploratory_results.csv) | `REAL PUBLIC DATA` (EXPLORATORY) | Exploratory IoT-23 cross-device benign transfer (seeds 42, 43, 44; TQH-C2 TPR skipped per §4.3) | `python demo/run_exploratory_p8.py` |
| [`docs/EXPLORATORY_P8.md`](../../docs/EXPLORATORY_P8.md) | `REAL PUBLIC DATA` (EXPLORATORY) | Pre-stated exploratory plan, measured cross-device FPR/KS table, and `log_iat` shift reading | `python demo/run_exploratory_p8.py` |
| [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) | `DOCUMENTATION` | 4 Mermaid diagrams (two-tier overview, checkpoint sequence, drift guard G1–G4, split governance) | Native Mermaid Markdown |
| [`demo/evidence/CLAIMS_VS_EVIDENCE.md`](CLAIMS_VS_EVIDENCE.md) | `DOCUMENTATION` | Honest claim-to-evidence & title-term audit matching `docs/PAPER_OUTLINE.md` statuses | Manual sync with `docs/PAPER_OUTLINE.md` |
| [`docs/GUIDE_DEMO.md`](../../docs/GUIDE_DEMO.md) | `DOCUMENTATION` | 7–10 minute guide-review script + 6 likely questions with honest answers | Guide-facing script |
