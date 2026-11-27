# Guide-Review Evidence Pack Index (`demo/evidence/INDEX.md`)

> **Branch**: `p9-fixes` (branched from `p8-demo` `31da19b`, never merged to `main`).
> **Honesty Statement (R1/R2)**: Every artefact below is tagged with its exact evidence type (`UNIT TEST`, `SYNTHETIC SMOKE`, `REAL PUBLIC DATA`, or `DOCUMENTATION`). **No Linux/kernel/real-testbed result exists yet.**

| Artefact Path | Evidence Type | Description | Regeneration Command |
|---|---|---|---|
| [`demo/run_demo.ps1`](../run_demo.ps1) | `UNIT TEST` + `SYNTHETIC SMOKE` | One-command Windows guide-review demo runner (runs from any directory) | `powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1` |
| [`demo/evidence/logs/pytest.log`](logs/pytest.log) | `UNIT TEST` | Timestamped raw output of full pytest suite (`73 passed, 0 failed`) | `python -m pytest -q` |
| [`demo/evidence/logs/compileall.log`](logs/compileall.log) | `UNIT TEST` | Timestamped Python bytecode syntax check across repository (`rc=0`) | `python -m compileall -q .` |
| [`demo/evidence/logs/check_claims.log`](logs/check_claims.log) | `UNIT TEST` | Timestamped forbidden-wording & 3-doc title consistency audit (`0` violations) | `python audit/check_claims.py` |
| [`demo/evidence/logs/mutation_runner.log`](logs/mutation_runner.log) | `UNIT TEST` | Timestamped adversarial mutation suite (`18/18 KILLED, 0 survived, 0 invalid`, incl. `M17` IAT norm) | `python audit/mutation_runner.py` |
| [`audit/mutation_results.md`](../../audit/mutation_results.md) | `UNIT TEST` | Markdown summary table of all 18 mutants (`M1–M17`, incl. `M10b`) | `python audit/mutation_runner.py` |
| [`demo/evidence/COMMANDS.md`](COMMANDS.md) | `UNIT TEST` / `REAL PUBLIC DATA` / `SYNTHETIC SMOKE` | Verbatim log of commands executed across Prompts 8 & 9 with observed outputs | Updated as commands run |
| [`demo/evidence/smoke/smoke_pipeline_summary.json`](smoke/smoke_pipeline_summary.json) | `SYNTHETIC SMOKE` | End-to-end smoke summary (`offline_int8_auroc=1.0`, `benign_sensor_1 -> BYPASS`, `10/10 IDENTICAL` determinism) | `python demo/run_smoke_pipeline.py --check-determinism` |
| [`demo/evidence/smoke/item1_diagnostic.md`](smoke/item1_diagnostic.md) | `SYNTHETIC SMOKE` + `UNIT TEST` | Root-cause table & fix record for Prompt-8 smoke ROC inversion (`0.3213 -> 1.0000`) & mock false DROP | Documented from diagnostic run |
| [`demo/figures/smoke/fig_a_roc_pr_per_checkpoint.png`](../figures/smoke/fig_a_roc_pr_per_checkpoint.png) | `SYNTHETIC SMOKE` | Watermarked ROC & PR curves per checkpoint `k=4, 8, 16` (+ `.caption.txt`) | `python demo/run_smoke_pipeline.py --check-determinism` |
| [`demo/figures/smoke/fig_b_detection_vs_packets_leaked.png`](../figures/smoke/fig_b_detection_vs_packets_leaked.png) | `SYNTHETIC SMOKE` | Watermarked progressive `[4,8,16]` vs. fixed checkpoint leakage Pareto (+ `.caption.txt`) | `python demo/run_smoke_pipeline.py --check-determinism` |
| [`demo/figures/smoke/fig_c_calibration_target_vs_achieved_fpr.png`](../figures/smoke/fig_c_calibration_target_vs_achieved_fpr.png) | `SYNTHETIC SMOKE` | Watermarked EVT vs. split-conformal vs. mean+3σ calibration curve (+ `.caption.txt`) | `python demo/run_smoke_pipeline.py --check-determinism` |
| [`demo/figures/smoke/fig_d_drift_s1_s5_fpr_over_time.png`](../figures/smoke/fig_d_drift_s1_s5_fpr_over_time.png) | `SYNTHETIC SMOKE` | Watermarked S1–S2 Clean Benign FPR & S3–S5 Attack/C2 TPR (Static vs. Unguarded ADWIN vs. Guarded) | `python demo/run_smoke_pipeline.py --check-determinism` |
| [`demo/figures/smoke/fig_e_cost_of_evasion_curve.png`](../figures/smoke/fig_e_cost_of_evasion_curve.png) | `SYNTHETIC SMOKE` | Watermarked white-box $Q=200$ cost-of-evasion curve for A4 exfil & A3 C2 (+ `.caption.txt`) | `python demo/run_smoke_pipeline.py --check-determinism` |
| [`demo/figures/diagrams/`](../figures/diagrams/) | `DOCUMENTATION` | 4 PNG + 4 SVG architecture diagrams (`01_two_tier_overview` .. `04_splits_and_leakage`) | `python demo/render_architecture_diagrams.py` |
| [`demo/evidence/real/tqh_c2_audit.csv`](real/tqh_c2_audit.csv) | `REAL PUBLIC DATA` | Real TQH-C2 Testbed D audit (`11,528` rows): `71/71` C2 pairs vs `0/157` (`0.00%`) benign pairs flagged (`CV<=0.35`) | `python demo/audit_tqh_c2_real.py` |
| [`demo/evidence/real/iot23_benign_audit.csv`](real/iot23_benign_audit.csv) | `REAL PUBLIC DATA` | Real IoT-23 benign pcap audit with `flow_idle_s=120s` (`1,447` flows; `72.7%` UDP; old preserved as `*_before_idle_split.csv`) | `python demo/audit_iot23_real.py` |
| [`docs/DATASET_AUDIT.md`](../../docs/DATASET_AUDIT.md) | `REAL PUBLIC DATA` | Narrative audit of TQH-C2 D (upper-bound reach + benign CV baseline) and IoT-23 (old vs. new idle split) | Generated from `tqh_c2_audit.csv` & `iot23_benign_audit.csv` |
| [`demo/evidence/real/exploratory_results.csv`](real/exploratory_results.csv) | `REAL PUBLIC DATA` (EXPLORATORY) | IoT-23 cross-device benign domain-shift diagnostic (`*_before_iat_norm.csv` & `*_after_iat_norm.csv` preserved) | `python demo/run_exploratory_p8.py` |
| [`docs/EXPLORATORY_P8.md`](../../docs/EXPLORATORY_P8.md) | `REAL PUBLIC DATA` (EXPLORATORY) | Three-stage before/after diagnostic table (`p8-demo` -> `/7.0` IAT norm -> `+120s` idle split) & honest caveats | `python demo/run_exploratory_p8.py` |
| [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) | `DOCUMENTATION` | 4 Mermaid diagrams + `FEATURE_SCHEMA_VERSION = 2` normalisation rationale | Native Mermaid + `demo/render_architecture_diagrams.py` |
| [`demo/evidence/CLAIMS_VS_EVIDENCE.md`](CLAIMS_VS_EVIDENCE.md) | `DOCUMENTATION` | Calibrated claim-to-evidence & title-term audit matching `docs/PAPER_OUTLINE.md` statuses | Manual sync with `docs/PAPER_OUTLINE.md` |
| [`docs/GUIDE_DEMO.md`](../../docs/GUIDE_DEMO.md) | `DOCUMENTATION` | 7–10 min guide-review script + before/after review-fixes slide + 6 Q&As | Guide-facing script |
