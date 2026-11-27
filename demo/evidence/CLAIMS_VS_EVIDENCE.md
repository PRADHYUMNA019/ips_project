# Claims vs. Evidence Matrix (`demo/evidence/CLAIMS_VS_EVIDENCE.md`)

> **Rule R1 / R2 / R4 Honesty Notice**: Statuses below match [`docs/PAPER_OUTLINE.md`](../../docs/PAPER_OUTLINE.md) §8 verbatim. **No claim has been upgraded.** **No Linux/kernel/real-testbed result exists yet.**

---

## 1. Primary Paper Claims (`C1–C4`)

| Claim / Term | Paper Outline Status | What Is Implemented | What Is Unit-Tested (`UNIT TEST`) | What Has Real Evidence (`REAL PUBLIC DATA`) | What Is Missing (Blocked Until Linux VM / Prompt 7) |
|---|---|---|---|---|---|
| **C1**: Progressive multi-checkpoint XDP inference (`[4, 8, 16]`) + "early drop, late bypass" verdict caching | `SMOKE-ONLY` (V1 verified; real testbed capture `NOT TESTED`) | `ebpf/ips_engine.c` (`emitted_mask`, `checkpoint_idx`, FIN/RST/idle reset), `ips/engine/engine.py` (`DROP_STICKY`, late BYPASS), `ips/models/{train,eval_offline}.py`, masked short-flow MSE | `test_kernel_source_invariants.py` (source guard), `test_schema_and_equivalence.py` (9 passed, 40-pkt C-mirror), `test_engine_closed_loop.py` (11 passed), `test_models.py` (12 passed) | `docs/DATASET_AUDIT.md`: IoT-23 benign shows only 6.54% reach `k=16` vs 22.01% at `k=4`; TQH-C2 D shows 100%/98.1%/97.7% reach est. `k=4/8/16` in ~31 s | Kernel compilation & execution on Linux (`ebpf/ips_engine.c`), live XDP equivalence (`S6`), real testbed LOFO detection & inline leakage measurements |
| **C2**: Poisoning-aware drift guard (`G1–G4` + bounded step + rollback) with honest failure mode (`S4`) | `SMOKE-ONLY` (V1 verified; real CESNET/testbed `NOT TESTED`) | `ips/drift/guard.py` (`G1–G4`, bounded step, rollback, small-class fail-closed), `ips/drift/scenarios.py` (`S1–S5`, CESNET mode) | `test_drift_guard.py` (5 passed, incl. quorum G2 & periodicity G3; M10/M10b/M16 KILLED) | None yet (CESNET-TLS-Year22 deferred to Prompt 7 VM) | Real testbed drift sessions (`S1–S5`) and real multi-week CESNET natural benign drift evaluation |
| **C3**: Two-tier detection (`[4, 8, 16]` + `SlowC2Tracker`) + white-box query-bounded ($Q=200$) cost-of-evasion curve | `SMOKE-ONLY` (V1 verified; real TQH-C2 D `NOT TESTED`) | `ips/drift/periodicity.py` (`SlowC2Tracker`), `ips/drift/evasion_cost.py` ($Q=200$ random + hill-climbing optimizer) | `test_drift_guard.py` (CV & SlowC2Tracker, M16 KILLED), `demo/run_smoke_pipeline.py` (deterministic `evasion_cost_curve.csv`) | `demo/evidence/real/tqh_c2_audit.csv`: real TQH-C2 D host-pair CV flags 15/15 pairs at 30 s (`CV=0.048–0.157`), 26/26 reaching ≥8 conns at 300 s, but 0/15 reach 8 conns at 1800–3600 s | Per-packet `3N+8` TQH-C2 D scoring from 1.82 GB pcap (`Prompt 7`), inline gateway validation of ≥5 evasion points |
| **C4**: Cross-domain benign generalisation (`Testbed <-> IoT-23`) + tail calibration, harm, netem, contamination, equivalence | `SMOKE-ONLY` (V1 verified; real pcaps `NOT TESTED`) | `ips/eval/cross_domain.py` (train-only scaler + leakage sentinel), `ips/models/evt.py`, `ips/eval/{harness,impairment,contamination,equivalence}.py` | `test_cross_eval.py`, `test_models.py` (EVT KAT 1.18% err, conformal exact order stat M8 KILLED), `test_engine_closed_loop.py` (M15 KILLED, wire reconciliation) | **Exploratory only** (`docs/EXPLORATORY_P8.md`): real IoT-23 cross-device shift `KS=0.921–0.928` (`Echo->Hue_cal->Somfy` FPR 94.5%, driven by `log_iat`) | Real testbed ↔ IoT-23 transfer, real netem sweeps, real contamination study, real kernel-vs-offline equivalence |

---

## 2. Paper Title Terms Audit (`TITLE_DECISION_PENDING`)

Working title (preserved verbatim per R4): *"Drift-Resilient On-Device Inline Intrusion Prevention for Encrypted Traffic in Resource-Constrained Smart Systems Against Zero-Day Attacks"*

| Title Term | Implemented? | Unit-Tested (`V1`)? | Real Evidence (`V2/V3`)? | Honest Gap / Action Needed |
|---|---|---|---|---|
| **Drift-Resilient** | Yes (`ips/drift/guard.py`) | Yes (5 tests, M10/M10b KILLED) | No (`SMOKE-ONLY`) | Needs real testbed drift sessions + CESNET multi-week evaluation (Prompt 7) |
| **On-Device** | **No physical device** (emulated via cgroups S/M/L) | N/A | **None** (`TITLE_DECISION_PENDING`) | Scope note states emulated gateway only; guide to approve title change or post-80% hardware run |
| **Inline Intrusion Prevention** | Yes (`ebpf/ips_engine.c` + `ips/engine/engine.py`) | Python mock only (`MockBPFBackend`) | **None** (`CODE WRITTEN, NOT COMPILED, NOT RUN (V2)`) | Needs Linux VM compile, BCC attach, and ≥10-rep inline egress pcap evaluation (Prompt 7) |
| **Encrypted Traffic** | Yes (payload-independent `3N+8` features, TLS generators) | Yes (`test_generator.py`, `test_features.py`) | Partial: TQH-C2 D audit (Merlin H2-TLS), IoT-23 audit (11.1% TLS) | Needs real TLS 1.2/1.3 testbed captures + TQH-C2 D raw pcap extraction (Prompt 7) |
| **Resource-Constrained Smart Systems** | Emulated cgroup profiles S/M/L + INT8 ONNX quantization | INT8 export & latency microbench PASS | None on real gateway | Needs Linux `systemd-run` cgroup profile S/M/L measurements (Prompt 7) |
| **Zero-Day Attacks** | LOFO protocol (`A3_c2, A4_exfil` held out; `build_splits.py` guards) | Yes (`test_splits_and_joins.py`, M5/M6 KILLED) | None (`SMOKE-ONLY`) | Needs real testbed held-out `A3`/`A4` sessions + TQH-C2 D pcap scoring (Prompt 7) |
