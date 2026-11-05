#!/usr/bin/env python3
"""audit/mutation_runner.py — Adversarial mutation testing auditor.

Applies deliberate mutations M1–M16 to throwaway copies of the codebase and verifies
whether the test suite catches them (KILLED) or allows them to pass silently (SURVIVED).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

# Definition of mutations M1..M16 with verified exact target strings and precise target tests
MUTATIONS = [
    {
        "id": "M1",
        "file": "ips/offline/pcap_to_flows.py",
        "target": "if payload_len > 0 and len(flow[\"sizes\"]) < early_n:",
        "replacement": "if payload_len >= 0 and len(flow[\"sizes\"]) < early_n:  # M1: count zero-payload",
        "tests": [
            "tests/test_features.py::test_pcap_to_flows_golden_fixture",
            "tests/test_features.py::test_reused_5tuple_flow_instances_and_metadata",
        ],
        "desc": "Count zero-payload packets (e.g. pure SYN/ACK) in early-flow window",
        "should_catch": "tests/test_features.py::test_reused_5tuple_flow_instances_and_metadata",
    },
    {
        "id": "M2",
        "file": "ips/features.py",
        "target": "if dirs[i] == 0:\n            bytes_up += sz",
        "replacement": "if dirs[i] == 1:\n            bytes_up += sz  # M2: flip direction convention",
        "tests": [
            "tests/test_features.py::test_pcap_to_flows_golden_fixture",
            "tests/test_features.py::test_direction_asymmetry_and_frac_upstream_b3",
        ],
        "desc": "Flip direction convention (0 = client->server from LAN side)",
        "should_catch": "tests/test_features.py::test_direction_asymmetry_and_frac_upstream_b3",
    },
    {
        "id": "M3",
        "file": "ips/features.py",
        "target": "norm_sizes[i] = min(1500.0, float(sizes[i])) / 1500.0",
        "replacement": "norm_sizes[i] = min(1500.0, float(sizes[i])) / 1400.0  # M3: wrong scaling",
        "tests": ["tests/test_features.py::test_pcap_to_flows_golden_fixture"],
        "desc": "Change normalization constant (/1500.0 -> /1400.0)",
        "should_catch": "tests/test_features.py::test_pcap_to_flows_golden_fixture",
    },
    {
        "id": "M4",
        "file": "ips/features.py",
        "target": "inter = lower_names.intersection(FORBIDDEN_COLUMNS)\n    if inter:\n        raise ValueError(f\"CRITICAL SHORTCUT LEARNING VIOLATION: Forbidden features found: {inter}\")",
        "replacement": "pass  # M4: neutralise forbidden-column shortcut guard",
        "tests": ["tests/test_features.py::test_shortcut_guard"],
        "desc": "Remove / neutralise forbidden-column shortcut guard",
        "should_catch": "tests/test_features.py::test_shortcut_guard",
    },
    {
        "id": "M5",
        "file": "ips/data/build_splits.py",
        "target": "if overlap:\n                raise ValueError(\n                    f\"CRITICAL SPLIT LEAKAGE (B2a): session_id(s) {overlap} appear in both '{k1}' and '{k2}'!\"\n                )",
        "replacement": "pass  # M5: allow session overlap across splits",
        "tests": ["tests/test_splits_and_joins.py::test_split_integrity_assertions_a_b_c_d"],
        "desc": "Disable assertion that sessions appear in only one split",
        "should_catch": "tests/test_splits_and_joins.py::test_split_integrity_assertions_a_b_c_d",
    },
    {
        "id": "M6",
        "file": "ips/data/build_splits.py",
        "target": "if \"is_attack\" in df_b.columns and (df_b[\"is_attack\"].astype(int) != 0).any():\n                raise ValueError(f\"CRITICAL SPLIT LEAKAGE (B2b): attack flows found in benign split '{b_name}'!\")",
        "replacement": "pass  # M6: allow attack in calibration split",
        "tests": ["tests/test_splits_and_joins.py::test_split_integrity_assertions_a_b_c_d"],
        "desc": "Allow attack flows into calibration split",
        "should_catch": "tests/test_splits_and_joins.py::test_split_integrity_assertions_a_b_c_d",
    },
    {
        "id": "M7",
        "file": "ips/models/evt.py",
        "target": "t = u + (sigma / xi) * term",
        "replacement": "t = u - (sigma / xi) * term  # M7: swap sign",
        "tests": ["tests/test_models.py::test_evt_gpd_fitting_and_threshold"],
        "desc": "Swap sign in EVT Generalized Pareto threshold formula",
        "should_catch": "tests/test_models.py::test_evt_gpd_fitting_and_threshold",
    },
    {
        "id": "M8",
        "file": "ips/models/evt.py",
        "target": "k_1idx = int(math.ceil((n + 1) * (1.0 - target_fpr)))",
        "replacement": "k_1idx = int(math.ceil((n + 1) * (1.0 - target_fpr))) + 1  # M8: off-by-one",
        "tests": ["tests/test_models.py::test_split_conformal_regime_and_alpha_budget"],
        "desc": "Off-by-one in split-conformal quantile index",
        "should_catch": "tests/test_models.py::test_split_conformal_regime_and_alpha_budget",
    },
    {
        "id": "M9",
        "file": "ips/data/label_join.py",
        "target": "if f_end >= ep_start and f_start <= ep_end:",
        "replacement": "if f_end >= ep_start + 1000.0 and f_start <= ep_end:  # M9: shifted window",
        "tests": ["tests/test_splits_and_joins.py::test_label_join_manifest_and_engine_events"],
        "desc": "Shift time window comparison in manifest label join",
        "should_catch": "tests/test_splits_and_joins.py::test_label_join_manifest_and_engine_events",
    },
    {
        "id": "M10",
        "file": "ips/drift/guard.py",
        "target": "if len(drifting_devices) < required_devices:",
        "replacement": "if False:  # M10: disable G2",
        "tests": ["tests/test_drift_guard.py::test_g2_quorum_and_g3_periodicity_checks"],
        "desc": "Disable guard check G2 (force cross-device quorum to always pass)",
        "should_catch": "tests/test_drift_guard.py::test_g2_quorum_and_g3_periodicity_checks",
    },
    {
        "id": "M10b",
        "file": "ips/drift/guard.py",
        "target": "if per_res[\"is_periodic\"]:",
        "replacement": "if False:  # M10b: disable G3",
        "tests": ["tests/test_drift_guard.py::test_g2_quorum_and_g3_periodicity_checks"],
        "desc": "Disable guard check G3 (force non-periodicity to always pass)",
        "should_catch": "tests/test_drift_guard.py::test_g2_quorum_and_g3_periodicity_checks",
    },
    {
        "id": "M11",
        "file": "ips/engine/engine.py",
        "target": "if self.mode == \"enforce\":",
        "replacement": "if self.mode in (\"enforce\", \"observe\"):  # M11: observe writes verdicts",
        "tests": ["tests/test_engine_closed_loop.py::test_observe_vs_enforce_and_explainability"],
        "desc": "Make observe mode write verdicts to BPF map (violates observe contract)",
        "should_catch": "tests/test_engine_closed_loop.py::test_observe_vs_enforce_and_explainability",
    },
    {
        "id": "M12",
        "file": "scripts/topology.sh",
        "target": "local trimmed=\"${line#\"${line%%[![:space:]]*}\"}\"",
        "replacement": "local trimmed=\"$line\"  # M12: reintroduce trimmed-line bug",
        "tests": ["tests/test_topology_parse.py::test_topology_sh_source_syntax_and_trimming"],
        "desc": "Reintroduce trimmed-line bug in topology.sh parse_devices",
        "should_catch": "tests/test_topology_parse.py::test_topology_sh_source_syntax_and_trimming",
    },
    {
        "id": "M13",
        "file": "ips/engine/engine.py",
        "target": "if now_ns < expiry_ns:\n            return action\n        del self.verdict_map[k]\n        return VERDICT_NONE",
        "replacement": "return action  # M13: ignore TTL expiry",
        "tests": ["tests/test_engine_closed_loop.py::test_enforce_per_flow_drop_and_ttl_expiry"],
        "desc": "Ignore TTL expiry in verdict cache logic (stale entries never expire)",
        "should_catch": "tests/test_engine_closed_loop.py::test_enforce_per_flow_drop_and_ttl_expiry",
    },
    {
        "id": "M14",
        "file": "ips/engine/schema.py",
        "target": "(\"checkpoint_idx\", ctypes.c_uint8),",
        "replacement": "(\"checkpoint_idx\", ctypes.c_uint32),  # M14: offset desync",
        "tests": [
            "tests/test_schema_and_equivalence.py::test_early_flow_event_roundtrip",
            "tests/test_schema_and_equivalence.py::test_c_header_and_ctypes_sync_across_early_n",
        ],
        "desc": "Change checkpoint_idx type from uint8 to uint32 in ctypes struct",
        "should_catch": "tests/test_schema_and_equivalence.py::test_c_header_and_ctypes_sync_across_early_n",
    },
    {
        "id": "M15",
        "file": "ips/eval/harness.py",
        "target": "fpr = (fp / max(1, (fp + tn)))",
        "replacement": "fpr = (fp / max(1, (tp + fn)))  # M15: wrong FPR denominator",
        "tests": [
            "tests/test_engine_closed_loop.py::test_operational_harm_and_netem_impairment_c10_c11",
            "tests/test_engine_closed_loop.py::test_confusion_matrix_and_decision_metrics_b2",
        ],
        "desc": "Corrupt FPR denominator (fp/(tp+fn) instead of fp/(fp+tn))",
        "should_catch": "tests/test_engine_closed_loop.py::test_confusion_matrix_and_decision_metrics_b2",
    },
    {
        "id": "M16",
        "file": "ips/drift/periodicity.py",
        "target": "cv = (std_val / mean_val) if mean_val > 1e-9 else 1.0",
        "replacement": "cv = (mean_val / std_val) if std_val > 1e-9 else 1.0  # M16: inverted CV",
        "tests": ["tests/test_drift_guard.py::test_periodicity_and_slow_c2_tracker"],
        "desc": "Invert Coefficient of Variation calculation (mean/std instead of std/mean)",
        "should_catch": "tests/test_drift_guard.py::test_periodicity_and_slow_c2_tracker",
    },
]


def custom_ignore(dir_path: str, names: List[str]) -> List[str]:
    ignored = []
    p = Path(dir_path)
    for name in names:
        if name in {".git", ".venv", "results", "__pycache__", ".pytest_cache"}:
            ignored.append(name)
        elif name == "models" and p == REPO_ROOT:
            # Only ignore root models/ dir (which contains giant binaries if any)
            ignored.append(name)
    return ignored


def copy_clean_repo(dest: Path):
    shutil.copytree(REPO_ROOT, dest, ignore=custom_ignore, dirs_exist_ok=True)


def run_tests_in_dir(work_dir: Path, test_targets: List[str]) -> Tuple[int, str]:
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-W", "ignore"] + test_targets
    env = os.environ.copy()
    env["PYTHONPATH"] = str(work_dir)
    proc = subprocess.run(
        cmd,
        cwd=str(work_dir),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    out = (proc.stdout + "\n" + proc.stderr).strip()
    return proc.returncode, out


def run_mutation_audit(only_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    print("=== Running Adversarial Mutation Testing Suite ===", flush=True)
    results = []

    for m in MUTATIONS:
        m_id = m["id"]
        if only_ids and m_id not in only_ids:
            continue

        print(f"\n--- Running Mutation {m_id}: {m['desc']} ---", flush=True)
        tmp_dir = Path(tempfile.mkdtemp(prefix=f"audit_mut_{m_id}_"))
        try:
            copy_clean_repo(tmp_dir)

            # 1. Baseline test run
            base_rc, base_out = run_tests_in_dir(tmp_dir, m["tests"])
            if base_rc != 0:
                print(f"  [BASELINE FAILS] rc={base_rc}", flush=True)
                results.append({
                    "id": m_id,
                    "desc": m["desc"],
                    "status": "BASELINE FAILS",
                    "file": m["file"],
                    "output": base_out.splitlines()[-1] if base_out else "",
                    "should_catch": m["should_catch"],
                })
                continue

            # 2. Apply mutation
            target_file = tmp_dir / m["file"]
            if not target_file.exists():
                print(f"  [FILE MISSING] {m['file']}", flush=True)
                results.append({
                    "id": m_id,
                    "desc": m["desc"],
                    "status": "NOT APPLICABLE (file missing)",
                    "file": m["file"],
                    "output": "",
                    "should_catch": m["should_catch"],
                })
                continue

            content = target_file.read_text(encoding="utf-8")
            if m["target"] not in content:
                print(f"  [TARGET NOT FOUND] in {m['file']}", flush=True)
                results.append({
                    "id": m_id,
                    "desc": m["desc"],
                    "status": "NOT APPLICABLE (target not found)",
                    "file": m["file"],
                    "output": "",
                    "should_catch": m["should_catch"],
                })
                continue

            mutated_content = content.replace(m["target"], m["replacement"], 1)
            target_file.write_text(mutated_content, encoding="utf-8")

            # 3. Run tests with mutation
            mut_rc, mut_out = run_tests_in_dir(tmp_dir, m["tests"])
            last_line = mut_out.splitlines()[-1] if mut_out else ""
            if mut_rc != 0:
                print(f"  [KILLED] Tests failed as expected! rc={mut_rc} ({last_line})", flush=True)
                results.append({
                    "id": m_id,
                    "desc": m["desc"],
                    "status": "KILLED",
                    "file": m["file"],
                    "output": last_line,
                    "should_catch": m["should_catch"],
                })
            else:
                print(f"  [SURVIVED] Tests passed despite mutation! (WEAK TEST DETECTED)", flush=True)
                results.append({
                    "id": m_id,
                    "desc": m["desc"],
                    "status": "SURVIVED",
                    "file": m["file"],
                    "output": last_line,
                    "should_catch": m["should_catch"],
                })

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    print("\n================== Mutation Results Summary ==================", flush=True)
    killed = sum(1 for r in results if r["status"] == "KILLED")
    survived = sum(1 for r in results if r["status"] == "SURVIVED")
    base_fails = sum(1 for r in results if r["status"] == "BASELINE FAILS")
    na = sum(1 for r in results if r["status"].startswith("NOT APPLICABLE"))
    print(f"Total: {len(results)} | KILLED: {killed} | SURVIVED: {survived} | BASELINE FAILS: {base_fails} | N/A: {na}", flush=True)

    # Generate markdown table
    md_lines = [
        "# Mutation Testing Audit Results (`audit/mutation_results.md`)\n",
        f"**Summary**: Total: {len(results)} | **KILLED**: {killed} | **SURVIVED**: {survived} | **BASELINE FAILS**: {base_fails} | **N/A**: {na}\n",
        "| ID | File | Description | Result | Output / Failure Line | Test that Should Catch |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        status_md = f"**{r['status']}**" if r["status"] == "SURVIVED" else r["status"]
        md_lines.append(
            f"| {r['id']} | `{r['file']}` | {r['desc']} | {status_md} | `{r['output']}` | `{r['should_catch']}` |"
        )
    md_lines.append("")

    out_md = REPO_ROOT / "audit" / "mutation_results.md"
    out_md.write_text("\n".join(md_lines), encoding="utf-8")
    print(f"Report written to: {out_md}", flush=True)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None, help="Comma-separated mutation IDs to run (e.g. M1,M3)")
    args = parser.parse_args()
    only = [x.strip() for x in args.only.split(",")] if args.only else None
    res = run_mutation_audit(only)
