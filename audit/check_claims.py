#!/usr/bin/env python3
"""audit/check_claims.py — Audit claims, forbidden wording, title consistency, and doc-vs-code sync (Prompt 10 §1.4).

Scans the repository for:
1. Forbidden laptop-simulation / unverified-claim phrases.
2. Unsupported WSL2 recommendations (WSL2 is only allowed in explicit 'no WSL2' / 'unsupported' warnings).
3. Exact canonical title consistency across README.md, docs/spec.md, and docs/PAPER_OUTLINE.md (Rule R4).
4. Existence of repo-local code/script/config files and Makefile targets referenced in docs, README, Makefile, and demo/run_demo.ps1.
5. Single-source-of-truth sync between configs/system.yaml, ips/engine/schema.py, and ebpf/generated_constants.h.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from ips.engine.c_struct_parser import verify_all_c_structs_match_ctypes
from ips.engine.schema import GENERATED_HEADER_PATH, generate_c_header, load_system_config

FORBIDDEN_PHRASES = [
    "on-device results",
    "validated on edge hardware",
    "real device",
    "resource-constrained device measurements",
    "Raspberry Pi results",
    "100% interception",
    "Interception Efficiency",
    "detects zero-day attacks",
    "zero-day detected",
    "validated on hardware",
    "real-time at line rate",
]

KEYWORDS = [
    "on-device",
    "On-Device",
    "Raspberry",
    "edge hardware",
    "physical device",
    "hardware validation",
]

SCAN_EXTENSIONS = {".md", ".py", ".sh", ".ps1", ".yaml", ".yml", ".c", ".h"}
EXCLUDE_DIRS = {".git", ".venv", "results", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"}

CANONICAL_TITLE = (
    "Drift-Resilient On-Device Inline Intrusion Prevention for Encrypted Traffic "
    "in Resource-Constrained Smart Systems Against Zero-Day Attacks"
)

CHECKED_REPO_PREFIXES = ("ips/", "datasets/", "scripts/", "configs/", "ebpf/", "engine/", "traffic/", "audit/", "demo/")
HISTORICAL_DOC_SKIP = {"AUDIT_REPORT.md", "PROGRESS.md", "SELF_REVIEW.md", "KNOWN_ISSUES.md", "CONSISTENCY_AUDIT.md"}


def scan_claims() -> tuple[list[tuple[str, int, str, str]], list[tuple[str, int, str, str]]]:
    print("=== Scanning Repository for Claims, Overstatements, and Forbidden Wording ===")

    findings_forbidden: list[tuple[str, int, str, str]] = []
    findings_keywords: list[tuple[str, int, str, str]] = []

    for path in sorted(REPO_ROOT.rglob("*")):
        if path.is_dir() or path.suffix not in SCAN_EXTENSIONS:
            continue
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        if "audit" in path.parts or path.name in {"AUDIT_REPORT.md", "SELF_REVIEW.md"}:
            continue
        if path.parts[-2:] == ("tests", "test_bugfixes_p10.py"):
            continue

        rel_path = path.relative_to(REPO_ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for idx, line in enumerate(text.splitlines(), 1):
            lower_line = line.lower()

            for phrase in FORBIDDEN_PHRASES:
                if phrase.lower() in lower_line:
                    # Allow explicit negative statements such as 'Never write "detects zero-day attacks"' or 'no "zero-day detected"'
                    if any(neg in lower_line for neg in ("never write", 'no "', "forbidding", "do not claim", "does not")):
                        continue
                    findings_forbidden.append((rel_path, idx, phrase, line.strip()))

            if "wsl2" in lower_line:
                if not any(ok in lower_line for ok in ("no wsl2", "unsupported", "removed wsl2", "not wsl2", "without wsl2")):
                    findings_forbidden.append((rel_path, idx, "WSL2 recommendation (unsupported for XDP)", line.strip()))

            for kw in KEYWORDS:
                if kw in line:
                    findings_keywords.append((rel_path, idx, kw, line.strip()))

    print(f"\n1. Explicit Forbidden Phrases / Unsupported WSL2 Found: {len(findings_forbidden)}")
    for f in findings_forbidden:
        print(f"  [FORBIDDEN] {f[0]}:{f[1]} (matched '{f[2]}'): {f[3]}")

    print(f"\n2. Keywords Scanned ('On-Device', 'Raspberry', etc.): {len(findings_keywords)}")
    return findings_forbidden, findings_keywords


def check_title_consistency() -> list[str]:
    """Verify README.md, docs/spec.md, and docs/PAPER_OUTLINE.md carry the identical canonical title."""
    errors: list[str] = []

    readme_line1 = (REPO_ROOT / "README.md").read_text(encoding="utf-8").splitlines()[0].strip()
    readme_title = readme_line1.removeprefix("# ").strip()

    spec_line1 = (REPO_ROOT / "docs" / "spec.md").read_text(encoding="utf-8").splitlines()[0].strip()
    spec_title = spec_line1.removeprefix("# System Specification:").removeprefix("#").strip()

    outline_lines = (REPO_ROOT / "docs" / "PAPER_OUTLINE.md").read_text(encoding="utf-8").splitlines()
    outline_title = ""
    for ln in outline_lines:
        if "**Working Title**:" in ln:
            m = re.search(r"\*([^*]+)\*", ln.split("**Working Title**:", 1)[1])
            if m:
                outline_title = m.group(1).strip()
            break

    titles = {
        "README.md": readme_title,
        "docs/spec.md": spec_title,
        "docs/PAPER_OUTLINE.md": outline_title,
    }
    print("\n3. Title Consistency Check (Rule R4):")
    for loc, t in titles.items():
        print(f"  [{loc}]: {t}")
        if t != CANONICAL_TITLE:
            errors.append(f"{loc} title '{t}' != canonical '{CANONICAL_TITLE}'")

    if len(set(titles.values())) > 1:
        errors.append("Titles differ across README.md, docs/spec.md, and docs/PAPER_OUTLINE.md!")

    for err in errors:
        print(f"  [TITLE MISMATCH] {err}")
    return errors


def check_docs_and_config_consistency() -> list[str]:
    """Verify file paths & Makefile targets in docs/README/Makefile/run_demo.ps1 and YAML<->C header sync."""
    errors: list[str] = []

    # 1. Parse Makefile targets
    makefile_text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    make_targets = set(re.findall(r"^([A-Za-z0-9_-]+)\s*:", makefile_text, flags=re.MULTILINE))

    # 2. Check backticked repo paths and `make <target>` commands across active docs
    doc_files = [REPO_ROOT / "README.md", REPO_ROOT / "Makefile", REPO_ROOT / "demo" / "run_demo.ps1"]
    doc_files.extend(sorted((REPO_ROOT / "docs").glob("*.md")))

    path_regex = re.compile(
        r"(?:^|[\s`\"'(])((?:ips|datasets|scripts|configs|ebpf|engine|traffic|audit|demo)/[A-Za-z0-9_./-]+\.(?:py|sh|ps1|yaml|yml|c|h))\b"
    )
    make_cmd_regex = re.compile(r"`make\s+([A-Za-z0-9_-]+)`")

    for doc in doc_files:
        if not doc.exists() or doc.name in HISTORICAL_DOC_SKIP:
            continue
        rel_doc = doc.relative_to(REPO_ROOT).as_posix()
        txt = doc.read_text(encoding="utf-8", errors="replace")
        for line_no, ln in enumerate(txt.splitlines(), 1):
            for m in path_regex.finditer(ln):
                ref_rel = m.group(1)
                if "*" in ref_rel or "<" in ref_rel or "{" in ref_rel:
                    continue
                # Planned Phase 4/8 files may be referenced in forward plans if marked future/planned
                if not (REPO_ROOT / ref_rel).exists():
                    if any(tag in ln.lower() for tag in ("planned", "phase ", "deferred", "not yet", "will ")):
                        continue
                    errors.append(f"Missing file referenced at {rel_doc}:{line_no}: '{ref_rel}'")
            for mm in make_cmd_regex.finditer(ln):
                tgt = mm.group(1)
                if tgt not in make_targets:
                    if any(tag in ln.lower() for tag in ("planned", "phase 3")):
                        continue
                    errors.append(f"Undefined Makefile target 'make {tgt}' at {rel_doc}:{line_no}")

    # 3. Verify configs/system.yaml <-> ebpf/generated_constants.h <-> C struct ABI
    cfg = load_system_config()
    expected_hdr = generate_c_header(cfg)
    gen_path = Path(GENERATED_HEADER_PATH)
    if not gen_path.exists():
        errors.append("Missing ebpf/generated_constants.h")
    else:
        actual_hdr = gen_path.read_text(encoding="utf-8")
        if actual_hdr != expected_hdr:
            errors.append("ebpf/generated_constants.h does not match configs/system.yaml via ips.engine.schema.generate_c_header()")

    early_n_yaml = int(cfg.get("system", {}).get("early_n", 16))
    struct_report = verify_all_c_structs_match_ctypes(early_n=early_n_yaml)
    if not struct_report["passed"]:
        for m_err in struct_report["mismatches"]:
            errors.append(f"C/ctypes struct mismatch: {m_err}")

    # Verify configs/devices.yaml is valid YAML with unique IPs and device_ids
    dev_cfg = yaml.safe_load((REPO_ROOT / "configs" / "devices.yaml").read_text(encoding="utf-8")) or {}
    devs = dev_cfg.get("devices", [])
    ids = [d["device_id"] for d in devs]
    ips = [d["ip"] for d in devs]
    if len(ids) != len(set(ids)) or len(ips) != len(set(ips)):
        errors.append("Duplicate device_id or IP in configs/devices.yaml")

    print(f"\n4. Docs, Configs & C/Python Schema Sync Errors: {len(errors)}")
    for err in errors:
        print(f"  [SYNC ERROR] {err}")
    return errors


if __name__ == "__main__":
    forbidden, _keywords = scan_claims()
    title_errors = check_title_consistency()
    sync_errors = check_docs_and_config_consistency()
    sys.exit(1 if (forbidden or title_errors or sync_errors) else 0)
