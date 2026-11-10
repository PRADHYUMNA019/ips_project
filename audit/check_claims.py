#!/usr/bin/env python3
"""audit/check_claims.py — Audit claims, forbidden wording, and hardware overstatements.

Scans the repository for:
1. Forbidden laptop-simulation wording:
   - "on-device results"
   - "validated on edge hardware"
   - "real device"
   - "resource-constrained device measurements"
   - "Raspberry Pi results"
   - Any hardware model named as if measured
2. Occurrences of "On-Device", "Raspberry", "edge hardware"
3. Audits paper contributions C1–C4 status
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_PHRASES = [
    "on-device results",
    "validated on edge hardware",
    "real device",
    "resource-constrained device measurements",
    "Raspberry Pi results",
    "100% interception",
    "Interception Efficiency",
]

KEYWORDS = [
    "on-device",
    "On-Device",
    "Raspberry",
    "edge hardware",
    "physical device",
    "hardware validation",
]

SCAN_EXTENSIONS = {".md", ".py", ".sh", ".yaml", ".yml", ".c", ".h"}
EXCLUDE_DIRS = {".git", ".venv", "results", "__pycache__"}


def scan_claims():
    print("=== Scanning Repository for Claims, Overstatements, and Forbidden Wording ===")

    findings_forbidden = []
    findings_keywords = []

    for path in sorted(REPO_ROOT.rglob("*")):
        if path.is_dir() or path.suffix not in SCAN_EXTENSIONS:
            continue
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        # Skip audit/ directory and AUDIT_REPORT.md itself to avoid matching check definitions
        if "audit" in path.parts or path.name == "AUDIT_REPORT.md":
            continue

        rel_path = path.relative_to(REPO_ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        lines = text.splitlines()
        for idx, line in enumerate(lines, 1):
            lower_line = line.lower()

            for phrase in FORBIDDEN_PHRASES:
                if phrase.lower() in lower_line:
                    findings_forbidden.append((rel_path, idx, phrase, line.strip()))

            for kw in KEYWORDS:
                if kw in line:
                    findings_keywords.append((rel_path, idx, kw, line.strip()))

    print(f"\n1. Explicit Forbidden Phrases Found: {len(findings_forbidden)}")
    for f in findings_forbidden:
        print(f"  [FORBIDDEN] {f[0]}:{f[1]} (matched '{f[2]}'): {f[3]}")

    print(f"\n2. Keywords Scanned ('On-Device', 'Raspberry', etc.): {len(findings_keywords)}")
    for f in findings_keywords:
        print(f"  [KEYWORD] {f[0]}:{f[1]} ({f[2]}): {f[3]}")

    return findings_forbidden, findings_keywords


CANONICAL_TITLE = (
    "Drift-Resilient On-Device Inline Intrusion Prevention for Encrypted Traffic "
    "in Resource-Constrained Smart Systems Against Zero-Day Attacks"
)


def check_title_consistency() -> list[str]:
    """Verify README.md, docs/spec.md, and docs/PAPER_OUTLINE.md carry the identical canonical title."""
    errors = []

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


if __name__ == "__main__":
    forbidden, keywords = scan_claims()
    title_errors = check_title_consistency()
    sys.exit(1 if (forbidden or title_errors) else 0)
