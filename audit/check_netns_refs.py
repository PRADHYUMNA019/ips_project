#!/usr/bin/env python3
"""audit/check_netns_refs.py - Audit network namespace and IP references across scripts.

Verifies:
1. Every `ip netns exec <name>` in any script targets a namespace created by scripts/topology.sh.
2. No script references legacy/removed namespaces (e.g. iot1, iot2).
3. Every IP referenced in scripts or configs matches the topology allocation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

SCRIPTS = [
    "scripts/demo.sh",
    "scripts/baseline.sh",
    "scripts/monitor.sh",
    "scripts/run_experiment.sh",
    "scripts/collect.sh",
    "scripts/verify_linux.sh",
    "scripts/capture.sh",
    "scripts/block_ip.sh",
    "scripts/netem_sweep.sh",
    "scripts/xdp_selftest.sh",
    "scripts/topology.sh",
]

# Load expected namespaces and IPs dynamically from configs/devices.yaml + topology defaults
DEVICES_YAML = REPO_ROOT / "configs" / "devices.yaml"
with open(DEVICES_YAML, "r", encoding="utf-8") as f:
    dev_cfg = yaml.safe_load(f)

EXPECTED_NETNS = {"gw", "srv", "attacker"}
REGISTERED_IPS = {
    "10.0.1.1", "10.0.2.1", "10.0.1.0", "10.0.2.0", "10.0.1.255", "10.0.2.255"
}

for dev in dev_cfg.get("devices", []):
    EXPECTED_NETNS.add(dev["device_id"])
    REGISTERED_IPS.add(dev["ip"])

if "attacker" in dev_cfg:
    EXPECTED_NETNS.add(dev_cfg["attacker"]["device_id"])
    REGISTERED_IPS.add(dev_cfg["attacker"]["ip"])

if "server" in dev_cfg:
    EXPECTED_NETNS.add(dev_cfg["server"]["device_id"])
    REGISTERED_IPS.add(dev_cfg["server"]["ip"])

FORBIDDEN_LEGACY_NETNS = {"iot1", "iot2"}
FORBIDDEN_LEGACY_IPS = {"10.0.1.2"}

NETNS_EXEC_RE = re.compile(r"ip\s+netns\s+exec\s+([A-Za-z0-9_\-\$\{\}]+)")
IP_RE = re.compile(r"\b(10\.0\.[0-9]+\.[0-9]+)\b")


def check_references():
    findings = []
    print("=== Auditing NetNS and IP References across scripts ===")
    print(f"Known expected netns ({len(EXPECTED_NETNS)}): {sorted(EXPECTED_NETNS)}")
    print(f"Known registered IPs ({len(REGISTERED_IPS)}): {sorted(REGISTERED_IPS)}")

    for script_rel in SCRIPTS:
        script_path = REPO_ROOT / script_rel
        if not script_path.exists():
            findings.append((script_rel, 0, f"File missing: {script_rel}", "MAJOR"))
            continue

        text = script_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            # Check netns exec
            for match in NETNS_EXEC_RE.finditer(line):
                target = match.group(1)
                # Ignore bash variables like "$dev", "${dev}", "$ns"
                if target.startswith("$"):
                    continue
                if target in FORBIDDEN_LEGACY_NETNS:
                    findings.append((
                        script_rel, idx,
                        f"References forbidden legacy netns '{target}': {line.strip()}",
                        "BLOCKER"
                    ))
                elif target not in EXPECTED_NETNS:
                    findings.append((
                        script_rel, idx,
                        f"Unknown netns target '{target}' (not created by topology.sh): {line.strip()}",
                        "MAJOR"
                    ))

            # Check IPs
            for match in IP_RE.finditer(line):
                ip = match.group(1)
                if ip in FORBIDDEN_LEGACY_IPS:
                    findings.append((
                        script_rel, idx,
                        f"References legacy 30% shared IP {ip}: {line.strip()}",
                        "BLOCKER"
                    ))
                elif ip not in REGISTERED_IPS:
                    findings.append((
                        script_rel, idx,
                        f"Unregistered IP '{ip}' found in script: {line.strip()}",
                        "MINOR"
                    ))

    print(f"\nTotal findings: {len(findings)}")
    for f in findings:
        print(f"[{f[3]}] {f[0]}:{f[1]} - {f[2]}")
    return findings


if __name__ == "__main__":
    findings = check_references()
    sys.exit(1 if any(f[3] in {"BLOCKER", "MAJOR"} for f in findings) else 0)
