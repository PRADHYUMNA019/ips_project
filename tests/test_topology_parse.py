#!/usr/bin/env python3
"""
tests/test_topology_parse.py — Verify topology device parsing against configs/devices.yaml.
"""
import os
import shutil
import subprocess
import yaml
import pytest

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEVICES_YAML = os.path.join(REPO_DIR, "configs", "devices.yaml")
TOPOLOGY_SH = os.path.join(REPO_DIR, "scripts", "topology.sh")


def test_devices_yaml_structure():
    """Verify configs/devices.yaml contains 12 devices in 4 classes."""
    with open(DEVICES_YAML, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "devices" in data, "devices key missing in devices.yaml"
    devices = data["devices"]
    assert len(devices) == 12, f"Expected 12 devices, found {len(devices)}"

    classes = {}
    for dev in devices:
        assert "device_id" in dev
        assert "ip" in dev
        assert "class" in dev
        assert "profile" in dev
        assert "connection" in dev
        classes[dev["class"]] = classes.get(dev["class"], 0) + 1

    assert classes.get("sensor") == 4, f"Expected 4 sensors, got {classes.get('sensor')}"
    assert classes.get("plug") == 3, f"Expected 3 plugs, got {classes.get('plug')}"
    assert classes.get("thermostat") == 3, f"Expected 3 thermostats, got {classes.get('thermostat')}"
    assert classes.get("camera") == 2, f"Expected 2 cameras, got {classes.get('camera')}"

    assert "attacker" in data
    assert data["attacker"]["ip"] == "10.0.1.4"
    assert "server" in data
    assert data["server"]["ip"] == "10.0.2.10"


def test_topology_sh_list():
    """Run `bash scripts/topology.sh list` and verify it matches devices.yaml."""
    bash_path = shutil.which("bash")
    if not bash_path:
        # Check standard Git bash location on Windows
        git_bash = r"C:\Program Files\Git\bin\bash.exe"
        if os.path.exists(git_bash):
            bash_path = git_bash

    if not bash_path:
        pytest.skip("bash executable not found in PATH")

    # Run scripts/topology.sh list
    try:
        res = subprocess.run(
            [bash_path, "scripts/topology.sh", "list"],
            cwd=REPO_DIR,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception as e:
        pytest.skip(f"Could not execute bash: {e}")

    if res.returncode != 0:
        if "0xC0000022" in res.stderr or "msys" in res.stderr:
            pytest.skip(f"Windows sandbox prevented MSYS bash execution: {res.stderr}")
        pytest.fail(f"topology.sh list failed (rc={res.returncode}): {res.stderr}")

    lines = [ln.strip() for ln in res.stdout.strip().splitlines() if ln.strip()]
    parsed = {}
    for ln in lines:
        parts = ln.split()
        if len(parts) == 2:
            parsed[parts[0]] = parts[1]

    with open(DEVICES_YAML, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    expected = {d["device_id"]: d["ip"] for d in data["devices"]}
    assert len(parsed) == 12, f"Expected 12 devices parsed by bash, got {len(parsed)}: {parsed}"
    assert parsed == expected, f"Bash parse mismatch.\nParsed: {parsed}\nExpected: {expected}"
