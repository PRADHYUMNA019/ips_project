#!/usr/bin/env python3
"""
tests/test_shell_permissions.py — Unit tests for A1 (executable .sh mode in git) and A5 (per-class TLS & protocols).
"""
import os
import ssl
import subprocess
import pytest

from traffic.benign_iot_generator import PROFILES, build_tls_context

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_all_shell_scripts_executable_in_git():
    """A1: Fail if any tracked .sh file in the repository does not have mode 100755 in git index."""
    out = subprocess.check_output(["git", "ls-files", "--stage", "*.sh"], cwd=REPO_DIR, text=True)
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    assert len(lines) > 0, "Expected tracked .sh scripts in git"

    non_exec = []
    for line in lines:
        # Format: "<mode> <sha1> <stage>\t<path>"
        parts = line.split()
        mode = parts[0]
        path = parts[-1]
        if mode != "100755":
            non_exec.append((path, mode))

    assert len(non_exec) == 0, f"Found .sh scripts without 100755 executable bit in git: {non_exec}"


def test_per_class_protocols_and_tls_contexts():
    """A5: Verify sensors/plugs/thermostats use mqtt, cameras use https (20-200 KB), and TLS versions differ."""
    assert PROFILES["temperature_sensor"]["protocol"] == "mqtt"
    assert PROFILES["smart_plug"]["protocol"] == "mqtt"
    assert PROFILES["smart_thermostat"]["protocol"] == "mqtt"
    assert PROFILES["smart_camera"]["protocol"] == "https"
    assert PROFILES["smart_camera"]["payload_size"] == (20480, 204800)

    ctx_sensor = build_tls_context("temperature_sensor")
    ctx_therm = build_tls_context("smart_thermostat")
    if hasattr(ssl, "TLSVersion"):
        assert ctx_therm.maximum_version == ssl.TLSVersion.TLSv1_2
        assert ctx_sensor.maximum_version != ssl.TLSVersion.TLSv1_2

