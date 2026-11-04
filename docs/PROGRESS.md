# Progress Tracker

> Last updated: WP0b (branch `wp0-fix-30pct`)
> Platform detected: Windows (`platform.system() == "Windows"`, win32, Python 3.12.3)

## Verification Classes
- **V1 – Ran here:** Pure-Python logic, models, EVT, drift, and unit tests. Executed on host.
- **V2 – Linux-only:** Topology (netns/veth/bridges), XDP/eBPF kernel programs, BCC loader, tcpdump capture, services (mosquitto/nginx), attack injectors, system measurements. Statically checked where possible; marked `CODE WRITTEN, NOT RUN (Linux required)`.
- **V3 – Data-dependent:** Experiments and metrics requiring real pcap captures or public datasets. Marked `NOT RUN (needs real data)`.

## 60% Checklist

| # | Item | WP | Status | Evidence |
|---|------|----|--------|----------|
| 1 | Repaired generator, per-device IPs, no committed secrets, truthful README | WP0 / WP0b | PARTIAL (V1 DONE, V2 code written) | V1: `pytest tests/test_generator.py tests/test_topology_parse.py` (7 passed); V2: `topology.sh` rewritten for 12 devices / 14 namespaces, `NOT RUN (Linux required)` |
| 2 | `docs/spec.md`, `docs/LIMITATIONS.md`, `docs/related_work_todo.md`, `docs/TODO_USER.md` | WP1 | In Progress | |
| 3 | `docs/DATA_CARD.md`, adapters, audit scripts | WP2 | Pending | |
| 4 | Labelled TLS testbed captures with manifest, services, attacks A1–A5 | WP3 | Pending | |
| 5 | Shared feature implementation (`ips/features.py`), shortcut guard | WP4 | Pending | |
| 6 | Offline detection (IF/AE/Kitsune-style), EVT calibration, INT8 quantization | WP5 | Pending | |
| 7 | Kernel v2 (`ebpf/ips_engine.c`), verdict cache, LRU state, tier-0 guard | WP6 | Pending | |
| 8 | Closed loop v2 (`ips/engine`), watchdog, measurement harness | WP7 | Pending | |
| 9 | Drift guard (ADWIN, G1–G4 checks, scenarios S1–S5) | WP8 | Pending | |
| 10 | `make reproduce`, `docs/RESULTS.md`, final consolidation | WP9 | Pending | |

## WP0b — Corrections Summary
- **F1 / A4 (Generator)**: Repaired `wait` order in `benign_iot_generator.py`. Added `--connection persistent|reconnect`, `--device-from-config`, `--time-scale`, and `reconnect_after_msgs` in profiles.
- **F2 / A1 (Topology Parsing)**: Fixed `scripts/topology.sh` `parse_devices` untrimmed regex. Added `scripts/topology.sh list`. Validated with `tests/test_topology_parse.py`. Config defines 12 devices in 4 classes, plus attacker and server (14 namespaces total).
- **A3 (Demo Scripts)**: Updated `scripts/demo.sh`, `scripts/baseline.sh`, and `scripts/monitor.sh` to match new 12-device fleet (`sensor-01` etc.) with dynamic IP resolution.
- **A5 (Config Status)**: Documented active vs WP6 keys in `configs/system.yaml`.
- **A6 (Certificates)**: Aligned `traffic/tls_server.py` and `scripts/gen_certs.sh` on common SAN (10.0.2.10, 127.0.0.1, localhost).
- **Environment**: Added `.gitattributes` (LF endings), `requirements.txt`, `requirements-linux.txt`.

## Evidence (V1 Executed)
- `pytest tests/test_generator.py`: 5 passed (test_device_sends_multiple_messages_one_connection, test_slow_profile_sends_multiple_messages, test_reconnect_connection_mode, test_persistent_reconnect_after_msgs, test_time_scale_speeds_up).
- `pytest tests/test_topology_parse.py`: 2 passed (YAML structure verified 12 devices, bash list parser verified).

## Not Run (V2 / Linux required)
- `scripts/topology.sh create|teardown|show`: requires Linux root + iproute2.
- `scripts/xdp.sh attach`: requires Linux root + BCC + kernel headers.
- `scripts/demo.sh`: requires Linux namespaces and XDP.

## Remaining 40% (Post-60% Scope)
- Gateway VM with hard cgroup CPU/RAM limits
- Raspberry Pi 4/5 hardware validation
- libbpf / CO-RE precompiled bytecode loader
- Extended public datasets (full CIC-IDS2018 220GB, full CIC-IoT-2023)
- Paper writing and camera-ready drafting
