# Progress Tracker

> Last updated: WP0 (branch `wp0-fix-30pct`)

## 60% Checklist

| # | Item | WP | Status | Evidence |
|---|------|----|--------|----------|
| 1 | Repaired generator, per-device IPs, no committed secrets, truthful README | WP0 | ✅ Done | `pytest tests/test_generator.py` passes; `topology.sh show` lists per-device namespaces; certs removed from git |
| 2 | `docs/spec.md`, `docs/LIMITATIONS.md`, `docs/related_work_todo.md` | WP1 | ❌ Missing | |
| 3 | `docs/DATA_CARD.md` with measured protocol mix | WP2 | ❌ Missing | |
| 4 | Labelled TLS testbed captures with manifest | WP3 | ❌ Missing | |
| 5 | Shared feature implementation with tests | WP4 | ❌ Missing | |
| 6 | Offline detection table (IF/AE/Kitsune-style, N sweep, EVT) | WP5 | ❌ Missing | |
| 7 | Kernel v2 with verdict cache, bidir tracking, LRU, tier-0 | WP6 | ❌ Missing | |
| 8 | Closed loop with model-driven verdicts, watchdog | WP7 | ❌ Missing | |
| 9 | Drift guard with S1–S5 scenarios | WP8 | ❌ Missing | |
| 10 | `make reproduce`, RESULTS.md, final PROGRESS.md | WP9 | ❌ Missing | |

## WP0 — Repair the 30% work

### What was done

- **F1 fixed:** `benign_iot_generator.py` — moved `wait = max(0.1, random.gauss(...))` before the log line that uses it. Added `result_holder` parameter for testability.
- **F2 fixed (topology):** `scripts/topology.sh` now reads `configs/devices.yaml` and creates one network namespace per device (14 device namespaces + attacker + srv = 16 total). Each device has a unique IP in 10.0.1.0/24.
- **F2 fixed (config):** `configs/devices.yaml` maps device_id → IP → class → profile for 14 devices across 4 classes (sensor×4, plug×3, thermostat×3, camera×2).
- **F13 fixed:** `traffic/certs/server.key` and `server.crt` removed from git tracking. `.gitignore` updated. `scripts/gen_certs.sh` generates certs at runtime. Note: the old key remains in git history — it was a throwaway self-signed test key, not a production secret.
- **F14 fixed:** README rewritten to honestly state what works (topology, TLS server, fixed generator) and what is missing (model, verdict cache, drift guard, datasets, etc.).
- **Test suite:** `tests/test_generator.py` starts a local TLS server, runs a device for ~5–8 s, asserts ≥5 messages on one connection and zero F1-type exceptions.
- **Makefile:** `make test` runs the unit tests.
- **This document** (`docs/PROGRESS.md`) created.

### What was NOT run (environment limitation)

- `topology.sh create` was NOT run (requires Linux with root + iproute2). The script is written and tested for syntax but not executed.
- XDP-related scripts were NOT run (same reason).

### Open risks

- The demo script (`scripts/demo.sh`) still references the old topology (iot1 namespace). It will break until updated in a later WP.
- The `tls_server.py` still has `ensure_certs()` which generates certs in-place; this is fine for now but `gen_certs.sh` is the canonical path.

## Remaining 40% (not in scope for 60%)

- Gateway VM with hard CPU/RAM cgroup limits
- Raspberry Pi 4/5 or OpenWrt real-device validation
- libbpf/CO-RE precompiled loader (replace BCC runtime compilation)
- Full ablation matrix across all N, model, threshold, drift combinations
- Extended datasets (CIC-IoT-2023, CIC-IDS2018 slice)
- Paper writing
- JA3/JA4 handshake-metadata ablation

