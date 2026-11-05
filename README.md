# Drift-Resilient Inline IPS for Encrypted Traffic

> **Scope note (evaluation):** All measurements are obtained on an emulated resource-constrained gateway (Linux network namespaces on a laptop/VM; user-space engine limited by cgroups; XDP in generic mode, unconstrained). No physical embedded device was measured. Title wording is pending guide approval (TITLE_DECISION_PENDING).

> **Status: 30% → 60% rebuild in progress (branch `wp0-fix-30pct`).**
> See [`docs/PROGRESS.md`](docs/PROGRESS.md) for the current checklist.

## What this project is

A two-tier inline Intrusion Prevention System research prototype:

- **Fast path (eBPF/XDP):** stateful per-flow tracking of the first N
  payload-bearing packets, verdict cache enforcement (bypass/drop with TTL).
- **Slow path (Python):** anomaly scoring with a quantized autoencoder,
  EVT-calibrated thresholds, poisoning-aware drift guard.

The target environment is a Linux gateway protecting an IoT/smart-system
network where traffic is TLS-encrypted and payloads cannot be inspected.

## What works today (30% baseline)

| Component | Status | Notes |
|-----------|--------|-------|
| Network topology (`scripts/topology.sh`) | ✅ Working | Per-device namespaces, idempotent create/teardown/show |
| TLS echo server (`traffic/tls_server.py`) | ✅ Working | Runtime cert generation |
| Benign traffic generator | ✅ Fixed | F1 `wait` bug fixed; per-device IPs |
| XDP baseline (`ebpf/xdp_v1.c`) | ✅ Working | Drop-map-only, no model, ingress-only |
| Ring-buffer engine (`engine/ringbuf_engine.py`) | ⚠️ Stub | Placeholder IAT rule, not a real detector |
| Attack beacon (`traffic/attack_beacon.py`) | ⚠️ Stub | 20 ms beacon ≠ real C2; timeout ≠ blocked |
| Offline pipeline | ❌ Missing | No feature extraction, no model, no data |
| Drift guard | ❌ Missing | Not yet implemented |
| Verdict cache | ❌ Missing | Print-only, no TTL, no kernel enforcement |

## What is NOT yet implemented

- Real anomaly detection model (WP5)
- EVT threshold calibration (WP5)
- Bidirectional XDP tracking (WP6)
- Per-flow verdict cache with TTL (WP6)
- Closed-loop model-driven verdicts (WP7)
- Drift detection and poisoning-aware guard (WP8)
- Public dataset integration (WP2)
- Resource-constrained evaluation (remaining 40%)
- Physical embedded hardware validation (planned post-60% scope)

## Quick start (demo of the 30% baseline)

```bash
# Requires: Linux with root, BCC (python3-bpfcc), openssl
sudo ./scripts/topology.sh create
sudo ./scripts/gen_certs.sh
sudo ip netns exec srv python3 traffic/tls_server.py &
sudo ip netns exec sensor-01 python3 traffic/benign_iot_generator.py \
    --device-id sensor-01 --profile temperature_sensor --duration 30
```

Full automated demo (XDP + engine): `sudo ./scripts/demo.sh`

## Repository layout

```
ebpf/               XDP kernel programs (xdp_v1.c baseline)
engine/              Ring-buffer engine (30% stub)
traffic/             Traffic generators (benign + attack)
scripts/             Topology, XDP attach, demo, cert generation
configs/             system.yaml, devices.yaml
tests/               pytest test suite
docs/                Specifications, progress, limitations
```

## Honesty policy

This is a research project. See `docs/LIMITATIONS.md` for known
limitations. Numbers in results come from reproducible scripts. Claims
are scoped to what has been measured. See `docs/PROGRESS.md` for the
full status.
