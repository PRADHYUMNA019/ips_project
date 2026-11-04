# Known Limitations and Open Engineering Constraints

This document records architectural, experimental, and empirical limitations of the prototype. In adherence to research honesty rules (H4, H5, H6), these boundaries are explicitly acknowledged.

---

## 1. Environment & Emulation Boundaries
- **Emulated Gateway Environment (Rule H4)**:
  - All multi-device experiments at 60% are conducted inside Linux network namespaces on a host/VM kernel, interconnected via software Linux bridges (`br-lan`, `br-wan`) and `veth` interface pairs.
  - Resource profiles (S, M, L) are enforced on the user-space process via Linux cgroups (`systemd-run -p CPUQuota=... -p MemoryMax=...`).
  - Physical embedded gateway deployments (e.g. Raspberry Pi 4/5, OpenWrt routers) are designated as post-60% validation.
- **XDP Driver Mode (Rule H5)**:
  - When evaluated on virtual `veth` interfaces, XDP runs in **Generic/SKB mode** (`XDP_FLAGS_SKB_MODE`).
  - Native driver XDP (`XDP_FLAGS_DRV_MODE`) requires hardware NIC driver support and provides significantly higher packet processing throughput than generic mode. Every performance table explicitly logs the driver mode used.

---

## 2. Kernel & Engine Toolchain (Finding F15)
- **BCC Runtime Clang Dependency**:
  - The user-space engine utilizes BCC (`python3-bpfcc`), which requires Clang, LLVM, and Linux kernel header packages (`linux-headers-$(uname -r)`) to compile eBPF C code at runtime initialization.
  - This compiler toolchain adds ~150–250 MB of disk overhead and initial startup latency, which conflicts with minimal edge firmware constraints.
  - *Remedy for 100%*: Migrate from BCC to precompiled CO-RE (Compile-Once Run-Everywhere) BPF bytecode loaded via `libbpf` and Python ctypes bindings.

---

## 3. Protocol & Inspection Boundaries
- **Early-Packet Leakage Window**:
  - By definition, an early-flow inline detector allows the first $N$ payload packets (default $N=12$) plus handshake packets to pass through the gateway while features are being gathered.
  - Attacks with short payloads (e.g. single-packet exploits) can deliver their full payload before the verdict is reached.
- **Slow Persistent Connections (Time-to-Verdict)**:
  - Devices configured with long transmission intervals (e.g. 30–60 seconds between telemetry reports) on keep-alive connections require multiple minutes to reach packet $N$.
  - An attacker leveraging an existing persistent connection can exfiltrate data slowly prior to triggering verdict evaluation.
- **QUIC, ECH, and IPv6**:
  - QUIC / HTTP/3 operates over UDP with connection migration, which bypasses the TCP 5-tuple canonicalization logic.
  - Encrypted Client Hello (ECH) masks SNI metadata; the current system remains payload-independent, but does not parse secondary outer/inner ClientHello structures.
  - Fast-path lookup tables are indexed by 32-bit IPv4 addresses; IPv6 is not implemented.

---

## 4. Drift Adaptation Boundaries
- **Coordinated Class-Wide Poisoning (Scenario S4)**:
  - Guard G2 enforces cross-device consistency within a device class: an update is considered legitimate only if at least $\rho = 60\%$ of devices in that class exhibit the behavioral shift.
  - If an adversary compromises $\ge 60\%$ of the devices within a specific class simultaneously, Guard G2 will be satisfied and coordinated poisoning can succeed. This is reported honestly as an inherent threshold limit.
- **Small Device Fleets**:
  - Device classes with fewer than 3 devices cannot reliably compute cross-device quorum ($\rho \times K \ge 2$). For these classes, automated adaptation is disabled and alerts require operator confirmation.
