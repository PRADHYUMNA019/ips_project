# Static C / eBPF Verification Report (`docs/KERNEL_STATIC_CHECKS.md`)

> **Artefact Label**: `STATIC ANALYSIS` (`V1` Python AST/regex guards + local `V2-compile` BPF object compilation via `zig cc`).
> **Honesty Boundary (Rule R2)**: Static syntax checking, `-target bpfel-freestanding` object compilation, and Python control-flow equivalence **DO NOT** prove that the Linux kernel BPF verifier accepts `ebpf/ips_engine.c` or that packets are dropped/bypassed in a live kernel (`V2`). Real kernel loading requires Prompt 7 inside an Ubuntu 22.04/24.04 VM.

---

## 1. Compiler Probe Order & What Worked on Windows (`§2.1`)

Probed in the required order (`zig cc`, `clang`, `gcc`, `cppcheck`, `clang-tidy`):

| Tool | Availability on Windows Host | Outcome |
|---|---|---|
| **`zig cc` (`ziglang 0.17.1`, Clang/LLVM 19 frontend + BPF target)** | Installed into Python environment (`python -m pip install ziglang==0.17.1`) | **WORKED**: Ran both `-fsyntax-only -Wall -Wextra -Wsign-compare` and full eBPF ELF compilation `-target bpfel-freestanding -O2 -g -Wall -Wextra -Wsign-compare -c` on `ebpf/ips_engine.c` and `ebpf/xdp_v1.c`. |
| `clang` (standalone system binary) | Not installed on Windows PATH | Covered via `zig cc` (Clang frontend) locally and `clang -target bpf` in `.github/workflows/ci.yml` (`ubuntu-24.04`). |
| `gcc` | Not installed on Windows PATH | Not needed once `zig cc` succeeded. |
| `cppcheck` / `clang-tidy` | Not installed on Windows PATH | Implemented dedicated 9-rule eBPF static source analyzer `ips/engine/bpf_source_checker.py` + 18 positive/negative unit tests (`§2.2`). |

---

## 2. Stub Headers Disclaimer (`ebpf/stubs/`)

- `ebpf/stubs/` provides minimal UAPI structure definitions (`bpf.h`, `if_ether.h`, `ip.h`, `tcp.h`, `udp.h`, `in.h`, `bpf_helpers.h`, `bpf_endian.h`) and `bcc_standalone_shim.h` (which translates BCC's `BPF_TABLE` / `BPF_RINGBUF_OUTPUT` DSL into strongly typed C function-pointer structs) **strictly for static checking and standalone CI compile tests**.
- **Never used in production Linux builds**: `ips/engine/engine.py::BCCKernelBackend` invokes BCC against the real running Linux kernel headers (`/lib/modules/$(uname -r)/build`) with `-Iebpf` (only `ebpf/generated_constants.h` is shared).

---

## 3. Warnings & Defects Found and Fixed During Static Compilation

1. **`BUG-07` (High — Missing IPv4 non-initial fragment check in `ebpf/ips_engine.c`)**:
   - **Defect**: `xdp_ips_prog` checked `ip_hdr_len` against `data_end` and immediately cast `l4 = (void *)ip + ip_hdr_len` to `struct tcphdr *` / `struct udphdr *` without checking `ip->frag_off & bpf_htons(0x1FFF)`. Non-initial IPv4 fragments carry payload bytes rather than an L4 header.
   - **Fix**: Added `if (ip->frag_off & bpf_htons(0x1FFF)) return XDP_PASS;` before L4 parsing.
2. **LLP64 Pointer-Cast Warning (`-Wint-to-void-pointer-cast` at `ebpf/ips_engine.c:172-173`)**:
   - **Warning**: Under host Windows `-fsyntax-only` (`LLP64`, `sizeof(long) == 4 < sizeof(void *) == 8`), `(void *)(long)ctx->data` emitted `warning: cast to 'void *' from smaller integer type 'long'`.
   - **Fix**: Widened cast to `(void *)(__u64)ctx->data` and `(void *)(__u64)ctx->data_end` (`64`-bit clean on both LLP64 static checks and LP64/BPF64 targets; **`0` warnings** under `-Wall -Wextra -Wsign-compare`).
3. **Standalone BPF Section & GPL License Metadata (`IPS_STANDALONE_BPF_BUILD`)**:
   - Added `#ifdef IPS_STANDALONE_BPF_BUILD SEC("xdp") #endif` and `char _license[] SEC("license") = "GPL";` so standalone `clang -target bpf -DIPS_STANDALONE_BPF_BUILD` emits an `xdp` ELF section and GPL license tag (required by `bpf_ringbuf_reserve`/`bpf_ringbuf_submit`) without altering BCC's runtime `load_func("xdp_ips_prog", BPF.XDP)` behavior.

---

## 4. Exact Static Compile Commands & Output Summary

```powershell
python -m ziglang cc -Wall -Wextra -Wsign-compare -Iebpf -Iebpf/stubs -include ebpf/stubs/bcc_standalone_shim.h -c ebpf/ips_engine.c -o results/zig_cache/ips_engine_host_check.o
# Exit code: 0 (0 warnings, 0 errors; note: in Zig 0.17.1 on Windows, -fsyntax-only skips .obj emission and triggers a Zig cache rename error, so -c -o is used for host syntax/semantic checking)

python -m ziglang cc -target bpfel-freestanding -O2 -g -Wall -Wextra -Wsign-compare -DIPS_STANDALONE_BPF_BUILD -Iebpf -Iebpf/stubs -include ebpf/stubs/bcc_standalone_shim.h -c ebpf/ips_engine.c -o results/zig_cache/ips_engine.o
# Exit code: 0 (0 warnings, 0 errors; 57,760 B ELF64 eBPF little-endian relocatable object generated)

python -m ziglang cc -target bpfel-freestanding -O2 -g -Wall -Wextra -Wsign-compare -Iebpf/stubs -c ebpf/xdp_v1.c -o results/zig_cache/xdp_v1.o
# Exit code: 0 (0 warnings, 0 errors; 13,288 B ELF64 eBPF little-endian relocatable object generated)
```

---

## 5. Nine BPF Static Source Invariants & Negative Mutation Guards (`§2.2`)

Implemented in `ips/engine/bpf_source_checker.py` and verified (both positive pass on `ebpf/ips_engine.c` and negative failure on mutated C source strings) in `tests/test_kernel_source_invariants.py`:
1. `bounded_loops`: No `while`/`do`; every `for` loop has `#pragma unroll` and a constant/macro upper bound.
2. `map_lookup_null`: Every pointer returned by `.lookup(...)` or `.ringbuf_reserve(...)` is NULL-checked before `->` dereference.
3. `packet_bounds`: Every packet header pointer (`eth`, `ip`, `tcp`, `udp`) + variable `ip_hdr_len` / `l4_hdr_len` is checked against `data_end` before field access.
4. `stack_limit`: Estimated local stack per function is $\le 512$ bytes (`xdp_ips_prog` allocates `flow_record` via per-CPU `scratch_map`, keeping stack $< 64$ bytes).
5. `allowed_helpers`: Only allowlisted BPF helpers/inline functions are called.
6. `no_floating_point`: Zero `float`/`double` types or literals.
7. `constant_divisors`: Every `/` or `%` divisor is a non-zero compile-time constant.
8. `ringbuf_pairing`: Every reserved ring-buffer slot is paired with `ringbuf_submit`/`ringbuf_discard` with zero early-return leaks.
9. `emitted_mask_order`: `rec->emitted_mask |=` appears once, strictly after `events.ringbuf_submit(ev, 0)` (Prompt 6 regression guard).

---

## 6. Statement-by-Statement C Control-Flow Equivalence (`§2.3`)

- `ips/engine/c_control_flow_model.py::CControlFlowModel` mirrors `ebpf/ips_engine.c` line-by-line (`verdict_map` lookup & monotonic TTL delete -> Tier-0 SYN fixed-point token bucket -> canonical `flow_key` -> FIN/RST+SYN and `FLOW_IDLE_NS` reinit -> `scratch_map` zero-init -> `valid_len` & `iat_ns` update -> `ckpt_hit` else-if chain -> `shed` -> `ringbuf_reserve` retry -> `ringbuf_submit` -> `emitted_mask |=`).
- Hypothesis test `test_c_control_flow_model_equals_mock_bpf_backend_on_random_traces` feeds 50 randomized 60-packet multi-flow traces (with SYN bursts, FIN+SYN 5-tuple reuse, 130 s idle gaps, load-shedding toggles, ring-buffer saturation, and verdict TTL expirations) into both `CControlFlowModel` and `MockBPFBackend`, asserting **100% identical XDP actions, emitted events, and telemetry counters**.
