# Static-Analysis Stub Headers (`ebpf/stubs/`)

> **WARNING — STATIC CHECKING ONLY (`V2-compile` / `STATIC ANALYSIS`)**
>
> The headers in `ebpf/stubs/` exist **exclusively** so standalone C compilers (`zig cc`, `clang -fsyntax-only`, CI `kernel-compile` jobs) can type-check and syntax-check `ebpf/ips_engine.c` and `ebpf/xdp_v1.c` with `-Wall -Wextra` without a live Linux kernel tree or BCC runtime Clang rewriter.
>
> - **NEVER** used by `ips/engine/engine.py::BCCKernelBackend` on Linux (which compiles `ebpf/ips_engine.c` against the real running kernel's `/lib/modules/$(uname -r)/build` headers via BCC).
> - Passing `zig cc` or `clang` against these stubs proves C syntax, type safety, pointer arithmetic diagnostics, and BPF target instruction selection (`V2-compile` at most) — it **DOES NOT** prove Linux kernel BPF verifier acceptance or live packet processing (`V2`).
