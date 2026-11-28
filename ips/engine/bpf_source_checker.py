#!/usr/bin/env python3
"""
ips/engine/bpf_source_checker.py — Static source-text eBPF verifier invariant checker (Prompt 10 §2.2).

NOTE: This module inspects C source text (`STATIC ANALYSIS`, V1). Passing these checks
does NOT execute `ebpf/ips_engine.c` in a Linux kernel and does NOT substitute for the
Linux kernel BPF verifier (`V2`).

Enforces 9 BPF-specific static rules on `ebpf/ips_engine.c`:
  R_LOOP:     Every `for`/`while` loop has an explicit `#pragma unroll` immediately preceding it
              and a constant upper bound (`no unbounded loops`).
  R_MAP_NULL: Every pointer returned by `.lookup(...)` or `.ringbuf_reserve(...)` is NULL-checked
              before any `->` or `*` dereference on that pointer variable.
  R_PKT_END:  Every packet header pointer (`eth`, `ip`, `tcp`, `udp`) derived from `data` has a
              `> data_end` bounds guard before field dereference.
  R_STACK:    Estimated local stack frame per function is <= 512 bytes (large structs like
              `flow_record` must come from per-CPU `scratch_map`, never allocated on the BPF stack).
  R_HELPERS:  Only allowlisted BPF helpers/macros/inline functions are called inside `xdp_ips_prog`.
  R_NO_FP:    No `float` or `double` types or floating-point literals appear in kernel C code.
  R_DIV_CONST: Every `/` or `%` divisor in executable code is a non-zero compile-time constant.
  R_RINGBUF:  Every `ringbuf_reserve` pointer is paired with `ringbuf_submit` or `ringbuf_discard`
              on every non-NULL exit path (no leaked reservation).
  R_MASK_ORD: `rec->emitted_mask |=` appears exactly once, strictly AFTER `ringbuf_submit` (Prompt 6).
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from ips.engine.c_struct_parser import C_TYPE_SIZES, parse_c_defines, parse_c_structs
from ips.engine.schema import REPO_DIR

ALLOWED_CALLS = {
    "bpf_htons",
    "bpf_ntohs",
    "bpf_ntohl",
    "bpf_htonl",
    "bpf_ktime_get_ns",
    "__builtin_memset",
    "check_tier0_syn",
    "lookup",
    "update",
    "delete",
    "ringbuf_reserve",
    "ringbuf_submit",
    "ringbuf_discard",
    "sizeof",
    "SEC",
}


def strip_c_comments(src: str) -> str:
    """Remove /* ... */ and // ... comments while preserving line structure."""
    no_block = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.DOTALL)
    return re.sub(r"//.*?$", "", no_block, flags=re.MULTILINE)


def check_bounded_loops(src: str) -> List[str]:
    """R_LOOP: Disallow `while`/`do` loops; require `#pragma unroll` + constant upper bound on every `for`."""
    clean = strip_c_comments(src)
    errors: List[str] = []
    lines = clean.splitlines()
    for idx, ln in enumerate(lines):
        stripped = ln.strip()
        if re.match(r"^(while|do)\b", stripped):
            errors.append(f"Line {idx + 1}: unbounded '{stripped.split()[0]}' loop disallowed in eBPF")
        if re.match(r"^for\s*\(", stripped):
            prev_nonempty = ""
            for back in range(idx - 1, max(-1, idx - 4), -1):
                cand = lines[back].strip()
                if cand:
                    prev_nonempty = cand
                    break
            if prev_nonempty != "#pragma unroll":
                errors.append(f"Line {idx + 1}: 'for' loop missing preceding '#pragma unroll'")
            m_cond = re.search(r"for\s*\([^;]+;\s*[A-Za-z_][A-Za-z0-9_]*\s*<\s*([A-Za-z0-9_]+)\s*;", stripped)
            if not m_cond:
                errors.append(f"Line {idx + 1}: 'for' loop condition lacks simple constant bound '< CONST'")
            else:
                bound_tok = m_cond.group(1)
                if not (bound_tok.isdigit() or bound_tok.isupper()):
                    errors.append(f"Line {idx + 1}: 'for' loop bound '{bound_tok}' is not a constant/macro")
    return errors


def check_map_lookup_null_guards(src: str) -> List[str]:
    """R_MAP_NULL: Every pointer returned by `.lookup(...)` or `.ringbuf_reserve(...)` must be NULL-checked before `->`."""
    clean = strip_c_comments(src)
    errors: List[str] = []

    # Split per function body
    fn_pattern = re.compile(r"(?:int|void)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{", re.MULTILINE)
    for m_fn in fn_pattern.finditer(clean):
        fn_name = m_fn.group(1)
        start = m_fn.end()
        depth = 1
        pos = start
        while pos < len(clean) and depth > 0:
            if clean[pos] == "{":
                depth += 1
            elif clean[pos] == "}":
                depth += 1 - 2
            pos += 1
        body = clean[start : pos - 1]

        lookup_pat = re.compile(
            r"struct\s+[A-Za-z0-9_]+\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[A-Za-z0-9_]+\.(lookup|ringbuf_reserve)\s*\([^;]+\)\s*;"
        )
        for m_lk in lookup_pat.finditer(body):
            ptr_name = m_lk.group(1)
            after = body[m_lk.end() :]
            deref_m = re.search(rf"\b{re.escape(ptr_name)}\s*->", after)
            if not deref_m:
                continue
            before_deref = after[: deref_m.start()]
            null_check = re.search(
                rf"if\s*\(\s*(!\s*{re.escape(ptr_name)}\b|{re.escape(ptr_name)}\b\s*(?:!=|==)\s*(?:NULL|0)|{re.escape(ptr_name)}\b(?:\s*&&|\s*\)))",
                before_deref,
            )
            if not null_check:
                errors.append(f"Function '{fn_name}': pointer '{ptr_name}' from {m_lk.group(2)}() dereferenced before NULL check")
    return errors


def check_packet_bounds_guards(src: str) -> List[str]:
    """R_PKT_END: Packet header pointers (`eth`, `ip`, `tcp`, `udp`) must be checked against `data_end` before `->`."""
    clean = strip_c_comments(src)
    errors: List[str] = []
    for hdr_var, hdr_type in [("eth", "ethhdr"), ("ip", "iphdr"), ("tcp", "tcphdr"), ("udp", "udphdr")]:
        decl = re.search(rf"struct\s+{hdr_type}\s*\*\s*{hdr_var}\s*=\s*[^;]+;", clean)
        if not decl:
            errors.append(f"Missing packet header pointer declaration for '{hdr_var}' ({hdr_type})")
            continue
        after = clean[decl.end() :]
        deref = re.search(rf"\b{hdr_var}\s*->", after)
        if not deref:
            continue
        guard_region = after[: deref.start()]
        if not re.search(rf"\(\s*{hdr_var}\s*\+\s*1\s*\)\s*>\s*data_end", guard_region):
            errors.append(f"Packet pointer '{hdr_var}' dereferenced before '({hdr_var} + 1) > data_end' check")
    # Also check variable IP/TCP header length bounds against data_end
    if not re.search(r"\(\s*void\s*\*\s*\)\s*ip\s*\+\s*ip_hdr_len\s*>\s*data_end", clean):
        errors.append("Missing variable IPv4 header length check '(void *)ip + ip_hdr_len > data_end'")
    if not re.search(r"\(\s*void\s*\*\s*\)\s*tcp\s*\+\s*l4_hdr_len\s*>\s*data_end", clean):
        errors.append("Missing variable TCP header length check '(void *)tcp + l4_hdr_len > data_end'")
    return errors


def check_bpf_stack_limit(src: str, max_stack_bytes: int = 512) -> List[str]:
    """R_STACK: Total local stack variables per BPF function must not exceed 512 bytes."""
    clean = strip_c_comments(src)
    macros = parse_c_defines()
    c_path = os.path.join(REPO_DIR, "ebpf", "ips_engine.c")
    struct_defs = parse_c_structs(c_path=c_path, macros=macros)
    errors: List[str] = []

    fn_pattern = re.compile(r"(?:static\s+__always_inline\s+)?int\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{", re.MULTILINE)
    for m_fn in fn_pattern.finditer(clean):
        fn_name = m_fn.group(1)
        start = m_fn.end()
        depth = 1
        pos = start
        while pos < len(clean) and depth > 0:
            if clean[pos] == "{":
                depth += 1
            elif clean[pos] == "}":
                depth -= 1
            pos += 1
        body = clean[start : pos - 1]

        stack_bytes = 0
        for raw_ln in body.splitlines():
            ln = raw_ln.strip()
            if not ln or ln.startswith(("if", "else", "for", "return", "#")):
                continue
            # Match non-pointer struct local allocation: `struct foo var ...;`
            m_st = re.match(r"^struct\s+([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)(?:\[(\d+)\])?\s*(?:=|;)", ln)
            if m_st:
                sname = m_st.group(1)
                cnt = int(m_st.group(3)) if m_st.group(3) else 1
                sz = struct_defs.get(sname, {"sizeof": 64})["sizeof"] * cnt
                stack_bytes += sz
                continue
            # Match primitive/array local allocation: `__u32 x[128];` or `__u64 now_ns = ...;`
            m_pr = re.match(r"^(__u8|__u16|__u32|__u64|int|unsigned int)\s+([A-Za-z_][A-Za-z0-9_]*)(?:\[([A-Za-z0-9_]+)\])?\s*(?:=|;)", ln)
            if m_pr:
                ptype = m_pr.group(1)
                arr_tok = m_pr.group(3)
                cnt = 1
                if arr_tok:
                    cnt = int(arr_tok) if arr_tok.isdigit() else int(macros.get(arr_tok, 64))
                stack_bytes += C_TYPE_SIZES.get(ptype, 8) * cnt

        if stack_bytes > max_stack_bytes:
            errors.append(f"Function '{fn_name}' estimated stack usage {stack_bytes}B exceeds BPF 512B limit")
    return errors


def check_allowed_helpers_only(src: str) -> List[str]:
    """R_HELPERS: Only allowlisted BPF helpers and inline functions may be called inside BPF functions."""
    clean = strip_c_comments(src)
    # Remove top-level BPF_TABLE / BPF_ARRAY / BPF_PERCPU_ARRAY / BPF_RINGBUF_OUTPUT macro lines
    body_lines = [
        ln
        for ln in clean.splitlines()
        if not ln.strip().startswith(("BPF_TABLE", "BPF_ARRAY", "BPF_PERCPU_ARRAY", "BPF_RINGBUF_OUTPUT", "#"))
    ]
    body = "\n".join(body_lines)
    errors: List[str] = []
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", body):
        callee = m.group(1)
        if callee in {"if", "for", "while", "switch", "return", "xdp_ips_prog", "__attribute__"}:
            continue
        if callee not in ALLOWED_CALLS:
            errors.append(f"Disallowed or unknown function/helper call in eBPF program: '{callee}()'")
    return errors


def check_no_floating_point(src: str) -> List[str]:
    """R_NO_FP: Disallow float/double types and floating-point literals in kernel C code."""
    clean = strip_c_comments(src)
    errors: List[str] = []
    if re.search(r"\b(float|double)\b", clean):
        errors.append("Floating-point type ('float'/'double') is forbidden in eBPF C code")
    if re.search(r"\b\d+\.\d+\b", clean):
        errors.append("Floating-point literal is forbidden in eBPF C code")
    return errors


def check_constant_divisors_only(src: str) -> List[str]:
    """R_DIV_CONST: Every `/` or `%` operation in executable code must divide by a non-zero constant."""
    clean = strip_c_comments(src)
    errors: List[str] = []
    for idx, ln in enumerate(clean.splitlines(), 1):
        s = ln.strip()
        if s.startswith("#"):
            continue
        for m in re.finditer(r"[/\%]\s*([A-Za-z_][A-Za-z0-9_]*|\d+)", s):
            rhs = m.group(1)
            if rhs.isdigit():
                if int(rhs) == 0:
                    errors.append(f"Line {idx}: division by zero constant")
            elif not rhs.isupper():
                errors.append(f"Line {idx}: division/modulo by non-constant '{rhs}' disallowed")
    return errors


def check_ringbuf_reserve_submit_pairing(src: str) -> List[str]:
    """R_RINGBUF: Every non-NULL `ringbuf_reserve` pointer must reach `ringbuf_submit` or `ringbuf_discard` without early return."""
    clean = strip_c_comments(src)
    errors: List[str] = []
    m_res = re.search(r"struct\s+[A-Za-z0-9_]+\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*events\.ringbuf_reserve\s*\([^;]+\)\s*;", clean)
    if not m_res:
        return ["Missing events.ringbuf_reserve(...) in ebpf/ips_engine.c"]

    ptr = m_res.group(1)
    after_res = clean[m_res.end() :]
    # Must immediately check `if (!ev) { ... return XDP_...; }` (allowing nested braces inside the guard)
    m_if = re.match(rf"\s*if\s*\(\s*!\s*{re.escape(ptr)}\s*\)\s*\{{", after_res)
    if not m_if:
        errors.append(f"ringbuf_reserve pointer '{ptr}' lacks immediate 'if (!{ptr}) {{ ... return ...; }}' guard")
        return errors
    depth = 1
    pos = m_if.end()
    while pos < len(after_res) and depth > 0:
        if after_res[pos] == "{":
            depth += 1
        elif after_res[pos] == "}":
            depth -= 1
        pos += 1
    null_block = after_res[m_if.end() : pos - 1]
    if not re.search(r"\breturn\s+XDP_[A-Z_]+\s*;", null_block):
        errors.append(f"ringbuf_reserve NULL block for '{ptr}' does not return an XDP action")
        return errors

    after_null = after_res[pos:]
    m_end = re.search(rf"events\.ringbuf_(submit|discard)\s*\(\s*{re.escape(ptr)}\b", after_null)
    if not m_end:
        errors.append(f"Reserved ringbuf pointer '{ptr}' is never submitted or discarded")
        return errors

    between = after_null[: m_end.start()]
    if re.search(r"\breturn\b", between):
        errors.append(f"Early 'return' between ringbuf_reserve('{ptr}') and ringbuf_submit/discard leaks ringbuf slot!")
    return errors


def check_emitted_mask_after_submit(src: str) -> List[str]:
    """R_MASK_ORD: `rec->emitted_mask |=` appears once, strictly after `ringbuf_submit` inside `if (ckpt_hit >= 0)`."""
    clean = strip_c_comments(src)
    matches = list(re.finditer(r"rec->emitted_mask\s*\|=", clean))
    if len(matches) != 1:
        return [f"Expected exactly 1 'rec->emitted_mask |=' statement, found {len(matches)}"]
    m_sub = re.search(r"ringbuf_submit\s*\(", clean)
    m_res = re.search(r"ringbuf_reserve\s*\(", clean)
    if not m_sub or not m_res:
        return ["Missing ringbuf_reserve or ringbuf_submit"]
    if not (m_res.start() < m_sub.start() < matches[0].start()):
        return ["rec->emitted_mask |= must appear strictly AFTER ringbuf_submit"]
    return []


def run_all_bpf_source_checks(src: str) -> Dict[str, Any]:
    """Run all 9 static BPF source-text invariant checks on C source string."""
    checks = {
        "bounded_loops": check_bounded_loops(src),
        "map_lookup_null": check_map_lookup_null_guards(src),
        "packet_bounds": check_packet_bounds_guards(src),
        "stack_limit": check_bpf_stack_limit(src),
        "allowed_helpers": check_allowed_helpers_only(src),
        "no_floating_point": check_no_floating_point(src),
        "constant_divisors": check_constant_divisors_only(src),
        "ringbuf_pairing": check_ringbuf_reserve_submit_pairing(src),
        "emitted_mask_order": check_emitted_mask_after_submit(src),
    }
    all_errors = [err for errs in checks.values() for err in errs]
    return {
        "passed": len(all_errors) == 0,
        "checks": checks,
        "errors": all_errors,
    }
