#!/usr/bin/env python3
"""
ips/engine/c_struct_parser.py — Automated C struct layout parser & ctypes ABI verifier (P10.1 §1.4).

Parses `struct <name> { ... } __attribute__((packed));` definitions directly from
`ebpf/ips_engine.c` (with preprocessor constants from `ebpf/generated_constants.h`),
computes field byte offsets, sizes, alignment, and total `sizeof`, and compares them
against the Python `ctypes.Structure` definitions in `ips/engine/schema.py`.
"""

from __future__ import annotations

import ast
import ctypes
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from ips.engine.schema import REPO_DIR, make_ctypes_schemas

C_TYPE_SIZES: Dict[str, int] = {
    "__u8": 1,
    "uint8_t": 1,
    "unsigned char": 1,
    "char": 1,
    "__u16": 2,
    "uint16_t": 2,
    "unsigned short": 2,
    "__u32": 4,
    "uint32_t": 4,
    "unsigned int": 4,
    "int": 4,
    "__u64": 8,
    "uint64_t": 8,
    "unsigned long long": 8,
}

STRUCT_MAP: Dict[str, str] = {
    "flow_key": "FlowKey",
    "verdict_entry": "VerdictEntry",
    "cfg_entry": "CfgEntry",
    "stats_entry": "StatsEntry",
    "early_flow_event": "EarlyFlowEvent",
}


def _safe_eval_int_expr(expr: str, macros: Dict[str, int]) -> int:
    """Safely evaluate integer arithmetic/comparison expressions from C preprocessor lines."""
    clean = re.sub(r"(\d+)(ULL|UL|LL|U|L)\b", r"\1", expr)
    clean = clean.replace("!=", "!=").replace("==", "==")
    for name in sorted(macros.keys(), key=len, reverse=True):
        clean = re.sub(rf"\b{re.escape(name)}\b", str(macros[name]), clean)

    tree = ast.parse(clean.strip(), mode="eval")
    allowed_nodes = (
        ast.Expression,
        ast.BinOp,
        ast.UnaryOp,
        ast.Compare,
        ast.Constant,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.FloorDiv,
        ast.Mod,
        ast.LShift,
        ast.RShift,
        ast.USub,
        ast.UAdd,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Div):
            raise ValueError(f"Floating division disallowed in C integer expression: {expr}")
        if not isinstance(node, allowed_nodes):
            raise ValueError(f"Unsupported AST node {type(node).__name__} in C expression: {expr}")

    # Replace `/` with `//` before eval if any integer division existed
    val = eval(compile(tree, "<c_expr>", "eval"), {"__builtins__": {}}, {})  # noqa: S307
    return int(val)


def parse_c_defines(header_path: Optional[str] = None, early_n_override: Optional[int] = None) -> Dict[str, int]:
    """Parse integer #define macros from ebpf/generated_constants.h."""
    if header_path is None:
        header_path = os.path.join(REPO_DIR, "ebpf", "generated_constants.h")
    macros: Dict[str, int] = {}
    with open(header_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = re.sub(r"/\*.*?\*/", "", raw_line).strip()
            m = re.match(r"^#define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+)$", line)
            if not m:
                continue
            name, val_str = m.group(1), m.group(2).strip()
            try:
                macros[name] = _safe_eval_int_expr(val_str, macros)
            except ValueError:
                continue
    if early_n_override is not None:
        macros["EARLY_N"] = int(early_n_override)
        macros["EARLY_N_MINUS_1"] = int(early_n_override) - 1
    return macros


def parse_c_structs(
    c_path: Optional[str] = None,
    macros: Optional[Dict[str, int]] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Parse all packed struct definitions from ebpf/ips_engine.c, evaluating `#if ... #endif`
    blocks under `macros`, and return `{struct_name: {"sizeof": int, "packed": bool, "fields": [...]}}`.
    """
    if c_path is None:
        c_path = os.path.join(REPO_DIR, "ebpf", "ips_engine.c")
    if macros is None:
        macros = parse_c_defines()

    with open(c_path, "r", encoding="utf-8") as f:
        src = f.read()

    # Strip C comments
    src_no_block = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    src_clean = re.sub(r"//.*?$", "", src_no_block, flags=re.MULTILINE)

    struct_pattern = re.compile(
        r"struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(.*?)\}\s*(__attribute__\(\(packed\)\))?\s*;",
        re.DOTALL,
    )
    parsed: Dict[str, Dict[str, Any]] = {}

    for match in struct_pattern.finditer(src_clean):
        sname = match.group(1)
        body = match.group(2)
        is_packed = bool(match.group(3))

        active_lines: List[str] = []
        cond_stack: List[bool] = [True]
        for raw_ln in body.splitlines():
            ln = raw_ln.strip()
            if not ln:
                continue
            if ln.startswith("#if "):
                cond_expr = ln[4:].strip()
                cond_val = bool(_safe_eval_int_expr(cond_expr, macros))
                cond_stack.append(cond_stack[-1] and cond_val)
                continue
            if ln.startswith("#endif"):
                if len(cond_stack) > 1:
                    cond_stack.pop()
                continue
            if cond_stack[-1]:
                active_lines.append(ln)

        offset = 0
        fields_info: List[Dict[str, Any]] = []
        for decl in active_lines:
            decl_clean = decl.rstrip(";").strip()
            if not decl_clean:
                continue
            m_field = re.match(
                r"^([A-Za-z0-9_ ]+?)\s+([A-Za-z_][A-Za-z0-9_]*)(?:\[(.+)\])?$",
                decl_clean,
            )
            if not m_field:
                raise ValueError(f"Cannot parse C struct field declaration in {sname}: '{decl}'")
            ctype = " ".join(m_field.group(1).split())
            fname = m_field.group(2)
            arr_expr = m_field.group(3)
            if ctype not in C_TYPE_SIZES:
                raise ValueError(f"Unknown C primitive type '{ctype}' in struct {sname}.{fname}")

            elem_size = C_TYPE_SIZES[ctype]
            count = _safe_eval_int_expr(arr_expr, macros) if arr_expr is not None else 1
            if not is_packed and (offset % elem_size) != 0:
                offset += elem_size - (offset % elem_size)
            fsize = elem_size * count
            fields_info.append(
                {
                    "name": fname,
                    "c_type": ctype,
                    "elem_size": elem_size,
                    "count": count,
                    "offset": offset,
                    "size": fsize,
                }
            )
            offset += fsize

        parsed[sname] = {
            "sizeof": offset,
            "packed": is_packed,
            "fields": fields_info,
        }
    return parsed


def verify_all_c_structs_match_ctypes(early_n: int = 16) -> Dict[str, Any]:
    """Compare every kernel↔user struct in ebpf/ips_engine.c against ips/engine/schema.py ctypes."""
    macros = parse_c_defines(early_n_override=early_n)
    c_structs = parse_c_structs(macros=macros)
    bundle = make_ctypes_schemas(early_n=early_n)

    mismatches: List[str] = []
    compared: Dict[str, Any] = {}

    for c_name, py_attr in STRUCT_MAP.items():
        if c_name not in c_structs:
            mismatches.append(f"Missing C struct '{c_name}' in ebpf/ips_engine.c")
            continue
        c_info = c_structs[c_name]
        py_cls = getattr(bundle, py_attr)
        py_sizeof = ctypes.sizeof(py_cls)

        if not c_info["packed"]:
            mismatches.append(f"C struct '{c_name}' is missing __attribute__((packed))")
        if c_info["sizeof"] != py_sizeof:
            mismatches.append(f"{c_name} sizeof mismatch: C={c_info['sizeof']} vs Python={py_sizeof}")

        py_fields: List[Tuple[str, int, int]] = []
        for f_tuple in py_cls._fields_:
            fname = f_tuple[0]
            descriptor = getattr(py_cls, fname)
            py_fields.append((fname, int(descriptor.offset), int(descriptor.size)))

        c_fields = [(f["name"], int(f["offset"]), int(f["size"])) for f in c_info["fields"]]
        if c_fields != py_fields:
            mismatches.append(f"{c_name} field layout mismatch: C={c_fields} vs Python={py_fields}")

        # Verify 8-byte natural alignment of 64-bit fields in early_flow_event & stats_entry & verdict_entry
        for f in c_info["fields"]:
            if f["elem_size"] == 8 and (f["offset"] % 8) != 0:
                mismatches.append(f"{c_name}.{f['name']} (64-bit) is misaligned at offset {f['offset']}")

        compared[c_name] = {
            "python_class": py_attr,
            "sizeof": c_info["sizeof"],
            "field_count": len(c_fields),
            "matched": (c_info["sizeof"] == py_sizeof and c_fields == py_fields),
        }

    return {
        "early_n": early_n,
        "passed": len(mismatches) == 0,
        "structs": compared,
        "mismatches": mismatches,
    }
