#!/usr/bin/env python3
"""
tests/test_kernel_source_invariants.py — V1 source-text invariant checks on ebpf/ips_engine.c.

NOTE: This is a static source-text guard (V1), NOT a compiled or executed test of the C kernel
code (which requires Linux + BCC/clang in V2).
"""
import os
import re

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
C_FILE = os.path.join(REPO_DIR, "ebpf", "ips_engine.c")


def test_emitted_mask_set_after_ringbuf_submit():
    """
    Source-text guard (V1, not C execution):
    Verify that in ebpf/ips_engine.c:
      (i)   there is exactly one `emitted_mask |=` statement;
      (ii)  it appears after `ringbuf_submit` and before the closing of the `if (ckpt_hit >= 0)` block;
      (iii) it does NOT appear before `ringbuf_reserve`.
    """
    with open(C_FILE, "r", encoding="utf-8") as f:
        src = f.read()

    # (i) Exactly one emitted_mask |= statement in the entire file
    matches = list(re.finditer(r"rec->emitted_mask\s*\|=", src))
    assert len(matches) == 1, (
        f"Expected exactly 1 'rec->emitted_mask |=' statement in ebpf/ips_engine.c, found {len(matches)}"
    )

    # Locate the if (ckpt_hit >= 0) block
    ckpt_block_match = re.search(r"if\s*\(\s*ckpt_hit\s*>=\s*0\s*\)\s*\{", src)
    assert ckpt_block_match is not None, "Could not find 'if (ckpt_hit >= 0) {' block in ebpf/ips_engine.c"

    block_start = ckpt_block_match.end()
    # Find matching closing brace for if (ckpt_hit >= 0) { ... }
    depth = 1
    pos = block_start
    while pos < len(src) and depth > 0:
        if src[pos] == "{":
            depth += 1
        elif src[pos] == "}":
            depth -= 1
        pos += 1
    assert depth == 0, "Unbalanced braces in 'if (ckpt_hit >= 0)' block"
    block_end = pos - 1  # position of closing '}'

    mask_pos = matches[0].start()
    reserve_match = re.search(r"ringbuf_reserve\s*\(", src)
    submit_match = re.search(r"ringbuf_submit\s*\(", src)
    assert reserve_match is not None, "Could not find ringbuf_reserve in ebpf/ips_engine.c"
    assert submit_match is not None, "Could not find ringbuf_submit in ebpf/ips_engine.c"

    reserve_pos = reserve_match.start()
    submit_pos = submit_match.start()

    # (iii) Does NOT appear before ringbuf_reserve
    assert mask_pos > reserve_pos, (
        f"emitted_mask |= (at {mask_pos}) must NOT appear before ringbuf_reserve (at {reserve_pos})"
    )

    # (ii) Appears after ringbuf_submit and before closing of if (ckpt_hit >= 0) block
    assert submit_pos < mask_pos < block_end, (
        f"emitted_mask |= (at {mask_pos}) must appear after ringbuf_submit (at {submit_pos}) "
        f"and before closing brace of if (ckpt_hit >= 0) (at {block_end})"
    )
