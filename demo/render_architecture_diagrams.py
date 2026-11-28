#!/usr/bin/env python3
"""
demo/render_architecture_diagrams.py — Deterministic Matplotlib PNG/SVG Renderer for the 4 Architecture Diagrams (Prompt 9 Item 5b).

Because `@mermaid-js/mermaid-cli` (`mmdc` + headless Chromium) and Graphviz (`dot`) are not installed locally,
this script renders clean, colour-blind-safe PNG and SVG versions of the four architecture diagrams in
docs/ARCHITECTURE.md into demo/figures/diagrams/ (while docs/ARCHITECTURE.md also retains native Mermaid blocks for GitHub).
"""

import os
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT_DIR = os.path.join(REPO_DIR, "demo", "figures", "diagrams")


def _box(ax, x, y, w, h, text, fc="#E8F1FA", ec="#0072B2", fontsize=8.5, weight="normal"):
    p = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.015,rounding_size=0.02",
        facecolor=fc,
        edgecolor=ec,
        linewidth=1.6,
    )
    ax.add_patch(p)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fontsize, fontweight=weight, color="#111111")


def _arrow(ax, x0, y0, x1, y1, label="", color="#333333", ls="-"):
    ax.annotate(
        "",
        xy=(x1, y1),
        xytext=(x0, y0),
        arrowprops=dict(arrowstyle="-|>", lw=1.5, color=color, linestyle=ls),
    )
    if label:
        ax.text((x0 + x1) / 2, (y0 + y1) / 2 + 0.018, label, ha="center", va="bottom", fontsize=7.5, color=color)


def _save_both(fig, stem: str):
    os.makedirs(OUT_DIR, exist_ok=True)
    fig.savefig(os.path.join(OUT_DIR, f"{stem}.png"), dpi=160, bbox_inches="tight")
    fig.savefig(os.path.join(OUT_DIR, f"{stem}.svg"), bbox_inches="tight")
    plt.close(fig)


def render_01_two_tier_overview():
    fig, ax = plt.subplots(figsize=(11, 5.6))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.text(
        0.5, 0.96, "1. Two-Tier Kernel (XDP) / User-Space IPS Architecture (SCHEMA_VERSION 4)", ha="center", fontsize=11, fontweight="bold"
    )

    # Kernel band
    _box(ax, 0.03, 0.54, 0.94, 0.36, "", fc="#F4F8FB", ec="#0072B2")
    ax.text(
        0.05,
        0.87,
        "eBPF / XDP Fast Path (ebpf/ips_engine.c — CODE WRITTEN, NOT RUN ON LINUX V2)",
        fontsize=9,
        fontweight="bold",
        color="#0072B2",
    )
    _box(ax, 0.05, 0.63, 0.19, 0.18, "Ingress L2/L3/L4\nBounds Parser\n(v-lan-gw / v-wan-gw)", fc="#FFFFFF", ec="#0072B2")
    _box(ax, 0.28, 0.63, 0.21, 0.18, "1. verdict_map (LRU)\nDROP -> XDP_DROP\nBYPASS -> XDP_PASS", fc="#FFF3E6", ec="#D55E00")
    _box(ax, 0.53, 0.63, 0.18, 0.18, "2. Tier-0 SYN\nToken Bucket\n(Rule-Based)", fc="#FFFFFF", ec="#0072B2")
    _box(
        ax,
        0.75,
        0.63,
        0.20,
        0.18,
        "3. flow_state (LRU)\nPayload sizes/dirs/iats\nEmit k=4, 8, 16\nIdle>120s / FIN+SYN",
        fc="#E6F6F0",
        ec="#009E73",
    )
    _arrow(ax, 0.24, 0.72, 0.28, 0.72)
    _arrow(ax, 0.49, 0.72, 0.53, 0.72, "miss")
    _arrow(ax, 0.71, 0.72, 0.75, 0.72, "pass")

    # User-space band
    _box(ax, 0.03, 0.06, 0.94, 0.38, "", fc="#FBF7FC", ec="#CC79A7")
    ax.text(
        0.05,
        0.41,
        "User-Space Inference, Verdict Manager & Drift Guard (ips/engine, ips/drift — V1 UNIT TESTED)",
        fontsize=9,
        fontweight="bold",
        color="#7A295C",
    )
    _box(ax, 0.05, 0.13, 0.20, 0.22, "Ringbuf Bounds &\nSCHEMA_VERSION 4\n(>10 mismatch->shed)", fc="#FFFFFF", ec="#CC79A7")
    _box(
        ax,
        0.29,
        0.13,
        0.21,
        0.22,
        "Canonical 3k+8 Features\n(ips/features.py v2)\nlog_iat / 7.0 in [0,1.5]\nNo IPs / Ports",
        fc="#FFFFFF",
        ec="#CC79A7",
    )
    _box(
        ax,
        0.54,
        0.13,
        0.20,
        0.22,
        "Per-Ckpt ONNX INT8 AE\nMasked MSE (<valid_len)\nEarly DROP (sticky)\nLate BYPASS at k=16",
        fc="#FFF3E6",
        ec="#D55E00",
    )
    _box(ax, 0.78, 0.13, 0.17, 0.22, "Drift Guard G1-G4\nBounded Step/Rollback\n+ Tier-2 SlowC2Tracker", fc="#E6F6F0", ec="#009E73")

    _arrow(ax, 0.85, 0.63, 0.15, 0.35, "BPF ringbuf (k=4,8,16)", color="#009E73", ls="--")
    _arrow(ax, 0.25, 0.24, 0.29, 0.24)
    _arrow(ax, 0.50, 0.24, 0.54, 0.24)
    _arrow(ax, 0.74, 0.24, 0.78, 0.24)
    _arrow(ax, 0.64, 0.35, 0.38, 0.63, "Write DROP / BYPASS + TTL", color="#D55E00", ls="--")
    _save_both(fig, "01_two_tier_overview")


def render_02_checkpoint_sequence():
    fig, ax = plt.subplots(figsize=(10.5, 5.2))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.text(0.5, 0.95, "2. Progressive Multi-Checkpoint Verdict Sequence (k = 4 -> 8 -> 16)", ha="center", fontsize=11, fontweight="bold")

    cols = [(0.14, "IoT / Attacker"), (0.40, "XDP Fast Path"), (0.68, "User-Space Engine"), (0.90, "verdict_map")]
    for cx, title in cols:
        _box(ax, cx - 0.09, 0.83, 0.18, 0.08, title, fc="#E8F1FA", ec="#0072B2", weight="bold")
        ax.plot([cx, cx], [0.06, 0.83], ls=":", color="#888888", lw=1.3)

    steps = [
        (0.75, 0.14, 0.40, "SYN / Pure ACK (0 payload) -> XDP_PASS (valid_len unchanged)", "#555555"),
        (0.65, 0.14, 0.40, "Payload pkts 1..4 arrive", "#0072B2"),
        (0.58, 0.40, 0.68, "ringbuf_submit(ckpt=0, k=4); emitted_mask |= 0x1", "#009E73"),
        (0.48, 0.68, 0.90, "If score_4 > tau_4: write sticky VERDICT_DROP -> pkts 5..N XDP_DROP", "#D55E00"),
        (0.37, 0.14, 0.40, "Else CONTINUE -> Payload pkts 5..8 arrive", "#0072B2"),
        (0.30, 0.40, 0.68, "ringbuf_submit(ckpt=1, k=8); score_8 vs tau_8 (DROP or CONTINUE)", "#009E73"),
        (0.19, 0.14, 0.68, "Payload pkts 9..16 -> ringbuf_submit(ckpt=2, k=16); score_16 <= tau_16", "#0072B2"),
        (0.10, 0.68, 0.90, "Write VERDICT_BYPASS (TTL) -> pkts 17..end XDP_PASS in O(1)", "#009E73"),
    ]
    for y, x0, x1, txt, col in steps:
        _arrow(ax, x0, y, x1, y, txt, color=col)
    _save_both(fig, "02_checkpoint_sequence")


def render_03_drift_guard_flow():
    fig, ax = plt.subplots(figsize=(11, 4.8))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.text(
        0.5,
        0.94,
        "3. Poisoning-Aware Drift Guard Decision Pipeline (G1-G4 + Bounded Step + Rollback)",
        ha="center",
        fontsize=11,
        fontweight="bold",
    )

    nodes = [
        (0.02, 0.55, 0.14, 0.24, "Window Scores\n& IATs\n(ADWIN Shift?)", "#E8F1FA", "#0072B2"),
        (0.20, 0.55, 0.14, 0.24, "G1: Persistence\n>= k Windows\n& Tail Check", "#E8F1FA", "#0072B2"),
        (0.38, 0.55, 0.15, 0.24, "G2: Class Quorum\n>= ceil(rho*M)\n(<3 devs: Fail-Closed)", "#E8F1FA", "#0072B2"),
        (0.57, 0.55, 0.14, 0.24, "G3: Aperiodic\nCV > 0.35 &\nFFT Peak OK", "#E8F1FA", "#0072B2"),
        (0.75, 0.55, 0.22, 0.24, "Bounded Step + G4:\nShadow Check on Frozen\nANCHOR & DEV CANARY", "#E6F6F0", "#009E73"),
    ]
    for x, y, w, h, t, fc, ec in nodes:
        _box(ax, x, y, w, h, t, fc=fc, ec=ec)
    _arrow(ax, 0.16, 0.67, 0.20, 0.67, "yes")
    _arrow(ax, 0.34, 0.67, 0.38, 0.67, "pass")
    _arrow(ax, 0.53, 0.67, 0.57, 0.67, "pass")
    _arrow(ax, 0.71, 0.67, 0.75, 0.67, "pass")

    _box(
        ax,
        0.32,
        0.12,
        0.26,
        0.22,
        "Reject Update (Keep tau_old)\nBlocks S3 Boiling Frog (G2/G3)\n& Unvalidated S4 Shifts (G4)",
        fc="#FDECEC",
        ec="#D55E00",
    )
    _box(
        ax,
        0.68,
        0.12,
        0.29,
        0.22,
        "Commit tau_new <= tau_old*(1+gamma)\n+ Post-Update Health Monitor\n(Alert Spike -> Instant ROLLBACK)",
        fc="#E6F6F0",
        ec="#009E73",
    )
    _arrow(ax, 0.45, 0.55, 0.45, 0.34, "G1/G2/G3/G4 fail", color="#D55E00")
    _arrow(ax, 0.86, 0.55, 0.86, 0.34, "G4 pass", color="#009E73")
    _save_both(fig, "03_drift_guard_flow")


def render_04_splits_and_leakage():
    fig, ax = plt.subplots(figsize=(10.8, 4.8))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.text(
        0.5,
        0.94,
        "4. Session-Isolated Data Splits & Leakage Governance (ips/data/build_splits.py)",
        ha="center",
        fontsize=11,
        fontweight="bold",
    )

    _box(ax, 0.03, 0.55, 0.21, 0.26, "Session S1 (Benign)\n-> TRAIN Split\n(AE Weights Only)", fc="#E8F1FA", ec="#0072B2")
    _box(ax, 0.27, 0.55, 0.21, 0.26, "Session S2 (Benign)\n-> CALIBRATION Split\n(EVT / Conformal tau)", fc="#E8F1FA", ec="#0072B2")
    _box(ax, 0.51, 0.55, 0.21, 0.26, "Session S3 (Benign +\nDEV A1/A2/A5)\n-> VALIDATION & Canary", fc="#FFF3E6", ec="#E69F00")
    _box(
        ax, 0.75, 0.55, 0.22, 0.26, "Session S4 (Benign +\nHeld-Out A3_c2 / A4_exfil)\n-> ZERO-DAY TEST (Once)", fc="#E6F6F0", ec="#009E73"
    )

    _box(
        ax,
        0.03,
        0.10,
        0.94,
        0.30,
        "Automated Leakage & Shortcut Assertions (Verified by Unit Tests + Mutants M4, M5, M6):\n"
        "1. Zero session_id overlap across splits   |   2. Zero attack or attack-window flows in Train/Calib\n"
        "3. Zero held-out A3_c2 / A4_exfil flows in Validation or G4 Canary   |   4. Zero IPs/Ports/MACs in 3N+8 features\n"
        "5. Public datasets (TQH-C2 D, IoT-23 Benign, CESNET) strictly OFFLINE ONLY (Rule H5 — never replayed through gateway)",
        fc="#FBF7FC",
        ec="#CC79A7",
        fontsize=8.5,
    )
    for cx in (0.135, 0.375, 0.615, 0.86):
        _arrow(ax, cx, 0.55, cx, 0.40, color="#7A295C", ls="--")
    _save_both(fig, "04_splits_and_leakage")


def main():
    render_01_two_tier_overview()
    render_02_checkpoint_sequence()
    render_03_drift_guard_flow()
    render_04_splits_and_leakage()
    print(f"[+] Rendered 4 PNG + 4 SVG architecture diagrams into {OUT_DIR}")


if __name__ == "__main__":
    main()
