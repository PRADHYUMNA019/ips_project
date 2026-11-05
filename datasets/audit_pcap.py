#!/usr/bin/env python3
"""
datasets/audit_pcap.py — Audit pcap files for protocol mix, TLS proportion, and flow stats.

Analyzes raw pcap/pcapng files to establish empirical data cards (Rule H1/H3).
Measures:
  - Total packets, total TCP/UDP flows
  - Share of flows with genuine TLS record headers (0x16 0x03 0x01..0x04)
  - Plaintext protocol presence
  - Top destination ports

Usage:
  python datasets/audit_pcap.py <file_or_dir> [--out docs/DATA_CARD.md]
"""
import os
import sys
import glob
import hashlib
import datetime
import socket
import argparse
from collections import defaultdict, Counter

# Ensure dpkt is available, fallback or error message
try:
    import dpkt
except ImportError:
    dpkt = None


def sha256_file(filepath, chunk_size=65536):
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()[:16]


def is_tls_handshake(payload: bytes) -> bool:
    """Check if byte payload starts with TLS Handshake record header (0x16 0x03 0x01..0x04)."""
    if len(payload) < 5:
        return False
    # ContentType == 0x16 (22 = Handshake)
    if payload[0] == 0x16:
        # Major version == 3
        if payload[1] == 0x03:
            # Minor version in {0x01, 0x02, 0x03, 0x04}
            if payload[2] in (0x01, 0x02, 0x03, 0x04):
                return True
    return False


def is_plaintext_marker(payload: bytes, port: int) -> bool:
    """Check if payload exhibits obvious plaintext signatures (HTTP, MQTT, etc.)."""
    if not payload:
        return False
    if port in (80, 8080) and (payload.startswith(b"GET ") or payload.startswith(b"POST ") or payload.startswith(b"HTTP/")):
        return True
    if port == 1883 and len(payload) >= 2 and payload[0] in (0x10, 0x20, 0x30): # MQTT packet types
        return True
    return False


def audit_single_pcap(filepath: str):
    """Parse a pcap file using dpkt and extract protocol statistics."""
    if dpkt is None:
        raise RuntimeError("dpkt is required for audit_pcap.py. Run: pip install dpkt")

    fhash = sha256_file(filepath)
    fsize_mb = os.path.getsize(filepath) / (1024.0 * 1024.0)

    total_pkts = 0
    flows = defaultdict(list)
    ports = Counter()

    with open(filepath, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)

        for ts, buf in pcap:
            total_pkts += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                proto = ip.p

                if proto == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    sport, dport = tcp.sport, tcp.dport
                    payload = tcp.data
                    key = tuple(sorted([(src_ip, sport), (dst_ip, dport)])) + ("TCP",)
                    flows[key].append((ts, payload, dport))
                    ports[dport] += 1

                elif proto == dpkt.ip.IP_PROTO_UDP:
                    udp = ip.data
                    sport, dport = udp.sport, udp.dport
                    payload = udp.data
                    key = tuple(sorted([(src_ip, sport), (dst_ip, dport)])) + ("UDP",)
                    flows[key].append((ts, payload, dport))
                    ports[dport] += 1
            except Exception:
                continue

    total_flows = len(flows)
    tls_flows = 0
    plaintext_flows = 0

    for key, pkt_list in flows.items():
        # Check first non-empty payload packet in flow
        first_payload = b""
        dport = 0
        for ts, p, dp in pkt_list:
            if len(p) > 0:
                first_payload = p
                dport = dp
                break

        if is_tls_handshake(first_payload):
            tls_flows += 1
        elif is_plaintext_marker(first_payload, dport):
            plaintext_flows += 1

    tls_share = (tls_flows / total_flows * 100.0) if total_flows > 0 else 0.0
    plain_share = (plaintext_flows / total_flows * 100.0) if total_flows > 0 else 0.0
    top_ports = ", ".join(f"{p}:{c}" for p, c in ports.most_common(3))

    return {
        "file": os.path.basename(filepath),
        "sha256": fhash,
        "size_mb": round(fsize_mb, 2),
        "packets": total_pkts,
        "flows": total_flows,
        "tls_flows": tls_flows,
        "tls_share_pct": round(tls_share, 1),
        "plain_share_pct": round(plain_share, 1),
        "top_ports": top_ports or "None",
    }


def generate_markdown_report(results: list, output_path: str = None) -> str:
    """Format audit results as a GitHub Flavored Markdown table."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# Dataset Provenance & Protocol Audit Card",
        "",
        f"> Last updated: {now} via `datasets/audit_pcap.py`",
        "",
        "| File | SHA-256 (Prefix) | Size (MB) | Packets | Flows | TLS Flows | TLS Share (%) | Plaintext (%) | Top Ports |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    if not results:
        lines.append("| (No pcap files audited yet) | - | - | - | - | - | - | - | - |")
    else:
        for r in results:
            lines.append(
                f"| `{r['file']}` | `{r['sha256']}` | {r['size_mb']} | {r['packets']:,} | "
                f"{r['flows']:,} | {r['tls_flows']:,} | {r['tls_share_pct']}% | "
                f"{r['plain_share_pct']}% | {r['top_ports']} |"
            )

    lines.extend([
        "",
        "### Audit Rules & Verification Criteria",
        "- **TLS Verification**: Confirms payload bytes `0x16 0x03 0x01..0x04` at start of first application packet.",
        "- **Honesty Rule H3**: Datasets lacking verified TLS record headers are classified as `plaintext-attack` or `plaintext-benign`, never as 'encrypted attacks'.",
        "- **Held-Out Criteria**: Datasets designated as zero-day evaluations are held strictly in held-out test splits.",
    ])
    md = "\n".join(lines)
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md)
    return md


def main():
    parser = argparse.ArgumentParser(description="Audit pcap files for TLS share and protocol mix")
    parser.add_argument("path", help="Path to a pcap file or directory containing pcaps")
    parser.add_argument("--out", default="docs/DATA_CARD.md", help="Output Markdown report path")
    args = parser.parse_args()

    files = []
    if os.path.isfile(args.path):
        files = [args.path]
    elif os.path.isdir(args.path):
        for ext in ("*.pcap", "*.pcapng", "*.cap"):
            files.extend(glob.glob(os.path.join(args.path, "**", ext), recursive=True))

    results = []
    for f in sorted(files):
        print(f"Auditing {f} ...")
        try:
            res = audit_single_pcap(f)
            results.append(res)
        except Exception as e:
            print(f"  Error reading {f}: {e}")

    md = generate_markdown_report(results, args.out)
    print(f"\nAudit complete. {len(results)} files processed.")
    print(f"Report written to: {args.out}")


if __name__ == "__main__":
    main()

