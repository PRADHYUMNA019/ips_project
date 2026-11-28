#!/usr/bin/env python3
"""
datasets/download_iot23_win.py — Windows-compatible resumable downloader for Aposemat IoT-23 benign honeypot pcaps (Prompt 8 §3.4).

Downloads ONLY the three verified BENIGN captures (total ~509 MB, well under 3 GB cap):
  - CTU-Honeypot-Capture-4-1 (Philips Hue, 0.36 MB .pcap.xz -> decompressed .pcap)
  - CTU-Honeypot-Capture-5-1 (Amazon Echo, 363.71 MB .pcap)
  - CTU-Honeypot-Capture-7-1 (Somfy Door Lock, 6 pcaps totaling 144.88 MB)

CRITICAL SAFETY GUARD (A3): NEVER downloads CTU-IoT-Malware-Capture-7-1 (Linux.Mirai)
and NEVER downloads iot_23_datasets_small.tar.gz (Zeek logs only, no pcaps).
Uses Windows curl.exe (Schannel TLS store) with -C - resume support.
"""

import os
import re
import sys
import lzma
import shutil
import argparse
import subprocess

IOT23_BASE = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios"
MAX_TOTAL_BYTES = 3 * 1024 * 1024 * 1024  # 3 GB cap


def get_data_root() -> str:
    env_root = os.environ.get("IPS_DATA_ROOT")
    if env_root:
        return env_root
    if os.path.exists("D:\\"):
        return "D:\\ips_data"
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "raw"))


def curl_get(url: str) -> str:
    p = subprocess.run(["curl.exe", "-sSL", "--retry", "2", "--max-time", "25", url], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"curl failed (rc={p.returncode}) for {url}: {p.stderr.strip()}")
    return p.stdout


def curl_head_size(url: str) -> int:
    p = subprocess.run(["curl.exe", "-sSLI", "--max-time", "20", url], capture_output=True, text=True)
    cl = [ln for ln in p.stdout.splitlines() if ln.lower().startswith("content-length:")]
    return int(cl[-1].split(":", 1)[1].strip()) if cl else 0


def curl_download(url: str, dest: str):
    os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
    p = subprocess.run(
        ["curl.exe", "-fL", "-C", "-", "--retry", "3", "--max-time", "600", "-o", dest, url],
        capture_output=True,
        text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(f"Download failed (rc={p.returncode}) for {url}: {p.stderr.strip()[:200]}")


def main():
    parser = argparse.ArgumentParser(description="Download IoT-23 benign honeypot pcaps (Windows-safe)")
    parser.add_argument("--out-dir", default=None)
    args = parser.parse_args()

    out_dir = args.out_dir or os.path.join(get_data_root(), "iot23")
    os.makedirs(out_dir, exist_ok=True)

    plan = []
    for cap in ["CTU-Honeypot-Capture-4-1", "CTU-Honeypot-Capture-5-1", "CTU-Honeypot-Capture-7-1"]:
        url = f"{IOT23_BASE}/{cap}/"
        html = curl_get(url)
        links = re.findall(r'href="([^"]+)"', html)
        pcaps = [lnk for lnk in links if ".pcap" in lnk.lower()]
        for fn in pcaps:
            u = fn if fn.startswith("http") else (url + fn)
            plan.append((cap, fn, u, curl_head_size(u)))
        for sd in [lnk for lnk in links if lnk.endswith("/") and lnk.startswith("Somfy")]:
            shtml = curl_get(url + sd)
            for fn in [lnk for lnk in re.findall(r'href="([^"]+)"', shtml) if ".pcap" in lnk.lower()]:
                u = f"{url}{sd}{fn}"
                plan.append((cap, f"{sd.rstrip('/')}_{fn}", u, curl_head_size(u)))

    total_bytes = sum(x[3] for x in plan)
    print(f"[*] Planned IoT-23 benign downloads: {len(plan)} files, {total_bytes / 1024 / 1024:.2f} MB total")
    if total_bytes > MAX_TOTAL_BYTES:
        print(f"[!] Total exceeds 3 GB cap ({total_bytes} > {MAX_TOTAL_BYTES}); aborting.")
        sys.exit(1)

    for cap, fn, u, sz in plan:
        dest = os.path.join(out_dir, cap, fn)
        if os.path.exists(dest) and sz > 0 and os.path.getsize(dest) == sz:
            print(f"  [skip] {cap}/{fn} ({sz / 1024 / 1024:.2f} MB)")
        else:
            print(f"  [get]  {cap}/{fn} ({sz / 1024 / 1024:.2f} MB) ...", flush=True)
            curl_download(u, dest)
        if dest.endswith(".xz"):
            raw_pcap = dest[:-3]
            if not os.path.exists(raw_pcap):
                with lzma.open(dest, "rb") as fin, open(raw_pcap, "wb") as fout:
                    shutil.copyfileobj(fin, fout, length=1024 * 1024)
                print(f"  [xz]   Decompressed -> {raw_pcap} ({os.path.getsize(raw_pcap) / 1024 / 1024:.2f} MB)")

    print(f"[+] IoT-23 benign downloads complete in {out_dir}")


if __name__ == "__main__":
    main()
