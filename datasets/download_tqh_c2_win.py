#!/usr/bin/env python3
"""
datasets/download_tqh_c2_win.py — Windows-compatible resumable downloader for TQH-C2 Testbed D small files (Prompt 8 §3.1).

Downloads ONLY the small Testbed D files from Zenodo record 21523144 (CC-BY-4.0):
  - SHA256SUMS_v120.txt (~906 B)
  - README_v120.md (~17.6 KB)
  - TQH-C2_features_D.zip (~1.22 MB)
  - TQH-C2_labels_D.zip (~0.79 MB)

Does NOT download the 1.8 GB pcap archive in Prompt 8 mode.
Saves to %IPS_DATA_ROOT%\\tqh_c2 (default D:\\ips_data\\tqh_c2 if D: exists, else datasets\\raw\\tqh_c2).
Verifies SHA-256 against SHA256SUMS_v120.txt.
"""

import os
import sys
import hashlib
import argparse
import urllib.error
import urllib.parse
import urllib.request

ZENODO_RECORD_ID = "21523144"
ZENODO_BASE = f"https://zenodo.org/records/{ZENODO_RECORD_ID}/files"

SMALL_FILES = [
    "SHA256SUMS_v120.txt",
    "README_v120.md",
    "TQH-C2_features_D.zip",
    "TQH-C2_labels_D.zip",
]


def get_data_root() -> str:
    env_root = os.environ.get("IPS_DATA_ROOT")
    if env_root:
        return env_root
    if os.path.exists("D:\\"):
        return "D:\\ips_data"
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "raw"))


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_resumable(url: str, dest: str):
    """Download HTTPS URL to dest with HTTP Range resume support (validates scheme per BUG-05 / B310)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"Refusing non-HTTPS or malformed download URL: {url!r}")
    os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
    part = dest + ".part"
    existing = os.path.getsize(part) if os.path.exists(part) else 0

    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        print(f"  [skip] Already exists: {dest} ({os.path.getsize(dest)} bytes)")
        return

    headers = {"User-Agent": "ips-project-downloader/1.0"}
    if existing > 0:
        headers["Range"] = f"bytes={existing}-"

    req = urllib.request.Request(url, headers=headers)  # noqa: S310 (HTTPS scheme validated above)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            status = getattr(resp, "status", 200)
            mode = "ab" if (status == 206 and existing > 0) else "wb"
            with open(part, mode) as out:
                while True:
                    buf = resp.read(256 * 1024)
                    if not buf:
                        break
                    out.write(buf)
    except urllib.error.HTTPError as e:
        if e.code == 416 and existing > 0:
            pass
        else:
            raise

    os.replace(part, dest)
    print(f"  [ok] Downloaded {dest} ({os.path.getsize(dest)} bytes)")


def parse_sha256sums(sums_path: str) -> dict:
    expected = {}
    with open(sums_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                digest = parts[0].lower()
                fname = parts[-1].lstrip("*")
                expected[os.path.basename(fname)] = digest
    return expected


def main():
    parser = argparse.ArgumentParser(description="Download TQH-C2 Testbed D small files (Windows-safe)")
    parser.add_argument("--out-dir", default=None, help="Override destination directory")
    args = parser.parse_args()

    out_dir = args.out_dir or os.path.join(get_data_root(), "tqh_c2")
    os.makedirs(out_dir, exist_ok=True)
    print(f"[*] TQH-C2 Zenodo record {ZENODO_RECORD_ID} -> {out_dir}")

    for fname in SMALL_FILES:
        url = f"{ZENODO_BASE}/{fname}?download=1"
        dest = os.path.join(out_dir, fname)
        download_resumable(url, dest)

    sums_path = os.path.join(out_dir, "SHA256SUMS_v120.txt")
    expected = parse_sha256sums(sums_path)
    print(f"[*] Verifying SHA-256 against {sums_path} ({len(expected)} entries in checksum file):")
    all_ok = True
    for fname in SMALL_FILES:
        if fname == "SHA256SUMS_v120.txt":
            continue
        dest = os.path.join(out_dir, fname)
        actual = sha256_file(dest)
        exp = expected.get(fname)
        if exp is None:
            print(f"  [WARN] {fname}: not listed in SHA256SUMS_v120.txt (sha256={actual})")
        elif actual == exp:
            print(f"  [PASS] {fname}: sha256={actual}")
        else:
            print(f"  [FAIL] {fname}: expected {exp}, got {actual}")
            all_ok = False

    if not all_ok:
        sys.exit(1)
    print("[+] TQH-C2 Testbed D small files downloaded and verified.")


if __name__ == "__main__":
    main()
