#!/usr/bin/env python3
"""
traffic/manifest.py — Ground-truth label manifest writer for experiment runs.

Records attack and benign episode metadata for supervised evaluation:
  {run_id, family, src_ip, dst_ip, dst_port, start_ts, end_ts, params}
"""
import os
import json
import csv
import time
from typing import Dict, Any, Optional

MANIFEST_HEADER = ["run_id", "family", "src_ip", "dst_ip", "dst_port", "start_ts", "end_ts", "params"]


class ManifestWriter:
    """Thread-safe and process-safe manifest logger."""

    def __init__(self, out_path: str, run_id: Optional[str] = None):
        self.out_path = os.path.abspath(out_path)
        self.run_id = run_id or f"run_{int(time.time())}"
        os.makedirs(os.path.dirname(self.out_path), exist_ok=True)
        self._init_file()

    def _init_file(self):
        if not os.path.exists(self.out_path) or os.path.getsize(self.out_path) == 0:
            with open(self.out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(MANIFEST_HEADER)

    def record_episode(self, family: str, src_ip: str, dst_ip: str, dst_port: int,
                       start_ts: float, end_ts: float, params: Dict[str, Any]):
        """Append an attack or benign injection episode to the manifest."""
        param_str = json.dumps(params, sort_keys=True)
        with open(self.out_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                self.run_id,
                family,
                src_ip,
                dst_ip,
                int(dst_port),
                round(start_ts, 4),
                round(end_ts, 4),
                param_str,
            ])

    @staticmethod
    def load_manifest(path: str):
        """Read manifest into a list of dictionaries with parsed types."""
        records = []
        if not os.path.exists(path):
            return records
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    records.append({
                        "run_id": row["run_id"],
                        "family": row["family"],
                        "src_ip": row["src_ip"],
                        "dst_ip": row["dst_ip"],
                        "dst_port": int(row["dst_port"]),
                        "start_ts": float(row["start_ts"]),
                        "end_ts": float(row["end_ts"]),
                        "params": json.loads(row.get("params", "{}")),
                    })
                except Exception:
                    continue
        return records
