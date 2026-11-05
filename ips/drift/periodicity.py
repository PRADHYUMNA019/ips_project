#!/usr/bin/env python3
"""
ips/drift/periodicity.py — Shared Periodicity Analyzer & Tier-2 Slow-C2 Detector (N1 G3 + N4).

Used in two places:
  1. Drift Guard Check G3 (Non-periodicity): rejects baseline/threshold adaptation when
     a drifting traffic stream exhibits strong periodicity characteristic of C2 beaconing.
  2. Tier-2 Slow-C2 Host-Pair Detector (N4): tracks connection start timestamps per
     (src_ip, dst_ip, dst_port) over long windows (minutes to hours) to detect slow
     beacons (e.g., 30s-3600s interval with jitter) that open a new TLS connection
     per beacon and therefore evade single-flow early-packet IAT features.
"""
from collections import defaultdict
from typing import List, Dict, Any, Tuple
import numpy as np


def analyze_periodicity(
    intervals: List[float],
    cv_threshold: float = 0.35,
    spectral_threshold: float = 3.5,
    min_samples: int = 6,
) -> Dict[str, Any]:
    """
    Analyze a sequence of inter-event intervals (seconds or milliseconds) for periodicity.

    Metrics:
      - cv: Coefficient of Variation (std / mean). Pure periodic = 0.0, Poisson = 1.0,
            jittered C2 beacon (0-30% uniform jitter) <= 0.20.
      - spectral_peak_ratio: Max non-DC FFT power divided by mean non-DC power.
      - autocorr_lag1: Normalized autocorrelation of interval series or binned arrivals.

    Returns dict with `is_periodic`, `cv`, `spectral_peak_ratio`, `mean_interval`.
    """
    arr = np.asarray(intervals, dtype=np.float64)
    arr = arr[np.isfinite(arr) & (arr > 0)]
    if len(arr) < min_samples:
        return {
            "is_periodic": False,
            "cv": 1.0,
            "spectral_peak_ratio": 1.0,
            "mean_interval": float(np.mean(arr)) if len(arr) > 0 else 0.0,
            "reason": "insufficient_samples",
        }

    mean_val = float(np.mean(arr))
    std_val = float(np.std(arr))
    cv = (std_val / mean_val) if mean_val > 1e-9 else 1.0

    # Build a binned arrival-count series over the cumulative timeline to measure FFT peak
    cum_t = np.cumsum(arr)
    total_span = cum_t[-1]
    n_bins = min(512, max(64, len(arr) * 8))
    if total_span > 1e-6:
        hist, _ = np.histogram(cum_t, bins=n_bins, range=(0.0, total_span))
        sig = hist.astype(np.float64) - np.mean(hist)
        spec = np.abs(np.fft.rfft(sig))[1:]  # exclude DC component
        mean_power = float(np.mean(spec)) if len(spec) > 0 else 1.0
        max_power = float(np.max(spec)) if len(spec) > 0 else 1.0
        spectral_ratio = (max_power / mean_power) if mean_power > 1e-9 else 1.0
    else:
        spectral_ratio = 1.0

    is_periodic = bool((cv <= cv_threshold) or (spectral_ratio >= spectral_threshold and cv <= 0.55))
    return {
        "is_periodic": is_periodic,
        "cv": round(cv, 4),
        "spectral_peak_ratio": round(spectral_ratio, 4),
        "mean_interval": round(mean_val, 4),
        "reason": "periodic_detected" if is_periodic else "aperiodic",
    }


class SlowC2Tracker:
    """
    Tier-2 Host-Pair Slow-C2 Beacon Detector (Supporting Novelty N4).

    Maintains connection-initiation timestamps per (src_ip, dst_ip, dst_port) tuple
    across multiple short-lived connections and flags pairs whose inter-connection
    intervals exhibit periodic C2 beaconing.
    """

    def __init__(
        self,
        max_history: int = 64,
        min_connections: int = 8,
        cv_threshold: float = 0.35,
        spectral_threshold: float = 3.5,
    ):
        self.max_history = max_history
        self.min_connections = min_connections
        self.cv_threshold = cv_threshold
        self.spectral_threshold = spectral_threshold
        self.conn_times: Dict[Tuple[str, str, int], List[float]] = defaultdict(list)

    def record_connection(self, src_ip: str, dst_ip: str, dst_port: int, timestamp_s: float) -> Dict[str, Any]:
        """Record a connection start timestamp and evaluate slow-C2 periodicity."""
        key = (str(src_ip), str(dst_ip), int(dst_port))
        ts_list = self.conn_times[key]
        ts_list.append(float(timestamp_s))
        if len(ts_list) > self.max_history:
            del ts_list[: len(ts_list) - self.max_history]

        if len(ts_list) < self.min_connections:
            return {
                "key": key,
                "is_c2_beacon": False,
                "connections_observed": len(ts_list),
                "cv": 1.0,
                "spectral_peak_ratio": 1.0,
            }

        intervals = np.diff(np.sort(np.asarray(ts_list, dtype=np.float64))).tolist()
        res = analyze_periodicity(
            intervals,
            cv_threshold=self.cv_threshold,
            spectral_threshold=self.spectral_threshold,
            min_samples=self.min_connections - 1,
        )
        return {
            "key": key,
            "is_c2_beacon": res["is_periodic"],
            "connections_observed": len(ts_list),
            "cv": res["cv"],
            "spectral_peak_ratio": res["spectral_peak_ratio"],
            "mean_interval_s": res["mean_interval"],
        }

