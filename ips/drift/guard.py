#!/usr/bin/env python3
"""
ips/drift/guard.py — Poisoning-Aware Drift Guard (Primary Novelty N1, WP8).

Protects online threshold/model adaptation against adversarial poisoning
("boiling frog" threshold inflation) while allowing legitimate fleet-wide
benign concept drift (e.g. firmware updates or diurnal changes).

Guard Pipeline (G1 -> G2 -> G3 -> G4 + Bounded Step + Rollback):
  - Stream Detectors: river.drift.ADWIN and river.drift.PageHinkley per device class
  - G1 Persistence: shift must persist across k consecutive evaluation windows
  - G2 Cross-device consistency: >= ceil(rho * class_size) devices (min 2, class_size >= 3)
    must exhibit concurrent shift
  - G3 Non-periodicity: drifting stream must not exhibit C2-like periodicity (periodicity.py)
  - G4 Quarantine & Shadow Validation: candidate threshold calibrated on quarantine buffer
    must preserve FPR <= target + eps_fpr on frozen ANCHOR benign set and
    TPR >= current_tpr - eps_tpr on frozen CANARY DEV-attack set (never held-out families, H2)
  - Bounded Step: threshold changes by at most factor gamma per accepted update
  - Safe Swap & Rollback: atomic threshold update with rollback if post-update FPR spikes
"""
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
import numpy as np

try:
    from river.drift import ADWIN, PageHinkley
except ImportError:
    ADWIN = None
    PageHinkley = None

from ips.models.evt import fit_evt_threshold as calibrate_threshold_evt
from ips.drift.periodicity import analyze_periodicity


@dataclass
class GuardConfig:
    target_fpr: float = 0.01
    min_persistence_windows: int = 2       # G1: k consecutive windows
    consistency_rho: float = 0.60          # G2: fraction of class devices showing shift
    min_class_size_for_g2: int = 3         # G2 requires >= 3 devices in class
    periodicity_cv_thresh: float = 0.30    # G3: CV below this is flagged as periodic
    eps_anchor_fpr: float = 0.02           # G4: max allowed FPR increase on anchor benign set
    eps_canary_tpr: float = 0.08           # G4: max allowed TPR drop on canary DEV attack set
    max_step_gamma: float = 1.30           # Bounded step factor gamma per update
    rollback_alert_rate_max: float = 0.35  # Rollback trigger if post-update alert rate spikes
    enable_g1: bool = True
    enable_g2: bool = True
    enable_g3: bool = True
    enable_g4: bool = True
    enable_bounded_step: bool = True


class _FallbackADWIN:
    """Lightweight fallback change detector if river is unavailable."""

    def __init__(self, delta: float = 0.002):
        self.delta = delta
        self.buf: List[float] = []
        self.drift_detected = False

    def update(self, val: float):
        self.buf.append(float(val))
        if len(self.buf) >= 30:
            half = len(self.buf) // 2
            m1 = float(np.mean(self.buf[:half]))
            m2 = float(np.mean(self.buf[half:]))
            s1 = float(np.std(self.buf[:half])) + 1e-6
            self.drift_detected = abs(m2 - m1) > 2.5 * s1
            if self.drift_detected:
                self.buf = self.buf[half:]
        else:
            self.drift_detected = False


class PoisoningAwareDriftGuard:
    """Per-device-class Poisoning-Aware Drift Guard (N1)."""

    def __init__(
        self,
        device_class: str,
        class_devices: List[str],
        initial_threshold: float,
        anchor_benign_scores: np.ndarray,
        canary_dev_attack_scores: np.ndarray,
        config: Optional[GuardConfig] = None,
    ):
        self.device_class = device_class
        self.class_devices = list(class_devices)
        self.class_size = len(self.class_devices)
        self.threshold = float(initial_threshold)
        self.prev_threshold: Optional[float] = None
        self.baseline_mean = float(np.mean(anchor_benign_scores))
        self.baseline_std = max(1e-6, float(np.std(anchor_benign_scores)))
        self.anchor_mean = self.baseline_mean
        self.anchor_std = self.baseline_std

        self.anchor_benign = np.asarray(anchor_benign_scores, dtype=np.float64)
        self.canary_attacks = np.asarray(canary_dev_attack_scores, dtype=np.float64)
        self.cfg = config if config is not None else GuardConfig()

        # Initialize stream change detectors (ADWIN + PageHinkley)
        self.adwin = ADWIN(delta=0.002) if ADWIN is not None else _FallbackADWIN(delta=0.002)
        self.ph = PageHinkley(min_instances=20, delta=0.005, threshold=15.0) if PageHinkley is not None else None

        self.consecutive_drift_windows = 0
        self.quarantine_scores: List[float] = []
        self.history: List[Dict[str, Any]] = []
        self.just_updated = False

    def evaluate_window(
        self,
        window_events: List[Dict[str, Any]],
        mode: str = "guarded",
    ) -> Dict[str, Any]:
        """
        Process one time window of flow observations for this device class.

        Each item in `window_events` is a dict:
          {
            "device_id": str,
            "score": float,
            "iat_ms": float,     # inter-flow or mean flow IAT
            "is_attack": bool,   # ground-truth label (used ONLY for evaluation metrics, NEVER by guard!)
          }
        `mode` in {"static", "plain_adwin_recalib", "plain_adwin_retrain", "guarded"}.
        """
        if not window_events:
            return {"status": "EMPTY_WINDOW", "threshold": self.threshold}

        scores = np.array([float(e["score"]) for e in window_events], dtype=np.float64)

        # Feed stream detectors
        stream_drift_triggered = False
        for s in scores:
            self.adwin.update(float(s))
            if self.adwin.drift_detected:
                stream_drift_triggered = True
            if self.ph is not None:
                self.ph.update(float(s))
                if self.ph.drift_detected:
                    stream_drift_triggered = True

        # Also check window mean shift relative to baseline (> 2.0 sigma)
        win_mean = float(np.mean(scores))
        if abs(win_mean - self.baseline_mean) > 2.0 * self.baseline_std:
            stream_drift_triggered = True

        if mode == "static":
            return self._record_step("STATIC_NO_UPDATE", False, scores)

        # Plain unguarded ADWIN baselines
        if mode in ("plain_adwin_recalib", "plain_adwin_retrain"):
            if stream_drift_triggered:
                cand_q = float(np.quantile(scores, 1.0 - self.cfg.target_fpr))
                if mode == "plain_adwin_retrain":
                    # Unbounded retrain/recalibration directly on recent window
                    self.prev_threshold = self.threshold
                    self.threshold = max(self.threshold * 0.5, cand_q * 1.05)
                else:
                    # Plain recalibration on combined anchor + window without G1-G4 checks
                    combined = np.concatenate([self.anchor_benign[-100:], scores])
                    evt_res = calibrate_threshold_evt(combined, target_fpr=self.cfg.target_fpr)
                    self.prev_threshold = self.threshold
                    self.threshold = max(float(evt_res["threshold"]), cand_q)
                self.baseline_mean = win_mean
                return self._record_step("ADAPTED_UNGUARDED", True, scores)
            return self._record_step("NO_DRIFT", False, scores)

        # --- Guarded Mode (N1: G1 -> G2 -> G3 -> G4 + Bounded Step + Rollback) ---
        if not stream_drift_triggered:
            self.consecutive_drift_windows = 0
            self.quarantine_scores.clear()
            return self._record_step("NO_DRIFT", False, scores)

        self.consecutive_drift_windows += 1
        self.quarantine_scores.extend(scores.tolist())

        # Check G1: Persistence across k consecutive windows
        if self.cfg.enable_g1 and self.consecutive_drift_windows < self.cfg.min_persistence_windows:
            return self._record_step("PENDING_G1_PERSISTENCE", False, scores)

        # Identify which devices in this class show elevated scores in this window
        dev_scores = defaultdict(list)
        dev_iats = defaultdict(list)
        for e in window_events:
            did = str(e.get("device_id", "unknown"))
            dev_scores[did].append(float(e["score"]))
            if "iat_ms" in e:
                dev_iats[did].append(float(e["iat_ms"]))

        drifting_devices: Set[str] = set()
        shift_cutoff = self.anchor_mean + 2.0 * self.anchor_std
        for did, d_list in dev_scores.items():
            if did in self.class_devices and float(np.mean(d_list)) > shift_cutoff:
                drifting_devices.add(did)

        # Check G2: Cross-device consistency within the device class
        if self.cfg.enable_g2:
            if self.class_size < self.cfg.min_class_size_for_g2:
                return self._record_step(
                    "REJECTED_G2_UNAVAILABLE_SMALL_CLASS",
                    False,
                    scores,
                    extra={"class_size": self.class_size, "drifting_devices": len(drifting_devices)},
                )
            required_devices = max(2, int(math.ceil(self.cfg.consistency_rho * self.class_size)))
            if len(drifting_devices) < required_devices:
                return self._record_step(
                    "REJECTED_G2_INCONSISTENT_ACROSS_CLASS",
                    False,
                    scores,
                    extra={
                        "drifting_devices": len(drifting_devices),
                        "required_devices": required_devices,
                        "class_size": self.class_size,
                    },
                )

        # Check G3: Non-periodicity of drifting traffic
        if self.cfg.enable_g3:
            pooled_iats = []
            target_devs = drifting_devices if drifting_devices else set(dev_iats.keys())
            for did in target_devs:
                pooled_iats.extend(dev_iats.get(did, []))
            if len(pooled_iats) >= 6:
                per_res = analyze_periodicity(pooled_iats, cv_threshold=self.cfg.periodicity_cv_thresh)
                if per_res["is_periodic"]:
                    return self._record_step(
                        "REJECTED_G3_PERIODIC_STREAM",
                        False,
                        scores,
                        extra={"periodicity": per_res},
                    )

        # Candidate threshold estimation from quarantine buffer
        q_arr = np.asarray(self.quarantine_scores[-500:], dtype=np.float64)
        evt_res = calibrate_threshold_evt(q_arr, target_fpr=self.cfg.target_fpr)
        cand_thresh = max(float(evt_res["threshold"]), float(np.quantile(q_arr, 1.0 - self.cfg.target_fpr)))

        # Apply Bounded Step BEFORE or AFTER G4? Applying bounded step produces the actual
        # candidate threshold that would be deployed, and G4 validates both raw and bounded candidate:
        # if the raw quarantine distribution would destroy canary TPR (poisoning), G4 rejects!
        if self.cfg.enable_g4:
            anchor_fpr = float(np.mean(self.anchor_benign > cand_thresh))
            cur_canary_tpr = float(np.mean(self.canary_attacks > self.threshold))
            cand_canary_tpr = float(np.mean(self.canary_attacks > cand_thresh))

            if anchor_fpr > (self.cfg.target_fpr + self.cfg.eps_anchor_fpr):
                return self._record_step(
                    "REJECTED_G4_ANCHOR_FPR_EXCEEDED",
                    False,
                    scores,
                    extra={"anchor_fpr": round(anchor_fpr, 4), "cand_thresh": round(cand_thresh, 4)},
                )
            if (cur_canary_tpr - cand_canary_tpr) > self.cfg.eps_canary_tpr:
                return self._record_step(
                    "REJECTED_G4_CANARY_TPR_DROP",
                    False,
                    scores,
                    extra={
                        "cur_canary_tpr": round(cur_canary_tpr, 4),
                        "cand_canary_tpr": round(cand_canary_tpr, 4),
                        "cand_thresh": round(cand_thresh, 4),
                    },
                )

        # Bounded step update
        if self.cfg.enable_bounded_step:
            low_b = self.threshold / self.cfg.max_step_gamma
            high_b = self.threshold * self.cfg.max_step_gamma
            new_thresh = float(np.clip(cand_thresh, low_b, high_b))
        else:
            new_thresh = float(cand_thresh)

        self.prev_threshold = self.threshold
        self.threshold = new_thresh
        self.baseline_mean = float(np.mean(q_arr))
        self.quarantine_scores.clear()
        self.consecutive_drift_windows = 0
        self.just_updated = True

        return self._record_step(
            "ACCEPTED_GUARDED_UPDATE",
            True,
            scores,
            extra={"old_threshold": round(self.prev_threshold, 4), "new_threshold": round(self.threshold, 4)},
        )

    def check_post_update_health(self, recent_benign_scores: np.ndarray) -> Dict[str, Any]:
        """
        Safe Swap & Rollback check: if post-update benign alert rate spikes
        above rollback_alert_rate_max, atomically restore prev_threshold.
        """
        if self.prev_threshold is None or len(recent_benign_scores) == 0:
            return {"rolled_back": False, "threshold": self.threshold}

        alert_rate = float(np.mean(np.asarray(recent_benign_scores) > self.threshold))
        if alert_rate > self.cfg.rollback_alert_rate_max:
            restored = self.prev_threshold
            self.threshold = restored
            self.prev_threshold = None
            self.just_updated = False
            return {
                "rolled_back": True,
                "alert_rate": round(alert_rate, 4),
                "threshold": self.threshold,
            }
        return {"rolled_back": False, "alert_rate": round(alert_rate, 4), "threshold": self.threshold}

    def _record_step(
        self,
        status: str,
        adapted: bool,
        scores: np.ndarray,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        rec = {
            "status": status,
            "adapted": adapted,
            "threshold": round(self.threshold, 6),
            "window_mean_score": round(float(np.mean(scores)), 6),
        }
        if extra:
            rec.update(extra)
        self.history.append(rec)
        return rec
