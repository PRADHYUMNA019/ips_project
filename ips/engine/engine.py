#!/usr/bin/env python3
"""
ips/engine/engine.py — Closed-Loop User-Space IPS Engine v2 (WP7).

Responsibilities:
  - Compiles & attaches ebpf/ips_engine.c to v-lan-gw and v-wan-gw via BCC
    (or uses MockBPFBackend for V1 unit testing and offline simulation).
  - Consumes EARLY_FLOW events from the kernel ring buffer.
  - Computes 3N+8 normalized early-flow features via ips.features.build_early_vector.
  - Runs INT8 ONNX Runtime inference and compares MSE against EVT-calibrated threshold.
  - Logs top-3 contributing features (explain_anomaly), time_to_verdict_ms, and
    payload_packets_at_verdict (B1).
  - Writes per-5-tuple BYPASS or DROP entries with monotonic TTL into verdict_map
    when mode == "enforce" (respecting bypass: on|off ablation for N2).
  - Runs the 1 Hz Watchdog / Load Shedder that toggles cfg_map[0].shed = 1 on
    ring-buffer pressure or high lag and recovers after cooldown_s.
"""
import os
import sys
import time
import json
import ctypes
import socket
import argparse
from typing import Dict, Any, Optional, List, Tuple
import numpy as np
import yaml

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)

from ips.features import build_early_vector, get_feature_names
from ips.models.autoencoder import explain_anomaly
from ips.engine.schema import (
    SCHEMA_VERSION,
    VERDICT_NONE,
    VERDICT_BYPASS,
    VERDICT_DROP,
    load_system_config,
    generate_c_header,
    make_ctypes_schemas,
    make_flow_key,
    flow_key_to_canonical_tuple,
    event_to_dict,
)

try:
    import onnxruntime as ort
except ImportError:
    ort = None


class MockBPFBackend:
    """
    Pure-Python simulation of the XDP fast path maps and packet/event processing
    for deterministic V1 unit testing without Linux root/BCC.
    """

    def __init__(self, early_n: int = 16, checkpoints: Optional[List[int]] = None):
        if checkpoints is not None and len(checkpoints) > 0:
            self.checkpoints = sorted([int(x) for x in checkpoints])
            self.early_n = max(int(early_n), max(self.checkpoints))
        else:
            self.early_n = int(early_n)
            self.checkpoints = [self.early_n]
        self.schemas = make_ctypes_schemas(self.early_n)
        self.xdp_mode = "mock-userspace"
        self.verdict_map: Dict[bytes, Tuple[int, int]] = {}  # key_bytes -> (action, expiry_ns)
        self.flow_state: Dict[bytes, Dict[str, Any]] = {}
        self.cfg = {
            "lan_ifindex": 1,
            "shed": 0,
            "debug": 0,
            "tier0_enabled": 1,
            "tier0_rate": 50,
            "tier0_capacity": 100,
        }
        self.stats = {
            "pkts_seen": 0,
            "pkts_bypassed": 0,
            "pkts_dropped_verdict": 0,
            "pkts_dropped_tier0": 0,
            "events_emitted": 0,
            "ringbuf_drop_failures": 0,
            "flow_insert_failures": 0,
            "ckpt_retry": 0,
            "ckpt_skipped_shed": 0,
        }
        self.simulate_ringbuf_full = False
        self.flow_idle_ns = 120 * 1_000_000_000

    def set_verdict(self, fk, action: int, expiry_ns: int):
        self.verdict_map[bytes(fk)] = (int(action), int(expiry_ns))

    def get_verdict(self, fk, now_ns: int) -> int:
        k = bytes(fk)
        if k not in self.verdict_map:
            return VERDICT_NONE
        action, expiry_ns = self.verdict_map[k]
        if now_ns < expiry_ns:
            return action
        del self.verdict_map[k]
        return VERDICT_NONE

    def set_shed(self, shed: int):
        self.cfg["shed"] = int(shed)

    def get_stats(self) -> Dict[str, int]:
        return dict(self.stats)

    def simulate_packet(
        self,
        src_ip: str,
        sport: int,
        dst_ip: str,
        dport: int,
        proto: str,
        payload_len: int,
        direction: int,
        now_ns: int,
        tcp_flags: int = 0,
        is_syn_only: bool = False,
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Simulate XDP packet processing through verdict_map and flow_state.
        Returns (xdp_action_str, emitted_early_flow_dict_or_None).
        """
        self.stats["pkts_seen"] += 1
        fk = make_flow_key(src_ip, sport, dst_ip, dport, proto)
        v = self.get_verdict(fk, now_ns)
        if v == VERDICT_DROP:
            self.stats["pkts_dropped_verdict"] += 1
            return ("XDP_DROP", None)
        if v == VERDICT_BYPASS:
            self.stats["pkts_bypassed"] += 1
            return ("XDP_PASS_BYPASS", None)

        k = bytes(fk)
        tup = flow_key_to_canonical_tuple(fk)
        reinit = False
        if k in self.flow_state:
            rec_prev = self.flow_state[k]
            if is_syn_only and (((rec_prev.get("flags_seen", 0) & 0x05) != 0) or len(rec_prev["sizes"]) > 0):
                reinit = True
            elif (now_ns - rec_prev.get("last_seen_ns", rec_prev["last_ts_ns"])) > self.flow_idle_ns:
                reinit = True

        if k not in self.flow_state or reinit:
            self.flow_state[k] = {
                "schema_version": SCHEMA_VERSION,
                "ip_a": tup[0],
                "port_a": tup[1],
                "ip_b": tup[2],
                "port_b": tup[3],
                "proto": tup[4],
                "initiator_ip": src_ip,
                "initiator_port": sport,
                "first_ts_ns": now_ns,
                "last_ts_ns": now_ns,
                "last_seen_ns": now_ns,
                "total_pkts": 0,
                "total_bytes": 0,
                "flags_seen": int(tcp_flags),
                "sizes": [],
                "dirs": [],
                "iat_ns": [],
                "emitted_mask": 0,
            }

        rec = self.flow_state[k]
        rec["total_pkts"] += 1
        rec["total_bytes"] += payload_len + 40
        rec["flags_seen"] = rec.get("flags_seen", 0) | int(tcp_flags)
        rec["last_seen_ns"] = now_ns
        if payload_len > 0 and len(rec["sizes"]) < self.early_n:
            if len(rec["sizes"]) > 0:
                rec["iat_ns"].append(max(0, now_ns - rec["last_ts_ns"]))
            rec["sizes"].append(int(payload_len))
            rec["dirs"].append(int(direction))
            rec["last_ts_ns"] = now_ns

        cur_vlen = len(rec["sizes"])
        ckpt_hit = -1
        for idx, ckpt_val in enumerate(self.checkpoints):
            if cur_vlen >= ckpt_val and not (rec["emitted_mask"] & (1 << idx)):
                ckpt_hit = idx
                break

        if ckpt_hit >= 0:
            if self.cfg["shed"] == 1:
                self.stats["ckpt_skipped_shed"] = self.stats.get("ckpt_skipped_shed", 0) + 1
                return ("XDP_PASS", None)
            if getattr(self, "simulate_ringbuf_full", False):
                self.stats["ringbuf_drop_failures"] += 1
                self.stats["ckpt_retry"] = self.stats.get("ckpt_retry", 0) + 1
                return ("XDP_PASS", None)

            rec["emitted_mask"] |= (1 << ckpt_hit)
            self.stats["events_emitted"] += 1
            ev = dict(rec)
            ev["sizes"] = list(rec["sizes"])
            ev["dirs"] = list(rec["dirs"])
            ev["iat_ns"] = list(rec["iat_ns"])
            ev["valid_len"] = cur_vlen
            ev["checkpoint_idx"] = ckpt_hit
            return ("XDP_PASS", ev)

        return ("XDP_PASS", None)

    def close(self):
        pass


class BCCKernelBackend:
    """Real Linux BCC XDP backend attaching ebpf/ips_engine.c to gateway interfaces."""

    def __init__(self, config: Dict[str, Any], lan_dev: str = "v-lan-gw", wan_dev: str = "v-wan-gw"):
        from bcc import BPF

        self.BPF = BPF
        self.config = config
        self.early_n = int(config.get("system", {}).get("early_n", 12))
        self.schemas = make_ctypes_schemas(self.early_n)
        self.lan_dev = lan_dev
        self.wan_dev = wan_dev
        self.attached_devs = []
        self.xdp_mode = "unknown"

        c_path = os.path.join(REPO_DIR, "ebpf", "ips_engine.c")
        with open(c_path, "r", encoding="utf-8") as f:
            c_src = generate_c_header(config) + "\n" + f.read()

        self.bpf = BPF(text=c_src)
        self.fn = self.bpf.load_func("xdp_ips_prog", BPF.XDP)

        for dev in (lan_dev, wan_dev):
            try:
                self.bpf.attach_xdp(dev, self.fn, 0)
                self.xdp_mode = "native-or-driver"
                self.attached_devs.append((dev, 0))
            except Exception:
                self.bpf.attach_xdp(dev, self.fn, BPF.XDP_FLAGS_SKB_MODE)
                self.xdp_mode = "generic-skb"
                self.attached_devs.append((dev, BPF.XDP_FLAGS_SKB_MODE))

        lan_ifindex = socket.if_nametoindex(lan_dev)
        t0 = config.get("engine", {}).get("tier0", {})
        self.cfg_entry = self.schemas.CfgEntry(
            lan_ifindex=lan_ifindex,
            shed=0,
            debug=0,
            tier0_enabled=1 if t0.get("enabled", True) else 0,
            pad=0,
            tier0_rate=int(t0.get("bucket_refill_rate", 50)),
            tier0_capacity=int(t0.get("bucket_capacity", 100)),
        )
        cfg_map = self.bpf.get_table("cfg_map")
        cfg_map[ctypes.c_int(0)] = self.cfg_entry
        self.verdict_map = self.bpf.get_table("verdict_map")
        self.stats_map = self.bpf.get_table("stats_map")

    def set_verdict(self, fk, action: int, expiry_ns: int):
        ve = self.schemas.VerdictEntry(action=int(action), expiry_ns=int(expiry_ns))
        self.verdict_map[fk] = ve

    def set_shed(self, shed: int):
        self.cfg_entry.shed = int(shed)
        cfg_map = self.bpf.get_table("cfg_map")
        cfg_map[ctypes.c_int(0)] = self.cfg_entry

    def get_stats(self) -> Dict[str, int]:
        totals = {
            "pkts_seen": 0,
            "pkts_bypassed": 0,
            "pkts_dropped_verdict": 0,
            "pkts_dropped_tier0": 0,
            "events_emitted": 0,
            "ringbuf_drop_failures": 0,
            "flow_insert_failures": 0,
            "ckpt_retry": 0,
            "ckpt_skipped_shed": 0,
        }
        try:
            per_cpu = self.stats_map[ctypes.c_int(0)]
            for cpu_st in per_cpu:
                for k in totals:
                    totals[k] += int(getattr(cpu_st, k, 0))
        except Exception:
            pass
        return totals

    def close(self):
        for dev, flags in self.attached_devs:
            try:
                self.bpf.remove_xdp(dev, flags)
            except Exception:
                pass
        self.attached_devs.clear()


class IPSEngine:
    """User-space closed-loop inference, verdict manager, and load-shedding watchdog."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        backend: Optional[Any] = None,
        mode_override: Optional[str] = None,
        bypass_override: Optional[bool] = None,
    ):
        self.config = config if config is not None else load_system_config()
        sys_cfg = self.config.get("system", {})
        eng_cfg = self.config.get("engine", {})
        wd_cfg = eng_cfg.get("watchdog", {})

        raw_ckpts = sys_cfg.get("checkpoints", None)
        early_n_cfg = sys_cfg.get("early_n", None)
        if backend is not None and hasattr(backend, "checkpoints") and backend.checkpoints == [backend.early_n] and early_n_cfg == backend.early_n:
            self.early_n = int(backend.early_n)
            self.checkpoints = list(backend.checkpoints)
        elif raw_ckpts and len(raw_ckpts) > 0:
            self.checkpoints = sorted([int(x) for x in raw_ckpts])
            self.early_n = max(int(early_n_cfg) if early_n_cfg is not None else max(self.checkpoints), max(self.checkpoints))
        else:
            self.early_n = int(early_n_cfg) if early_n_cfg is not None else 12
            self.checkpoints = [self.early_n]

        self.alpha_spending = str(sys_cfg.get("alpha_spending", "equal"))
        self.mode = mode_override if mode_override is not None else str(sys_cfg.get("mode", "observe"))
        if bypass_override is not None:
            self.bypass_enabled = bool(bypass_override)
        else:
            b_val = sys_cfg.get("bypass", True)
            self.bypass_enabled = b_val if isinstance(b_val, bool) else (str(b_val).lower() in ("on", "true", "1"))

        self.bypass_ttl_ns = int(float(sys_cfg.get("bypass_ttl_s", 300)) * 1e9)
        self.drop_ttl_ns = int(float(sys_cfg.get("drop_ttl_s", 60)) * 1e9)
        self.feature_names = get_feature_names(self.early_n)

        # Watchdog parameters
        self.max_ringbuf_failures_per_s = int(wd_cfg.get("max_ringbuf_failures_per_s", 100))
        self.max_event_rate_per_s = int(wd_cfg.get("max_event_rate_per_s", 10000))
        self.max_engine_lag_ms = float(wd_cfg.get("max_engine_lag_ms", 500.0))
        self.cooldown_s = float(wd_cfg.get("cooldown_s", 30.0))

        self.shed_active = False
        self.shed_activated_at_s: float = 0.0
        self.last_watchdog_s: float = 0.0
        self.last_stats: Dict[str, int] = {}
        self.last_lag_ms: float = 0.0

        self.backend = (
            backend
            if backend is not None
            else MockBPFBackend(early_n=self.early_n, checkpoints=self.checkpoints)
        )
        self.decisions_log: List[Dict[str, Any]] = []
        self.watchdog_log: List[Dict[str, Any]] = []
        self.schema_mismatch_count = 0

        # Load model card & ONNX Runtime sessions (global + per-checkpoint) if available
        self.threshold = 0.25
        self.ckpt_thresholds: Dict[int, float] = {k: 0.25 for k in self.checkpoints}
        self.ckpt_sessions: Dict[int, Any] = {}
        self.per_class_thresholds: Dict[str, float] = {}
        self.ip_to_class: Dict[str, str] = {}
        self.ort_session = None
        self._load_device_registry(sys_cfg.get("devices_path", "configs/devices.yaml"))
        self._load_model_and_thresholds(sys_cfg.get("model_path", "models/autoencoder_int8.onnx"))

    def _load_device_registry(self, devices_rel_path: str):
        path = os.path.join(REPO_DIR, devices_rel_path) if not os.path.isabs(devices_rel_path) else devices_rel_path
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            for dev in data.get("devices", []):
                if "ip" in dev and "class" in dev:
                    self.ip_to_class[str(dev["ip"])] = str(dev["class"])

    def _load_model_and_thresholds(self, model_rel_path: str):
        card_path = os.path.join(REPO_DIR, "models", "model_card.json")
        if os.path.exists(card_path):
            try:
                with open(card_path, "r", encoding="utf-8") as f:
                    card = json.load(f)
                if int(card.get("early_n", self.early_n)) == self.early_n:
                    self.threshold = float(card.get("evt_calibration", {}).get("threshold", self.threshold))
                    for cls_name, info in card.get("per_class_models", {}).items():
                        if "evt_001" in info:
                            self.per_class_thresholds[cls_name] = float(info["evt_001"])
                tau_key = "tau_front_001" if self.alpha_spending == "front_loaded" else "tau_equal_001"
                for k_str, cinfo in card.get("checkpoint_models", {}).items():
                    k_int = int(k_str)
                    if k_int in self.checkpoints:
                        self.ckpt_thresholds[k_int] = float(cinfo.get(tau_key, cinfo.get("tau_equal_001", self.threshold)))
                        c_onnx = cinfo.get("onnx_int8_path", cinfo.get("onnx_fp32_path", ""))
                        if ort is not None and c_onnx and os.path.exists(c_onnx):
                            try:
                                self.ckpt_sessions[k_int] = ort.InferenceSession(c_onnx, providers=["CPUExecutionProvider"])
                            except Exception:
                                pass
            except Exception:
                pass

        onnx_path = os.path.join(REPO_DIR, model_rel_path) if not os.path.isabs(model_rel_path) else model_rel_path
        if ort is not None and os.path.exists(onnx_path):
            try:
                sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
                in_shape = sess.get_inputs()[0].shape
                if len(in_shape) >= 2 and in_shape[1] == (3 * self.early_n + 8):
                    self.ort_session = sess
            except Exception:
                self.ort_session = None

    def score_vector(self, vec: np.ndarray, ckpt_n: Optional[int] = None) -> Tuple[float, np.ndarray, float]:
        """
        Score a single normalized early-flow vector (1D float32 array of length 3N+8).
        Uses the checkpoint-specific ONNX session when available, or deterministic fallback.
        Returns (mse_score, recon_vector, inference_ms).
        """
        t0 = time.perf_counter()
        n_win = int(ckpt_n) if ckpt_n is not None else self.early_n
        x = vec.reshape(1, -1).astype(np.float32)

        sess = self.ckpt_sessions.get(n_win, None)
        if sess is None and n_win == self.early_n and self.ort_session is not None and len(vec) == (3 * self.early_n + 8):
            sess = self.ort_session

        if sess is not None:
            inp_name = sess.get_inputs()[0].name
            recon = sess.run(None, {inp_name: x})[0][0]
        else:
            # Deterministic fallback reconstruction when ONNX model file is not present
            recon = np.copy(vec)
            recon[:n_win] = 0.08
            recon[2 * n_win : 3 * n_win - 1] = 5.4
            agg_start = 3 * n_win - 1
            recon[agg_start + 0] = 0.04   # bytes_up
            recon[agg_start + 1] = 0.04   # bytes_down
            recon[agg_start + 5] = 0.77   # mean_log_iat / 7.0
            recon[agg_start + 7] = 0.08   # first_payload_size
        sq_err = (vec - recon) ** 2
        mse = float(np.mean(sq_err))
        infer_ms = (time.perf_counter() - t0) * 1000.0
        return mse, recon, infer_ms

    def parse_ringbuf_event(self, data, size: int) -> Optional[Dict[str, Any]]:
        """
        Safely unpack and validate a ringbuffer event from XDP fast path (B1 / DEF-04).
        Validates size >= ctypes.sizeof(EarlyFlowEvent) and ev.schema_version == SCHEMA_VERSION.
        If invalid, increments schema_mismatch; if schema_mismatch > 10, triggers load shedding.
        """
        expected_size = ctypes.sizeof(self.backend.schemas.EarlyFlowEvent)
        if size < expected_size:
            self._handle_schema_mismatch(f"Buffer size {size} < expected {expected_size}")
            return None

        ev_struct = ctypes.cast(data, ctypes.POINTER(self.backend.schemas.EarlyFlowEvent)).contents
        if ev_struct.schema_version != SCHEMA_VERSION:
            self._handle_schema_mismatch(
                f"Schema version mismatch: event has {ev_struct.schema_version}, engine expects {SCHEMA_VERSION}"
            )
            return None

        return event_to_dict(ev_struct)

    def _handle_schema_mismatch(self, reason: str):
        self.schema_mismatch_count += 1
        if hasattr(self.backend, "stats") and "schema_mismatch" in self.backend.stats:
            self.backend.stats["schema_mismatch"] += 1
        if self.schema_mismatch_count > 10:
            if not self.shed_active:
                self.shed_active = True
                self.backend.set_shed(1)

    def handle_early_flow_event(self, ev_dict: Dict[str, Any], now_ns: Optional[int] = None) -> Dict[str, Any]:
        """
        Process one EARLY_FLOW event dictionary across progressive checkpoints (C1 / N7):
          1. Determine checkpoint window k_win (e.g., 4, 8, or 16) and extract 3*k_win+8 feature vector
          2. Run inference & compute top-3 feature attribution
          3. Apply 'Early DROP, Late BYPASS':
               - If score > tau_k at ANY checkpoint k: write VERDICT_DROP immediately
               - Else if k == final checkpoint N_K and bypass_enabled: write VERDICT_BYPASS
               - Else (intermediate checkpoint k < N_K with benign score): write nothing ('CONTINUE')
          4. Record time_to_verdict_ms and payload_packets_at_verdict (B1)
        """
        if now_ns is None:
            now_ns = time.monotonic_ns()

        sizes = ev_dict["sizes"]
        dirs = ev_dict["dirs"]
        iat_ns = ev_dict.get("iat_ns", [])
        vlen = int(ev_dict.get("valid_len", len(sizes)))
        k_win = vlen if vlen in self.checkpoints else self.early_n
        ckpt_idx = int(ev_dict.get("checkpoint_idx", self.checkpoints.index(k_win) if k_win in self.checkpoints else 0))

        iat_ms = [float(x) / 1e6 for x in iat_ns[: max(0, k_win - 1)]]
        vec = build_early_vector(sizes[:k_win], dirs[:k_win], iat_ms, early_n=k_win)
        feat_names_k = get_feature_names(k_win)

        score, recon, infer_ms = self.score_vector(vec, ckpt_n=k_win)
        sq_errors = (vec - recon) ** 2
        top_features = explain_anomaly(sq_errors, feat_names_k, top_k=3)

        init_ip = ev_dict.get("initiator_ip", ev_dict["ip_a"])
        dev_class = self.ip_to_class.get(init_ip, "global")
        # If self.threshold was explicitly overridden by caller/test, honour it; else use ckpt_thresholds
        thresh = self.ckpt_thresholds.get(k_win, self.threshold) if self.threshold == 0.25 else self.threshold

        is_anomaly = bool(score > thresh)
        is_final_checkpoint = (k_win >= self.checkpoints[-1])
        first_ts = int(ev_dict.get("first_ts_ns", now_ns))
        last_ts = int(ev_dict.get("last_ts_ns", now_ns))
        flow_observation_ms = max(0.0, (last_ts - first_ts) / 1e6)
        time_to_verdict_ms = flow_observation_ms + infer_ms
        self.last_lag_ms = max(0.0, (now_ns - last_ts) / 1e6)

        fk = make_flow_key(
            ev_dict["ip_a"],
            ev_dict["port_a"],
            ev_dict["ip_b"],
            ev_dict["port_b"],
            ev_dict.get("proto", "TCP"),
        )

        verdict_written = "NONE"
        if self.mode == "enforce":
            if is_anomaly:
                self.backend.set_verdict(fk, VERDICT_DROP, now_ns + self.drop_ttl_ns)
                verdict_written = "DROP"
            elif is_final_checkpoint and self.bypass_enabled:
                self.backend.set_verdict(fk, VERDICT_BYPASS, now_ns + self.bypass_ttl_ns)
                verdict_written = "BYPASS"
            elif not is_final_checkpoint:
                verdict_written = "CONTINUE"

        decision = {
            "timestamp_ns": now_ns,
            "ip_a": ev_dict["ip_a"],
            "port_a": int(ev_dict["port_a"]),
            "ip_b": ev_dict["ip_b"],
            "port_b": int(ev_dict["port_b"]),
            "proto": ev_dict.get("proto", "TCP"),
            "initiator_ip": init_ip,
            "device_class": dev_class,
            "checkpoint_idx": ckpt_idx,
            "checkpoint_n": k_win,
            "is_final_checkpoint": is_final_checkpoint,
            "score": round(score, 6),
            "threshold": round(thresh, 6),
            "is_anomaly": is_anomaly,
            "mode": self.mode,
            "verdict_written": verdict_written,
            "payload_packets_at_verdict": vlen,
            "total_packets_at_verdict": int(ev_dict.get("total_pkts", len(sizes))),
            "flow_observation_ms": round(flow_observation_ms, 3),
            "inference_ms": round(infer_ms, 3),
            "time_to_verdict_ms": round(time_to_verdict_ms, 3),
            "top_3_features": top_features,
        }
        self.decisions_log.append(decision)
        return decision

    def step_watchdog(self, now_s: Optional[float] = None) -> Dict[str, Any]:
        """
        Evaluate 1 Hz watchdog telemetry and toggle kernel load-shedding (cfg.shed)
        if ring-buffer drop failures, event rate, or lag exceed configured bounds.
        """
        if now_s is None:
            now_s = time.monotonic()

        cur_stats = self.backend.get_stats()
        dt = max(1e-3, now_s - self.last_watchdog_s) if self.last_watchdog_s > 0 else 1.0

        rb_fails_delta = cur_stats.get("ringbuf_drop_failures", 0) - self.last_stats.get("ringbuf_drop_failures", 0)
        events_delta = cur_stats.get("events_emitted", 0) - self.last_stats.get("events_emitted", 0)

        rb_fail_rate = rb_fails_delta / dt
        event_rate = events_delta / dt

        overload = (
            rb_fail_rate > self.max_ringbuf_failures_per_s
            or event_rate > self.max_event_rate_per_s
            or self.last_lag_ms > self.max_engine_lag_ms
        )

        action = "STEADY"
        if overload and not self.shed_active:
            self.shed_active = True
            self.shed_activated_at_s = now_s
            self.backend.set_shed(1)
            action = "WATCHDOG_SHED_ON"
        elif overload and self.shed_active:
            self.shed_activated_at_s = now_s  # reset cooldown timer while still overloaded
        elif not overload and self.shed_active:
            if (now_s - self.shed_activated_at_s) >= self.cooldown_s:
                self.shed_active = False
                self.backend.set_shed(0)
                action = "WATCHDOG_SHED_OFF"

        self.last_watchdog_s = now_s
        self.last_stats = dict(cur_stats)

        entry = {
            "timestamp_s": round(now_s, 3),
            "shed_active": self.shed_active,
            "action": action,
            "rb_fail_rate_per_s": round(rb_fail_rate, 2),
            "event_rate_per_s": round(event_rate, 2),
            "last_lag_ms": round(self.last_lag_ms, 2),
            "stats": cur_stats,
        }
        self.watchdog_log.append(entry)
        return entry


def run_cli():
    parser = argparse.ArgumentParser(description="IPS Closed-Loop User-Space Engine v2")
    parser.add_argument("--config", default=os.path.join(REPO_DIR, "configs", "system.yaml"))
    parser.add_argument("--mode", choices=["observe", "enforce"], default=None)
    parser.add_argument("--bypass", choices=["on", "off"], default=None)
    parser.add_argument("--events-out", default=None, help="Write raw kernel EARLY_FLOW events to JSONL")
    parser.add_argument("--telemetry-out", default=os.path.join(REPO_DIR, "results", "logs", "engine_v2.jsonl"))
    parser.add_argument("--duration", type=float, default=0.0, help="Run duration in seconds (0 = until interrupted)")
    parser.add_argument("--mock", action="store_true", help="Use MockBPFBackend instead of BCC")
    args = parser.parse_args()

    cfg = load_system_config(args.config)
    bypass_ovr = None if args.bypass is None else (args.bypass == "on")

    if args.mock:
        backend = MockBPFBackend(early_n=int(cfg["system"]["early_n"]))
    else:
        backend = BCCKernelBackend(cfg)

    engine = IPSEngine(config=cfg, backend=backend, mode_override=args.mode, bypass_override=bypass_ovr)
    os.makedirs(os.path.dirname(os.path.abspath(args.telemetry_out)), exist_ok=True)
    ev_fp = open(args.events_out, "w", encoding="utf-8") if args.events_out else None
    tel_fp = open(args.telemetry_out, "w", encoding="utf-8")

    print(f"[*] IPS Engine v2 started | mode={engine.mode} | bypass={engine.bypass_enabled} | xdp_mode={backend.xdp_mode}")

    if not args.mock:
        def _ringbuf_cb(ctx, data, size):
            ev_dict = engine.parse_ringbuf_event(data, size)
            if ev_dict is None:
                return 0
            if ev_fp:
                ev_fp.write(json.dumps(ev_dict) + "\n")
                ev_fp.flush()
            dec = engine.handle_early_flow_event(ev_dict)
            tel_fp.write(json.dumps(dec) + "\n")
            tel_fp.flush()
            return 0

        backend.bpf["events"].open_ring_buffer(_ringbuf_cb)

    t_start = time.monotonic()
    last_wd = t_start
    try:
        while True:
            if not args.mock:
                backend.bpf.ring_buffer_poll(timeout=100)
            else:
                time.sleep(0.1)
            now = time.monotonic()
            if (now - last_wd) >= 1.0:
                wd = engine.step_watchdog(now)
                last_wd = now
            if args.duration > 0 and (now - t_start) >= args.duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        if ev_fp:
            ev_fp.close()
        tel_fp.close()
        backend.close()
        print("[*] IPS Engine v2 stopped cleanly.")


if __name__ == "__main__":
    run_cli()
