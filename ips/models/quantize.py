#!/usr/bin/env python3
"""
ips/models/quantize.py — Export PyTorch models to ONNX and INT8 dynamic quantization.

Measures:
  - FP32 vs INT8 file size (KB)
  - Single-flow inference latency (p50, p95, p99 in microseconds)
  - Numerical fidelity (mean relative difference)
"""
import os
import time
import logging
import warnings
from typing import Dict, Any, Tuple
import numpy as np

from ips.features import build_valid_mask_matrix

try:
    import torch
except ImportError:
    torch = None

try:
    import onnx
    import onnxruntime as ort
    from onnxruntime.quantization import quantize_dynamic, QuantType
    try:
        from onnxruntime.quantization.shape_inference import quant_pre_process
    except ImportError:
        quant_pre_process = None
except ImportError:
    onnx = None
    ort = None
    quantize_dynamic = None
    quant_pre_process = None


def export_to_onnx(pytorch_model, input_dim: int, onnx_path: str):
    """Export PyTorch Autoencoder to ONNX format without legacy TorchScript deprecation noise."""
    if torch is None:
        raise RuntimeError("torch required to export ONNX")
    os.makedirs(os.path.dirname(os.path.abspath(onnx_path)), exist_ok=True)
    pytorch_model.eval()

    dummy_input = torch.randn(1, input_dim, dtype=torch.float32)
    export_kwargs = dict(
        export_params=True,
        opset_version=14,
        do_constant_folding=True,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={"input": {0: "batch_size"}, "output": {0: "batch_size"}},
    )
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        try:
            torch.onnx.export(
                pytorch_model,
                dummy_input,
                onnx_path,
                dynamo=False,
                **export_kwargs,
            )
        except TypeError:
            torch.onnx.export(
                pytorch_model,
                dummy_input,
                onnx_path,
                **export_kwargs,
            )
    return onnx_path


def quantize_to_int8(fp32_onnx_path: str, int8_onnx_path: str) -> str:
    """Pre-process FP32 ONNX graph and quantize to INT8 using dynamic quantization."""
    if quantize_dynamic is None:
        raise RuntimeError("onnxruntime.quantization is required for INT8 quantization")
    os.makedirs(os.path.dirname(os.path.abspath(int8_onnx_path)), exist_ok=True)

    prep_path = int8_onnx_path + ".prep.onnx"
    src_for_quant = fp32_onnx_path
    try:
        if quant_pre_process is not None:
            try:
                quant_pre_process(
                    input_model_path=fp32_onnx_path,
                    output_model_path=prep_path,
                    skip_symbolic_shape=True,
                )
                if os.path.exists(prep_path):
                    src_for_quant = prep_path
            except Exception:
                src_for_quant = fp32_onnx_path

        root_logger = logging.getLogger()
        prev_level = root_logger.level
        try:
            if src_for_quant == fp32_onnx_path:
                root_logger.setLevel(logging.ERROR)
            quantize_dynamic(
                model_input=src_for_quant,
                model_output=int8_onnx_path,
                weight_type=QuantType.QInt8,
            )
        finally:
            root_logger.setLevel(prev_level)
    finally:
        if os.path.exists(prep_path):
            try:
                os.remove(prep_path)
            except OSError:
                pass
    return int8_onnx_path


def score_masked_onnx(onnx_path: str, X: np.ndarray) -> np.ndarray:
    """Compute masked per-sample reconstruction MSE over positions < valid_len using an ONNX session."""
    if ort is None:
        raise RuntimeError("onnxruntime is required for score_masked_onnx")
    mask = build_valid_mask_matrix(X)
    x_masked = (X.astype(np.float32) * mask)
    sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    inp_name = sess.get_inputs()[0].name
    out = sess.run(None, {inp_name: x_masked})[0]
    sq_err = ((x_masked - out) ** 2) * mask
    denom = np.maximum(1.0, mask.sum(axis=1))
    return (sq_err.sum(axis=1) / denom).astype(np.float32)


def benchmark_onnx_latency(onnx_path: str, input_dim: int, n_warmup: int = 20, n_iter: int = 100) -> Dict[str, float]:
    """Benchmark single-flow inference latency in microseconds."""
    if ort is None:
        return {"p50_us": 0.0, "p95_us": 0.0, "p99_us": 0.0}

    session = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    dummy = np.random.randn(1, input_dim).astype(np.float32)

    # Warmup
    for _ in range(n_warmup):
        _ = session.run(None, {input_name: dummy})

    latencies_us = []
    for _ in range(n_iter):
        t0 = time.perf_counter()
        _ = session.run(None, {input_name: dummy})
        dt_us = (time.perf_counter() - t0) * 1e6
        latencies_us.append(dt_us)

    latencies_us.sort()
    return {
        "p50_us": float(np.percentile(latencies_us, 50)),
        "p95_us": float(np.percentile(latencies_us, 95)),
        "p99_us": float(np.percentile(latencies_us, 99)),
        "mean_us": float(np.mean(latencies_us)),
    }


def compare_fp32_int8(fp32_path: str, int8_path: str, input_dim: int,
                      test_x: np.ndarray) -> Dict[str, Any]:
    """Compare size, latency, and numerical fidelity between FP32 and INT8 models."""
    fp32_size_kb = os.path.getsize(fp32_path) / 1024.0
    int8_size_kb = os.path.getsize(int8_path) / 1024.0

    lat_fp32 = benchmark_onnx_latency(fp32_path, input_dim)
    lat_int8 = benchmark_onnx_latency(int8_path, input_dim)

    # Numerical divergence on test batch
    sess_fp32 = ort.InferenceSession(fp32_path, providers=["CPUExecutionProvider"])
    sess_int8 = ort.InferenceSession(int8_path, providers=["CPUExecutionProvider"])
    inp_name = sess_fp32.get_inputs()[0].name

    batch = test_x[:100].astype(np.float32)
    out_fp32 = sess_fp32.run(None, {inp_name: batch})[0]
    out_int8 = sess_int8.run(None, {inp_name: batch})[0]

    max_abs_diff = float(np.max(np.abs(out_fp32 - out_int8)))
    mean_abs_diff = float(np.mean(np.abs(out_fp32 - out_int8)))

    return {
        "fp32_size_kb": round(fp32_size_kb, 2),
        "int8_size_kb": round(int8_size_kb, 2),
        "size_reduction_pct": round((1.0 - int8_size_kb / fp32_size_kb) * 100.0, 1),
        "latency_fp32": lat_fp32,
        "latency_int8": lat_int8,
        "max_abs_diff": max_abs_diff,
        "mean_abs_diff": mean_abs_diff,
    }

