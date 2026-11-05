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
from typing import Dict, Any, Tuple
import numpy as np

try:
    import torch
except ImportError:
    torch = None

try:
    import onnx
    import onnxruntime as ort
    from onnxruntime.quantization import quantize_dynamic, QuantType
except ImportError:
    onnx = None
    ort = None
    quantize_dynamic = None


def export_to_onnx(pytorch_model, input_dim: int, onnx_path: str):
    """Export PyTorch Autoencoder to ONNX format."""
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
    """Quantize FP32 ONNX model to INT8 using dynamic quantization."""
    if quantize_dynamic is None:
        raise RuntimeError("onnxruntime.quantization is required for INT8 quantization")
    os.makedirs(os.path.dirname(os.path.abspath(int8_onnx_path)), exist_ok=True)

    quantize_dynamic(
        model_input=fp32_onnx_path,
        model_output=int8_onnx_path,
        weight_type=QuantType.QInt8,
    )
    return int8_onnx_path


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

