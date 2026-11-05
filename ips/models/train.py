#!/usr/bin/env python3
"""
ips/models/train.py — Train benign baseline models and calibrate EVT thresholds.

Trains (strictly on benign data only, Rule H2):
  1. Global Autoencoder (PyTorch D -> 32 -> 16 -> 8 -> 16 -> 32 -> D)
  2. Per-device-class Autoencoders (sensor, plug, thermostat, camera) for ablation N5
  3. Kitsune-style ensemble of tiny autoencoders over feature groups
  4. Isolation Forest baseline (sklearn)
Fits EVT thresholds (POT GPD with KS selection) on a separate benign calibration split,
exports ONNX FP32 + INT8 models, and writes models/model_card.json.

Usage:
  python ips/models/train.py [--data results/smoke/smoke_train_sess.csv] [--early-n 12] [--epochs 20]
"""
import os
import sys
import json
import hashlib
import argparse
import pickle
from typing import Tuple, List, Dict, Any
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_DIR)

from ips.features import get_feature_names, build_early_vector, assert_no_forbidden_features
from ips.models.autoencoder import EarlyFlowAutoencoder, KitsuneStyleEnsemble
from ips.models.evt import fit_evt_threshold
from ips.models.quantize import export_to_onnx, quantize_to_int8, compare_fp32_int8
from ips.smoke.synth import SMOKE_BANNER

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import TensorDataset, DataLoader
except ImportError:
    torch = None


def is_smoke_dataframe(df: pd.DataFrame, data_path: str = "") -> bool:
    """Detect whether data is synthetic smoke data."""
    if "smoke" in data_path.lower():
        return True
    if "source" in df.columns:
        sources = set(df["source"].dropna().astype(str).unique())
        if any("smoke" in s.lower() for s in sources):
            return True
    return False


def extract_matrix_from_df(df: pd.DataFrame, early_n: int = 12) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """Extract canonical feature matrix X (shape: [M, 3*N+8]) and labels y from dataframe."""
    feature_names = get_feature_names(early_n)
    assert_no_forbidden_features(feature_names)

    # Check if df already has the exact pre-computed normalized feature columns from pcap_to_flows
    has_all_features = all(c in df.columns for c in feature_names)
    if has_all_features and "log_iat_0" in df.columns:
        X = df[feature_names].values.astype(np.float32)
    else:
        rows = []
        for _, row in df.iterrows():
            sizes = [int(row[f"size_{i}"]) for i in range(early_n) if f"size_{i}" in row and pd.notna(row[f"size_{i}"])]
            dirs = [int(row[f"dir_{i}"]) for i in range(early_n) if f"dir_{i}" in row and pd.notna(row[f"dir_{i}"])]
            iats = [float(row[f"iat_{i}"]) for i in range(early_n - 1) if f"iat_{i}" in row and pd.notna(row[f"iat_{i}"])]
            rows.append(build_early_vector(sizes, dirs, iats, early_n=early_n))
        X = np.array(rows, dtype=np.float32) if rows else np.zeros((0, len(feature_names)), dtype=np.float32)

    y = df["is_attack"].values.astype(int) if "is_attack" in df.columns else np.zeros(len(df), dtype=int)
    return X, y, feature_names


def train_autoencoder(X_train: np.ndarray, X_val: np.ndarray, input_dim: int,
                      epochs: int = 25, batch_size: int = 64, lr: float = 0.002,
                      seed: int = 42):
    """Train PyTorch Autoencoder with early stopping on benign validation loss."""
    if torch is None:
        raise RuntimeError("torch is required to train Autoencoder")
    torch.manual_seed(seed)
    np.random.seed(seed)

    model = EarlyFlowAutoencoder(input_dim=input_dim)
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    criterion = nn.MSELoss()

    dataset = TensorDataset(torch.from_numpy(X_train), torch.from_numpy(X_train))
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    val_t = torch.from_numpy(X_val)
    best_loss = float("inf")
    best_weights = None
    patience = 5
    patience_counter = 0

    model.train()
    for _ in range(epochs):
        for batch_x, _ in loader:
            optimizer.zero_grad()
            out = model(batch_x)
            loss = criterion(out, batch_x)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            val_out = model(val_t)
            val_loss = criterion(val_out, val_t).item()

        if val_loss < best_loss:
            best_loss = val_loss
            best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= patience:
                break
        model.train()

    if best_weights:
        model.load_state_dict(best_weights)
    model.eval()
    return model, best_loss


def train_pipeline(data_path: str, calib_path: str = None, early_n: int = 12,
                   epochs: int = 20, seed: int = 42, model_dir: str = None) -> Dict[str, Any]:
    """Run full benign-only training, EVT calibration, and quantization pipeline."""
    if model_dir is None:
        model_dir = os.path.join(REPO_DIR, "models")
    os.makedirs(model_dir, exist_ok=True)

    df = pd.read_csv(data_path) if data_path.endswith(".csv") else pd.read_parquet(data_path)
    is_smoke = is_smoke_dataframe(df, data_path)
    if is_smoke:
        print(SMOKE_BANNER)

    with open(data_path, "rb") as f:
        data_hash = hashlib.sha256(f.read()).hexdigest()[:16]

    # Strict benign-only training rule (H2)
    benign_df = df[df["is_attack"] == 0].copy() if "is_attack" in df.columns else df.copy()
    X_all, _, feat_names = extract_matrix_from_df(benign_df, early_n=early_n)
    input_dim = X_all.shape[1]

    if calib_path and os.path.exists(calib_path):
        calib_df = pd.read_csv(calib_path) if calib_path.endswith(".csv") else pd.read_parquet(calib_path)
        calib_benign = calib_df[calib_df["is_attack"] == 0] if "is_attack" in calib_df.columns else calib_df
        X_calib_full, _, _ = extract_matrix_from_df(calib_benign, early_n=early_n)
        n_tr = int(len(X_all) * 0.85)
        X_train, X_val = X_all[:n_tr], X_all[n_tr:]
        X_calib = X_calib_full
    else:
        # Partition into separate train (60%), val (15%), calibration (25%)
        n_total = len(X_all)
        n_tr = int(n_total * 0.60)
        n_val = int(n_total * 0.75)
        X_train = X_all[:n_tr]
        X_val = X_all[n_tr:n_val]
        X_calib = X_all[n_val:]

    print(f"[Train] Splits (benign only): train={len(X_train)}, val={len(X_val)}, calib={len(X_calib)}, dim={input_dim}")

    # 1. Global PyTorch Autoencoder
    ae_model, best_val_loss = train_autoencoder(X_train, X_val, input_dim=input_dim, epochs=epochs, seed=seed)
    calib_scores, _ = ae_model.get_reconstruction_error(X_calib)
    evt_001 = fit_evt_threshold(calib_scores, target_fpr=0.001)
    evt_01 = fit_evt_threshold(calib_scores, target_fpr=0.01)

    # 2. Per-device-class Autoencoders (N5 ablation)
    per_class_thresholds = {}
    if "device_class" in benign_df.columns:
        for cls_name in ["sensor", "plug", "thermostat", "camera"]:
            cls_df = benign_df[benign_df["device_class"] == cls_name]
            if len(cls_df) >= 30:
                X_cls, _, _ = extract_matrix_from_df(cls_df, early_n=early_n)
                c_tr = int(len(X_cls) * 0.7)
                cls_ae, _ = train_autoencoder(X_cls[:c_tr], X_cls[c_tr:], input_dim=input_dim, epochs=epochs, seed=seed)
                cls_calib_scores, _ = cls_ae.get_reconstruction_error(X_cls[c_tr:])
                cls_evt = fit_evt_threshold(cls_calib_scores, target_fpr=0.001)
                cls_onnx = os.path.join(model_dir, f"ae_class_{cls_name}.onnx")
                export_to_onnx(cls_ae, input_dim, cls_onnx)
                per_class_thresholds[cls_name] = {
                    "onnx_path": cls_onnx,
                    "evt_001": cls_evt["threshold"],
                    "three_sigma": cls_evt["three_sigma"],
                }

    # 3. Kitsune-style ensemble
    kitsune_ens = KitsuneStyleEnsemble(early_n=early_n)
    kitsune_ens.fit(X_train, epochs=epochs, seed=seed)
    kit_calib_scores = kitsune_ens.score(X_calib)
    kit_evt_001 = fit_evt_threshold(kit_calib_scores, target_fpr=0.001)
    kit_evt_01 = fit_evt_threshold(kit_calib_scores, target_fpr=0.01)
    kit_pkl = os.path.join(model_dir, "kitsune_style.pkl")
    with open(kit_pkl, "wb") as f:
        pickle.dump(kitsune_ens, f)

    # 4. Isolation Forest baseline
    iso_forest = IsolationForest(n_estimators=100, contamination="auto", random_state=seed)
    iso_forest.fit(X_train)
    # Convert decision_function so higher = more anomalous
    if_calib_scores = -iso_forest.score_samples(X_calib)
    if_evt_001 = fit_evt_threshold(if_calib_scores, target_fpr=0.001)
    if_evt_01 = fit_evt_threshold(if_calib_scores, target_fpr=0.01)
    if_pkl = os.path.join(model_dir, "isolation_forest.pkl")
    with open(if_pkl, "wb") as f:
        pickle.dump(iso_forest, f)

    # 5. Export ONNX FP32 and INT8 & compare
    onnx_fp32 = os.path.join(model_dir, "autoencoder.onnx")
    onnx_int8 = os.path.join(model_dir, "autoencoder_int8.onnx")
    export_to_onnx(ae_model, input_dim, onnx_fp32)
    quantize_to_int8(onnx_fp32, onnx_int8)
    quant_comparison = compare_fp32_int8(onnx_fp32, onnx_int8, input_dim, X_calib)

    # Save calibration scores for calibration curve generation
    calib_scores_path = os.path.join(model_dir, "calib_scores.npy")
    np.save(calib_scores_path, calib_scores)

    # Save anchor benign vectors (frozen trusted set for G4 drift validation in WP8)
    anchor_path = os.path.join(model_dir, "anchor_benign.npy")
    np.save(anchor_path, X_train[:min(200, len(X_train))])

    model_card = {
        "data_source": "synthetic-smoke" if is_smoke else "real",
        "data_sha256": data_hash,
        "early_n": early_n,
        "input_dim": input_dim,
        "seed": seed,
        "train_samples": len(X_train),
        "val_samples": len(X_val),
        "calibration_samples": len(X_calib),
        "best_val_mse": round(float(best_val_loss), 6),
        "evt_calibration": evt_001,
        "evt_calibration_01": evt_01,
        "kitsune_evt_001": kit_evt_001,
        "kitsune_evt_01": kit_evt_01,
        "iforest_evt_001": if_evt_001,
        "iforest_evt_01": if_evt_01,
        "per_class_models": per_class_thresholds,
        "quantization": quant_comparison,
        "feature_names": feat_names,
        "onnx_fp32_path": onnx_fp32,
        "onnx_int8_path": onnx_int8,
        "kitsune_pkl_path": kit_pkl,
        "iforest_pkl_path": if_pkl,
        "calib_scores_path": calib_scores_path,
        "anchor_path": anchor_path,
    }
    card_path = os.path.join(model_dir, "model_card.json")
    with open(card_path, "w", encoding="utf-8") as f:
        json.dump(model_card, f, indent=2)

    print(f"[OK] Training complete. Card saved to {card_path}")
    return model_card


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train benign anomaly detection models and fit EVT")
    parser.add_argument("--data", default="results/smoke/smoke_train_sess.csv", help="Training data CSV/parquet")
    parser.add_argument("--calib", default=None, help="Optional separate calibration session CSV/parquet")
    parser.add_argument("--early-n", type=int, default=12, help="Payload packets per flow")
    parser.add_argument("--epochs", type=int, default=20, help="Training epochs")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    if not os.path.exists(args.data):
        from ips.smoke.synth import generate_smoke_dataset
        generate_smoke_dataset(
            n_benign=1500, n_attack=300, early_n=args.early_n,
            session_id="smoke_train_sess", out_csv=args.data
        )

    train_pipeline(
        data_path=args.data,
        calib_path=args.calib,
        early_n=args.early_n,
        epochs=args.epochs,
        seed=args.seed,
    )
