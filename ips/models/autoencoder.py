#!/usr/bin/env python3
"""
ips/models/autoencoder.py — Autoencoder & Kitsune-style ensemble models.

Implements:
  1. EarlyFlowAutoencoder: PyTorch D -> 32 -> 16 -> 8 -> 16 -> 32 -> D
  2. KitsuneStyleEnsemble: Ensemble of tiny autoencoders over feature groups
  3. Explainability: Top-k feature attribution for alerts
"""
import os
from typing import List, Tuple, Dict, Any
import numpy as np
from ips.features import build_valid_mask_matrix

# PyTorch will be imported dynamically when available or at module level
try:
    import torch
    import torch.nn as nn
except ImportError:
    torch = None
    nn = None


class EarlyFlowAutoencoder(nn.Module if nn else object):
    """Small symmetric Autoencoder: D -> 32 -> 16 -> 8 -> 16 -> 32 -> D."""

    def __init__(self, input_dim: int = 44):
        if nn is None:
            raise RuntimeError("PyTorch is required for EarlyFlowAutoencoder")
        super().__init__()
        self.input_dim = input_dim

        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(inplace=True),
            nn.Linear(32, 16),
            nn.ReLU(inplace=True),
            nn.Linear(16, 8),
            nn.ReLU(inplace=True),
        )

        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(inplace=True),
            nn.Linear(16, 32),
            nn.ReLU(inplace=True),
            nn.Linear(32, input_dim),
        )

    def forward(self, x):
        z = self.encoder(x)
        out = self.decoder(z)
        return out

    def get_reconstruction_error(self, x: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Compute masked sample MSE and per-feature squared errors over positions < valid_len (C1).

        Args:
            x: 2D numpy array of shape (batch_size, input_dim)

        Returns:
            sample_mse: 1D array of shape (batch_size,)
            feat_errors: 2D array of shape (batch_size, input_dim)
        """
        self.eval()
        mask = build_valid_mask_matrix(x)
        x_masked = x.astype(np.float32) * mask
        with torch.no_grad():
            t_x = torch.from_numpy(x_masked)
            t_out = self.forward(t_x)
            sq_err = ((t_x - t_out).pow(2).numpy()) * mask
            denom = np.maximum(1.0, mask.sum(axis=1))
            sample_mse = (sq_err.sum(axis=1) / denom).astype(np.float32)
        return sample_mse, sq_err


class TinyGroupAE(nn.Module if nn else object):
    """Tiny sub-autoencoder for a specific feature group."""

    def __init__(self, in_dim: int):
        super().__init__()
        hidden = max(2, in_dim // 2)
        latent = max(1, hidden // 2)
        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden),
            nn.ReLU(inplace=True),
            nn.Linear(hidden, latent),
            nn.ReLU(inplace=True),
            nn.Linear(latent, hidden),
            nn.ReLU(inplace=True),
            nn.Linear(hidden, in_dim),
        )

    def forward(self, x):
        return self.net(x)


class KitsuneStyleEnsemble:
    """Ensemble of tiny autoencoders over feature groups (Kitsune-style)."""

    def __init__(self, early_n: int = 12):
        if nn is None:
            raise RuntimeError("PyTorch is required for KitsuneStyleEnsemble")
        self.early_n = early_n
        # Group 1: sizes (early_n)
        # Group 2: dirs (early_n)
        # Group 3: log_iats (early_n - 1)
        # Group 4: aggregates (8)
        self.g1_dim = early_n
        self.g2_dim = early_n
        self.g3_dim = early_n - 1
        self.g4_dim = 9  # 9 aggregates in ips.features

        self.ae1 = TinyGroupAE(self.g1_dim)
        self.ae2 = TinyGroupAE(self.g2_dim)
        self.ae3 = TinyGroupAE(self.g3_dim)
        self.ae4 = TinyGroupAE(self.g4_dim)

    def split_features(self, x: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        idx1 = self.g1_dim
        idx2 = idx1 + self.g2_dim
        idx3 = idx2 + self.g3_dim
        idx4 = idx3 + self.g4_dim
        return x[:, :idx1], x[:, idx1:idx2], x[:, idx2:idx3], x[:, idx3:idx4]

    def fit(self, x_train: np.ndarray, epochs: int = 20, lr: float = 0.003, batch_size: int = 64, seed: int = 42):
        """Train each sub-autoencoder on its respective benign feature group."""
        torch.manual_seed(seed)
        g_list = self.split_features(x_train)
        aes = [self.ae1, self.ae2, self.ae3, self.ae4]
        criterion = nn.MSELoss()

        for ae, g_data in zip(aes, g_list):
            optimizer = torch.optim.Adam(ae.parameters(), lr=lr, weight_decay=1e-5)
            t_data = torch.from_numpy(g_data.astype(np.float32))
            ds = torch.utils.data.TensorDataset(t_data, t_data)
            loader = torch.utils.data.DataLoader(ds, batch_size=batch_size, shuffle=True)
            ae.train()
            for _ in range(epochs):
                for bx, _ in loader:
                    optimizer.zero_grad()
                    out = ae(bx)
                    loss = criterion(out, bx)
                    loss.backward()
                    optimizer.step()
            ae.eval()

    def score(self, x: np.ndarray) -> np.ndarray:
        """Compute aggregated ensemble reconstruction error."""
        g1, g2, g3, g4 = self.split_features(x)
        self.ae1.eval(); self.ae2.eval(); self.ae3.eval(); self.ae4.eval()

        with torch.no_grad():
            e1 = (torch.from_numpy(g1.astype(np.float32)) - self.ae1(torch.from_numpy(g1.astype(np.float32)))).pow(2).mean(dim=1).numpy()
            e2 = (torch.from_numpy(g2.astype(np.float32)) - self.ae2(torch.from_numpy(g2.astype(np.float32)))).pow(2).mean(dim=1).numpy()
            e3 = (torch.from_numpy(g3.astype(np.float32)) - self.ae3(torch.from_numpy(g3.astype(np.float32)))).pow(2).mean(dim=1).numpy()
            e4 = (torch.from_numpy(g4.astype(np.float32)) - self.ae4(torch.from_numpy(g4.astype(np.float32)))).pow(2).mean(dim=1).numpy()

        # Weighted combination or maximum
        return np.maximum.reduce([e1, e2, e3, e4])


def explain_anomaly(sq_errors_row: np.ndarray, feature_names: List[str], top_k: int = 3) -> List[Dict[str, Any]]:
    """Return top-k contributing features for an alert explanation."""
    top_indices = np.argsort(sq_errors_row)[::-1][:top_k]
    explanations = []
    for idx in top_indices:
        explanations.append({
            "feature": feature_names[idx] if idx < len(feature_names) else f"feat_{idx}",
            "squared_error": float(sq_errors_row[idx]),
        })
    return explanations

