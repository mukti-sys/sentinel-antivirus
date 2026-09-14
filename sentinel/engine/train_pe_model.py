"""Harvests real PE feature datasets from system binaries and trains the
persistent IsolationForest PE anomaly detection model.

Replaces development/testing scaffolding with genuine machine learning weights
trained on real Windows binaries and representative anomalous PE profiles.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from sentinel.engine.static_classifier import PEFeatures, extract_pe_features

logger = logging.getLogger("sentinel.train_pe_model")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
MODEL_PATH = DATA_DIR / "pe_model.joblib"
DATASET_PATH = DATA_DIR / "pe_training_dataset.joblib"

# Representative anomalous PE feature profiles (e.g., UPX-packed, encrypted payloads,
# stripped import tables, anomalous section names, extreme entropy).
ANOMALOUS_PROFILES = [
    # UPX packed sample 1 (tiny stub, UPX sections, high entropy, 0 debug, 0 sig)
    [85000, 3, 0x14000, 7.82, 0.0, 0.0, 4, 0, 2, 7.2, 7.95, 256],
    # UPX packed sample 2 (small executable, high max entropy, 1 import)
    [142000, 3, 0x22000, 7.91, 0.0, 0.0, 2, 0, 2, 7.4, 7.98, 512],
    # Themida / VMProtect style packer (extreme entropy, suspicious sections, high sections)
    [1850000, 12, 0x80000, 7.88, 0.0, 0.0, 8, 0, 3, 7.1, 7.99, 128],
    # Masqueraded PE with 0 imports and high entropy
    [320000, 4, 0x1000, 7.75, 0.0, 0.0, 0, 0, 1, 7.0, 7.89, 512],
    # Crypted loader (very small, high entropy, zero imports, no debug, no signature)
    [45000, 2, 0x400, 7.94, 0.0, 0.0, 0, 0, 0, 7.8, 7.99, 1024],
    # Ransomware payload profile (high entropy, stripped debug, tiny import count)
    [412000, 5, 0x2000, 7.89, 0.0, 0.0, 6, 0, 1, 7.5, 7.97, 512],
    # Dropper with suspicious section names (.adata, .packed)
    [98000, 4, 0x1200, 7.65, 0.0, 0.0, 12, 0, 2, 6.9, 7.82, 512],
    # High-entropy shellcode carrier
    [64000, 3, 0x800, 7.96, 0.0, 0.0, 1, 0, 1, 7.6, 7.99, 256],
    # Anomalous tiny section raw size with high section count
    [250000, 8, 0x5000, 7.71, 0.0, 0.0, 15, 0, 2, 6.8, 7.85, 64],
    # Obfuscated .NET crypter (high entropy, packed section)
    [520000, 4, 0x2000, 7.85, 0.0, 0.0, 8, 0, 1, 7.3, 7.92, 512],
]


def harvest_real_pe_features(
    max_samples: int = 300,
    search_dirs: list[Path] | None = None,
) -> tuple[list[list[float]], list[str]]:
    """Harvest feature vectors from real Windows system binaries and installed runtimes."""
    if search_dirs is None:
        search_dirs = []
        sys32 = Path(r"C:\Windows\System32")
        if sys32.is_dir():
            search_dirs.append(sys32)
        # Python runtime environment
        py_root = Path(sys.prefix)
        if py_root.is_dir():
            search_dirs.append(py_root)
            dlls = py_root / "DLLs"
            if dlls.is_dir():
                search_dirs.append(dlls)

    feature_vectors: list[list[float]] = []
    file_names: list[str] = []

    logger.info("Harvesting real PE files from %s...", [str(p) for p in search_dirs])
    for sdir in search_dirs:
        if not sdir.exists():
            continue
        try:
            # Look for .exe and .dll files
            for entry in sdir.iterdir():
                if len(feature_vectors) >= max_samples:
                    break
                if not entry.is_file():
                    continue
                if entry.suffix.lower() not in (".exe", ".dll"):
                    continue

                try:
                    features = extract_pe_features(entry)
                    if features is not None:
                        feature_vectors.append(features.to_vector())
                        file_names.append(entry.name)
                except Exception as exc:
                    logger.debug("Failed extracting features from %s: %s", entry.name, exc)
        except (PermissionError, OSError) as exc:
            logger.warning("Could not list directory %s: %s", sdir, exc)

    logger.info("Successfully extracted %d real PE feature vectors", len(feature_vectors))
    return feature_vectors, file_names


def train_and_save_model(
    max_samples: int = 300,
    contamination: float = 0.05,
    output_path: Path = MODEL_PATH,
) -> dict[str, Any]:
    """Harvest real PE data, combine with anomalous profiles, train IsolationForest, and save."""
    real_vectors, file_names = harvest_real_pe_features(max_samples=max_samples)

    if not real_vectors:
        raise RuntimeError("No real PE binaries could be harvested for training!")

    # Combine real clean binaries with anomalous profiles
    all_vectors = list(real_vectors) + ANOMALOUS_PROFILES
    X = np.array(all_vectors, dtype=np.float64)

    logger.info("Training IsolationForest on %d total vectors (%d clean, %d anomalous profiles)...",
                len(all_vectors), len(real_vectors), len(ANOMALOUS_PROFILES))

    model = IsolationForest(
        n_estimators=150,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    metadata = {
        "num_samples": len(all_vectors),
        "clean_samples_count": len(real_vectors),
        "anomalous_samples_count": len(ANOMALOUS_PROFILES),
        "contamination": contamination,
        "n_estimators": 150,
        "features_dim": 12,
        "sample_files": file_names[:25],
    }

    bundle = {
        "model": model,
        "metadata": metadata,
        "training_data_summary": {
            "mean": np.mean(X, axis=0).tolist(),
            "std": np.std(X, axis=0).tolist(),
        },
    }

    joblib.dump(bundle, output_path)
    logger.info("Saved trained model bundle to %s (size: %d bytes)", output_path, output_path.stat().st_size)

    # Also save dataset snapshot for test repeatability
    joblib.dump(all_vectors, DATASET_PATH)

    return metadata


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    parser = argparse.ArgumentParser(description="Train real PE IsolationForest anomaly model")
    parser.add_argument("--samples", type=int, default=300, help="Max real binaries to harvest")
    parser.add_argument("--contamination", type=float, default=0.05, help="IsolationForest contamination")
    args = parser.parse_args()

    meta = train_and_save_model(max_samples=args.samples, contamination=args.contamination)
    print(f"[OK] Training complete! {meta['num_samples']} samples processed. Model: {MODEL_PATH}")
