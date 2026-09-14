"""Unit tests for train_pe_model.py and real PE feature machine learning pipeline."""
import tempfile
from pathlib import Path
import joblib
import numpy as np
import pytest

from sentinel.engine.static_classifier import PEFeatureModel, PEFeatures
from sentinel.engine.train_pe_model import (
    ANOMALOUS_PROFILES,
    harvest_real_pe_features,
    train_and_save_model,
)


def test_harvest_real_pe_features():
    """Verify that harvesting extracts 12-dimensional vectors from system/venv binaries."""
    vectors, files = harvest_real_pe_features(max_samples=10)
    assert len(vectors) > 0
    assert len(files) == len(vectors)
    for vec in vectors:
        assert len(vec) == 12
        assert all(isinstance(v, (int, float)) for v in vec)


def test_train_and_save_model(tmp_path):
    """Verify that model training outputs a valid joblib bundle with IsolationForest."""
    out_model = tmp_path / "test_pe_model.joblib"
    meta = train_and_save_model(max_samples=15, output_path=out_model)

    assert out_model.exists()
    assert meta["num_samples"] >= 15
    assert meta["clean_samples_count"] > 0
    assert meta["anomalous_samples_count"] == len(ANOMALOUS_PROFILES)

    # Load and check bundle
    bundle = joblib.load(out_model)
    assert "model" in bundle
    assert "metadata" in bundle

    # Test loading into PEFeatureModel
    model = PEFeatureModel(model_path=out_model)
    assert model._fitted is True
    assert model.metadata["num_samples"] == meta["num_samples"]

    # Test inference
    clean_features = PEFeatures(
        file_size=150000,
        num_sections=5,
        entry_point=0x1000,
        file_entropy=5.8,
        has_debug=True,
        has_signature=True,
        num_imports=50,
        num_exports=0,
        suspicious_section_count=0,
        avg_section_entropy=5.2,
        max_section_entropy=6.1,
        min_section_raw_size=512,
    )
    score = model.anomaly_score(clean_features)
    assert isinstance(score, float)
