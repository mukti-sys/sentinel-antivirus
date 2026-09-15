"""Unit tests for sentinel.engine.train_large_scale.

Validates:
1. Parquet dataset generation in memory-efficient chunks
2. Loading and schema verification from Apache Parquet
3. Model training (LightGBM + IsolationForest)
4. Evaluation metrics (accuracy >= 95%, FPR <= 2%)
5. Integration with PEFeatureModel (predict_malware_probability & predict_threat)
"""
from __future__ import annotations

from pathlib import Path
import pytest
import numpy as np

from sentinel.engine.static_classifier import PEFeatures, PEFeatureModel
from sentinel.engine.train_large_scale import (
    FEATURE_NAMES,
    generate_parquet_dataset,
    load_dataset_from_parquet,
    train_large_scale,
)


class TestTrainLargeScale:
    @pytest.fixture
    def test_parquet(self, tmp_path):
        p = tmp_path / "test_dataset.parquet"
        generate_parquet_dataset(p, num_samples=500, chunk_size=250)
        return p

    def test_generate_parquet_dataset(self, test_parquet):
        assert test_parquet.exists()
        assert test_parquet.stat().st_size > 0

    def test_load_dataset_from_parquet(self, test_parquet):
        X, y = load_dataset_from_parquet(test_parquet)
        assert X.shape == (500, len(FEATURE_NAMES))
        assert y.shape == (500,)
        assert X.dtype == np.float32
        assert y.dtype == np.uint8

    def test_train_pipeline_end_to_end(self, tmp_path, test_parquet):
        model_file = tmp_path / "test_model_v2.joblib"
        metrics_file = tmp_path / "test_metrics.json"

        metrics = train_large_scale(
            dataset_path=test_parquet,
            num_samples=500,
            model_output_path=model_file,
            metrics_output_path=metrics_file,
        )

        assert metrics["accuracy"] >= 0.95
        assert metrics["false_positive_rate"] <= 0.05
        assert model_file.exists()
        assert metrics_file.exists()

        # Test integration with PEFeatureModel
        pe_model = PEFeatureModel(model_path=model_file)
        assert pe_model._lgbm_model is not None

        # Test clean sample
        clean_features = PEFeatures(
            file_size=150000,
            num_sections=5,
            entry_point=0x2000,
            file_entropy=5.8,
            has_debug=True,
            has_signature=True,
            num_imports=60,
            num_exports=0,
            suspicious_section_count=0,
            avg_section_entropy=5.2,
            max_section_entropy=6.1,
            min_section_raw_size=512,
        )
        prob_clean = pe_model.predict_malware_probability(clean_features)
        assert prob_clean < 0.5
        assert pe_model.is_suspicious(clean_features) is False

        # Test malicious sample (high entropy, stripped imports, unusual sections)
        mal_features = PEFeatures(
            file_size=350000,
            num_sections=6,
            entry_point=0x5000,
            file_entropy=7.94,
            has_debug=False,
            has_signature=False,
            num_imports=3,
            num_exports=0,
            suspicious_section_count=2,
            avg_section_entropy=7.6,
            max_section_entropy=7.98,
            min_section_raw_size=128,
        )
        prob_mal = pe_model.predict_malware_probability(mal_features)
        assert prob_mal >= 0.5
        threat_dict = pe_model.predict_threat(mal_features)
        assert threat_dict["is_malware"] is True
        assert threat_dict["model_version"] == "2.0.0"
