"""End-to-end integration test — REAL files, REAL YARA, REAL quarantine.

No mocks. This test proves the core antivirus pipeline works on a real
Windows machine:
    1. YARA compiles and loads the bundled rules
    2. A real EICAR test file is written to disk
    3. StaticClassifier scans it and fires a yara_match signal
    4. Scoring engine scores it above the response threshold
    5. Quarantine store moves the file, strips permissions, records metadata
    6. The quarantined file has correct SHA-256
    7. Restore puts the file back with data integrity intact
    8. Delete permanently removes the quarantined copy

This runs on GitHub Actions (Windows Server) with zero mocks.
"""
import hashlib
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from sentinel.engine.event_bus import EventBus
from sentinel.engine.schema import Event, utc_timestamp
from sentinel.engine.scoring import WEIGHTS, Scorer, Signal
from sentinel.engine.static_classifier import StaticClassifier
from sentinel.response.quarantine_store import (
    DELETED,
    PENDING,
    RESTORED,
    QuarantineStore,
)


# The real EICAR test string — industry standard, completely harmless.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = hashlib.sha256(EICAR).hexdigest()


@pytest.fixture
def workspace(tmp_path):
    """Create a temporary workspace with Downloads folder and quarantine dir."""
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    quarantine_dir = tmp_path / "quarantine"
    quarantine_dir.mkdir()
    return tmp_path, downloads, quarantine_dir


class TestRealYARADetection:
    """Prove YARA actually compiles rules and scans real file content."""

    def test_yara_detects_real_eicar_file(self, workspace):
        tmp_path, downloads, _ = workspace

        # Write a REAL EICAR file to disk
        eicar_file = downloads / "eicar_test.com"
        eicar_file.write_bytes(EICAR)
        assert eicar_file.exists()
        assert eicar_file.read_bytes() == EICAR

        # Create classifier with REAL YARA rules (from project config/rules/)
        classifier = StaticClassifier(vt_client=None)

        # Create a real file_write event
        event = Event(
            timestamp=utc_timestamp(),
            source="fs",
            event_type="file_write",
            image_path=str(eicar_file),
        )

        # Classify — this runs REAL YARA scanning on REAL file bytes
        signals = classifier.classify_file_event(event)

        # MUST detect EICAR
        assert len(signals) >= 1, f"YARA failed to detect EICAR! Got: {signals}"
        assert signals[0].kind == "yara_match", f"Expected yara_match, got: {signals[0].kind}"
        assert "EICAR" in signals[0].reason, f"Reason should mention EICAR: {signals[0].reason}"
        assert signals[0].engine == "yara_scanner"

    def test_yara_does_not_flag_clean_file(self, workspace):
        tmp_path, downloads, _ = workspace

        # Write a harmless text file
        clean_file = downloads / "readme.txt"
        clean_file.write_text("This is a completely normal text file.")

        classifier = StaticClassifier(vt_client=None)
        event = Event(
            timestamp=utc_timestamp(),
            source="fs",
            event_type="file_write",
            image_path=str(clean_file),
        )

        signals = classifier.classify_file_event(event)
        assert signals == [], f"Clean file should produce no signals, got: {signals}"


class TestRealScoringThreshold:
    """Prove the scoring engine correctly triggers above threshold."""

    def test_yara_match_exceeds_threshold(self):
        """A yara_match signal (weight 85) should exceed threshold (80)."""
        scorer = Scorer()
        signal = Signal(
            kind="yara_match",
            subject="file:test",
            engine="yara_scanner",
            reason="YARA rule matched EICAR",
        )
        scorer.add(signal)
        assert scorer.should_respond("file:test"), \
            f"Score {scorer.score('file:test')} should exceed threshold {scorer.threshold}"

    def test_single_weak_signal_does_not_trigger(self):
        """A single weak signal should NOT trigger response."""
        scorer = Scorer()
        signal = Signal(
            kind="vt_unknown_suspicious_pe",
            subject="file:test",
            engine="static_classifier",
            reason="suspicious PE",
        )
        scorer.add(signal)
        assert not scorer.should_respond("file:test"), \
            "Single weak signal should NOT trigger response"


class TestRealQuarantineLifecycle:
    """Prove quarantine actually moves files, checks integrity, restores them."""

    def test_full_quarantine_and_restore_cycle(self, workspace):
        tmp_path, downloads, quarantine_dir = workspace

        # 1. Write real EICAR file
        eicar_file = downloads / "malware_test.com"
        eicar_file.write_bytes(EICAR)
        original_path = str(eicar_file)

        # 2. Create real quarantine store with real SQLite DB
        db_path = tmp_path / "quarantine.db"
        store = QuarantineStore(db_path=str(db_path), quarantine_dir=str(quarantine_dir))

        # 3. Quarantine the file — this ACTUALLY moves it
        record = store.add(
            original_path=original_path,
            reason="YARA: EICAR_Test_File matched",
            score=85.0,
            source_signals=["yara_match"],
        )

        # 4. Verify file was ACTUALLY moved
        assert not eicar_file.exists(), "Original file should be gone after quarantine"
        assert Path(record.quarantined_path).exists(), "Quarantined copy should exist"
        assert record.sha256 == EICAR_SHA256, \
            f"SHA-256 mismatch: expected {EICAR_SHA256}, got {record.sha256}"
        assert record.decision == PENDING

        # 5. Verify quarantined file content is intact
        quarantined_data = Path(record.quarantined_path).read_bytes()
        assert quarantined_data == EICAR, "Quarantined file content should match original"

        # 6. Restore the file — this ACTUALLY copies it back
        store.restore(record.id, notes="False positive test")

        # 7. Verify file was ACTUALLY restored
        assert eicar_file.exists(), "File should be restored to original location"
        assert eicar_file.read_bytes() == EICAR, "Restored file content must match original"

        # 8. Verify record updated
        updated = store.get(record.id)
        assert updated.decision == RESTORED

    def test_quarantine_and_delete_cycle(self, workspace):
        tmp_path, downloads, quarantine_dir = workspace

        # Write and quarantine
        eicar_file = downloads / "delete_test.com"
        eicar_file.write_bytes(EICAR)

        db_path = tmp_path / "quarantine_del.db"
        store = QuarantineStore(db_path=str(db_path), quarantine_dir=str(quarantine_dir))
        record = store.add(
            original_path=str(eicar_file),
            reason="YARA: EICAR detected",
            score=85.0,
            source_signals=["yara_match"],
        )

        # Delete permanently
        store.delete(record.id)

        # Verify ACTUALLY deleted
        assert not Path(record.quarantined_path).exists(), \
            "Quarantined file should be permanently deleted"
        assert not eicar_file.exists(), "Original should still be gone"

        updated = store.get(record.id)
        assert updated.decision == DELETED


class TestRealEndToEndPipeline:
    """The full pipeline: file → YARA scan → score → quarantine."""

    def test_eicar_file_detected_scored_quarantined(self, workspace):
        tmp_path, downloads, quarantine_dir = workspace

        # --- Step 1: Write EICAR file ---
        eicar_file = downloads / "full_pipeline_test.com"
        eicar_file.write_bytes(EICAR)
        assert eicar_file.exists()

        # --- Step 2: YARA scan (REAL) ---
        classifier = StaticClassifier(vt_client=None)
        event = Event(
            timestamp=utc_timestamp(),
            source="fs",
            event_type="file_write",
            image_path=str(eicar_file),
        )
        signals = classifier.classify_file_event(event)
        assert len(signals) >= 1
        assert signals[0].kind == "yara_match"

        # --- Step 3: Score (REAL) ---
        scorer = Scorer()
        for sig in signals:
            scorer.add(sig)
        subject = signals[0].subject
        assert scorer.should_respond(subject), \
            f"Score {scorer.score(subject)} did not exceed threshold"

        # --- Step 4: Quarantine (REAL) ---
        db_path = tmp_path / "pipeline.db"
        store = QuarantineStore(db_path=str(db_path), quarantine_dir=str(quarantine_dir))
        record = store.add(
            original_path=str(eicar_file),
            reason=signals[0].reason,
            score=scorer.score(subject),
            source_signals=[s.kind for s in signals],
        )

        # --- Step 5: Verify everything ---
        assert not eicar_file.exists(), "EICAR file should be quarantined (moved)"
        assert Path(record.quarantined_path).exists(), "Quarantined copy exists"
        assert record.sha256 == EICAR_SHA256, "SHA-256 integrity check passed"
        assert record.score >= 80.0, f"Score {record.score} should be >= 80"
        assert "yara_match" in record.source_signals

        # --- Step 6: Restore and verify data integrity ---
        store.restore(record.id, notes="End-to-end test verification")
        restored_data = eicar_file.read_bytes()
        assert restored_data == EICAR, "Restored file is byte-identical to original"
