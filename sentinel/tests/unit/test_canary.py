"""Unit tests for Ransomware Canary Deception Engine (sentinel/engine/canary.py)."""
import tempfile
from pathlib import Path
import pytest

from sentinel.engine.canary import CanaryManager, CANARY_TEMPLATES, write_canary_content
from sentinel.engine.heuristics_ransomware import RansomwareHeuristic
from sentinel.engine.schema import Event, utc_timestamp
from sentinel.engine.scoring import Scorer, WEIGHTS


class TestCanaryManager:
    def test_arm_traps_creates_templates(self, tmp_path):
        target_dir = tmp_path / "Documents"
        target_dir.mkdir()
        manager = CanaryManager(target_directories=[target_dir])

        armed = manager.arm_traps()
        assert armed == len(CANARY_TEMPLATES)
        assert len(manager._canaries) == len(CANARY_TEMPLATES)

        # Check all template files exist
        for tmpl in CANARY_TEMPLATES:
            expected_file = target_dir / tmpl.filename
            assert expected_file.exists()
            assert expected_file.read_bytes() == tmpl.sample_content
            assert manager.is_canary(expected_file) is True

    def test_is_canary_negative(self, tmp_path):
        manager = CanaryManager(target_directories=[tmp_path])
        manager.arm_traps()

        regular_file = tmp_path / "normal_resume.docx"
        regular_file.write_bytes(b"Normal User Resume Content")
        assert manager.is_canary(regular_file) is False
        assert manager.is_canary("C:\\Windows\\notepad.exe") is False

    def test_check_tampering_content_modified(self, tmp_path):
        manager = CanaryManager(target_directories=[tmp_path])
        manager.arm_traps()

        canary_file = tmp_path / CANARY_TEMPLATES[0].filename
        # Untampered check
        tampered, reason = manager.check_tampering(canary_file)
        assert tampered is False
        assert reason == "clean"

        # Simulate ransomware encrypting the file
        write_canary_content(canary_file, b"ENCRYPTED_AES256_PAYLOAD_GARBAGE\x00\xff", set_hidden=False)
        tampered_after, reason_after = manager.check_tampering(canary_file)
        assert tampered_after is True
        assert "canary_modified_content" in reason_after

    def test_check_tampering_file_deleted(self, tmp_path):
        manager = CanaryManager(target_directories=[tmp_path])
        manager.arm_traps()

        canary_file = tmp_path / CANARY_TEMPLATES[1].filename
        canary_file.unlink()

        tampered, reason = manager.check_tampering(canary_file)
        assert tampered is True
        assert "canary_deleted" in reason

    def test_repair_canaries(self, tmp_path):
        manager = CanaryManager(target_directories=[tmp_path])
        manager.arm_traps()

        canary_file = tmp_path / CANARY_TEMPLATES[0].filename
        write_canary_content(canary_file, b"MALWARE_ENCRYPTED", set_hidden=False)
        assert manager.check_tampering(canary_file)[0] is True

        repaired = manager.repair_canaries()
        assert repaired == 1
        assert manager.check_tampering(canary_file)[0] is False
        assert canary_file.read_bytes() == CANARY_TEMPLATES[0].sample_content

    def test_disarm_traps_cleans_up(self, tmp_path):
        manager = CanaryManager(target_directories=[tmp_path])
        manager.arm_traps()

        for tmpl in CANARY_TEMPLATES:
            assert (tmp_path / tmpl.filename).exists()

        manager.disarm_traps()
        for tmpl in CANARY_TEMPLATES:
            assert not (tmp_path / tmpl.filename).exists()
        assert len(manager._canaries) == 0


class TestRansomwareHeuristicCanaryIntegration:
    def test_canary_tripped_emits_immediate_high_severity_signal(self, tmp_path):
        manager = CanaryManager(target_directories=[tmp_path])
        manager.arm_traps()

        heuristic = RansomwareHeuristic(canary_manager=manager)
        canary_path = tmp_path / CANARY_TEMPLATES[0].filename

        # Simulate ransomware encrypting the file
        write_canary_content(canary_path, b"RANSOMWARE_ENCRYPTED_DATA", set_hidden=False)

        event = Event(
            timestamp=utc_timestamp(),
            source="fs",
            event_type="file_write",
            pid=7744,
            image_path=str(canary_path),
            extra={"action": "modified", "watched_root": str(tmp_path)},
        )

        signals = heuristic.process_fs_event(event)
        assert len(signals) == 1
        sig = signals[0]
        assert sig.kind == "canary_tripped"
        assert sig.subject == "pid:7744"
        assert "honeypot" in sig.reason.lower()

        # Check scoring threshold
        scorer = Scorer()
        scorer.add_signal(sig)
        score_state = scorer.get("pid:7744")
        assert score_state.total >= 80.0
        assert scorer.should_respond("pid:7744") is True
        assert WEIGHTS["canary_tripped"] == 85.0
