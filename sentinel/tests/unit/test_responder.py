"""Tests for response/responder.py.

Validates the process suspension and quarantine action per phases.md Phase 3:
    responder.py: suspend process (NtSuspendProcess), move file to
    data/quarantine/, strip execute permission

Test coverage:
1. suspend_process() with invalid PID returns error string
2. resume_process() with invalid PID returns error string
3. quarantine_process() integration with mock store + bus
4. Audit event emitted to bus after suspension
5. resolve_process_image() basic coverage
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from sentinel.response.responder import (
    quarantine_process,
    resolve_process_image,
    resume_process,
    suspend_process,
)
from sentinel.response.quarantine_store import QuarantineRecord, QuarantineStore


# --------------------------------------------------------------------------- #
# suspend / resume with invalid PIDs
# --------------------------------------------------------------------------- #

class TestSuspendResume:
    def test_suspend_invalid_pid_none(self):
        err = suspend_process(None)
        assert err is not None
        assert "invalid" in err.lower()

    def test_suspend_invalid_pid_zero(self):
        err = suspend_process(0)
        assert err is not None
        assert "invalid" in err.lower()

    def test_suspend_invalid_pid_negative(self):
        err = suspend_process(-1)
        assert err is not None
        assert "invalid" in err.lower()

    def test_resume_invalid_pid_none(self):
        err = resume_process(None)
        assert err is not None
        assert "invalid" in err.lower()

    def test_resume_invalid_pid_zero(self):
        err = resume_process(0)
        assert err is not None
        assert "invalid" in err.lower()

    def test_suspend_nonexistent_pid(self):
        """Suspending a PID that doesn't exist should return an error,
        not crash."""
        err = suspend_process(99999999)
        assert err is not None  # OpenProcess should fail

    def test_resume_nonexistent_pid(self):
        err = resume_process(99999999)
        assert err is not None


# --------------------------------------------------------------------------- #
# quarantine_process() with mocks
# --------------------------------------------------------------------------- #

class TestQuarantineProcess:
    def test_quarantine_with_failed_suspend(self):
        """If suspend fails, quarantine_process returns error without
        touching the store."""
        mock_store = MagicMock(spec=QuarantineStore)
        mock_bus = MagicMock()

        result = quarantine_process(
            pid=-1,  # will fail suspend
            reason="test detection",
            quarantine_store=mock_store,
            bus=mock_bus,
        )
        assert result["success"] is False
        assert "suspend failed" in result["error"]
        # Store should NOT have been called.
        mock_store.add.assert_not_called()

    @patch("sentinel.response.responder.suspend_process", return_value=None)
    def test_quarantine_with_successful_suspend(self, mock_suspend, tmp_path):
        """If suspend succeeds, quarantine_process moves file and emits audit."""
        test_file = tmp_path / "evil.exe"
        test_file.write_bytes(b"malware_payload")

        mock_store = MagicMock(spec=QuarantineStore)
        mock_store.add.return_value = QuarantineRecord(
            id="abc123",
            subject="pid:1234",
            original_path=str(test_file),
            quarantined_path=str(tmp_path / "quarantine" / "abc123_evil.exe"),
            reason="test detection",
            score=90.0,
        )

        mock_bus = MagicMock()
        mock_bus.publish.return_value = 42  # rowid

        result = quarantine_process(
            pid=1234,
            reason="test detection",
            quarantine_store=mock_store,
            bus=mock_bus,
            image_path=str(test_file),
        )

        assert result["success"] is True
        assert result["suspension"] is None  # no error
        assert result["quarantine"] is not None
        assert result["quarantine"].id == "abc123"
        # Audit event should have been published.
        mock_bus.publish.assert_called_once()
        event = mock_bus.publish.call_args[0][0]
        assert event.event_type == "process_suspended"
        assert event.pid == 1234

    @patch("sentinel.response.responder.suspend_process", return_value=None)
    def test_quarantine_without_store_no_image(self, mock_suspend):
        """quarantine_process works even without a store or image path
        (just suspends, nothing to quarantine)."""
        result = quarantine_process(
            pid=1234,
            reason="test",
            # No image_path, no store -> success (nothing to quarantine).
        )
        assert result["success"] is True
        assert result["quarantine"] is None

    @patch("sentinel.response.responder.suspend_process", return_value=None)
    def test_quarantine_without_store_with_image_partial_fail(self, mock_suspend):
        """When image_path is given but no store, the process is suspended
        but file can't be quarantined -> partial failure."""
        result = quarantine_process(
            pid=1234,
            reason="test",
            image_path="/fake/path.exe",
        )
        # Process is suspended but file wasn't quarantined.
        assert result["success"] is False
        assert result["suspension"] is None  # suspend worked
        assert "quarantined" in result["error"]

    @patch("sentinel.response.responder.suspend_process", return_value=None)
    def test_quarantine_emits_audit_event(self, mock_suspend):
        """The audit event contains the right metadata."""
        mock_bus = MagicMock()
        mock_bus.publish.return_value = 99

        quarantine_process(
            pid=5555,
            reason="cryptominer detected",
            bus=mock_bus,
            image_path="C:\\malware\\miner.exe",
        )

        mock_bus.publish.assert_called_once()
        event = mock_bus.publish.call_args[0][0]
        assert event.source == "etw_process"
        assert event.event_type == "process_suspended"
        assert event.pid == 5555
        assert event.image_path == "C:\\malware\\miner.exe"
        assert event.extra["reason"] == "cryptominer detected"


# --------------------------------------------------------------------------- #
# resolve_process_image()
# --------------------------------------------------------------------------- #

class TestResolveProcessImage:
    def test_resolve_current_process(self):
        """Should resolve our own PID successfully."""
        path = resolve_process_image(os.getpid())
        assert path is not None
        assert "python" in path.lower()

    def test_resolve_invalid_pid(self):
        result = resolve_process_image(-1)
        assert result is None

    def test_resolve_nonexistent_pid(self):
        result = resolve_process_image(99999999)
        assert result is None
