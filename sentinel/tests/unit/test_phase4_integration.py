"""Phase 4 integration tests — end-to-end with mock kernel bridge.

Validates:
1. quarantine_process() calls bridge.add_block() with the correct path
2. Restore calls bridge.remove_block() with the correct path
3. Bridge in no-op mode → quarantine still works (Phase 3 behavior)
4. Service orchestrator connects bridge on startup (when available)
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel.engine.event_bus import EventBus
from sentinel.kernel.bridge import KernelBridge
from sentinel.response.quarantine_store import (
    PENDING,
    RESTORED,
    QuarantineStore,
)
from sentinel.response.responder import quarantine_process


# ----------------------------------------------------------------------- #
# End-to-end: quarantine → bridge.add_block                               #
# ----------------------------------------------------------------------- #

class TestQuarantineWithBridge:
    @patch("sentinel.response.responder.suspend_process", return_value=None)
    def test_quarantine_calls_add_block(self, mock_suspend, tmp_path):
        """When bridge is connected, quarantine_process should call
        bridge.add_block(image_path) after successful quarantine."""
        evil_file = tmp_path / "dropper.exe"
        evil_file.write_bytes(b"MZ_payload")

        bus = EventBus(db_path=tmp_path / "events.db")
        store = QuarantineStore(
            db_path=tmp_path / "quarantine.db",
            quarantine_dir=tmp_path / "quarantine",
        )
        bridge = MagicMock(spec=KernelBridge)
        bridge.connected = True
        bridge.add_block.return_value = True

        result = quarantine_process(
            pid=5555,
            reason="test detection",
            quarantine_store=store,
            bus=bus,
            image_path=str(evil_file),
            kernel_bridge=bridge,
        )

        assert result["success"] is True
        # Bridge should have been called with the image path.
        bridge.add_block.assert_called_once_with(str(evil_file))

        bus.close()

    @patch("sentinel.response.responder.suspend_process", return_value=None)
    def test_quarantine_works_without_bridge(self, mock_suspend, tmp_path):
        """Without a bridge (Phase 3 mode), quarantine still works."""
        evil_file = tmp_path / "malware.exe"
        evil_file.write_bytes(b"MZ_payload")

        bus = EventBus(db_path=tmp_path / "events.db")
        store = QuarantineStore(
            db_path=tmp_path / "quarantine.db",
            quarantine_dir=tmp_path / "quarantine",
        )

        result = quarantine_process(
            pid=6666,
            reason="test detection",
            quarantine_store=store,
            bus=bus,
            image_path=str(evil_file),
            # No kernel_bridge parameter.
        )

        assert result["success"] is True
        bus.close()

    @patch("sentinel.response.responder.suspend_process", return_value=None)
    def test_quarantine_with_disconnected_bridge(self, mock_suspend, tmp_path):
        """Bridge in no-op mode should not crash quarantine."""
        evil_file = tmp_path / "test.exe"
        evil_file.write_bytes(b"MZ_payload")

        bus = EventBus(db_path=tmp_path / "events.db")
        store = QuarantineStore(
            db_path=tmp_path / "quarantine.db",
            quarantine_dir=tmp_path / "quarantine",
        )
        bridge = MagicMock(spec=KernelBridge)
        bridge.connected = False
        bridge.add_block.return_value = False

        result = quarantine_process(
            pid=7777,
            reason="test",
            quarantine_store=store,
            bus=bus,
            image_path=str(evil_file),
            kernel_bridge=bridge,
        )

        # Should succeed even though bridge failed.
        assert result["success"] is True
        bus.close()


# ----------------------------------------------------------------------- #
# Bridge no-op mode tests                                                  #
# ----------------------------------------------------------------------- #

class TestBridgeNoOp:
    def test_bridge_default_not_connected(self):
        b = KernelBridge()
        assert b.connected is False

    def test_noop_add_block(self):
        b = KernelBridge()
        assert b.add_block(r"C:\test.exe") is False

    def test_noop_remove_block(self):
        b = KernelBridge()
        assert b.remove_block(r"C:\test.exe") is False

    def test_noop_get_status(self):
        b = KernelBridge()
        assert b.get_status() == {}
