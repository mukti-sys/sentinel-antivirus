"""Tests for response/notifier.py.

Validates the notification system per phases.md Phase 3:
    notifier.py: calm, clear toast notification with what/why

Test coverage:
1. Notification dataclass construction
2. notify_alert() formats calm message (no alarmist language)
3. notify_info() / notify_resolved() format correctly
4. Notifier degrades gracefully when no UI channel available
5. NFR-1 compliance: language is calm, not alarmist
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sentinel.response.notifier import Notification, Notifier


# --------------------------------------------------------------------------- #
# Notification dataclass
# --------------------------------------------------------------------------- #

class TestNotificationDataclass:
    def test_default_type_is_alert(self):
        n = Notification(title="Test", body="Body text")
        assert n.notification_type == "alert"

    def test_custom_type(self):
        n = Notification(title="Test", body="Body", notification_type="info")
        assert n.notification_type == "info"

    def test_optional_fields_default_to_none(self):
        n = Notification(title="Test", body="Body")
        assert n.quarantine_id is None
        assert n.pid is None
        assert n.process_name is None
        assert n.extra is None

    def test_all_fields(self):
        n = Notification(
            title="Sentinel", body="Alert",
            notification_type="alert", quarantine_id="abc123",
            pid=1234, process_name="evil.exe",
            extra={"score": 90},
        )
        assert n.quarantine_id == "abc123"
        assert n.pid == 1234
        assert n.process_name == "evil.exe"
        assert n.extra == {"score": 90}


# --------------------------------------------------------------------------- #
# Notifier formatting
# --------------------------------------------------------------------------- #

class TestNotifierFormatting:
    """Verify the notifier produces calm, clear language per NFR-1.
    No words like DANGER, CRITICAL, THREAT, VIRUS, MALWARE in the
    notification title/body."""

    ALARMIST_WORDS = {"danger", "critical", "threat", "virus", "malware",
                      "warning", "urgent", "emergency"}

    @patch("sentinel.response.notifier._check_toast_available", return_value=False)
    @patch("sentinel.response.notifier._send_balloon", return_value=False)
    def test_alert_uses_calm_language(self, mock_balloon, mock_toast):
        notifier = Notifier()
        # Capture what would be logged.
        with patch("sentinel.response.notifier.logger") as mock_logger:
            notifier.notify_alert(
                process_name="miner.exe",
                reason="sustained high CPU + stratum connection",
                pid=5555,
                score=95.0,
            )
            # The notification was logged (no UI channel).
            mock_logger.info.assert_called()
            log_msg = str(mock_logger.info.call_args)
            # Check no alarmist words.
            for word in self.ALARMIST_WORDS:
                assert word not in log_msg.lower(), \
                    f"found alarmist word '{word}' in notification: {log_msg}"

    @patch("sentinel.response.notifier._check_toast_available", return_value=False)
    @patch("sentinel.response.notifier._send_balloon", return_value=False)
    def test_info_notification(self, mock_balloon, mock_toast):
        notifier = Notifier()
        with patch("sentinel.response.notifier.logger") as mock_logger:
            notifier.notify_info("Service started successfully")
            mock_logger.info.assert_called()

    @patch("sentinel.response.notifier._check_toast_available", return_value=False)
    @patch("sentinel.response.notifier._send_balloon", return_value=False)
    def test_resolved_notification(self, mock_balloon, mock_toast):
        notifier = Notifier()
        with patch("sentinel.response.notifier.logger") as mock_logger:
            notifier.notify_resolved(
                process_name="benign.exe",
                action="restored",
                quarantine_id="abc123",
            )
            mock_logger.info.assert_called()


# --------------------------------------------------------------------------- #
# Graceful degradation
# --------------------------------------------------------------------------- #

class TestGracefulDegradation:
    @patch("sentinel.response.notifier._check_toast_available", return_value=False)
    @patch("sentinel.response.notifier._send_balloon", return_value=False)
    def test_no_ui_channel_does_not_crash(self, mock_balloon, mock_toast):
        """When no UI channel is available, the notifier logs the
        notification and does not crash."""
        notifier = Notifier()
        # Should not raise.
        notifier.notify_alert(
            process_name="test.exe",
            reason="test detection",
            pid=1234,
        )
        notifier.notify_info("test info")
        notifier.notify_resolved("test.exe", "deleted")

    @patch("sentinel.response.notifier._check_toast_available", return_value=True)
    @patch("sentinel.response.notifier._send_toast", return_value=True)
    def test_toast_channel_used_when_available(self, mock_send, mock_check):
        notifier = Notifier()
        notifier.notify_info("test")
        mock_send.assert_called_once()

    @patch("sentinel.response.notifier._check_toast_available", return_value=True)
    @patch("sentinel.response.notifier._send_toast", return_value=False)
    @patch("sentinel.response.notifier._send_balloon", return_value=True)
    def test_balloon_fallback_when_toast_fails(self, mock_balloon, mock_toast, mock_check):
        notifier = Notifier()
        notifier.notify_info("test")
        # Toast tried first, failed, then balloon.
        mock_toast.assert_called_once()
        mock_balloon.assert_called_once()
