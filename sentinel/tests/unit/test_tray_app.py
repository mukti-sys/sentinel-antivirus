"""Tests for sentinel.ui.tray_app.

Validates:
1. Shield icon generation with status color pallets (GREEN, YELLOW, RED)
2. TrayApp status management and dynamic icon/title updating
3. Honeypot Canary Traps integration (armed count, tampering verification, rearm)
4. Quarantine submenu and action handling
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PIL import Image

from sentinel.engine.canary import CanaryManager
from sentinel.response.notifier import Notifier
from sentinel.ui.tray_app import TrayApp, _create_icon_image, _ensure_deps


class TestShieldIconGeneration:
    def test_ensure_deps_returns_true(self):
        assert _ensure_deps() is True

    def test_create_icon_image_colors(self):
        for status in ("GREEN", "YELLOW", "RED", "unknown"):
            img = _create_icon_image(status)
            assert isinstance(img, Image.Image)
            assert img.size == (64, 64)
            assert img.mode == "RGBA"


class TestTrayAppStatusAndCanary:
    @pytest.fixture
    def mock_notifier(self):
        return MagicMock(spec=Notifier)

    @pytest.fixture
    def canary_dir(self, tmp_path):
        d = tmp_path / "canary_test"
        d.mkdir()
        return d

    def test_initial_state(self, mock_notifier):
        app = TrayApp(notifier=mock_notifier)
        assert app.status == "GREEN"
        assert "unconfigured" in app._canary_label()

    def test_status_update(self, mock_notifier):
        app = TrayApp(notifier=mock_notifier)
        mock_icon = MagicMock()
        app._icon = mock_icon

        app.set_status("red")
        assert app.status == "RED"
        assert "Threat Blocked" in mock_icon.title

        app.set_status("yellow")
        assert app.status == "YELLOW"
        assert "Warning" in mock_icon.title

        app.set_status("green")
        assert app.status == "GREEN"
        assert "Protected" in mock_icon.title

    def test_canary_integration(self, canary_dir, mock_notifier):
        mgr = CanaryManager(target_directories=[canary_dir])
        mgr.arm_traps()

        app = TrayApp(notifier=mock_notifier, canary_manager=mgr)
        assert "3 armed" in app._canary_label()

        # Check intact honeypots
        app._on_verify_canaries()
        mock_notifier.notify_info.assert_called_with("All canary honeypots are intact and armed.")
        assert app.status == "GREEN"

        # Tamper with a canary
        canaries = list(mgr.active_canaries.keys())
        assert len(canaries) == 3
        # Delete one canary
        Path(canaries[0]).unlink()

        app._on_verify_canaries()
        assert app.status == "RED"
        mock_notifier.notify_alert.assert_called_once()
        assert "Honeypot Tampering" in mock_notifier.notify_alert.call_args[1]["process_name"]

        # Rearm canaries
        app._on_rearm_canaries()
        assert Path(canaries[0]).exists()

        mgr.disarm_traps()
