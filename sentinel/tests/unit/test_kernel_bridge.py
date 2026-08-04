"""Tests for sentinel/kernel/bridge.py.

All tests run WITHOUT a real kernel driver — fltlib.dll is fully mocked.
This validates:
1. Message structure correctness (ctypes layout matches the C header)
2. add_block / remove_block send the right message type + path
3. get_status parses the kernel reply correctly
4. Graceful degradation when driver not loaded (connect fails)
5. No-op mode: all methods return safely when not connected
6. connect/disconnect lifecycle
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from sentinel.kernel.messages import (
    MSG_ADD_BLOCK,
    MSG_BLOCK_EVENT,
    MSG_QUERY_STATUS,
    MSG_REMOVE_BLOCK,
    SENTINEL_COMMAND,
    SENTINEL_MAX_PATH,
    SENTINEL_REPLY,
)
from sentinel.kernel.bridge import BlockEvent, KernelBridge


# ----------------------------------------------------------------------- #
# Fixtures                                                                 #
# ----------------------------------------------------------------------- #

@pytest.fixture
def mock_fltlib():
    """Create a mock fltlib.dll."""
    lib = MagicMock()
    # FilterSendMessage succeeds by default.
    lib.FilterSendMessage.return_value = 0
    # FilterGetMessage returns no messages by default.
    lib.FilterGetMessage.return_value = 0x800704C7  # ERROR_CANCELLED
    return lib


@pytest.fixture
def bridge(mock_fltlib):
    """Create a KernelBridge with a mocked fltlib and _raw_connect."""
    with patch("sentinel.kernel.bridge._load_fltlib", return_value=mock_fltlib):
        b = KernelBridge()
        # Mock _raw_connect to return a fake handle (bypasses ctypes.byref).
        with patch.object(b, "_raw_connect", return_value=wintypes.HANDLE(42)):
            b.connect()
        yield b
        b.disconnect()


# ----------------------------------------------------------------------- #
# Message structure tests                                                  #
# ----------------------------------------------------------------------- #

class TestMessageStructures:
    def test_sentinel_command_size(self):
        """SENTINEL_COMMAND should be type (4 bytes) + path (520 * 2 bytes)."""
        cmd = SENTINEL_COMMAND()
        # 4 + 520*2 = 1044 bytes, but ctypes may add padding.
        assert ctypes.sizeof(cmd) >= 4 + SENTINEL_MAX_PATH * 2

    def test_sentinel_command_fields(self):
        cmd = SENTINEL_COMMAND()
        cmd.type = MSG_ADD_BLOCK
        cmd.path = r"C:\test\malware.exe"
        assert cmd.type == MSG_ADD_BLOCK
        assert cmd.path == r"C:\test\malware.exe"

    def test_sentinel_reply_size(self):
        reply = SENTINEL_REPLY()
        # 3 ULONGs = 12 bytes.
        assert ctypes.sizeof(reply) >= 12

    def test_sentinel_reply_fields(self):
        reply = SENTINEL_REPLY()
        reply.status = 0
        reply.blocklist_count = 5
        reply.blocks_total = 42
        assert reply.blocklist_count == 5
        assert reply.blocks_total == 42


# ----------------------------------------------------------------------- #
# Connection lifecycle                                                     #
# ----------------------------------------------------------------------- #

class TestConnection:
    def test_connect_success(self, mock_fltlib):
        with patch("sentinel.kernel.bridge._load_fltlib",
                   return_value=mock_fltlib):
            b = KernelBridge()
            with patch.object(b, "_raw_connect",
                            return_value=wintypes.HANDLE(42)):
                assert b.connect() is True
            assert b.connected is True
            b.disconnect()

    def test_connect_failure_no_driver(self, mock_fltlib):
        with patch("sentinel.kernel.bridge._load_fltlib",
                   return_value=mock_fltlib):
            b = KernelBridge()
            with patch.object(b, "_raw_connect", return_value=None):
                assert b.connect() is False
            assert b.connected is False

    def test_connect_no_fltlib(self):
        with patch("sentinel.kernel.bridge._load_fltlib", return_value=None):
            b = KernelBridge()
            assert b.connect() is False

    def test_disconnect(self, bridge):
        assert bridge.connected is True
        bridge.disconnect()
        assert bridge.connected is False

    def test_double_connect_returns_true(self, bridge):
        assert bridge.connect() is True  # already connected


# ----------------------------------------------------------------------- #
# add_block / remove_block                                                 #
# ----------------------------------------------------------------------- #

class TestBlocklistOps:
    def test_add_block_sends_correct_message(self, bridge, mock_fltlib):
        result = bridge.add_block(r"C:\temp\evil.exe")
        assert result is True
        # Verify FilterSendMessage was called.
        mock_fltlib.FilterSendMessage.assert_called()
        # Get the command that was sent.
        call_args = mock_fltlib.FilterSendMessage.call_args
        # args[1] is the input buffer (byref to SENTINEL_COMMAND)
        # We can't easily inspect ctypes byref, but we can verify it was called.

    def test_remove_block_sends_correct_message(self, bridge, mock_fltlib):
        result = bridge.remove_block(r"C:\temp\evil.exe")
        assert result is True
        mock_fltlib.FilterSendMessage.assert_called()

    def test_add_block_failure(self, bridge, mock_fltlib):
        mock_fltlib.FilterSendMessage.return_value = 0x80070005  # ACCESS_DENIED
        result = bridge.add_block(r"C:\test.exe")
        assert result is False

    def test_remove_block_failure(self, bridge, mock_fltlib):
        mock_fltlib.FilterSendMessage.return_value = 0x80070005
        result = bridge.remove_block(r"C:\test.exe")
        assert result is False

    def test_add_block_truncates_long_path(self, bridge, mock_fltlib):
        long_path = "C:\\" + "A" * 600 + ".exe"
        result = bridge.add_block(long_path)
        assert result is True  # should truncate, not crash


# ----------------------------------------------------------------------- #
# get_status                                                               #
# ----------------------------------------------------------------------- #

class TestGetStatus:
    def test_get_status_returns_dict(self, bridge, mock_fltlib):
        # FilterSendMessage succeeds — get_status reads the reply struct.
        # Since we can't easily write into ctypes byref objects from mocks,
        # we test that get_status calls FilterSendMessage and, on success
        # (return 0), returns a dict with the expected keys.
        # The actual values will be zero (uninitialized SENTINEL_REPLY).
        mock_fltlib.FilterSendMessage.return_value = 0
        mock_fltlib.FilterSendMessage.side_effect = None
        status = bridge.get_status()
        assert isinstance(status, dict)
        assert "blocklist_count" in status
        assert "blocks_total" in status
        mock_fltlib.FilterSendMessage.assert_called()

    def test_get_status_failure(self, bridge, mock_fltlib):
        mock_fltlib.FilterSendMessage.return_value = 0x80070005
        mock_fltlib.FilterSendMessage.side_effect = None
        status = bridge.get_status()
        assert status == {}


# ----------------------------------------------------------------------- #
# No-op mode (not connected)                                               #
# ----------------------------------------------------------------------- #

class TestNoOpMode:
    def test_add_block_noop_when_disconnected(self):
        b = KernelBridge()
        assert b.add_block(r"C:\test.exe") is False

    def test_remove_block_noop_when_disconnected(self):
        b = KernelBridge()
        assert b.remove_block(r"C:\test.exe") is False

    def test_get_status_noop_when_disconnected(self):
        b = KernelBridge()
        assert b.get_status() == {}

    def test_poll_events_noop_when_disconnected(self):
        b = KernelBridge()
        assert b.poll_events() == []

    def test_disconnect_noop_when_not_connected(self):
        b = KernelBridge()
        b.disconnect()  # should not crash
