"""Unit tests for Sentinel CLI entry point."""

import argparse
from unittest.mock import MagicMock, patch
from pathlib import Path
import pytest

from sentinel.cli_entry import cmd_status, cmd_scan, cmd_sandbox, cmd_canaries, cmd_quarantine, main


class TestCliEntry:
    def test_cmd_status_no_connection(self, capsys):
        args = argparse.Namespace(pipe=r"\\.\pipe\SentinelNonExistentPipeTest")
        code = cmd_status(args)
        assert code == 1
        captured = capsys.readouterr().out
        assert "Could not connect" in captured

    def test_cmd_status_success(self, capsys):
        args = argparse.Namespace(pipe=r"\\.\pipe\SentinelMockPipe")
        with patch("sentinel.cli_entry.NamedPipeClient") as mock_client:
            instance = mock_client.return_value
            instance.send.return_value = {
                "status": "ok",
                "shield": "GREEN",
                "driver": "connected",
                "canaries_armed": 3,
            }
            code = cmd_status(args)
            assert code == 0
            captured = capsys.readouterr().out
            assert "SENTINEL SERVICE STATUS" in captured
            assert "GREEN" in captured

    def test_cmd_scan_clean_binary(self, capsys):
        # Scan real python.exe or notepad.exe
        notepad = Path(r"C:\Windows\System32\notepad.exe")
        if not notepad.exists():
            pytest.skip("notepad.exe not found")

        args = argparse.Namespace(path=str(notepad), verbose=True)
        code = cmd_scan(args)
        assert code == 0
        captured = capsys.readouterr().out
        assert "SENTINEL SCAN REPORT" in captured
        assert "0 threats detected" in captured

    def test_cmd_canaries_lifecycle(self, capsys):
        args_disarm = argparse.Namespace(arm=False, disarm=True)
        code_disarm = cmd_canaries(args_disarm)
        assert code_disarm == 0
        captured = capsys.readouterr().out
        assert "Disarmed" in captured

    def test_cmd_quarantine(self, capsys, tmp_path):
        with patch("sentinel.cli_entry.QuarantineStore") as mock_store:
            instance = mock_store.return_value
            instance.list_records.return_value = []
            args = argparse.Namespace(limit=10)
            code = cmd_quarantine(args)
            assert code == 0
            captured = capsys.readouterr().out
            assert "empty" in captured

    def test_cmd_sandbox(self, capsys, tmp_path):
        dummy = tmp_path / "dummy.exe"
        dummy.write_bytes(b"\x90\x90\xC3")
        args = argparse.Namespace(target=str(dummy), mode="emulation", timeout=3.0)
        code = cmd_sandbox(args)
        assert code == 0
        captured = capsys.readouterr().out
        assert "SENTINEL DYNAMIC SANDBOX STUDIO" in captured
        assert "Verdict" in captured
        assert "BENIGN" in captured

    def test_main_help_no_args(self, capsys):
        with patch("sys.argv", ["sentinel"]):
            code = main()
            assert code == 0
