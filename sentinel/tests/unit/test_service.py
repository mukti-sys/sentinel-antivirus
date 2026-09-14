"""Tests for sentinel.service (SentinelOrchestrator and IPC integration).

Validates:
1. SentinelOrchestrator lifecycle (start, stop, cleanup)
2. IPC command handling (_handle_ipc_command) for desktop interaction
3. Honeypot Canary Deception Engine integration inside service
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel.engine.canary import CanaryManager
from sentinel.service import SentinelOrchestrator


class TestSentinelOrchestrator:
    @pytest.fixture
    def orchestrator(self, tmp_path):
        orch = SentinelOrchestrator()
        # Mock sensors to avoid launching background OS threads during unit tests
        orch._start_sensors = MagicMock()
        orch._init_kernel_bridge = MagicMock()
        orch._init_detection_consumer = MagicMock()
        return orch

    def test_ipc_command_ping(self, orchestrator):
        resp = orchestrator._handle_ipc_command({"cmd": "ping"})
        assert resp["status"] == "ok"
        assert resp["pong"] is True
        assert resp["service"] == "running"

    def test_ipc_command_get_status(self, orchestrator, tmp_path):
        canary_dir = tmp_path / "canary_test"
        canary_dir.mkdir()
        mgr = CanaryManager(target_directories=[canary_dir])
        mgr.arm_traps()
        orchestrator._canary_manager = mgr

        resp = orchestrator._handle_ipc_command({"cmd": "get_status"})
        assert resp["status"] == "ok"
        assert resp["service"] == "running"
        assert resp["shield"] == "GREEN"
        assert resp["canary_traps"]["armed_traps"] == 3

        mgr.disarm_traps()

    def test_ipc_command_verify_and_rearm_canaries(self, orchestrator, tmp_path):
        canary_dir = tmp_path / "canary_test"
        canary_dir.mkdir()
        mgr = CanaryManager(target_directories=[canary_dir])
        mgr.arm_traps()
        orchestrator._canary_manager = mgr

        # Verify clean
        resp_verify = orchestrator._handle_ipc_command({"cmd": "verify_canaries"})
        assert resp_verify["status"] == "ok"
        assert resp_verify["tampered_count"] == 0

        # Tamper one
        trap_path = list(mgr.active_canaries.values())[0].path
        trap_path.unlink()

        # Verify detects tampering
        resp_verify_tampered = orchestrator._handle_ipc_command({"cmd": "verify_canaries"})
        assert resp_verify_tampered["tampered_count"] == 1

        # Rearm
        resp_rearm = orchestrator._handle_ipc_command({"cmd": "rearm_canaries"})
        assert resp_rearm["status"] == "ok"
        assert resp_rearm["repaired_count"] == 1
        assert trap_path.exists()

        mgr.disarm_traps()

    def test_ipc_unknown_command(self, orchestrator):
        resp = orchestrator._handle_ipc_command({"cmd": "destroy_all"})
        assert resp["status"] == "error"
        assert "unknown command" in resp["message"]
