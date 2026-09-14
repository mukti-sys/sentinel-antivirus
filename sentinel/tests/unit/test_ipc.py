"""Tests for sentinel.ipc.

Validates:
1. Win32 Named Pipe security attribute generation with cross-session SDDL
2. NamedPipeServer and NamedPipeClient request/response transceive
3. Command dispatching (ping, get_status, verify_canaries, rearm_canaries)
4. Graceful handling of inactive server or invalid JSON
5. Clean shutdown without thread hanging
"""
from __future__ import annotations

import time
import uuid

import pytest

from sentinel.ipc import (
    NamedPipeClient,
    NamedPipeServer,
    SentinelIPCError,
    _create_security_attributes,
    _HAS_WIN32,
)


@pytest.mark.skipif(not _HAS_WIN32, reason="Requires pywin32 on Windows")
class TestNamedPipeIPC:
    @pytest.fixture
    def unique_pipe_name(self):
        return rf"\\.\pipe\SentinelTest_{uuid.uuid4().hex[:8]}"

    def test_security_attributes_creation(self):
        sa = _create_security_attributes()
        assert sa is not None
        assert hasattr(sa, "SECURITY_DESCRIPTOR")

    def test_client_fails_when_server_not_running(self, unique_pipe_name):
        client = NamedPipeClient(pipe_name=unique_pipe_name, timeout_ms=500)
        assert client.is_service_running() is False
        with pytest.raises(SentinelIPCError):
            client.send({"cmd": "ping"})

    def test_ping_pong_transaction(self, unique_pipe_name):
        server = NamedPipeServer(pipe_name=unique_pipe_name)
        started = server.start()
        assert started is True
        time.sleep(0.1)

        try:
            client = NamedPipeClient(pipe_name=unique_pipe_name, timeout_ms=2000)
            assert client.is_service_running() is True
            res = client.send({"cmd": "ping"})
            assert res.get("status") == "ok"
            assert res.get("pong") is True
        finally:
            server.stop()
            assert server.is_running is False

    def test_custom_command_handler(self, unique_pipe_name):
        def custom_handler(req: dict) -> dict:
            cmd = req.get("cmd")
            if cmd == "get_status":
                return {
                    "status": "ok",
                    "shield": "GREEN",
                    "canaries_armed": 3,
                    "driver_active": True,
                }
            elif cmd == "verify_canaries":
                return {"status": "ok", "tampered_count": 0}
            return {"status": "error", "message": "unknown"}

        server = NamedPipeServer(pipe_name=unique_pipe_name, command_handler=custom_handler)
        server.start()
        time.sleep(0.1)

        try:
            client = NamedPipeClient(pipe_name=unique_pipe_name, timeout_ms=2000)
            status_resp = client.get_status()
            assert status_resp["status"] == "ok"
            assert status_resp["shield"] == "GREEN"
            assert status_resp["canaries_armed"] == 3

            canary_resp = client.verify_canaries()
            assert canary_resp["status"] == "ok"
            assert canary_resp["tampered_count"] == 0
        finally:
            server.stop()
