"""Win32 Named Pipe IPC for Sentinel Antivirus.

Enables communication across Windows Session 0 Isolation:
- Windows Service runs under NT AUTHORITY\\SYSTEM in Session 0.
- System Tray App and Desktop GUI Dashboard run in Session 1+ (User Interactive Session).
- Inter-Process Communication (IPC) operates over \\\\.\\pipe\\SentinelIPC with a permissive DACL
  granting Authenticated Users and World access to query status and request scans.
"""
from __future__ import annotations

import json
import logging
import sys
import threading
import time
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

DEFAULT_PIPE_NAME = r"\\.\pipe\SentinelIPC"
BUFFER_SIZE = 65536
DEFAULT_TIMEOUT_MS = 3000

# Win32 security and pipe imports
_HAS_WIN32 = False
try:
    import win32file
    import win32pipe
    import win32security
    import pywintypes
    _HAS_WIN32 = True
except ImportError:
    win32file = None
    win32pipe = None
    win32security = None
    pywintypes = None


class SentinelIPCError(Exception):
    """Raised on IPC communication or pipe failure."""
    pass


def _create_security_attributes() -> Any:
    """Create Win32 SECURITY_ATTRIBUTES allowing non-admin and interactive callers.

    SDDL Breakdown:
    - (A;;GA;;;SY): Generic All for SYSTEM
    - (A;;GRGW;;;BA): Generic Read/Write for Administrators
    - (A;;GRGW;;;AU): Generic Read/Write for Authenticated Users
    - (A;;GRGW;;;WD): Generic Read/Write for Everyone / World
    """
    if not _HAS_WIN32 or win32security is None:
        return None
    try:
        sddl = "D:(A;;GA;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;AU)(A;;GRGW;;;WD)"
        sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            sddl, win32security.SDDL_REVISION_1
        )
        sa = win32security.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = sd
        sa.bInheritHandle = False
        return sa
    except Exception as exc:
        logger.warning("Failed to build named pipe DACL: %s (using default)", exc)
        return None


class NamedPipeServer:
    """Multi-client request-response server over Win32 Named Pipe."""

    def __init__(
        self,
        pipe_name: str = DEFAULT_PIPE_NAME,
        command_handler: Optional[Callable[[dict[str, Any]], dict[str, Any]]] = None,
    ) -> None:
        self.pipe_name = pipe_name
        self.command_handler = command_handler or self._default_handler
        self._stop_event = threading.Event()
        self._server_thread: Optional[threading.Thread] = None
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    def _default_handler(self, request: dict[str, Any]) -> dict[str, Any]:
        cmd = request.get("cmd")
        if cmd == "ping":
            return {"status": "ok", "pong": True, "time": time.time()}
        return {"status": "error", "message": f"unknown command: {cmd}"}

    def set_handler(self, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self.command_handler = handler

    def start(self) -> bool:
        """Start the pipe listening server in a background thread."""
        if not _HAS_WIN32:
            logger.warning("NamedPipeServer unavailable: pywin32 not present")
            return False

        if self._is_running:
            return True

        self._stop_event.clear()
        self._server_thread = threading.Thread(
            target=self._listen_loop,
            name="Sentinel-NamedPipeServer",
            daemon=True,
        )
        self._server_thread.start()
        self._is_running = True
        logger.info("NamedPipeServer started listening on %s", self.pipe_name)
        return True

    def stop(self, timeout_sec: float = 2.0) -> None:
        """Signal stop and wake up pending pipe listener."""
        if not self._is_running:
            return

        self._stop_event.set()
        self._is_running = False

        # Connect a client to unblock ConnectNamedPipe
        try:
            if _HAS_WIN32 and win32pipe is not None:
                shutdown_payload = json.dumps({"cmd": "__shutdown__"}).encode("utf-8")
                win32pipe.CallNamedPipe(
                    self.pipe_name,
                    shutdown_payload,
                    BUFFER_SIZE,
                    500,
                )
        except Exception:
            pass

        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=timeout_sec)
        logger.info("NamedPipeServer stopped")

    def _listen_loop(self) -> None:
        """Main connection and message handling loop."""
        sa = _create_security_attributes()
        h_pipe = None
        try:
            h_pipe = win32pipe.CreateNamedPipe(
                self.pipe_name,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                DEFAULT_TIMEOUT_MS,
                sa,
            )
        except Exception as exc:
            logger.error("Failed to create named pipe %s: %s", self.pipe_name, exc)
            return

        try:
            while not self._stop_event.is_set():
                try:
                    win32pipe.ConnectNamedPipe(h_pipe, None)
                except pywintypes.error as exc:
                    # Error 535: ERROR_PIPE_CONNECTED (client already connected before call)
                    if exc.winerror != 535:
                        if self._stop_event.is_set():
                            break
                        continue

                try:
                    hr, raw_data = win32file.ReadFile(h_pipe, BUFFER_SIZE)
                except Exception:
                    try:
                        win32pipe.DisconnectNamedPipe(h_pipe)
                    except Exception:
                        pass
                    continue

                if self._stop_event.is_set():
                    try:
                        win32pipe.DisconnectNamedPipe(h_pipe)
                    except Exception:
                        pass
                    break

                try:
                    request = json.loads(raw_data.decode("utf-8"))
                except Exception as exc:
                    response = {"status": "error", "message": f"invalid JSON: {exc}"}
                else:
                    if request.get("cmd") == "__shutdown__":
                        try:
                            win32file.WriteFile(h_pipe, json.dumps({"status": "ok", "shutdown": True}).encode("utf-8"))
                            win32file.FlushFileBuffers(h_pipe)
                            win32pipe.DisconnectNamedPipe(h_pipe)
                        except Exception:
                            pass
                        break
                    try:
                        response = self.command_handler(request)
                    except Exception as exc:
                        logger.exception("Error handling IPC command %s", request)
                        response = {"status": "error", "message": str(exc)}

                try:
                    resp_bytes = json.dumps(response).encode("utf-8")
                    win32file.WriteFile(h_pipe, resp_bytes)
                    win32file.FlushFileBuffers(h_pipe)
                except Exception as exc:
                    logger.debug("Failed writing response: %s", exc)
                finally:
                    try:
                        win32pipe.DisconnectNamedPipe(h_pipe)
                    except Exception:
                        pass
        finally:
            if h_pipe is not None:
                try:
                    win32file.CloseHandle(h_pipe)
                except Exception:
                    pass


class NamedPipeClient:
    """Client for querying Sentinel Core Service over Win32 Named Pipe."""

    def __init__(
        self,
        pipe_name: str = DEFAULT_PIPE_NAME,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> None:
        self.pipe_name = pipe_name
        self.timeout_ms = timeout_ms

    def is_service_running(self) -> bool:
        """Quick check if Sentinel Service is listening on the named pipe."""
        try:
            res = self.send({"cmd": "ping"})
            return res.get("status") == "ok" and res.get("pong") is True
        except Exception:
            return False

    def send(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send a request dictionary and return the response dictionary."""
        if not _HAS_WIN32 or win32pipe is None:
            raise SentinelIPCError("pywin32 is not installed or available on this platform")

        raw_req = json.dumps(request).encode("utf-8")
        deadline = time.time() + (self.timeout_ms / 1000.0)

        while True:
            try:
                raw_resp = win32pipe.CallNamedPipe(
                    self.pipe_name,
                    raw_req,
                    BUFFER_SIZE,
                    self.timeout_ms,
                )
                return json.loads(raw_resp.decode("utf-8"))
            except pywintypes.error as exc:
                # Error 2 = ERROR_FILE_NOT_FOUND, 231 = ERROR_PIPE_BUSY
                if exc.winerror in (2, 231) and time.time() < deadline:
                    try:
                        win32pipe.WaitNamedPipe(self.pipe_name, 200)
                    except Exception:
                        time.sleep(0.05)
                    continue
                raise SentinelIPCError(f"Named pipe error ({exc.winerror}): {exc.strerror}") from exc
            except Exception as exc:
                raise SentinelIPCError(f"IPC transaction failed: {exc}") from exc


    def get_status(self) -> dict[str, Any]:
        return self.send({"cmd": "get_status"})

    def verify_canaries(self) -> dict[str, Any]:
        return self.send({"cmd": "verify_canaries"})

    def rearm_canaries(self) -> dict[str, Any]:
        return self.send({"cmd": "rearm_canaries"})

    def scan_path(self, target_path: str) -> dict[str, Any]:
        return self.send({"cmd": "scan_path", "target": target_path})
