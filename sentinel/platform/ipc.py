"""Cross-platform IPC abstraction for Sentinel Antivirus.

Provides unified client/server IPC that auto-selects the transport:
    - Windows: Win32 Named Pipes (delegates to sentinel.ipc)
    - Linux:   Unix Domain Socket (/var/run/sentinel/sentinel.sock)
    - macOS:   Unix Domain Socket (~/Library/Application Support/Sentinel/sentinel.sock)

Both transports speak the same JSON-line protocol as the existing
NamedPipeServer/NamedPipeClient.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger("sentinel.platform.ipc")

_PLATFORM = sys.platform

# Default socket paths
if _PLATFORM == "linux":
    _DEFAULT_SOCKET_PATH = "/var/run/sentinel/sentinel.sock"
elif _PLATFORM == "darwin":
    _DEFAULT_SOCKET_PATH = str(
        Path.home() / "Library" / "Application Support" / "Sentinel" / "sentinel.sock"
    )
else:
    _DEFAULT_SOCKET_PATH = ""

BUFFER_SIZE = 65536


class IPCError(Exception):
    """Raised on IPC communication failure."""
    pass


# ---------------------------------------------------------------------------
# Unix Domain Socket Server (Linux / macOS)
# ---------------------------------------------------------------------------
class UnixSocketServer:
    """JSON-line IPC server over a Unix Domain Socket.

    Drop-in replacement for ``sentinel.ipc.NamedPipeServer`` on POSIX systems.
    """

    def __init__(
        self,
        command_handler: Callable[[dict[str, Any]], dict[str, Any]],
        socket_path: str = "",
    ) -> None:
        self._handler = command_handler
        self._socket_path = socket_path or _DEFAULT_SOCKET_PATH
        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        """Start accepting connections on the Unix socket."""
        sock_path = Path(self._socket_path)
        sock_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove stale socket file
        if sock_path.exists():
            sock_path.unlink()

        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(str(sock_path))
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)  # allow periodic stop checks

        # Set socket permissions: owner + group read/write
        os.chmod(str(sock_path), stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)

        self._running = True
        self._thread = threading.Thread(
            target=self._accept_loop,
            name="sentinel-ipc-unix",
            daemon=True,
        )
        self._thread.start()
        logger.info("Unix socket IPC server started: %s", self._socket_path)

    def stop(self) -> None:
        """Stop the server and clean up the socket file."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)

        # Clean up socket file
        try:
            Path(self._socket_path).unlink(missing_ok=True)
        except Exception:
            pass
        logger.info("Unix socket IPC server stopped")

    def _accept_loop(self) -> None:
        """Accept incoming connections and dispatch to handler threads."""
        while self._running:
            try:
                conn, _ = self._server_socket.accept()
                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn,),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.debug("Socket accept error (shutting down?)")
                break

    def _handle_client(self, conn: socket.socket) -> None:
        """Handle a single client connection."""
        try:
            conn.settimeout(5.0)
            data = b""
            while True:
                chunk = conn.recv(BUFFER_SIZE)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break

            if not data:
                return

            request = json.loads(data.decode("utf-8").strip())
            response = self._handler(request)
            response_bytes = (json.dumps(response) + "\n").encode("utf-8")
            conn.sendall(response_bytes)
        except Exception as exc:
            logger.debug("IPC client handler error: %s", exc)
            try:
                err = json.dumps({"status": "error", "message": str(exc)}) + "\n"
                conn.sendall(err.encode("utf-8"))
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Unix Domain Socket Client (Linux / macOS)
# ---------------------------------------------------------------------------
class UnixSocketClient:
    """JSON-line IPC client over a Unix Domain Socket.

    Drop-in replacement for ``sentinel.ipc.NamedPipeClient`` on POSIX systems.
    """

    def __init__(self, socket_path: str = "") -> None:
        self._socket_path = socket_path or _DEFAULT_SOCKET_PATH

    def send_command(
        self,
        command: dict[str, Any],
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        """Send a JSON command and return the JSON response."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(self._socket_path)
            payload = (json.dumps(command) + "\n").encode("utf-8")
            sock.sendall(payload)

            data = b""
            while True:
                chunk = sock.recv(BUFFER_SIZE)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break

            if not data:
                raise IPCError("Empty response from server")

            return json.loads(data.decode("utf-8").strip())
        except (ConnectionRefusedError, FileNotFoundError):
            raise IPCError("Sentinel service is not running")
        except socket.timeout:
            raise IPCError("IPC request timed out")
        finally:
            sock.close()

    def ping(self) -> bool:
        """Quick health check — returns True if the service responds."""
        try:
            resp = self.send_command({"cmd": "ping"}, timeout=2.0)
            return resp.get("pong", False)
        except IPCError:
            return False


# ---------------------------------------------------------------------------
# Factory functions — auto-select based on platform
# ---------------------------------------------------------------------------
def create_ipc_server(
    command_handler: Callable[[dict[str, Any]], dict[str, Any]],
) -> Any:
    """Create the appropriate IPC server for the current platform."""
    if _PLATFORM == "win32":
        from sentinel.ipc import NamedPipeServer
        return NamedPipeServer(command_handler=command_handler)
    else:
        return UnixSocketServer(command_handler=command_handler)


def create_ipc_client() -> Any:
    """Create the appropriate IPC client for the current platform."""
    if _PLATFORM == "win32":
        from sentinel.ipc import NamedPipeClient
        return NamedPipeClient()
    else:
        return UnixSocketClient()
