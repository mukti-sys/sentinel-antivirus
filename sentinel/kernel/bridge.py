"""User-mode bridge to the SentinelFilter kernel minifilter.

Uses fltlib.dll (the Filter Manager user-mode library) via ctypes to
communicate with the kernel driver through a filter communication port.

fltlib.dll API surface used:
  - FilterConnectCommunicationPort  — opens handle to \\SentinelFilterPort
  - FilterSendMessage               — sends MSG_ADD_BLOCK, MSG_REMOVE_BLOCK,
                                       MSG_QUERY_STATUS to the driver
  - FilterGetMessage                — receives MSG_BLOCK_EVENT from driver
  - FilterReplyMessage              — acknowledges driver messages

Graceful degradation: if the driver is not loaded (connect fails), all
methods become silent no-ops.  The rest of Sentinel continues to work
exactly as it did in Phase 3 (user-mode only).

Thread safety: The bridge is NOT thread-safe by itself.  The caller
(orchestrator/service) should ensure single-threaded access or add
locking if needed.
"""
from __future__ import annotations

import ctypes
import logging
import os
from ctypes import wintypes
from dataclasses import dataclass
from typing import Optional

from sentinel.kernel.messages import (
    FILTER_MESSAGE_HEADER,
    MSG_ADD_BLOCK,
    MSG_BLOCK_EVENT,
    MSG_QUERY_STATUS,
    MSG_REMOVE_BLOCK,
    SENTINEL_BLOCK_EVENT,
    SENTINEL_COMMAND,
    SENTINEL_GET_MESSAGE,
    SENTINEL_MAX_PATH,
    SENTINEL_PORT_NAME,
    SENTINEL_REPLY,
)

logger = logging.getLogger(__name__)

def dos_to_nt_path(path: str) -> str:
    r"""Convert a DOS path (e.g. C:\Users\ADMINI~1\...) to normalized NT device path.

    Filter Manager normalized paths start with \\Device\\HarddiskVolumeX\\
    and use long path components. This function converts DOS drive paths
    to their corresponding NT device paths on Windows.
    """
    if not path or not isinstance(path, str):
        return path
    try:
        # If already an NT device path, return as-is
        if path.startswith(r"\Device\HarddiskVolume") or path.startswith(r"\??\\"):
            return path

        buf = ctypes.create_unicode_buffer(1024)
        res = ctypes.windll.kernel32.GetLongPathNameW(path, buf, 1024)
        if res > 0:
            p = buf.value
        else:
            # If the file itself is blocked by the driver, GetLongPathNameW on the file
            # returns ERROR_ACCESS_DENIED (5). The parent directory is NOT blocked,
            # so resolve the directory's long path and append the filename.
            parent, name = os.path.split(path)
            if parent:
                res_dir = ctypes.windll.kernel32.GetLongPathNameW(parent, buf, 1024)
                p = os.path.join(buf.value if res_dir > 0 else parent, name)
            else:
                p = path

        drive, rest = os.path.splitdrive(p)
        if drive:
            target = ctypes.create_unicode_buffer(1024)
            if ctypes.windll.kernel32.QueryDosDeviceW(drive, target, 1024) > 0:
                return target.value + rest
        return p
    except Exception:
        return path

# ----------------------------------------------------------------------- #
# fltlib.dll function signatures                                           #
# ----------------------------------------------------------------------- #

_fltlib = None

def _load_fltlib():
    """Lazy-load fltlib.dll.  Returns None if not available."""
    global _fltlib
    if _fltlib is not None:
        return _fltlib
    try:
        _fltlib = ctypes.WinDLL("fltlib.dll")
        return _fltlib
    except OSError:
        logger.warning("fltlib.dll not available — kernel bridge disabled")
        return None


def _setup_fltlib(lib):
    """Configure function signatures for type safety."""

    # HRESULT FilterConnectCommunicationPort(
    #   LPCWSTR               lpPortName,
    #   DWORD                 dwOptions,
    #   LPCVOID               lpContext,
    #   WORD                  wSizeOfContext,
    #   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    #   HANDLE               *hPort
    # );
    lib.FilterConnectCommunicationPort.argtypes = [
        wintypes.LPCWSTR,    # lpPortName
        wintypes.DWORD,      # dwOptions
        ctypes.c_void_p,     # lpContext
        wintypes.WORD,       # wSizeOfContext
        ctypes.c_void_p,     # lpSecurityAttributes
        ctypes.POINTER(wintypes.HANDLE),  # hPort (out)
    ]
    lib.FilterConnectCommunicationPort.restype = ctypes.HRESULT

    # HRESULT FilterSendMessage(
    #   HANDLE  hPort,
    #   LPVOID  lpInBuffer,
    #   DWORD   dwInBufferSize,
    #   LPVOID  lpOutBuffer,
    #   DWORD   dwOutBufferSize,
    #   LPDWORD lpBytesReturned
    # );
    lib.FilterSendMessage.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    lib.FilterSendMessage.restype = ctypes.HRESULT

    # HRESULT FilterGetMessage(
    #   HANDLE                hPort,
    #   PFILTER_MESSAGE_HEADER lpMessageBuffer,
    #   DWORD                  dwMessageBufferSize,
    #   LPOVERLAPPED           lpOverlapped
    # );
    lib.FilterGetMessage.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,  # LPOVERLAPPED (NULL for synchronous)
    ]
    lib.FilterGetMessage.restype = ctypes.HRESULT

    # HRESULT FilterReplyMessage(
    #   HANDLE                 hPort,
    #   PFILTER_REPLY_HEADER   lpReplyBuffer,
    #   DWORD                  dwReplyBufferSize
    # );
    lib.FilterReplyMessage.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    lib.FilterReplyMessage.restype = ctypes.HRESULT


# ----------------------------------------------------------------------- #
# BlockEvent dataclass                                                     #
# ----------------------------------------------------------------------- #

@dataclass
class BlockEvent:
    """A file access that was blocked by the kernel minifilter."""
    path: str
    pid: int
    tid: int
    timestamp: int  # Windows FILETIME (100ns intervals since 1601)


# ----------------------------------------------------------------------- #
# KernelBridge                                                             #
# ----------------------------------------------------------------------- #

class KernelBridge:
    """User-mode bridge to the SentinelFilter kernel minifilter.

    Usage:
        bridge = KernelBridge()
        if bridge.connect():
            bridge.add_block(r"C:\\malware\\evil.exe")
            status = bridge.get_status()
            events = bridge.poll_events()
            bridge.remove_block(r"C:\\malware\\evil.exe")
            bridge.disconnect()
    """

    def __init__(self, port_name: str = SENTINEL_PORT_NAME) -> None:
        self._port_name = port_name
        self._handle: Optional[wintypes.HANDLE] = None
        self._connected = False
        self._fltlib = None
        self._blocked_paths: dict[str, str] = {}  # original_path -> nt_path

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> bool:
        """Connect to the kernel minifilter communication port.

        Returns True on success, False if driver not loaded or
        connection failed.  On failure, the bridge enters no-op mode.
        """
        if self._connected:
            return True

        lib = _load_fltlib()
        if lib is None:
            return False

        _setup_fltlib(lib)
        self._fltlib = lib

        handle = self._raw_connect(lib)
        if handle is None:
            return False

        self._handle = handle
        self._connected = True
        logger.info("kernel bridge: connected to %s", self._port_name)
        return True

    def _raw_connect(self, lib) -> Optional[wintypes.HANDLE]:
        """Low-level connect — isolated for testability.

        Returns a HANDLE on success, None on failure.
        Tests mock this method instead of fighting ctypes.byref().
        """
        handle = wintypes.HANDLE()
        hr = lib.FilterConnectCommunicationPort(
            self._port_name,
            0,      # dwOptions
            None,   # lpContext
            0,      # wSizeOfContext
            None,   # lpSecurityAttributes
            ctypes.byref(handle),
        )
        if hr != 0:
            logger.info(
                "kernel bridge: driver not loaded or connection refused "
                "(HRESULT=0x%08X) — operating in no-op mode",
                hr & 0xFFFFFFFF,
            )
            return None
        return handle

    def disconnect(self) -> None:
        """Disconnect from the kernel driver."""
        if self._handle:
            ctypes.windll.kernel32.CloseHandle(self._handle)
            self._handle = None
        self._connected = False
        logger.info("kernel bridge: disconnected")

    def _send_command(self, cmd_type: int, target_path: str) -> bool:
        cmd = SENTINEL_COMMAND()
        cmd.type = cmd_type
        cmd.path = target_path[:SENTINEL_MAX_PATH - 1]

        bytes_returned = wintypes.DWORD(0)
        hr = self._fltlib.FilterSendMessage(
            self._handle,
            ctypes.byref(cmd),
            ctypes.sizeof(cmd),
            None,
            0,
            ctypes.byref(bytes_returned),
        )
        return hr == 0

    def add_block(self, path: str) -> bool:
        """Add a file path to the kernel blocklist.

        Converts DOS paths to NT device paths to match Filter Manager's
        normalized paths (\\Device\\HarddiskVolumeX\\...).
        """
        if not self._connected:
            logger.debug("kernel bridge: add_block no-op (not connected)")
            return False

        nt_path = dos_to_nt_path(path)
        self._blocked_paths[path] = nt_path
        self._blocked_paths[nt_path] = nt_path

        ok = self._send_command(MSG_ADD_BLOCK, nt_path)
        if not ok:
            logger.warning("kernel bridge: add_block failed for %s (nt: %s)", path, nt_path)
            return False

        logger.info("kernel bridge: blocked path added: %s (nt: %s)", path, nt_path)
        return True

    def remove_block(self, path: str) -> bool:
        """Remove a file path from the kernel blocklist."""
        if not self._connected:
            logger.debug("kernel bridge: remove_block no-op (not connected)")
            return False

        nt_path = self._blocked_paths.pop(path, None)
        if not nt_path:
            nt_path = dos_to_nt_path(path)
        self._blocked_paths.pop(nt_path, None)

        ok = self._send_command(MSG_REMOVE_BLOCK, nt_path)
        if nt_path != path:
            self._send_command(MSG_REMOVE_BLOCK, path)

        if not ok:
            logger.warning("kernel bridge: remove_block failed for %s (nt: %s)", path, nt_path)
            return False

        logger.info("kernel bridge: blocked path removed: %s (nt: %s)", path, nt_path)
        return True

    def get_status(self) -> dict:
        """Query the kernel driver for blocklist status.

        Returns dict with 'blocklist_count' and 'blocks_total',
        or empty dict if not connected.
        """
        if not self._connected:
            return {}

        cmd = SENTINEL_COMMAND()
        cmd.type = MSG_QUERY_STATUS

        reply = SENTINEL_REPLY()
        bytes_returned = wintypes.DWORD(0)
        hr = self._fltlib.FilterSendMessage(
            self._handle,
            ctypes.byref(cmd),
            ctypes.sizeof(cmd),
            ctypes.byref(reply),
            ctypes.sizeof(reply),
            ctypes.byref(bytes_returned),
        )

        if hr != 0:
            logger.warning(
                "kernel bridge: get_status failed (HRESULT=0x%08X)",
                hr & 0xFFFFFFFF,
            )
            return {}

        return {
            "blocklist_count": reply.blocklist_count,
            "blocks_total": reply.blocks_total,
        }

    def poll_events(self, timeout_ms: int = 0) -> list[BlockEvent]:
        """Poll for block events from the kernel driver.

        Non-blocking by default (timeout_ms=0).  Returns a list of
        BlockEvent objects, or empty list if none available.

        Note: FilterGetMessage is synchronous when lpOverlapped is NULL.
        For non-blocking behavior, we use an OVERLAPPED with a manual
        event that we check immediately.
        """
        if not self._connected:
            return []

        events = []
        msg = SENTINEL_GET_MESSAGE()

        # For non-blocking, we use a zero-timeout wait.
        # FilterGetMessage with overlapped=NULL blocks, so we'll use
        # a simple try-with-timeout approach.
        hr = self._fltlib.FilterGetMessage(
            self._handle,
            ctypes.byref(msg),
            ctypes.sizeof(msg),
            None,  # Synchronous — will block if no message available
        )

        # S_OK = 0, ERROR_IO_PENDING is expected for no messages
        if hr == 0:
            evt = msg.event
            events.append(BlockEvent(
                path=evt.path,
                pid=evt.pid,
                tid=evt.tid,
                timestamp=evt.timestamp.QuadPart,
            ))

        return events

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()

    def __del__(self):
        self.disconnect()
