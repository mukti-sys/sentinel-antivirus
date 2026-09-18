"""Linux real-time filesystem monitoring via fanotify.

Provides kernel-level file access/modify/execute event monitoring using
the ``fanotify`` API (Linux kernel 5.1+). Falls back to the existing
``watchdog``-based ``fs_sensor.py`` if fanotify is unavailable.

Requirements:
    - Linux kernel 5.1+ with CONFIG_FANOTIFY=y
    - CAP_SYS_ADMIN capability or root privileges
    - Python ctypes (standard library)

fanotify provides system-wide file event monitoring directly from the
kernel, which is significantly more performant and comprehensive than
inotify/watchdog for antivirus use cases.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import struct
import sys
import threading
from pathlib import Path
from typing import Optional

from sentinel.engine.event_bus import EventBus
from sentinel.engine.schema import Event, utc_timestamp

logger = logging.getLogger("sentinel.sensors.fanotify")

# fanotify constants (from <linux/fanotify.h>)
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_CLASS_CONTENT = 0x00000004
FAN_CLASS_NOTIF = 0x00000000
FAN_CLASS_PRE_CONTENT = 0x00000008
FAN_UNLIMITED_QUEUE = 0x00000010
FAN_UNLIMITED_MARKS = 0x00000020

# Event flags
FAN_ACCESS = 0x00000001
FAN_MODIFY = 0x00000002
FAN_CLOSE_WRITE = 0x00000008
FAN_CLOSE_NOWRITE = 0x00000010
FAN_OPEN = 0x00000020
FAN_OPEN_EXEC = 0x00001000
FAN_OPEN_PERM = 0x00010000
FAN_OPEN_EXEC_PERM = 0x00040000
FAN_EVENT_ON_CHILD = 0x08000000
FAN_ONDIR = 0x40000000

# Mark flags
FAN_MARK_ADD = 0x00000001
FAN_MARK_REMOVE = 0x00000002
FAN_MARK_FLUSH = 0x00000080
FAN_MARK_MOUNT = 0x00000010
FAN_MARK_FILESYSTEM = 0x00000100

# Response flags (for permission events)
FAN_ALLOW = 0x01
FAN_DENY = 0x02

# fanotify_event_metadata size
_EVENT_META_SIZE = 24  # sizeof(struct fanotify_event_metadata)


class FanotifyEventMetadata(ctypes.Structure):
    """struct fanotify_event_metadata from <linux/fanotify.h>."""
    _fields_ = [
        ("event_len", ctypes.c_uint32),
        ("vers", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("metadata_len", ctypes.c_uint16),
        ("mask", ctypes.c_uint64),
        ("fd", ctypes.c_int32),
        ("pid", ctypes.c_int32),
    ]


class FanotifyResponse(ctypes.Structure):
    """struct fanotify_response for permission event replies."""
    _fields_ = [
        ("fd", ctypes.c_int32),
        ("response", ctypes.c_uint32),
    ]


def _fanotify_available() -> bool:
    """Check if fanotify is available on this system."""
    if sys.platform != "linux":
        return False
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        # Check if fanotify_init exists
        _ = libc.fanotify_init
        return True
    except (OSError, AttributeError):
        return False


class FanotifySensor:
    """Real-time filesystem sensor using Linux fanotify.

    Monitors file open, modify, close-write, and execute events across
    specified mount points or the entire filesystem.
    """

    def __init__(
        self,
        bus: EventBus,
        watch_paths: Optional[list[str]] = None,
        monitor_execute: bool = True,
    ) -> None:
        self._bus = bus
        self._watch_paths = watch_paths or ["/"]
        self._monitor_execute = monitor_execute
        self._fan_fd: int = -1
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._libc = None

    def start(self) -> None:
        """Initialize fanotify and start the monitoring thread."""
        if not _fanotify_available():
            raise RuntimeError(
                "fanotify not available — kernel too old or missing CAP_SYS_ADMIN"
            )

        self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        # Initialize fanotify instance
        init_flags = FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_UNLIMITED_QUEUE
        event_flags = os.O_RDONLY | os.O_LARGEFILE if hasattr(os, "O_LARGEFILE") else os.O_RDONLY

        self._fan_fd = self._libc.fanotify_init(init_flags, event_flags)
        if self._fan_fd < 0:
            errno = ctypes.get_errno()
            raise RuntimeError(
                f"fanotify_init failed (errno={errno}). "
                f"Ensure CAP_SYS_ADMIN capability or root privileges."
            )

        # Set up marks for watched paths
        mark_mask = FAN_MODIFY | FAN_CLOSE_WRITE | FAN_OPEN
        if self._monitor_execute:
            mark_mask |= FAN_OPEN_EXEC

        for path in self._watch_paths:
            ret = self._libc.fanotify_mark(
                self._fan_fd,
                FAN_MARK_ADD | FAN_MARK_MOUNT,
                mark_mask,
                -1,  # dirfd (AT_FDCWD)
                path.encode("utf-8"),
            )
            if ret < 0:
                errno = ctypes.get_errno()
                logger.warning(
                    "fanotify_mark failed for %s (errno=%d) — skipping",
                    path, errno,
                )
            else:
                logger.info("fanotify mark added: %s", path)

        self._running = True
        self._thread = threading.Thread(
            target=self._read_loop,
            name="sentinel-fanotify",
            daemon=True,
        )
        self._thread.start()
        logger.info("fanotify sensor started (fd=%d, paths=%s)", self._fan_fd, self._watch_paths)

    def stop(self) -> None:
        """Stop the fanotify sensor and release resources."""
        self._running = False
        if self._fan_fd >= 0:
            os.close(self._fan_fd)
            self._fan_fd = -1
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("fanotify sensor stopped")

    def _read_loop(self) -> None:
        """Continuously read fanotify events and emit to EventBus."""
        buf_size = 4096 * _EVENT_META_SIZE
        while self._running and self._fan_fd >= 0:
            try:
                buf = os.read(self._fan_fd, buf_size)
                if not buf:
                    continue
                self._process_events(buf)
            except OSError as exc:
                if self._running:
                    logger.debug("fanotify read error: %s", exc)
                break

    def _process_events(self, buf: bytes) -> None:
        """Parse raw fanotify event buffer and emit events."""
        offset = 0
        while offset < len(buf) - _EVENT_META_SIZE + 1:
            meta = FanotifyEventMetadata.from_buffer_copy(buf[offset:offset + _EVENT_META_SIZE])

            if meta.event_len < _EVENT_META_SIZE:
                break

            if meta.fd >= 0:
                try:
                    # Resolve file path from fd via /proc/self/fd/<fd>
                    file_path = os.readlink(f"/proc/self/fd/{meta.fd}")
                    self._emit_event(file_path, meta.mask, meta.pid)
                except (OSError, FileNotFoundError):
                    pass
                finally:
                    try:
                        os.close(meta.fd)
                    except OSError:
                        pass

            offset += meta.event_len

    def _emit_event(self, file_path: str, mask: int, pid: int) -> None:
        """Convert a fanotify event into a Sentinel EventBus event."""
        # Determine event type
        if mask & FAN_OPEN_EXEC:
            event_type = "file_exec"
        elif mask & FAN_CLOSE_WRITE:
            event_type = "file_write"
        elif mask & FAN_MODIFY:
            event_type = "file_modify"
        elif mask & FAN_OPEN:
            event_type = "file_open"
        else:
            event_type = "file_access"

        # Resolve process name
        proc_name = ""
        try:
            proc_name = Path(f"/proc/{pid}/comm").read_text().strip()
        except Exception:
            pass

        event = Event(
            timestamp=utc_timestamp(),
            source="fanotify",
            event_type=event_type,
            severity="info",
            description=f"{event_type}: {file_path}",
            extra={
                "path": file_path,
                "pid": pid,
                "process": proc_name,
                "mask": hex(mask),
            },
        )
        self._bus.publish(event)
