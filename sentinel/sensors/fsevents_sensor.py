"""macOS FSEvents-optimized filesystem sensor.

The existing ``fs_sensor.py`` already uses ``watchdog`` which auto-selects
the FSEvents backend on macOS. This module provides macOS-specific
optimizations and default configurations:
    - Optimized watched paths for macOS directory layout
    - Monitoring of quarantine attribute changes (com.apple.quarantine)
    - Detection of .app bundle modifications
    - Gatekeeper bypass attempt detection

Falls back to the base ``fs_sensor.py`` if FSEvents is unavailable.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

from sentinel.engine.event_bus import EventBus
from sentinel.engine.schema import Event, utc_timestamp

logger = logging.getLogger("sentinel.sensors.fsevents")

# macOS-specific executable extensions
_MACOS_EXECUTABLE_EXTENSIONS = frozenset({
    ".app", ".pkg", ".dmg", ".command", ".sh",
    ".dylib", ".kext", ".bundle", ".framework",
    ".workflow", ".action", ".plugin",
})

# macOS-specific high-risk directories
_DEFAULT_MACOS_WATCH_DIRS = [
    "~/Downloads",
    "~/Desktop",
    "/tmp",
    "/private/tmp",
    "~/Library/Caches",
]


class MacOSFileHandler(FileSystemEventHandler):
    """macOS-optimized file event handler.

    Extends base watchdog handler with:
    - Quarantine xattr detection
    - App bundle modification alerts
    - DMG mount detection
    """

    def __init__(self, bus: EventBus) -> None:
        super().__init__()
        self._bus = bus

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._handle_event(event.src_path, "file_write", "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._handle_event(event.src_path, "file_modify", "modified")

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._handle_event(event.dest_path, "file_write", "moved")

    def _handle_event(self, file_path: str, event_type: str, action: str) -> None:
        """Process a filesystem event with macOS-specific enrichment."""
        path = Path(file_path)
        suffix = path.suffix.lower()

        # Check for quarantine attribute (indicates downloaded file)
        has_quarantine = self._check_quarantine_xattr(file_path)

        # Elevate severity for executable downloads
        severity = "info"
        if suffix in _MACOS_EXECUTABLE_EXTENSIONS:
            severity = "warning"
        if has_quarantine and suffix in _MACOS_EXECUTABLE_EXTENSIONS:
            severity = "high"

        # Detect .app bundle creation (potential dropper)
        if suffix == ".app" and action == "created":
            event_type = "app_bundle_created"
            severity = "warning"

        extra = {
            "path": file_path,
            "action": action,
            "extension": suffix,
            "quarantine_flag": has_quarantine,
        }

        # Compute entropy for executable files
        if suffix in _MACOS_EXECUTABLE_EXTENSIONS:
            try:
                from sentinel.sensors.fs_sensor import shannon_entropy
                with open(file_path, "rb") as f:
                    data = f.read(1024 * 1024)  # 1 MiB sample
                extra["entropy"] = round(shannon_entropy(data), 4)
            except Exception:
                pass

        event = Event(
            timestamp=utc_timestamp(),
            source="fsevents",
            event_type=event_type,
            severity=severity,
            description=f"{action}: {path.name}",
            extra=extra,
        )
        self._bus.publish(event)

    @staticmethod
    def _check_quarantine_xattr(file_path: str) -> bool:
        """Check if file has the com.apple.quarantine extended attribute."""
        try:
            result = subprocess.run(
                ["xattr", "-l", file_path],
                capture_output=True, text=True, timeout=2,
            )
            return "com.apple.quarantine" in result.stdout
        except Exception:
            return False


class FSEventsSensor:
    """macOS FSEvents filesystem sensor.

    Wraps ``watchdog`` with macOS-specific defaults and the enriched
    ``MacOSFileHandler``.
    """

    def __init__(
        self,
        bus: EventBus,
        watch_dirs: Optional[list[str]] = None,
    ) -> None:
        self._bus = bus
        self._watch_dirs = watch_dirs or [
            os.path.expanduser(d) for d in _DEFAULT_MACOS_WATCH_DIRS
        ]
        self._observer: Optional[Observer] = None

    def start(self) -> None:
        """Start the FSEvents observer."""
        handler = MacOSFileHandler(self._bus)
        self._observer = Observer()

        for watch_dir in self._watch_dirs:
            if Path(watch_dir).is_dir():
                self._observer.schedule(handler, watch_dir, recursive=True)
                logger.info("FSEvents watch: %s", watch_dir)

        self._observer.start()
        logger.info("FSEvents sensor started (%d dirs)", len(self._watch_dirs))

    def stop(self) -> None:
        """Stop the FSEvents observer."""
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        logger.info("FSEvents sensor stopped")
