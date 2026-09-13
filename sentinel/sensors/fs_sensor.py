"""File-system sensor — watches folders for new/modified files.

Implements architecture.md Section 5.1 (`fs_sensor.py` via `watchdog`):
captures new/modified files in the watched folders (Downloads/Desktop/Temp
per plan.md sample config) and emits shared-schema `file_write` events into
the event bus.

PHASE 1 SCOPE: capture only — no detection logic. The entropy and write-rate
signals this sensor records in `extra` are consumed by the ransomware
heuristic in Phase 2 (`engine/scoring.py`), not here.

Entropy note: file entropy (a ransomware signal per prd.md glossary and
architecture.md Section 4B) is computed here at capture time so the event
already carries it. Computing it once at capture avoids re-reading the file
in every downstream consumer. Entropy of the *written bytes* is a strong
ransomware indicator; for very large files we sample the first N bytes to
keep the sensor cheap (NFR-6).
"""
from __future__ import annotations

import hashlib
import logging
import math
import os
import threading
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from sentinel.engine.event_bus import EventBus
from sentinel.engine.schema import Event, utc_timestamp

logger = logging.getLogger(__name__)

# Cap how many bytes we read for entropy/hash on a single event, to protect
# the NFR-6 idle-resource budget (architecture.md Section 8). Full hashing
# of large files would make the sensor a hotspot.
_MAX_BYTES_FOR_ENTROPY = 1 * 1024 * 1024  # 1 MiB sample

# Event subtypes watchdog reports that we treat as a write of interest.
# `created` and `modified` are the ones relevant to ransomware mass-write and
# new-download detection; `moved` is also captured (a rename/move is a common
# ransomware step: original -> encrypted copy).
_WATCHED_ACTIONS = {"created", "modified", "moved"}


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of `data` in bits/byte, 0.0–8.0.

    Used by the ransomware heuristic: encryption/compression spikes entropy
    toward ~8.0 (prd.md glossary: "Entropy (file)"). Pure code is far lower.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def sha256_of(path: str | Path, limit_bytes: int | None = _MAX_BYTES_FOR_ENTROPY) -> str:
    """SHA-256 of (up to `limit_bytes` of) the file. For files larger than
    the limit we hash the leading sample — enough for reputation/dedup in
    v1; full-file hashing can be added later if a rule needs it."""
    h = hashlib.sha256()
    read = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
            read += len(chunk)
            if limit_bytes is not None and read >= limit_bytes:
                break
    return h.hexdigest()


class _Handler(FileSystemEventHandler):
    """Translates watchdog events into shared-schema `file_write` events."""

    def __init__(self, bus: EventBus, watched_root: str) -> None:
        self._bus = bus
        self._watched_root = watched_root

    def _emit(self, path: str, action: str) -> None:
        # Directory events aren't file writes; skip them.
        p = Path(path)
        if p.is_dir():
            return
        entropy: float | None = None
        hash_sha256: str | None = None
        size: int | None = None
        try:
            if p.exists():
                size = p.stat().st_size
                # Read once, use for both entropy and hash.
                with open(p, "rb") as fh:
                    sample = fh.read(_MAX_BYTES_FOR_ENTROPY)
                entropy = round(shannon_entropy(sample), 3)
                # Hash the same sample range for consistency/cheapness.
                h = hashlib.sha256()
                h.update(sample)
                # If file is larger than the sample, read+hash the rest too,
                # but cap total work.
                rest = p.stat().st_size - len(sample)
                if rest > 0 and len(sample) >= _MAX_BYTES_FOR_ENTROPY:
                    # Already at sample cap; mark hash as sample-only.
                    hash_sha256 = h.hexdigest() + " (sample)"
                else:
                    hash_sha256 = h.hexdigest()
        except OSError as exc:
            # File may vanish between the event and our read (common for temp
            # files). Log at debug and emit with nulls — the event still
            # records that the path was written.
            logger.debug("could not read %s: %s", path, exc)

        event = Event(
            timestamp=utc_timestamp(),
            source="fs",
            event_type="file_write",
            image_path=str(p),
            hash_sha256=hash_sha256,
            extra={
                "action": action,
                "watched_root": self._watched_root,
                "entropy": entropy,
                "size_bytes": size,
            },
        )
        try:
            self._bus.publish(event)
        except Exception as exc:  # pragma: no cover - never let FS kill the bus
            logger.exception("failed to publish fs event for %s: %s", path, exc)

    def on_created(self, event):  # type: ignore[override]
        if not event.is_directory:
            self._emit(event.src_path, "created")

    def on_modified(self, event):  # type: ignore[override]
        if not event.is_directory:
            self._emit(event.src_path, "modified")

    def on_moved(self, event):  # type: ignore[override]
        if not event.is_directory:
            self._emit(event.dest_path, "moved")

    def on_deleted(self, event):  # type: ignore[override]
        # Deletions are recorded as a write-signal too (ransomware deletes
        # originals after making encrypted copies). Kept lightweight: no
        # content read (file is gone).
        if event.is_directory:
            return
        p = Path(event.src_path)
        try:
            self._bus.publish(
                Event(
                    timestamp=utc_timestamp(),
                    source="fs",
                    event_type="file_write",
                    image_path=str(p),
                    extra={
                        "action": "deleted",
                        "watched_root": self._watched_root,
                        "entropy": None,
                        "size_bytes": None,
                    },
                )
            )
        except Exception:  # pragma: no cover
            logger.exception("failed to publish fs delete event for %s", event.src_path)


class FsSensor:
    """Watches configured folders and publishes file_write events.

    One watchdog Observer per watched folder (architecture.md Section 8:
    each sensor runs independently). Run `start()` then `join()`/`stop()`.
    """

    def __init__(self, bus: EventBus, watched_folders: list[str] | None = None) -> None:
        self._bus = bus
        if watched_folders is None:
            watched_folders = [
                str(Path.home() / "Downloads"),
                str(Path.home() / "Desktop"),
            ]
        expanded = [os.path.expandvars(os.path.expanduser(f)) for f in watched_folders]
        self._watched = [str(f) for f in expanded if Path(f).exists()]
        missing = [f for f in expanded if not Path(f).exists()]
        if missing:
            logger.warning("fs_sensor: skipping missing watched folders: %s", missing)
        self._observers: list[Observer] = []

    def start(self) -> None:
        for folder in self._watched:
            obs = Observer()
            obs.schedule(_Handler(self._bus, folder), folder, recursive=True)
            obs.start()
            self._observers.append(obs)
            logger.info("fs_sensor watching: %s", folder)

    def stop(self) -> None:
        for obs in self._observers:
            obs.stop()
        for obs in self._observers:
            obs.join(timeout=5)
        self._observers.clear()

    @property
    def watched_folders(self) -> list[str]:
        return list(self._watched)


def run() -> None:
    """Standalone run: load settings, watch configured folders for ~30s.
    Useful for a quick live spot-check (Phase 1 DoD) without the full
    service harness."""
    import time

    from sentinel.sensors.etw_sensor import load_settings

    settings = load_settings()
    bus = EventBus()
    sensor = FsSensor(bus, settings.get("watched_folders", []))
    sensor.start()
    print(f"fs_sensor: watching {sensor.watched_folders}. Will run 30s then report.")
    print("Create/modify a file in a watched folder to see an event.")
    time.sleep(30)
    sensor.stop()
    rows = bus.recent(limit=20, where="source=?", params=("fs",))
    print(f"fs_sensor: {len(rows)} fs event(s) captured:")
    for r in rows:
        print("  ", r["timestamp"], r["event_type"], r["image_path"], r.get("extra"))
    bus.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    run()
