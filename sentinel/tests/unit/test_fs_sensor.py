"""Tests for sensors/fs_sensor.py.

Two layers:
- Pure unit tests for the entropy/hash helpers.
- An integration test that starts a real watchdog observer on a temp dir,
  writes a file, and confirms a correctly-shaped `file_write` event row
  lands in events.db (the Phase 1 DoD pattern for the FS sensor).
"""
import time

import pytest

from sentinel.engine.event_bus import EventBus
from sentinel.engine.schema import SOURCES
from sentinel.sensors.fs_sensor import FsSensor, shannon_entropy


def test_entropy_of_empty_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_entropy_of_constant_bytes_is_zero():
    assert shannon_entropy(b"AAAA") == 0.0


def test_entropy_of_random_bytes_is_high():
    # 256 distinct byte values -> max entropy ~8.0 bits/byte.
    data = bytes(range(256))
    ent = shannon_entropy(data)
    assert 7.9 < ent <= 8.0


def test_entropy_is_in_0_to_8_range():
    assert 0.0 <= shannon_entropy(b"hello world hello") <= 8.0


def test_fs_sensor_skips_missing_folders(tmp_path):
    bus = EventBus(db_path=tmp_path / "events.db")
    try:
        sensor = FsSensor(bus, [str(tmp_path / "nope")])
        assert sensor.watched_folders == []
    finally:
        bus.close()


def test_fs_sensor_writes_create_a_schema_shaped_event_row(tmp_path):
    """Phase 1 DoD for the FS sensor: a new file in a watched folder produces
    a correctly-shaped row in events.db."""
    watched = tmp_path / "watched"
    watched.mkdir()
    bus = EventBus(db_path=tmp_path / "events.db")
    sensor = FsSensor(bus, [str(watched)])
    sensor.start()
    try:
        # Give the observer a moment to register, then create a file.
        time.sleep(0.4)
        target = watched / "sentinel_test_file.txt"
        target.write_text("hello sentinel")
        # watchdog delivers asynchronously; poll briefly.
        deadline = time.time() + 3
        rows = []
        while time.time() < deadline:
            rows = bus.recent(limit=20, where="source=?", params=("fs",))
            if rows:
                break
            time.sleep(0.1)
    finally:
        sensor.stop()
        bus.close()

    assert rows, "no fs event captured for the new file"
    # On Windows, watchdog typically fires both `created` and `modified` for
    # a new file (the creating write also counts as a modification). Either
    # is a valid file_write event — validate shape on whichever row(s) we got
    # for our target file.
    target_rows = [
        r for r in rows if r["image_path"].endswith("sentinel_test_file.txt")
    ]
    assert target_rows, "captured events were for other paths"
    r = target_rows[0]
    # Correct shape (architecture.md Section 7 + fs extra payload).
    assert r["source"] == "fs"
    assert r["source"] in SOURCES
    assert r["event_type"] == "file_write"
    extra = r["extra"]
    assert extra["action"] in {"created", "modified", "moved"}
    assert extra["watched_root"] == str(watched)
    # At least one captured event for the file should carry content metrics.
    with_metrics = [
        rr for rr in target_rows if rr["extra"].get("entropy") is not None
    ]
    assert with_metrics, "no event carried entropy/size for the new file"
    m = with_metrics[0]["extra"]
    assert m["size_bytes"] == len("hello sentinel")
    # Entropy of "hello sentinel" is low (plain text).
    assert m["entropy"] < 5.0
