"""Phase 1 integration smoke test — exercises the real, runnable sensors
together against a single event bus + events.db and confirms each produces
a correctly-shaped row (architecture.md Section 7). This is the runnable
portion of the Phase 1 DoD; the admin-gated live sensors (ETW, EventLog)
are verified separately on an elevated terminal.

Combines: fs_sensor (real watchdog) + network_sensor (real psutil poll,
loopback connection) + event_bus (SQLite persistence) + schema (shape).
"""
import socket
import time
from pathlib import Path

import pytest

from sentinel.engine.event_bus import EventBus
from sentinel.engine.schema import EVENT_TYPES, SOURCES
from sentinel.sensors.fs_sensor import FsSensor
from sentinel.sensors.network_sensor import NetworkSensor


def _assert_schema_shape(row, expected_source, expected_event_type):
    """The Phase 1 DoD: 'a correctly-shaped row in events.db'."""
    assert row["source"] == expected_source
    assert row["source"] in SOURCES
    assert row["event_type"] == expected_event_type
    assert row["event_type"] in EVENT_TYPES
    assert row["timestamp"]
    # extra must be a persisted dict (JSON round-tripped)
    assert isinstance(row["extra"], dict)


def test_fs_and_network_events_persist_with_correct_shape(tmp_path):
    db = tmp_path / "events.db"
    bus = EventBus(db_path=db)

    # FS: watch a temp dir, create a file.
    watched = tmp_path / "watched"
    watched.mkdir()
    fs = FsSensor(bus, [str(watched)])
    fs.start()

    # Network: open a real loopback connection.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    accepted, _ = listener.accept()

    net = NetworkSensor(bus, poll_interval=0.1)
    net.start()

    try:
        # Trigger an fs event.
        time.sleep(0.3)
        (watched / "phase1_smoke.txt").write_text("sentinel phase 1 smoke test")
        # Wait for both sensor events to land.
        deadline = time.time() + 4
        fs_row = None
        net_row = None
        while time.time() < deadline and (fs_row is None or net_row is None):
            rows = bus.recent(limit=100)
            for r in rows:
                if r["source"] == "fs" and fs_row is None:
                    fs_row = r
                if (
                    r["source"] == "network"
                    and net_row is None
                    and r["extra"].get("remote_ip") == "127.0.0.1"
                    and r["extra"].get("dest_port") == port
                ):
                    net_row = r
            time.sleep(0.1)
    finally:
        fs.stop()
        net.stop()
        accepted.close()
        client.close()
        listener.close()
        bus.close()

    assert fs_row is not None, "fs_sensor produced no row"
    assert net_row is not None, "network_sensor produced no row for the loopback conn"
    _assert_schema_shape(fs_row, "fs", "file_write")
    _assert_schema_shape(net_row, "network", "connection")
    # Event-specific extra sanity.
    assert fs_row["extra"].get("action") in {"created", "modified", "moved"}
    assert fs_row["extra"].get("entropy") is not None
    assert net_row["extra"].get("dest_port") == port


def test_events_db_file_created(tmp_path):
    """events.db exists on disk after publishing (plan.md structure + DoD)."""
    db = tmp_path / "events.db"
    assert not db.exists()
    bus = EventBus(db_path=db)
    bus.publish(
        __import__("sentinel.engine.schema", fromlist=["Event"]).Event(
            timestamp=__import__("sentinel.engine.schema", fromlist=["utc_timestamp"]).utc_timestamp(),
            source="fs",
            event_type="file_write",
            image_path="C:\\x\\y.txt",
        )
    )
    bus.close()
    assert db.exists() and db.stat().st_size > 0
