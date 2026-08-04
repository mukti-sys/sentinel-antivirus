"""Unit tests for engine/event_bus.py.

Verifies: normalize() coercion, SQLite persistence to events.db with the
schema-shaped columns, in-memory queue delivery, high-volume batching,
and thread-safe concurrent publish (architecture.md Sections 5.2 & 8).
"""
import threading
from pathlib import Path

import pytest

from sentinel.engine.event_bus import EventBus, normalize
from sentinel.engine.schema import Event, utc_timestamp


@pytest.fixture()
def bus(tmp_path):
    b = EventBus(db_path=tmp_path / "events.db")
    yield b
    b.close()


def _ev(**kw):
    base = {"timestamp": utc_timestamp(), "source": "fs", "event_type": "file_write"}
    base.update(kw)
    return Event(**base)


def test_normalize_fills_timestamp_and_sweeps_unknown_into_extra():
    raw = {
        "source": "network",
        "event_type": "connection",
        "pid": 7,
        "remote_ip": "1.2.3.4",  # not a schema field -> swept into extra
        "dest_port": 443,
    }
    ev = normalize(raw)
    assert ev.timestamp  # filled automatically
    assert ev.extra["remote_ip"] == "1.2.3.4"
    assert ev.extra["dest_port"] == 443


def test_normalize_keeps_existing_extra_and_timestamp():
    raw = {
        "timestamp": "2026-07-16T10:22:31.000Z",
        "source": "eventlog",
        "event_type": "login_failed",
        "extra": {"source_user": "admin"},
    }
    ev = normalize(raw)
    assert ev.timestamp == "2026-07-16T10:22:31.000Z"
    assert ev.extra == {"source_user": "admin"}


def test_publish_persists_schema_shaped_row(bus):
    ev = _ev(
        pid=4821,
        parent_pid=3300,
        image_path="C:\\x\\y.exe",
        command_line="y --flag",
        hash_sha256="deadbeef",
        extra={"entropy": 7.8},
    )
    rowid = bus.publish(ev)
    assert rowid > 0
    assert bus.count() == 1
    rows = bus.recent()
    assert len(rows) == 1
    r = rows[0]
    # Every documented schema column is present and correct.
    assert r["source"] == "fs"
    assert r["event_type"] == "file_write"
    assert r["pid"] == 4821
    assert r["parent_pid"] == 3300
    assert r["image_path"] == "C:\\x\\y.exe"
    assert r["command_line"] == "y --flag"
    assert r["hash_sha256"] == "deadbeef"
    assert r["extra"] == {"entropy": 7.8}


def test_normal_event_delivered_to_queue(bus):
    ev = _ev(pid=10)
    bus.publish(ev)
    got = bus.consume(timeout=1.0)
    assert isinstance(got, Event)
    assert got.pid == 10


def test_high_volume_event_is_batched_not_immediately_delivered(bus):
    # image_load is a high-volume type -> buffered until batch threshold.
    ev = _ev(source="etw_process", event_type="image_load", pid=11)
    bus.publish(ev)
    got = bus.consume(timeout=0.2)
    assert got is None  # not delivered yet (still in batch)
    bus.flush()
    batch = bus.consume(timeout=1.0)
    assert isinstance(batch, list)
    assert len(batch) == 1
    assert batch[0].event_type == "image_load"


def test_high_volume_batch_auto_flushes_at_threshold(bus):
    bus._high_volume_batch = 3
    for i in range(3):
        bus.publish(_ev(source="etw_process", event_type="registry_write", pid=i))
    batch = bus.consume(timeout=1.0)
    assert isinstance(batch, list)
    assert len(batch) == 3
    assert {e.pid for e in batch} == {0, 1, 2}


def test_publish_rejects_non_event(bus):
    with pytest.raises(TypeError):
        bus.publish({"source": "fs", "event_type": "file_write"})  # type: ignore[arg-type]


def test_concurrent_publish_is_thread_safe(bus):
    # architecture.md Section 8: sensors run in their own threads.
    n_threads, per_thread = 4, 50

    def worker():
        for i in range(per_thread):
            bus.publish(_ev(pid=i))

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert bus.count() == n_threads * per_thread


def test_recent_orders_newest_first(bus):
    for i in range(5):
        bus.publish(_ev(pid=i))
    rows = bus.recent(limit=3)
    # newest first -> last published pid appears first
    assert rows[0]["pid"] == 4
    assert len(rows) == 3


def test_count_with_where_filter(bus):
    bus.publish(_ev(source="fs", event_type="file_write"))
    bus.publish(_ev(source="network", event_type="connection"))
    assert bus.count(where="source=?", params=("fs",)) == 1
    assert bus.count(where="source=?", params=("network",)) == 1
