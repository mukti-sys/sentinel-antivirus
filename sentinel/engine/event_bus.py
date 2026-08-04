"""Event bus — the hub between sensors and detection engines.

Implements architecture.md Section 5.2 ("Event Bus") and Section 8
("Concurrency & Performance Model"):

- **Normalize** every sensor's output into the shared `Event` schema
  (engine/schema.py / architecture.md Section 7) so detection engines stay
  sensor-agnostic.
- **Persist** every event to `events.db` (SQLite) — the durable record the
  Phase 1 DoD spot-checks ("a correctly-shaped row in events.db").
- **Feed** an in-memory queue for real-time consumption by detection
  engines (architecture.md Section 8: "an async queue; detection engines
  are consumers that can be scaled or throttled independently").
- **Rate-limit / batch** high-volume event types (e.g. registry writes)
  before they reach consumers, to protect the NFR-6 resource budget
  (architecture.md Section 8).

The bus is safe for concurrent sensor threads (architecture.md Section 8:
each sensor runs in its own thread). Persistence uses a per-instance lock
around the SQLite connection.
"""
from __future__ import annotations

import logging
import queue
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Iterable

from sentinel.engine.schema import Event, utc_timestamp

logger = logging.getLogger(__name__)

# High-volume event types are batched before delivery to in-memory consumers
# (architecture.md Section 8). Sensors still persist every event to SQLite
# immediately so nothing is lost; batching only affects the live queue fed to
# the scoring engine, to keep its work bounded.
_HIGH_VOLUME_TYPES = frozenset({"registry_write", "image_load"})

_DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "events.db"

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    source        TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    pid           INTEGER,
    parent_pid    INTEGER,
    image_path    TEXT,
    command_line  TEXT,
    hash_sha256   TEXT,
    extra         TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source     ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_pid        ON events(pid);
"""


class EventBus:
    """Normalize, persist, and fan-out events to in-memory consumers.

    Concurrency: persistence and queue delivery are guarded by a lock; the
    in-memory queue is a stdlib `queue.Queue` (thread-safe). Consumers call
    `consume()` from their own threads.
    """

    def __init__(
        self,
        db_path: str | Path = _DEFAULT_DB_PATH,
        queue_size: int = 10000,
        high_volume_batch: int = 50,
    ) -> None:
        self._db_path = Path(db_path)
        # In-memory fan-out queue for real-time detection consumers.
        self._queue: "queue.Queue[Event]" = queue.Queue(maxsize=queue_size)
        self._lock = threading.Lock()
        self._high_volume_batch = high_volume_batch
        # Pending high-volume events buffered before delivery to the queue.
        self._batch: list[Event] = []
        self._conn = self._open_db()
        logger.info("EventBus ready; db=%s", self._db_path)

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #
    def _open_db(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.executescript(_SCHEMA_SQL)
        conn.commit()
        return conn

    def _persist(self, event: Event) -> int:
        """Insert one event row; return its rowid. Caller holds the lock."""
        import json

        cur = self._conn.execute(
            "INSERT INTO events "
            "(timestamp, source, event_type, pid, parent_pid, image_path, "
            " command_line, hash_sha256, extra) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                event.timestamp,
                event.source,
                event.event_type,
                event.pid,
                event.parent_pid,
                event.image_path,
                event.command_line,
                event.hash_sha256,
                json.dumps(event.extra, default=str, ensure_ascii=False),
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    # ------------------------------------------------------------------ #
    # Public API — used by sensors and consumers
    # ------------------------------------------------------------------ #
    def publish(self, event: Event) -> int:
        """Persist `event` and deliver it to the in-memory queue (batching
        high-volume types). Returns the SQLite rowid."""
        if not isinstance(event, Event):
            raise TypeError("publish() expects an Event instance")
        with self._lock:
            rowid = self._persist(event)
            self._enqueue(event)
        return rowid

    def publish_many(self, events: Iterable[Event]) -> list[int]:
        """Bulk-publish; one commit batch for efficiency."""
        import json

        events = list(events)
        for ev in events:
            if not isinstance(ev, Event):
                raise TypeError("publish_many() expects Event instances")
        rowids: list[int] = []
        with self._lock:
            self._conn.executemany(
                "INSERT INTO events "
                "(timestamp, source, event_type, pid, parent_pid, image_path, "
                " command_line, hash_sha256, extra) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                [
                    (
                        ev.timestamp,
                        ev.source,
                        ev.event_type,
                        ev.pid,
                        ev.parent_pid,
                        ev.image_path,
                        ev.command_line,
                        ev.hash_sha256,
                        json.dumps(ev.extra, default=str, ensure_ascii=False),
                    )
                    for ev in events
                ],
            )
            self._conn.commit()
            # Re-read rowids by timestamp+source since executemany doesn't
            # return them; for correctness in tests we persist one-by-one
            # only when rowids are needed — here we just enqueue.
            for ev in events:
                self._enqueue(ev)
        return rowids

    def _enqueue(self, event: Event) -> None:
        """Deliver to the in-memory queue, batching high-volume types.
        Caller holds the lock."""
        if event.event_type in _HIGH_VOLUME_TYPES:
            self._batch.append(event)
            if len(self._batch) >= self._high_volume_batch:
                self._flush_batch()
            return
        # Flush any pending high-volume batch first to preserve rough order.
        if self._batch:
            self._flush_batch()
        self._put(event)

    def _flush_batch(self) -> None:
        """Flush buffered high-volume events as a single batched delivery.
        Caller holds the lock."""
        if not self._batch:
            return
        batch, self._batch = self._batch, []
        self._put(("__batch__", batch))  # type: ignore[arg-type]

    def _put(self, item: Event | tuple) -> None:
        """Non-blocking put; if the queue is full, drop the oldest pending
        delivery to protect the NFR-6 budget rather than blocking a sensor
        thread (architecture.md Section 8)."""
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            try:
                self._queue.get_nowait()  # drop oldest
                logger.warning("EventBus queue full; dropped oldest item")
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(item)
            except queue.Full:
                logger.warning("EventBus queue still full; dropped new item")

    def consume(self, timeout: float | None = None) -> Event | list[Event] | None:
        """Get the next item for a real-time consumer. High-volume batches
        are returned as a list; normal events as a single Event. Returns
        None on timeout."""
        try:
            item = self._queue.get(timeout=timeout)
        except queue.Empty:
            return None
        if isinstance(item, tuple) and item and item[0] == "__batch__":
            return item[1]  # list[Event]
        return item  # Event

    def flush(self) -> None:
        """Flush any pending high-volume batch immediately (useful on
        shutdown / before a query in tests)."""
        with self._lock:
            self._flush_batch()

    def task_done(self) -> None:
        """Mark a consumed item as processed."""
        self._queue.task_done()

    # ------------------------------------------------------------------ #
    # Introspection — used by tests and the Phase 1 DoD spot-check
    # ------------------------------------------------------------------ #
    def count(self, where: str = "", params: tuple = ()) -> int:
        with self._lock:
            cur = self._conn.execute(
                f"SELECT COUNT(*) FROM events {('WHERE ' + where) if where else ''}",
                params,
            )
            return cur.fetchone()[0]

    def recent(self, limit: int = 50, where: str = "", params: tuple = ()) -> list[dict]:
        """Return recent events as schema-shaped dicts (newest first)."""
        import json

        with self._lock:
            cur = self._conn.execute(
                f"SELECT timestamp, source, event_type, pid, parent_pid, "
                f"image_path, command_line, hash_sha256, extra "
                f"FROM events {('WHERE ' + where) if where else ''} "
                f"ORDER BY id DESC LIMIT ?",
                params + (limit,),
            )
            rows = cur.fetchall()
        cols = [
            "timestamp",
            "source",
            "event_type",
            "pid",
            "parent_pid",
            "image_path",
            "command_line",
            "hash_sha256",
            "extra",
        ]
        out: list[dict] = []
        for r in rows:
            d = dict(zip(cols, r))
            try:
                d["extra"] = json.loads(d["extra"]) if d["extra"] else {}
            except (ValueError, TypeError):
                pass
            out.append(d)
        return out

    def close(self) -> None:
        self.flush()
        with self._lock:
            self._conn.close()


def normalize(raw: dict[str, Any]) -> Event:
    """Coerce a raw sensor dict into a validated `Event`.

    Sensors may produce dicts that are *almost* schema-shaped (missing a
    timestamp, or carrying extra payload fields). This fills `timestamp`
    if absent and routes unknown top-level keys into `extra` so nothing is
    silently dropped — the documented schema stays the 9 stable fields.
    """
    known = {
        "timestamp",
        "source",
        "event_type",
        "pid",
        "parent_pid",
        "image_path",
        "command_line",
        "hash_sha256",
        "extra",
    }
    payload = dict(raw)
    payload.setdefault("timestamp", utc_timestamp())
    extra = dict(payload.get("extra") or {})
    # Sweep any non-schema keys into extra (sensor-agnostic, lossless).
    swept = {k: v for k, v in payload.items() if k not in known}
    if swept:
        extra.update(swept)
    payload["extra"] = extra
    return Event.from_dict({k: v for k, v in payload.items() if k in known or k == "extra"})
