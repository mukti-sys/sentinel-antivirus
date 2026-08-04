"""Unit tests for engine/schema.py — the shared event dataclass.

Verifies the schema matches architecture.md Section 7: required fields,
source/event_type validation, `extra` dict, round-trip dict/JSON, and the
ISO-8601 UTC timestamp helper.
"""
import json
from datetime import datetime, timezone

from sentinel.engine.schema import (
    EVENT_TYPES,
    SOURCES,
    Event,
    utc_timestamp,
)


def test_canonical_sources_match_docs():
    # architecture.md Section 7 lists these four sources.
    assert SOURCES == {"etw_process", "fs", "network", "eventlog"}


def test_canonical_event_types_include_docs():
    # The four documented event types must be present.
    for required in ("process_create", "file_write", "connection", "login_failed"):
        assert required in EVENT_TYPES


def test_minimal_event_with_required_fields():
    ev = Event(timestamp="2026-07-16T10:22:31.000Z", source="fs", event_type="file_write")
    assert ev.source == "fs"
    assert ev.event_type == "file_write"
    assert ev.pid is None and ev.parent_pid is None
    assert ev.extra == {}


def test_full_event_with_extra_payload():
    # Mirrors the architecture.md Section 7 example shape.
    ev = Event(
        timestamp="2026-07-16T10:22:31.000Z",
        source="etw_process",
        event_type="process_create",
        pid=4821,
        parent_pid=3300,
        image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell -enc ...",
        hash_sha256="abc123",
        extra={"entropy": 7.8, "remote_ip": "1.2.3.4", "dest_port": 3333},
    )
    assert ev.extra["entropy"] == 7.8
    assert ev.extra["dest_port"] == 3333


def test_invalid_source_rejected():
    try:
        Event(timestamp="t", source="bogus", event_type="file_write")
    except ValueError:
        return
    raise AssertionError("invalid source should raise ValueError")


def test_invalid_event_type_rejected():
    try:
        Event(timestamp="t", source="fs", event_type="bogus")
    except ValueError:
        return
    raise AssertionError("invalid event_type should raise ValueError")


def test_extra_must_be_dict():
    try:
        Event(timestamp="t", source="fs", event_type="file_write", extra=["not", "a", "dict"])
    except TypeError:
        return
    raise AssertionError("non-dict extra should raise TypeError")


def test_roundtrip_dict():
    ev = Event(
        timestamp="2026-07-16T10:22:31.000Z",
        source="network",
        event_type="connection",
        pid=9,
        extra={"remote_ip": "8.8.8.8", "dest_port": 53},
    )
    rt = Event.from_dict(ev.to_dict())
    assert rt == ev


def test_roundtrip_json():
    ev = Event(
        timestamp="2026-07-16T10:22:31.000Z",
        source="eventlog",
        event_type="login_failed",
        extra={"source_user": "admin", "failure_reason": "badpw"},
    )
    rt = Event.from_dict(json.loads(ev.to_json()))
    assert rt == ev


def test_from_dict_ignores_unknown_keys():
    ev = Event.from_dict(
        {
            "timestamp": "t",
            "source": "fs",
            "event_type": "file_write",
            "unknown_field": "should be dropped",
        }
    )
    assert ev.source == "fs"
    # unknown key must not leak onto the dataclass
    assert not hasattr(ev, "unknown_field")


def test_event_is_frozen():
    ev = Event(timestamp="t", source="fs", event_type="file_write")
    try:
        ev.pid = 5  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("Event should be frozen/immutable")


def test_utc_timestamp_format():
    ts = utc_timestamp(datetime(2026, 7, 16, 10, 22, 31, 123000, tzinfo=timezone.utc))
    # Documented format: ...T10:22:31.123Z
    assert ts == "2026-07-16T10:22:31.123Z"
    assert ts.endswith("Z")


def test_utc_timestamp_default_is_now_utc():
    ts = utc_timestamp()
    assert ts.endswith("Z")
    # Sanity: year prefix is current-era
    assert ts.startswith("20")
