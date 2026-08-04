"""Shared event schema for all Sentinel sensors.

Implements architecture.md Section 7 ("Shared Event Schema"). Every sensor
emits this shape so the detection engines stay sensor-agnostic.

Schema fields (architecture.md Section 7):
    timestamp    : ISO-8601 UTC, e.g. "2026-07-16T10:22:31.000Z"
    source       : "etw_process" | "fs" | "network" | "eventlog"
    event_type   : "process_create" | "file_write" | "connection" | "login_failed"
                   (extensible; see EVENT_TYPES)
    pid          : int | None
    parent_pid   : int | None
    image_path   : str | None     (full path of the responsible process/image)
    command_line : str | None
    hash_sha256  : str | None     (of the image/file, when available)
    extra        : dict           (signal-specific fields, e.g. entropy,
                                   remote_ip, dest_port — see architecture.md)

The `extra` dict carries per-signal payloads. It is kept as a dict (not
flattened) so the schema stays stable while detectors can attach arbitrary
structured data, exactly as the documented schema shows.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# Canonical sources (architecture.md Section 7). `etw_process` is the
# documented spelling; image-load / registry-write events also originate from
# ETW and are distinguished by `event_type`.
SOURCES = frozenset({"etw_process", "fs", "network", "eventlog"})

# Canonical event types (architecture.md Section 7 + the event types each
# sensor in Section 5.1 captures). Extensible -- detectors may introduce more
# (e.g. process_exit, image_load, registry_write) without changing the schema.
# Phase 3 adds response audit events (process_suspended, file_quarantined).
EVENT_TYPES = frozenset(
    {
        "process_create",
        "process_exit",
        "image_load",
        "registry_write",
        "file_write",
        "connection",
        "login_failed",
        # Phase 3: response audit events (FR-11)
        "process_suspended",
        "file_quarantined",
    }
)


@dataclass(frozen=True)
class Event:
    """A single normalized telemetry event.

    Frozen so events can be safely shared across sensor/detector threads
    (architecture.md Section 8: sensors run in their own threads).
    """

    timestamp: str
    source: str
    event_type: str
    pid: int | None = None
    parent_pid: int | None = None
    image_path: str | None = None
    command_line: str | None = None
    hash_sha256: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Validate the two fields that define routing/sensor-agnostic matching.
        # `extra` must be a dict so per-signal payloads stay structured.
        if self.source not in SOURCES:
            raise ValueError(
                f"invalid source {self.source!r}; expected one of {sorted(SOURCES)}"
            )
        if self.event_type not in EVENT_TYPES:
            raise ValueError(
                f"invalid event_type {self.event_type!r}; "
                f"expected one of {sorted(EVENT_TYPES)}"
            )
        if not isinstance(self.extra, dict):
            raise TypeError("extra must be a dict of per-signal fields")

    def to_dict(self) -> dict[str, Any]:
        """Return the schema-shaped dict (architecture.md Section 7)."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize to a JSON string (for the structured-logs line format,
        architecture.md Section 9)."""
        return json.dumps(self.to_dict(), default=str, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        """Reconstruct an Event from a schema-shaped dict. Tolerant of
        missing optional fields; unknown keys are dropped (schema-stable)."""
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
        return cls(**{k: v for k, v in data.items() if k in known})


def utc_timestamp(dt: datetime | None = None) -> str:
    """Return an ISO-8601 UTC timestamp in the documented format
    ("2026-07-16T10:22:31.000Z"). Uses the provided datetime or, by default,
    the current UTC time."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{dt.microsecond // 1000:03d}Z"
    )
