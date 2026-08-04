"""Security Event Log sensor — monitors Event ID 4625 (failed logon).

Implements architecture.md Section 5.1 (`eventlog_sensor.py`): captures
failed login attempts (Event ID 4625) from the Windows Security Event Log,
emitting shared-schema `login_failed` events into the event bus.

PHASE 1 SCOPE: capture only — one event per new 4625 log entry. The
brute-force heuristic (N failed logins within a window) lives in
`engine/scoring.py` in Phase 2. Here we faithfully record each individual
failure and nothing more.

PRIVILEGES: reading the Security Event Log requires Administrator rights
(plan.md Section 9 FAQ). `EventLogSensor.start()` raises PermissionError
if not elevated, with a clear message.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

from sentinel.engine.event_bus import EventBus
from sentinel.engine.schema import Event, utc_timestamp

logger = logging.getLogger(__name__)

_EVENT_ID_FAILED_LOGON = 4625

# Standard domain of the local machine for RDP / local login failures.
_LOCAL_HOST = "localhost"

# Kept at module level so it's easy to monkeypatch in tests and swap for a
# different elevation-check mechanism if needed.
from sentinel.sensors.etw_sensor import is_admin  # noqa: F401


def _coerce_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_str(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


class EventLogSensor:
    """Monitors the Security Event Log for Event ID 4625 (failed logon).

    Polls the log on a configurable interval via a daemon thread. Tracks the
    most recent event record number seen so each poll only processes new
    entries.
    """

    def __init__(self, bus: EventBus, poll_interval: float = 10.0) -> None:
        self._bus = bus
        self._poll_interval = poll_interval
        self._last_record_number = 0
        self._running = False
        self._thread: None | threading.Thread = None

    # ------------------------------------------------------------------ #
    def _open_event_log(self):
        if not is_admin():
            raise PermissionError(
                "Security Event Log access requires Administrator privileges. "
                "Relaunch the terminal/service as Administrator (plan.md FAQ)."
            )
        import win32con
        import win32evtlog

        return win32evtlog.OpenEventLog(None, "Security"), (
            win32con.EVENTLOG_FORWARDS_READ | win32con.EVENTLOG_SEQUENTIAL_READ
        )

    # ------------------------------------------------------------------ #
    def poll_once(self) -> list[Event]:
        """Read new 4625 events from the Security log since the last poll.

        Returns a list of normalized `login_failed` Events (empty if none).
        Caller must hold the lock or call this from the thread."""
        import win32evtlog

        events: list[Event] = []
        try:
            hand, flags = self._open_event_log()
        except PermissionError:
            logger.warning(
                "eventlog_sensor: not elevated — skipping Security log poll"
            )
            return events

        try:
            while True:
                records = win32evtlog.ReadEventLog(hand, flags, 0)
                if not records:
                    break
                for rec in records:
                    if rec.EventID != _EVENT_ID_FAILED_LOGON:
                        continue
                    if rec.RecordNumber <= self._last_record_number:
                        continue
                    self._last_record_number = rec.RecordNumber
                    norm = self._normalize_4625(rec)
                    if norm is not None:
                        events.append(norm)
        except win32evtlog.error as exc:
            # Empty log or no new records — expected between polls.
            if "no more events" in str(exc).lower():
                pass
            else:
                logger.exception("eventlog_sensor: win32evtlog error")
        except Exception:
            logger.exception("eventlog_sensor: unexpected error reading event log")
        finally:
            try:
                win32evtlog.CloseEventLog(hand)
            except Exception:
                pass
        return events

    def _normalize_4625(self, rec) -> Event | None:
        """Parse a single 4625 EventLogRecord into a login_failed Event.

        The standard 4625 format includes strings: SubjectUserSid,
        SubjectUserName, SubjectDomainName, SubjectLogonId, TargetUserSid,
        TargetUserName, TargetDomainName, Status, FailureReason,
        SubStatus, LogonType, AuthenticationPackageName, WorkstationName,
        TransmittedServices, LmPackageName, KeyLength, ProcessId,
        ProcessName, IpAddress, IpPort.
        We pull the fields needed for the brute-force heuristic (Phase 2):
        TargetUserName, IpAddress, LogonType.
        """
        try:
            strings = rec.StringInserts
        except AttributeError:
            return None

        if not strings or len(strings) < 18:
            return None  # malformed 4625 entry — skip

        # StringInserts indices (0-based) for a standard 4625 event:
        #   0  SubjectUserSid      1  SubjectUserName     2  SubjectDomainName
        #   3  SubjectLogonId       4  TargetUserSid       5  TargetUserName
        #   6  TargetDomainName     7  Status              8  FailureReason
        #   9  SubStatus           10  LogonType          11  AuthenticationPackageName
        #  12  WorkstationName     13  TransmittedServices 14 LmPackageName
        #  15  KeyLength           16  ProcessId          17  ProcessName
        #  18  IpAddress           19  IpPort
        target_user = _safe_str(strings[5]) if len(strings) > 5 else None
        target_domain = _safe_str(strings[6]) if len(strings) > 6 else None
        workstation = _safe_str(strings[12]) if len(strings) > 12 else None
        logon_type = _coerce_int(strings[10]) if len(strings) > 10 else None
        ip_address = _safe_str(strings[18]) if len(strings) > 18 else None

        # Only log meaningful failures — skip empty SYSTEM / anonymous
        if target_user is None:
            return None

        source = _LOCAL_HOST
        if ip_address and ip_address not in ("-", "::1", "127.0.0.1", "", " "):
            source = ip_address

        return Event(
            timestamp=utc_timestamp(),
            source="eventlog",
            event_type="login_failed",
            pid=rec.Sid if hasattr(rec, "Sid") else None,
            extra={
                "target_user": target_user,
                "target_domain": target_domain,
                "source_host": source,
                "logon_type": logon_type,
                "workstation": workstation,
                "event_record_number": rec.RecordNumber,
            },
        )

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self._running:
            return
        # Probe: are we elevated? Fail fast if not.
        self._open_event_log()  # raises PermissionError if not admin
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="sentinel-eventlog", daemon=True
        )
        self._thread.start()
        logger.info("eventlog_sensor: started (poll_interval=%ss)", self._poll_interval)

    def _loop(self) -> None:
        while self._running:
            try:
                for ev in self.poll_once():
                    self._bus.publish(ev)
            except Exception:
                logger.exception("eventlog_sensor: poll error")
            time.sleep(self._poll_interval)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=self._poll_interval + 2)
            self._thread = None
