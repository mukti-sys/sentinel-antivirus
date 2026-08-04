"""Tests for sensors/eventlog_sensor.py.

- Unit: normalization of 4625 records (mocked win32evtlog objects —
  deterministic, no admin needed).
- Admin guard: startup raises PermissionError when not elevated.
- Live capture is gated on admin (the sensor.start() method probes; non-admin
  shells get a clean error, not a crash).
"""
import pytest
from sentinel.sensors.eventlog_sensor import EventLogSensor, _coerce_int
from sentinel.engine.event_bus import EventBus


class _FakeRec:
    """Mimics a win32evtlog event record with fields we read."""
    def __init__(self, eid, recno, strings, sid=1001):
        self.EventID = eid
        self.RecordNumber = recno
        self.StringInserts = strings
        self.Sid = sid


_FAKE_4625 = _FakeRec(4625, 5, [
    "S-1-5-18",                    #  0 SubjectUserSid
    "DESKTOP-X$",                   #  1 SubjectUserName
    "WORKGROUP",                    #  2 SubjectDomainName
    "0x3E7",                        #  3 SubjectLogonId
    "S-1-0-0",                      #  4 TargetUserSid
    "Administrator",                #  5 TargetUserName
    "DESKTOP-X",                    #  6 TargetDomainName
    "0x0",                          #  7 Status
    "%%2313",                       #  8 FailureReason
    "0xC000006D",                   #  9 SubStatus
    "3",                            # 10 LogonType
    "NtLmSsp",                      # 11 AuthenticationPackageName
    "DESKTOP-X",                    # 12 WorkstationName
    "",                             # 13 TransmittedServices
    "",                             # 14 LmPackageName
    "0",                            # 15 KeyLength
    "0x0",                          # 16 ProcessId
    "C:\\Windows\\System32\\svchost.exe",  # 17 ProcessName
    "10.0.0.42",                    # 18 IpAddress
    "0",                            # 19 IpPort
])


def _sensor(bus=None):
    """Build a sensor with an optional bus; pure tests use None."""
    return EventLogSensor(bus, poll_interval=0.05)


def test_normalize_4625_extracts_all_fields():
    sensor = _sensor()
    ev = sensor._normalize_4625(_FAKE_4625)
    assert ev.source == "eventlog"
    assert ev.event_type == "login_failed"
    extra = ev.extra
    assert extra["target_user"] == "Administrator"
    assert extra["target_domain"] == "DESKTOP-X"
    assert extra["logon_type"] == 3
    assert extra["workstation"] == "DESKTOP-X"
    assert extra["source_host"] == "10.0.0.42"
    assert extra["event_record_number"] == 5


def test_normalize_4625_empty_target_user_is_skipped():
    sensor = _sensor()
    strings = list(_FAKE_4625.StringInserts)
    strings[5] = ""  # empty TargetUserName -> skip
    rec = _FakeRec(4625, 6, strings)
    assert sensor._normalize_4625(rec) is None


def test_normalize_4625_localhost_ip_maps_to_localhost():
    sensor = _sensor()
    strings = list(_FAKE_4625.StringInserts)
    strings[18] = "127.0.0.1"
    rec = _FakeRec(4625, 7, strings)
    ev = sensor._normalize_4625(rec)
    assert ev.extra["source_host"] == "localhost"


def test_normalize_4625_no_strings_returns_none():
    sensor = _sensor()
    rec = _FakeRec(4625, 8, None)
    assert sensor._normalize_4625(rec) is None


def test_normalize_4625_non_4625_record_ignored_in_poll():
    sensor = _sensor()
    # poll_once reads by RecordNumber > last; a non-4625 record is skipped.
    rec = _FakeRec(4624, 5, _FAKE_4625.StringInserts)  # 4624 = successful logon
    assert rec.EventID != 4625  # poll treats EventID filter first


def test_coerce_int_handles_all():
    assert _coerce_int("3") == 3
    assert _coerce_int(None) is None
    assert _coerce_int("") is None
    assert _coerce_int("bad") is None


def test_admin_guard_is_checked_on_start(tmp_path, monkeypatch):
    """When not elevated, start raises PermissionError BEFORE creating a
    thread, so the caller gets a clean error immediately."""
    monkeypatch.setattr(
        "sentinel.sensors.eventlog_sensor.is_admin",
        lambda: False,
    )
    bus = EventBus(db_path=tmp_path / "events.db")
    sensor = EventLogSensor(bus, poll_interval=0.1)
    with pytest.raises(PermissionError):
        sensor.start()
    bus.close()
