"""Tests for sensors/etw_sensor.py — the pure normalization layer.

These tests use the REAL dict shape that pywintrace hands to the event
callback (verified by reading the etw package source):
  out = {
    'EventHeader': { 'ProcessId': int, 'ProviderId': '<guid str>',
                     'ThreadId': int, 'EventDescriptor': {'Id': ...}, ... },
    'Task Name':   'PROCESSSTART' (uppercased),
    <payload field>: <value>,   # flattened, e.g. ImageName, CommandLine
    ...
  }
The callback receives (event_id, out).

The live ETW session requires Administrator privileges, so the *capture*
path is verified separately on an elevated terminal (Phase 1 DoD). These
tests exercise the deterministic translation of parsed ETW event dicts into
shared-schema Events — the part that must be exactly right before live
capture is trusted.
"""
import pytest

from sentinel.engine.schema import Event
from sentinel.sensors.etw_sensor import (
    _coerce_int,
    is_admin,
    normalize_etw_event,
)

# Provider GUIDs exactly as the sensor registers them (lowercased for the
# classification table; pywintrace may surface them with varied case).
_PROC_GUID = "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"
_REG_GUID = "{70eb4f03-c1de-4f73-a051-33d13d5413bd}"


def _proc_start_out():
    # Real pywintrace shape for a Kernel-Process ProcessStart (id 1).
    return {
        "EventHeader": {
            "ProcessId": 3300,            # the *parent* (emitting) process
            "ThreadId": 4000,
            "ProviderId": _PROC_GUID,
            "EventDescriptor": {"Id": 1, "Task": 1},
        },
        "Task Name": "PROCESSSTART",
        "ProcessID": 4821,                # flattened payload: the NEW process
        "ParentID": 3300,
        "ImageName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell -nop",
        "SessionID": 1,
    }


def test_process_start_normalized_to_process_create():
    norm = normalize_etw_event(1, _proc_start_out())
    assert isinstance(norm, Event)
    assert norm.source == "etw_process"
    assert norm.event_type == "process_create"
    # Payload ProcessID (the new process) takes precedence over header.ProcessId.
    assert norm.pid == 4821
    assert norm.parent_pid == 3300
    assert norm.image_path.endswith("powershell.exe")
    assert norm.command_line == "powershell -nop"
    # Non-schema fields land in extra (lossless).
    assert norm.extra["SessionID"] == 1
    assert norm.extra["etw_event_id"] == 1
    assert norm.extra["provider_guid"] == _PROC_GUID
    assert norm.extra["task_name"] == "PROCESSSTART"


def test_process_stop_normalized_to_process_exit():
    out = {
        "EventHeader": {"ProcessId": 4821, "ProviderId": _PROC_GUID},
        "Task Name": "PROCESSSTOP",
        "ImageName": "C:\\x\\app.exe",
    }
    norm = normalize_etw_event(2, out)
    assert norm.event_type == "process_exit"
    # No payload ProcessID -> falls back to header.ProcessId.
    assert norm.pid == 4821


def test_image_load_id5_normalized_to_image_load():
    out = {
        "EventHeader": {"ProcessId": 4821, "ProviderId": _PROC_GUID},
        "Task Name": "IMAGELOAD",
        "ImageName": "C:\\Windows\\System32\\KERNELBASE.dll",
    }
    norm = normalize_etw_event(5, out)
    assert norm.event_type == "image_load"
    assert norm.image_path.endswith("KERNELBASE.dll")


def test_image_unload_id6_deliberately_unclassified():
    # Event id 6 = IMAGEUNLOAD. Unloads aren't useful for detection, so the
    # sensor intentionally returns None (observed live in the ETW diagnostic).
    out = {
        "EventHeader": {"ProcessId": 4821, "ProviderId": _PROC_GUID},
        "Task Name": "IMAGEUNLOAD",
        "ImageName": "C:\\Windows\\System32\\KERNELBASE.dll",
        "ProcessID": 4821,
    }
    assert normalize_etw_event(6, out) is None


def test_registry_provider_normalized_to_registry_write():
    out = {
        "EventHeader": {"ProcessId": 100, "ProviderId": _REG_GUID},
        "Task Name": "REGISTRY",
        "KeyName": "\\REGISTRY\\MACHINE\\SOFTWARE\\X",
    }
    norm = normalize_etw_event(1, out)
    assert norm.event_type == "registry_write"
    assert norm.extra["KeyName"].endswith("SOFTWARE\\X")


def test_provider_guid_case_insensitive():
    # pywintrace may surface the GUID with different casing; classification
    # must be case-insensitive.
    out = {
        "EventHeader": {"ProcessId": 1, "ProviderId": _PROC_GUID.upper()},
        "Task Name": "PROCESSSTART",
        "ImageName": "C:\\x.exe",
    }
    norm = normalize_etw_event(1, out)
    assert norm.event_type == "process_create"


def test_task_name_fallback_classifies_when_guid_unknown():
    # If the GUID table ever misses, the task-name fallback still classifies
    # the common kernel-process events.
    out = {
        "EventHeader": {"ProcessId": 1, "ProviderId": "{some-unknown-guid}"},
        "Task Name": "PROCESSSTART",
        "ImageName": "C:\\x.exe",
    }
    norm = normalize_etw_event(1, out)
    assert norm.event_type == "process_create"


def test_unknown_provider_and_task_returns_none():
    out = {
        "EventHeader": {"ProcessId": 1, "ProviderId": "{some-other-guid}"},
        "Task Name": "THREADSTART",
    }
    assert normalize_etw_event(3, out) is None


def test_unknown_event_id_for_process_provider_returns_none():
    # ThreadStart (3) is enabled by the PROCESS keyword but not one of our
    # mapped types and has no task-name fallback -> skipped, not an error.
    out = {
        "EventHeader": {"ProcessId": 1, "ProviderId": _PROC_GUID},
        "Task Name": "THREADSTART",
    }
    assert normalize_etw_event(3, out) is None


def test_coerce_int_handles_dec_hex_and_empty():
    assert _coerce_int(5) == 5
    assert _coerce_int("4821") == 4821
    assert _coerce_int("0x12d5") == 4821
    assert _coerce_int("") is None
    assert _coerce_int(None) is None


def test_missing_optional_fields_are_none():
    out = {"EventHeader": {"ProviderId": _PROC_GUID}, "Task Name": "PROCESSSTART"}
    norm = normalize_etw_event(1, out)
    assert norm.pid is None
    assert norm.parent_pid is None
    assert norm.image_path is None
    assert norm.command_line is None


def test_is_admin_returns_bool():
    # On this non-elevated shell it will be False; on an elevated one True.
    assert isinstance(is_admin(), bool)


@pytest.mark.skipif(not is_admin(), reason="requires elevated privileges for live ETW")
def test_live_etw_capture(tmp_path):
    pytest.importorskip("etw", reason="etw package not installed (optional)")
    """Live DoD check: with admin, a real ETW session captures a process
    launch. Runs only when the test suite is executed as Administrator."""
    import subprocess
    import time

    from sentinel.engine.event_bus import EventBus
    from sentinel.sensors.etw_sensor import EtwSensor

    bus = EventBus(db_path=tmp_path / "events.db")
    sensor = EtwSensor(bus)
    sensor.start()
    try:
        for _ in range(3):
            subprocess.Popen(["cmd.exe", "/c", "exit"])
            time.sleep(0.3)
        deadline = time.time() + 8
        rows = []
        while time.time() < deadline:
            rows = bus.recent(limit=50, where="source=?", params=("etw_process",))
            if any(r["event_type"] == "process_create" for r in rows):
                break
            time.sleep(0.2)
    finally:
        sensor.stop()
        bus.close()
    assert any(r["event_type"] == "process_create" for r in rows), (
        "no process_create event captured from live ETW"
    )
