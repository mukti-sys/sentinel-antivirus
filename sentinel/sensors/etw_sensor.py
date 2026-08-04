"""ETW (Event Tracing for Windows) sensor.

Implements architecture.md Section 5.1 `sensors/etw_sensor.py`: captures
process create/exit, image loads, and registry writes via ETW, emitting
events in the shared schema (architecture.md Section 7) into the event bus.

ETW providers used (architecture.md Section 5.1; GUIDs verified via
`logman query providers` on the target build):
- Microsoft-Windows-Kernel-Process  — process create/exit (Event IDs 1,2)
                                       AND image loads (Event ID 5, under
                                       the WINEVENT_KEYWORD_IMAGE keyword).
                                       No separate Kernel-Image provider is
                                       registered on this build.
- Microsoft-Windows-Kernel-Registry — registry writes

PRIVILEGES: ETW consumption requires Administrator rights (plan.md Section 9
FAQ). `EtwSensor.start()` will raise a clear error if not elevated.

DESIGN NOTES (anti-Defender-FP, per architecture.md Section 5.3):
This sensor *captures* image-load events (source=etw_process,
event_type=image_load) but does NOT score them. The layered DLL-handling
logic (self-load vs cross-process, reflective vs LoadLibrary, unsigned≠guilty,
reputation cache, publisher/hash allowlist) lives in engine/scoring.py in
Phase 2. Here we faithfully record what ETW reports and nothing more — no
single weak signal is treated as a verdict at capture time.

We use the `etw` package (pywintrace) programmatically: build an `ETW`
session with a list of `ProviderInfo` and our own `event_callback`. We do
NOT use the library's built-in `on_event_callback` (it imports
`collections.Mapping`, removed in Python 3.10+; we're on 3.12).
"""
from __future__ import annotations

import logging
import threading
from typing import Any

from sentinel.engine.event_bus import EventBus
from sentinel.engine.schema import Event, utc_timestamp

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ETW provider GUIDs — verified against `logman query providers` on this
# machine (2026-07-28). Do NOT change from memory; ETW GUIDs must be exact.
# ---------------------------------------------------------------------------
# Microsoft-Windows-Kernel-Process — process create/exit AND image loads.
# The separate Microsoft-Windows-Kernel-Image provider is NOT registered on
# this build; image loads are emitted by Kernel-Process under the
# WINEVENT_KEYWORD_IMAGE keyword (0x40), event ID 5.
_PROVIDER_KERNEL_PROCESS = (
    "Microsoft-Windows-Kernel-Process",
    "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}",
)
# Microsoft-Windows-Kernel-Registry — registry writes.
_PROVIDER_KERNEL_REGISTRY = (
    "Microsoft-Windows-Kernel-Registry",
    "{70eb4f03-c1de-4f73-a051-33d13d5413bd}",
)

# Kernel-Process keywords (from `logman query providers`): enable PROCESS
# (0x10) and IMAGE (0x40) so we get process create/exit and image loads.
_KERNEL_PROCESS_KEYWORDS = 0x10 | 0x40

# Kernel-Process event IDs (Microsoft docs):
#   1 = ProcessStart, 2 = ProcessStop, 3 = ThreadStart, 4 = ThreadStop,
#   5 = ImageLoad (under WINEVENT_KEYWORD_IMAGE)
_PROCESS_START_ID = 1
_PROCESS_STOP_ID = 2
_PROCESS_IMAGE_LOAD_ID = 5

# Classification keyed by provider GUID (lowercased, since pywintrace surfaces
# the provider GUID as a str(GUID) that may vary in case). This is the robust
# key — pywintrace does NOT put a human provider name on the parsed `out`
# dict, but the provider GUID is reliably at out['EventHeader']['ProviderId'].
_PROVIDER_GUID_TO_EVENT_TYPES = {
    _PROVIDER_KERNEL_PROCESS[1].lower(): {
        _PROCESS_START_ID: "process_create",
        _PROCESS_STOP_ID: "process_exit",
        _PROCESS_IMAGE_LOAD_ID: "image_load",
    },
    _PROVIDER_KERNEL_REGISTRY[1].lower(): {  # any event id -> registry_write
        None: "registry_write",
    },
}


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        # ETW may surface numbers as hex strings or floats; try hex.
        try:
            return int(str(value), 0)
        except (TypeError, ValueError):
            return None


def _extract_provider_guid(event: dict) -> str | None:
    """Pull the provider GUID string from a parsed ETW `out` dict.

    pywintrace puts it at out['EventHeader']['ProviderId'] (a str(GUID),
    case may vary). Some fallback keys are checked for robustness.
    """
    header = event.get("EventHeader")
    if isinstance(header, dict):
        pid = header.get("ProviderId")
        if pid:
            return str(pid)
    for key in ("ProviderId", "Provider Name", "provider_name", "ProviderGuid"):
        if key in event and event[key]:
            return str(event[key])
    return None


def _extract_task_name(event: dict) -> str | None:
    tn = event.get("Task Name")
    return str(tn).upper() if tn else None


def _classify(provider_guid: str | None, event_id: int | None,
              task_name: str | None = None) -> str | None:
    """Map (provider_guid, event_id) -> shared-schema event_type.

    First try the GUID-keyed table. As a safety net, also accept a task-name
    hint (pywintrace uppercases it, e.g. "PROCESSSTART") when the GUID table
    has no entry for the id."""
    if provider_guid:
        table = _PROVIDER_GUID_TO_EVENT_TYPES.get(provider_guid.lower())
        if table is not None:
            if event_id in table:
                return table[event_id]
            if None in table:  # whole-provider single type (e.g. registry_write)
                return table[None]
    # Fallback by task name for the kernel-process provider.
    if task_name:
        if task_name.startswith("PROCESSSTART") or task_name == "PROCESSSTART":
            return "process_create"
        if task_name.startswith("PROCESSSTOP") or task_name == "PROCESSSTOP":
            return "process_exit"
        if task_name.startswith("IMAGELOAD") or task_name == "IMAGELOAD":
            return "image_load"
    return None


def normalize_etw_event(event_id: int | None, event: dict) -> Event | None:
    """Convert a parsed ETW `out` dict into a shared-schema `Event`.

    `event` is the dict pywintrace hands to the callback: it has an
    `EventHeader` sub-dict (ProcessId, ThreadId, ProviderId, EventDescriptor),
    a `Task Name` (uppercased), and the flattened payload fields at top level
    (e.g. ImageName, CommandLine). Returns None if the event can't be
    classified so the sensor can skip it without raising. Pure/testable.
    """
    provider_guid = _extract_provider_guid(event)
    task_name = _extract_task_name(event)
    event_type = _classify(provider_guid, event_id, task_name)
    if event_type is None:
        return None

    header = event.get("EventHeader") if isinstance(event.get("EventHeader"), dict) else {}

    def get(*keys):
        for k in keys:
            if k in event and event[k] not in (None, ""):
                return event[k]
        return None

    image_path = get("ImageName", "Image", "ImagePath", "FileName", "FullPathName", "image_path")
    command_line = get("CommandLine", "command_line", "CommandLineKey", "CmdLine")
    # ProcessId is in the EventHeader; payload sometimes also has ProcessID
    # (e.g. the *newly created* process for ProcessStart events).
    pid = _coerce_int(get("ProcessID", "ProcessId", "pid", "PID"))
    if pid is None:
        pid = _coerce_int(header.get("ProcessId"))
    parent_pid = _coerce_int(get("ParentID", "ParentProcessId", "ParentProcessID", "parent_pid"))

    # Keep everything else in `extra` so no signal is lost (scoring.py reads
    # what it needs from extra in Phase 2). EventHeader is kept nested as-is.
    reserved = {
        "ImageName", "Image", "ImagePath", "FileName", "FullPathName", "image_path",
        "CommandLine", "command_line", "CommandLineKey", "CmdLine",
        "ProcessID", "ProcessId", "pid", "PID",
        "ParentID", "ParentProcessId", "ParentProcessID", "parent_pid",
        "ProviderId", "Provider Name", "provider_name", "ProviderGuid",
        "Task Name", "EventID", "event_id", "EventHeader",
    }
    extra = {k: v for k, v in event.items()
             if k not in reserved and v not in (None, "")}
    extra["etw_event_id"] = event_id
    extra["provider_guid"] = provider_guid
    extra["task_name"] = task_name
    if header.get("ProcessId") is not None:
        extra["header_process_id"] = _coerce_int(header.get("ProcessId"))

    return Event(
        timestamp=utc_timestamp(),
        source="etw_process",
        event_type=event_type,
        pid=pid,
        parent_pid=parent_pid,
        image_path=str(image_path) if image_path is not None else None,
        command_line=str(command_line) if command_line is not None else None,
        extra=extra,
    )


def is_admin() -> bool:
    """True if the current process token is elevated. Used to give a clear
    error before attempting an ETW session (plan.md FAQ: ETW needs admin)."""
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover - non-Windows or missing shell32
        return False


class EtwSensor:
    """Runs a kernel ETW capture session and publishes normalized events.

    Each provider is enabled in its own `ProviderInfo`; one `ETW` session
    consumes them all. The callback (our own, not the broken built-in) runs
    in pywintrace's consumer thread and publishes to the thread-safe bus.
    """

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._session = None
        self._lock = threading.Lock()
        self._running = False

    # ------------------------------------------------------------------ #
    def _on_event(self, event_tufo, logfile=None):
        """Our ETW callback. Receives (event_id, event_dict) from pywintrace.

        Runs on the consumer thread; must stay fast and never raise (an
        exception here would tear down the consumer). We classify + publish;
        anything unclassifiable is skipped.
        """
        try:
            event_id, event = event_tufo
            norm = normalize_etw_event(event_id, event)
            if norm is not None:
                self._bus.publish(norm)
        except Exception:
            logger.exception("etw_sensor: callback error (event skipped)")

    # ------------------------------------------------------------------ #
    def _build_providers(self):
        from etw import GUID, ProviderInfo

        # pywintrace's EnableTraceEx2 call passes `ct.byref(provider.guid)`,
        # so `guid` must be a ctypes GUID instance — a string GUID raises
        # "byref() argument must be a ctypes instance". Convert here.
        return [
            # Kernel-Process with PROCESS + IMAGE keywords -> process
            # create/exit and image loads from one provider (no separate
            # Kernel-Image provider is registered on this build).
            ProviderInfo(
                _PROVIDER_KERNEL_PROCESS[0],
                GUID(_PROVIDER_KERNEL_PROCESS[1]),
                any_keywords=_KERNEL_PROCESS_KEYWORDS,
            ),
            ProviderInfo(
                _PROVIDER_KERNEL_REGISTRY[0],
                GUID(_PROVIDER_KERNEL_REGISTRY[1]),
            ),
        ]

    def start(self) -> None:
        """Start the ETW capture session. Requires admin privileges."""
        if self._running:
            return
        if not is_admin():
            raise PermissionError(
                "ETW capture requires Administrator privileges. "
                "Relaunch the terminal/service as Administrator (plan.md FAQ)."
            )
        # Lazy import: keep the module importable even if the binding is
        # broken on a given Windows build (plan.md FAQ / pywintrace issues).
        from etw import ETW

        # Use a UNIQUE session name per run. ETW sessions persist after the
        # creating process exits (until stopped or reboot). If a previous run
        # left a same-named session behind, pywintrace's ETW.start() swallows
        # the resulting ERROR_ALREADY_EXISTS (ignore_exists_error=True) and
        # the consumer then attaches to the stale session — producing zero
        # events with no error and a live thread. A unique name avoids that
        # entire failure mode.
        import time

        session_name = f"sentinel-etw-{int(time.time() * 1000) % 10_000_000}"
        with self._lock:
            self._session = ETW(
                session_name=session_name,
                providers=self._build_providers(),
                event_callback=self._on_event,
                ignore_exists_error=False,
            )
            self._session.start()
            self._running = True
        logger.info(
            "etw_sensor: ETW session %r started (providers: process/image/registry)",
            session_name,
        )

    def stop(self) -> None:
        with self._lock:
            if self._session is not None:
                try:
                    self._session.stop()
                except Exception:
                    logger.exception("etw_sensor: error stopping session")
                self._session = None
            self._running = False
        logger.info("etw_sensor: ETW session stopped")

    @property
    def running(self) -> bool:
        return self._running


# ---------------------------------------------------------------------------
# Config loader (kept from the Phase 0 stub; used by standalone run()).
# ---------------------------------------------------------------------------
from pathlib import Path

_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
_DEFAULT_SETTINGS = _CONFIG_DIR / "settings.yaml"


def load_settings(path: str | Path = _DEFAULT_SETTINGS) -> dict[str, Any]:
    """Load and return the YAML settings (plan.md sample config)."""
    import yaml

    settings_path = Path(path)
    if not settings_path.exists():
        raise FileNotFoundError(f"Settings file not found: {settings_path}")
    with settings_path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def run() -> None:
    """Standalone run.

    If elevated, starts a live ETW capture for ~30s and reports captured
    events (Phase 1 live DoD). If NOT elevated, logs that admin is required
    and exits 0 — this preserves the Phase 0 DoD ("runs without error") and
    documents the prerequisite rather than crashing.
    """
    settings = load_settings()
    if not is_admin():
        logger.warning(
            "etw_sensor: not running as Administrator — live ETW capture "
            "skipped. ETW requires elevated privileges (plan.md FAQ). "
            "Phase 0 DoD (runs without error) still satisfied; run an "
            "elevated terminal for the Phase 1 live DoD."
        )
        print(
            "sentinel.sensors.etw_sensor: not elevated — live capture skipped "
            "(ETW needs admin). Scaffold OK; rerun as Administrator for live events."
        )
        return

    bus = EventBus()
    sensor = EtwSensor(bus)
    sensor.start()
    print("etw_sensor: live capture running for 30s. Launch an app to see events.")
    import time

    time.sleep(30)
    sensor.stop()
    rows = bus.recent(limit=40, where="source=?", params=("etw_process",))
    print(f"etw_sensor: {len(rows)} ETW event(s) captured:")
    for r in rows:
        e = r.get("extra", {})
        print("  ", r["timestamp"], r["event_type"], "pid=", r["pid"],
              r.get("image_path") or "", e.get("provider", ""))
    bus.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        run()
    except Exception as exc:  # pragma: no cover - surface any failure clearly
        logger.exception("ETW sensor failed to start")
        raise SystemExit(1)
