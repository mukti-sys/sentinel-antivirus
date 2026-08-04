"""Focused ETW diagnostic — run ELEVATED:

    .venv\\Scripts\\python.exe -m sentinel.tests.etw_diag

Tries BOTH ETW mechanisms pywintrace supports and reports which one
actually yields process events:
  A) user-named session + EnableTraceEx2 on Kernel-Process provider GUIDs
  B) "NT Kernel Logger" session + EnableFlags (PROCESS|THREAD|IMAGE_LOAD|REGISTRY)

For each: session start result, consumer thread liveness, how many raw
events reached the callback, and how many matched our classifier. No real
malware — only launches `cmd /c exit`.
"""
from __future__ import annotations

import subprocess
import time

from sentinel.sensors.etw_sensor import (
    _PROVIDER_KERNEL_PROCESS,
    _PROVIDER_KERNEL_REGISTRY,
    is_admin,
    normalize_etw_event,
)

# EnableFlags for the NT Kernel Logger (from etw.evntrace constants).
ENABLEFLAGS = 0x00000001 | 0x00000002 | 0x00000004 | 0x00020000  # PROCESS|THREAD|IMAGE_LOAD|REGISTRY


class _Counter:
    def __init__(self, label):
        self.label = label
        self.raw = 0
        self.classified = 0
        self.unclassified = []

    def on_event(self, tufo, logfile=None):
        self.raw += 1
        event_id, event = tufo
        if normalize_etw_event(event_id, event) is not None:
            self.classified += 1
        elif len(self.unclassified) < 4:
            self.unclassified.append(
                (event_id, event.get("Task Name"),
                 event.get("EventHeader", {}).get("ProviderId"),
                 [k for k in event.keys() if k != "EventHeader"])
            )


def _run_path(label, providers, session_name):
    from etw import ETW

    print(f"\n--- Path {label}: session_name={session_name!r} ---")
    counter = _Counter(label)
    session = ETW(session_name=session_name, providers=providers,
                  event_callback=counter.on_event)
    try:
        session.start()
        print(f"  session.start(): OK")
    except Exception as exc:
        print(f"  session.start(): RAISED {exc!r}")
        return False

    consumer = session.consumer
    print(f"  consumer thread alive after start: "
          f"{consumer.process_thread.is_alive() if consumer.process_thread else 'n/a'}")

    for _ in range(5):
        subprocess.Popen(["cmd.exe", "/c", "exit"])
        time.sleep(0.3)

    deadline = time.time() + 8
    while time.time() < deadline and counter.raw == 0:
        time.sleep(0.3)
    # brief extra settle
    time.sleep(1.0)

    print(f"  raw events to callback: {counter.raw}")
    print(f"  classified: {counter.classified}")
    for u in counter.unclassified:
        print(f"    unclassified: id={u[0]} task={u[1]!r} provider={u[2]!r} keys={u[3]}")
    try:
        session.stop()
    except Exception as exc:
        print(f"  session.stop(): RAISED {exc!r}")
    return counter.classified > 0


def main() -> int:
    if not is_admin():
        print("NOT ELEVATED — relaunch as Administrator, then:")
        print("  .venv\\Scripts\\python.exe -m sentinel.tests.etw_diag")
        return 2

    from etw import GUID, ProviderInfo

    # Path A: user-named session with EnableTraceEx2 on kernel provider GUIDs.
    providers_a = [
        ProviderInfo(_PROVIDER_KERNEL_PROCESS[0],
                     GUID(_PROVIDER_KERNEL_PROCESS[1]), any_keywords=0x50),
        ProviderInfo(_PROVIDER_KERNEL_REGISTRY[0],
                     GUID(_PROVIDER_KERNEL_REGISTRY[1])),
    ]
    ok_a = _run_path("A (EnableTraceEx2)", providers_a, "sentinel-diag-a")

    # Path B: NT Kernel Logger with EnableFlags.
    providers_b = [
        ProviderInfo(_PROVIDER_KERNEL_PROCESS[0],
                     GUID(_PROVIDER_KERNEL_PROCESS[1]), any_keywords=ENABLEFLAGS),
    ]
    ok_b = _run_path("B (NT Kernel Logger)", providers_b, "NT Kernel Logger")

    print("\n=== VERDICT ===")
    print(f"  Path A (EnableTraceEx2 user session): {'WORKS' if ok_a else 'no events'}")
    print(f"  Path B (NT Kernel Logger):            {'WORKS' if ok_b else 'no events'}")
    if ok_b and not ok_a:
        print("  -> Use the NT Kernel Logger path in the sensor.")
    elif ok_a:
        print("  -> The EnableTraceEx2 user session works; sensor is fine as-is.")
    elif not ok_a and not ok_b:
        print("  -> Neither path produced events. Deeper investigation needed.")
    return 0 if (ok_a or ok_b) else 1


if __name__ == "__main__":
    raise SystemExit(main())
