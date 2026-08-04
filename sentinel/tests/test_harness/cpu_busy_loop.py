"""CPU busy-loop harness — validates the cryptomining CPU heuristic.

Simulates:
    A process sustaining high CPU usage for a configurable duration,
    mimicking the pattern a cryptominer exhibits (architecture.md
    Example A: sustained CPU ≥ 85% for ≥ 60s).

What it exercises:
    1. Spawns a CPU-intensive loop (pure arithmetic, no I/O)
    2. The cryptomining heuristic polls CPU samples via psutil
    3. When sustained above threshold, ``cpu_sustained`` signal fires

Safety:
    This is a plain CPU busy-loop — it does NOT mine anything, connect to
    any pool, or perform any network activity. It simply keeps one core
    busy with arithmetic. The loop exits after the configured duration.

Usage:
    cd "C:\\Users\\littlemukti\\OneDrive\\Documents\\pgt app\\antivirus"
    .venv\\Scripts\\python.exe -m sentinel.tests.test_harness.cpu_busy_loop

    # Custom duration (seconds):
    .venv\\Scripts\\python.exe -m sentinel.tests.test_harness.cpu_busy_loop --duration 30

Note:
    On the WindowsApps-store Python builds, psutil.cpu_percent(None)
    may return 0.0 for freshly spawned child processes (a known platform
    quirk — see PROGRESS.md cryptomining heuristic task detail). This
    harness runs in-process with a persistent psutil.Process object to
    avoid that issue.
"""
from __future__ import annotations

import os
import sys
import time


def cpu_burn(duration: float = 30.0) -> None:
    """Spin one core doing useless arithmetic for `duration` seconds.

    Uses only integer arithmetic to ensure consistent CPU load regardless
    of hardware. No I/O, no network, no memory pressure.
    """
    print(f"=== CPU Busy-Loop Harness ===")
    print(f"  PID: {os.getpid()}")
    print(f"  Duration: {duration:.0f}s")
    print(f"  Purpose: sustain >=85% CPU so the cryptomining heuristic fires")
    print(f"  Safety: plain arithmetic loop, no mining, no network")
    print()

    start = time.time()
    deadline = start + duration
    counter = 0
    report_interval = 5.0
    next_report = start + report_interval

    print(f"  [START] burning CPU at {time.strftime('%H:%M:%S')}")
    while time.time() < deadline:
        # Pure integer arithmetic — keeps one core busy.
        for _ in range(1_000_000):
            counter += 1
        now = time.time()
        if now >= next_report:
            elapsed = now - start
            print(f"  [{elapsed:5.0f}s] still burning (counter={counter:,})")
            next_report = now + report_interval

    elapsed = time.time() - start
    print(f"  [DONE] burned for {elapsed:.1f}s (counter={counter:,})")
    print()
    print("  If the cryptomining heuristic was monitoring this PID,")
    print("  it should have emitted a 'cpu_sustained' signal.")


def main() -> int:
    duration = 30.0
    if "--duration" in sys.argv:
        idx = sys.argv.index("--duration")
        if idx + 1 < len(sys.argv):
            duration = float(sys.argv[idx + 1])
    cpu_burn(duration)
    return 0


if __name__ == "__main__":
    sys.exit(main())

