"""Failed-login harness — validates the brute-force heuristic.

Simulates:
    A burst of failed login attempts from a single source within the
    configured time window, mimicking the pattern a brute-force attack
    exhibits (architecture.md: "detect brute-force / repeated failed
    login attempts").

What it exercises:
    1. Generates synthetic ``login_failed`` events (as if from eventlog sensor)
    2. The brute-force heuristic tracks per-source failure counts
    3. When the count crosses ``failed_login_count`` within the window,
       ``failed_login_burst`` signal fires

Safety:
    This harness does NOT actually fail any logins. It generates synthetic
    Event objects that look like eventlog sensor output. No passwords are
    attempted, no accounts are locked, and no Security Event Log entries
    are created.

Usage:
    cd "C:\\Users\\littlemukti\\OneDrive\\Documents\\pgt app\\antivirus"
    .venv\\Scripts\\python.exe -m sentinel.tests.test_harness.failed_login

    # With real logins (will prompt to deliberately fail a login):
    .venv\\Scripts\\python.exe -m sentinel.tests.test_harness.failed_login --real
"""
from __future__ import annotations

import sys
import time

from sentinel.engine.heuristics_bruteforce import BruteForceHeuristic
from sentinel.engine.schema import Event, utc_timestamp
from sentinel.engine.scoring import Scorer


def run_synthetic(
    num_attempts: int = 8,
    source_host: str = "192.168.1.100",
) -> bool:
    """Generate synthetic failed-login events and check that the
    brute-force heuristic fires."""
    print("=== Failed Login Harness (brute-force detector) ===")
    print(f"  Source: {source_host}")
    print(f"  Attempts: {num_attempts}")
    print(f"  Safety: synthetic events only — no real logins are failed")
    print()

    heuristic = BruteForceHeuristic(
        failed_login_count=5,
        window_seconds=120.0,
    )
    scorer = Scorer()
    all_signals = []

    # Generate N failed login events from the same source.
    for i in range(num_attempts):
        event = Event(
            timestamp=utc_timestamp(),
            source="eventlog",
            event_type="login_failed",
            extra={
                "event_id": 4625,
                "source_host": source_host,
                "account": "Administrator",
                "logon_type": 10,  # RDP
            },
        )
        sig = heuristic.process_login_event(event)
        if sig is not None:
            all_signals.append(sig)
            scorer.add_signal(sig)
            print(f"  [{i + 1}/{num_attempts}] SIGNAL: {sig.kind} "
                  f"(weight {sig.effective_weight})")
        else:
            print(f"  [{i + 1}/{num_attempts}] no signal (below threshold)")

    print()

    # Verify.
    passed = True
    if all_signals:
        sig = all_signals[0]
        subject = sig.subject
        score = scorer.get(subject)
        print(f"  Subject: '{subject}', score: {score.total:.0f}")
        print(f"  [PASS] failed_login_burst fired after {num_attempts} attempts")
        print(f"         Reason: {sig.reason}")
    else:
        print(f"  [FAIL] No signal emitted after {num_attempts} attempts")
        passed = False

    return passed


def main() -> int:
    if "--real" in sys.argv:
        print("Real login mode: deliberately fail a login (lock screen wrong")
        print("PIN/pw, or `runas /user:fakeuser cmd`) and the eventlog sensor")
        print("will capture the 4625. This harness only generates synthetic events.")
        return 1

    ok = run_synthetic()
    print(f"\n{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

