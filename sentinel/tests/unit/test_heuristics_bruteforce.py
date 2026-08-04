"""Tests for engine/heuristics_bruteforce.py.

- Pure logic: sliding-window count and burst threshold via injected
  login_failed events (deterministic).
- plan.md Section 7 harness analogue: simulate deliberately failing login
  several times from the same source.
"""
import pytest

from sentinel.engine.heuristics_bruteforce import BruteForceHeuristic
from sentinel.engine.schema import Event, utc_timestamp


def _login_failed(source_host="10.0.0.42", target_user="Administrator", logon_type=3):
    return Event(
        timestamp=utc_timestamp(),
        source="eventlog",
        event_type="login_failed",
        extra={
            "source_host": source_host,
            "target_user": target_user,
            "logon_type": logon_type,
        },
    )


def test_below_threshold_no_signal():
    h = BruteForceHeuristic(failed_login_count=5, window_seconds=120.0)
    now = 1000.0
    sig = None
    for i in range(4):
        sig = h.process_login_event(_login_failed(), now=now + i)
    assert sig is None
    assert h.current_count("10.0.0.42", now=now + 3) == 4


def test_burst_fires_at_threshold():
    h = BruteForceHeuristic(failed_login_count=5, window_seconds=120.0)
    now = 1000.0
    sig = None
    for i in range(5):
        sig = h.process_login_event(_login_failed(), now=now + i * 5)
    assert sig is not None
    assert sig.kind == "failed_login_burst"
    assert sig.subject == "source:10.0.0.42"
    assert "10.0.0.42" in sig.reason
    assert "Administrator" in sig.reason


def test_burst_deduped_per_source():
    h = BruteForceHeuristic(failed_login_count=3, window_seconds=60.0)
    now = 100.0
    first = None
    for i in range(3):
        first = h.process_login_event(_login_failed(), now=now + i)
    assert first is not None
    second = h.process_login_event(_login_failed(), now=now + 10)
    assert second is None


def test_sources_tracked_independently():
    h = BruteForceHeuristic(failed_login_count=3, window_seconds=60.0)
    now = 200.0
    for i in range(2):
        assert h.process_login_event(_login_failed("1.2.3.4"), now=now + i) is None
    sig_a = h.process_login_event(_login_failed("1.2.3.4"), now=now + 2)
    assert sig_a and sig_a.subject == "source:1.2.3.4"

    for i in range(2):
        assert h.process_login_event(_login_failed("5.6.7.8"), now=now + i) is None
    sig_b = h.process_login_event(_login_failed("5.6.7.8"), now=now + 2)
    assert sig_b and sig_b.subject == "source:5.6.7.8"


def test_old_attempts_fall_out_of_window():
    h = BruteForceHeuristic(failed_login_count=5, window_seconds=60.0)
    now = 500.0
    for i in range(4):
        h.process_login_event(_login_failed(), now=now + i)
    # Fifth attempt, but first four are now outside the 60s window.
    sig = h.process_login_event(_login_failed(), now=now + 200)
    assert sig is None
    assert h.current_count("10.0.0.42", now=now + 200) == 1


def test_localhost_source_tracked():
    h = BruteForceHeuristic(failed_login_count=3, window_seconds=120.0)
    now = 100.0
    sig = None
    for i in range(3):
        sig = h.process_login_event(_login_failed("localhost"), now=now + i)
    assert sig and sig.subject == "source:localhost"


def test_non_login_event_ignored():
    h = BruteForceHeuristic()
    ev = Event(timestamp=utc_timestamp(), source="network", event_type="connection")
    assert h.process_login_event(ev, now=100.0) is None


def test_missing_source_host_ignored():
    h = BruteForceHeuristic(failed_login_count=2)
    ev = Event(
        timestamp=utc_timestamp(),
        source="eventlog",
        event_type="login_failed",
        extra={"target_user": "x"},
    )
    assert h.process_login_event(ev, now=100.0) is None


def test_failed_login_burst_harness():
    """plan.md Section 7 analogue: deliberately failing login several times
    from one source produces a burst signal for that source."""
    h = BruteForceHeuristic(failed_login_count=5, window_seconds=120.0)
    now = 3000.0
    sig = None
    for attempt in range(5):
        sig = h.process_login_event(
            _login_failed(source_host="192.168.1.99", target_user="User"),
            now=now + attempt * 2,
        )
    assert sig is not None
    assert sig.kind == "failed_login_burst"
    assert sig.engine == "bruteforce_heuristic"
