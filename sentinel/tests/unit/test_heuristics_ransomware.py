"""Tests for engine/heuristics_ransomware.py.

- Pure logic: entropy_spike and mass_modification thresholds via injected fs
  events (deterministic).
- plan.md Section 7 harness analogue: a "dummy file rewrite" burst —
  simulated here by feeding many high-entropy write events for one folder,
  exactly what a ransomware-style rewriter produces.
"""
import pytest

from sentinel.engine.heuristics_ransomware import RansomwareHeuristic
from sentinel.engine.schema import Event, utc_timestamp


def _fs_write(path, entropy=None, pid=None, root="C:\\Users\\x\\Downloads", action="modified"):
    return Event(
        timestamp=utc_timestamp(), source="fs", event_type="file_write",
        pid=pid, image_path=path,
        extra={"action": action, "watched_root": root,
               "entropy": entropy, "size_bytes": 100},
    )


# --------------------------------------------------------------------------- #
# entropy_spike
# --------------------------------------------------------------------------- #
def test_high_entropy_write_emits_entropy_spike():
    h = RansomwareHeuristic()
    sigs = h.process_fs_event(_fs_write("a.enc", entropy=7.9), now=100.0)
    kinds = [s.kind for s in sigs]
    assert "entropy_spike" in kinds


def test_low_entropy_write_no_spike():
    h = RansomwareHeuristic()
    sigs = h.process_fs_event(_fs_write("a.txt", entropy=4.2), now=100.0)
    assert not any(s.kind == "entropy_spike" for s in sigs)


def test_entropy_spike_deduped_per_path():
    h = RansomwareHeuristic()
    h.process_fs_event(_fs_write("a.enc", entropy=7.9), now=100.0)
    sigs = h.process_fs_event(_fs_write("a.enc", entropy=7.9), now=101.0)
    assert not any(s.kind == "entropy_spike" for s in sigs)


def test_null_entropy_no_spike():
    h = RansomwareHeuristic()
    sigs = h.process_fs_event(_fs_write("a.bin", entropy=None), now=100.0)
    assert not any(s.kind == "entropy_spike" for s in sigs)


# --------------------------------------------------------------------------- #
# mass_modification (write rate)
# --------------------------------------------------------------------------- #
def test_mass_modification_fires_when_rate_exceeded():
    h = RansomwareHeuristic(write_rate_per_min=10.0)
    now = 100.0
    fired = []
    for i in range(15):
        sigs = h.process_fs_event(_fs_write(f"f{i}.enc", entropy=8.0), now=now + i)
        fired.extend([s for s in sigs if s.kind == "mass_modification"])
    assert len(fired) >= 1
    assert fired[0].subject.startswith("folder:")


def test_mass_modification_not_fired_below_rate():
    h = RansomwareHeuristic(write_rate_per_min=100.0)
    now = 100.0
    fired = []
    for i in range(5):
        sigs = h.process_fs_event(_fs_write(f"f{i}.txt", entropy=4.0), now=now + i * 10)
        fired.extend([s for s in sigs if s.kind == "mass_modification"])
    assert fired == []


def test_mass_modification_emitted_once_per_scope():
    h = RansomwareHeuristic(write_rate_per_min=5.0)
    now = 100.0
    fired = []
    for i in range(20):
        sigs = h.process_fs_event(_fs_write(f"f{i}.enc", entropy=8.0), now=now + i)
        fired.extend([s for s in sigs if s.kind == "mass_modification"])
    # deduped to one per scope
    assert len(fired) == 1


def test_pid_scope_takes_precedence_over_folder():
    h = RansomwareHeuristic(write_rate_per_min=3.0)
    now = 100.0
    fired = []
    for i in range(6):
        sigs = h.process_fs_event(_fs_write(f"f{i}.enc", entropy=8.0, pid=7777), now=now + i)
        fired.extend([s for s in sigs if s.kind == "mass_modification"])
    assert fired and fired[0].subject == "pid:7777"


def test_non_fs_event_ignored():
    h = RansomwareHeuristic()
    ev = Event(timestamp=utc_timestamp(), source="network", event_type="connection")
    assert h.process_fs_event(ev, now=100.0) == []


# --------------------------------------------------------------------------- #
# Dummy-rewrite burst harness (plan.md Section 7 analogue)
# --------------------------------------------------------------------------- #
def test_ransomware_burst_produces_both_signals():
    """Simulate a ransomware-style rewriter: many high-entropy writes in one
    folder in a short window. Expect BOTH entropy_spike and mass_modification
    for that scope (rate + entropy), matching architecture.md Example B."""
    h = RansomwareHeuristic(write_rate_per_min=20.0, entropy_alert=7.5)
    now = 100.0
    all_sigs = []
    for i in range(25):  # 25 high-entropy writes within 60s -> rate 25/min
        sigs = h.process_fs_event(
            _fs_write(f"document_{i}.locked", entropy=7.95), now=now + i
        )
        all_sigs.extend(sigs)
    kinds = {s.kind for s in all_sigs}
    assert "mass_modification" in kinds
    assert "entropy_spike" in kinds
    # Both attributed to the same folder scope so scoring can combine them.
    subjects = {s.subject for s in all_sigs}
    assert len(subjects) == 1


def test_current_rate_computation():
    h = RansomwareHeuristic()
    now = 100.0
    for i in range(10):
        h.process_fs_event(_fs_write(f"f{i}.txt"), now=now + i)
    rate = h.current_rate("folder:C:\\Users\\x\\Downloads", now=now + 10)
    assert rate == pytest.approx(10.0)
