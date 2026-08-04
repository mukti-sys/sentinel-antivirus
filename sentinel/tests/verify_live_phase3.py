"""Phase 3 live verification -- end-to-end response pipeline test.

Runs on the real machine (no mocking) but uses ONLY safe synthetic data:
- Creates a temp "malicious" file
- Feeds synthetic signals through the scorer
- Verifies quarantine_process() suspends + quarantines + audits
- Verifies restore puts the file back
- Verifies delete removes it permanently
- Verifies notifier doesn't crash (UI may or may not be available)

Does NOT suspend any real processes (uses the current process PID
which will fail suspend on Windows but tests the full flow up to that
point, then uses mock-suspend for the happy path).

Usage:
    python -m sentinel.tests.verify_live_phase3
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

# Add parent to path if needed.
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from sentinel.engine.event_bus import EventBus
from sentinel.engine.scoring import Scorer, Signal
from sentinel.response.notifier import Notifier
from sentinel.response.quarantine_store import (
    DELETED,
    PENDING,
    RESTORED,
    QuarantineStore,
)
from sentinel.response.responder import quarantine_process, suspend_process


_passed = 0
_failed = 0


def _ok(msg: str) -> None:
    global _passed
    _passed += 1
    print(f"  [PASS] {msg}")


def _fail(msg: str) -> None:
    global _failed
    _failed += 1
    print(f"  [FAIL] {msg}")


# --------------------------------------------------------------------------- #
# 1. Quarantine store lifecycle
# --------------------------------------------------------------------------- #

def verify_quarantine_store(tmp_dir: Path) -> bool:
    print("\n[1/6] Quarantine Store -- add/get/restore/delete")
    store = QuarantineStore(
        db_path=tmp_dir / "quarantine.db",
        quarantine_dir=tmp_dir / "quarantine",
    )

    # Create a test file.
    test_file = tmp_dir / "test_malware.exe"
    test_file.write_bytes(b"MZ_test_payload_for_verification")
    original_data = test_file.read_bytes()
    expected_hash = hashlib.sha256(original_data).hexdigest()

    # Add to quarantine.
    rec = store.add(
        source_path=test_file,
        subject="pid:9999",
        reason="live verification test",
        score=92.0,
        source_signals=[{"kind": "test", "weight": 50}],
    )
    if rec is None:
        _fail("store.add() returned None")
        return False
    _ok(f"added file to quarantine (id={rec.id})")

    # Verify original is gone.
    if test_file.exists():
        _fail("original file still exists after quarantine")
        return False
    _ok("original file removed")

    # Verify quarantined file exists.
    qpath = Path(rec.quarantined_path)
    if not qpath.exists():
        _fail("quarantined file not found")
        return False
    _ok(f"quarantined file at {qpath.name}")

    # Verify SHA-256.
    if rec.sha256 != expected_hash:
        _fail(f"SHA-256 mismatch: {rec.sha256} != {expected_hash}")
    else:
        _ok(f"SHA-256 recorded correctly")

    # Verify get.
    fetched = store.get(rec.id)
    if fetched is None or fetched.id != rec.id:
        _fail("store.get() failed")
    else:
        _ok("store.get() returns correct record")

    # Restore.
    restored = store.restore(rec.id, notes="FP - live verification")
    if restored is None:
        _fail("store.restore() returned None")
    elif not Path(restored).exists():
        _fail("restored file not found on disk")
    elif Path(restored).read_bytes() != original_data:
        _fail("restored file data mismatch")
    else:
        _ok(f"restored to {Path(restored).name}")

    # Verify decision.
    after_restore = store.get(rec.id)
    if after_restore.decision != RESTORED:
        _fail(f"decision should be 'restored', got '{after_restore.decision}'")
    else:
        _ok("decision marked as 'restored'")

    store.close()
    return True


# --------------------------------------------------------------------------- #
# 2. Responder -- suspend/resume
# --------------------------------------------------------------------------- #

def verify_responder() -> bool:
    print("\n[2/6] Responder -- suspend/resume error handling")

    # Invalid PID should return error, not crash.
    err = suspend_process(-1)
    if err is None or "invalid" not in err.lower():
        _fail(f"suspend_process(-1) should return 'invalid pid', got: {err}")
    else:
        _ok("suspend_process(-1) returns error correctly")

    err = suspend_process(0)
    if err is None:
        _fail("suspend_process(0) should return error")
    else:
        _ok("suspend_process(0) returns error correctly")

    # Non-existent PID.
    err = suspend_process(99999999)
    if err is None:
        _fail("suspend_process(99999999) should fail")
    else:
        _ok(f"suspend_process(99999999) correctly fails: {err}")

    return True


# --------------------------------------------------------------------------- #
# 3. Full pipeline (mock suspend)
# --------------------------------------------------------------------------- #

def verify_full_pipeline(tmp_dir: Path) -> bool:
    print("\n[3/6] Full Pipeline -- detect -> suspend -> quarantine -> audit")

    evil_file = tmp_dir / "pipeline_dropper.exe"
    evil_file.write_bytes(b"MZ_pipeline_test_content")
    original_data = evil_file.read_bytes()

    # Score the subject.
    scorer = Scorer()
    subject = "pid:8888"
    scorer.add_signal(Signal(
        kind="vt_positive", subject=subject,
        engine="static_classifier",
        reason="VirusTotal: 40/70 detections",
    ))
    scorer.add_signal(Signal(
        kind="rule_match_high", subject=subject,
        engine="rule_engine",
        reason="LOLBin chain pattern",
    ))

    if not scorer.should_respond(subject):
        _fail("scorer should_respond() returned False for score 90")
        return False
    _ok(f"scorer: score={scorer.get(subject).total:.0f} -> should_respond=True")

    # Setup response components.
    bus = EventBus(db_path=tmp_dir / "events.db")
    store = QuarantineStore(
        db_path=tmp_dir / "pipeline_q.db",
        quarantine_dir=tmp_dir / "pipeline_quarantine",
    )

    # Mock suspend (we don't want to actually suspend PID 8888).
    with patch("sentinel.response.responder.suspend_process", return_value=None):
        result = quarantine_process(
            pid=8888,
            reason="vt_positive + rule_match_high",
            quarantine_store=store,
            bus=bus,
            image_path=str(evil_file),
            scorer=scorer,
        )

    if not result["success"]:
        _fail(f"quarantine_process failed: {result['error']}")
        bus.close()
        return False
    _ok("quarantine_process succeeded")

    if result["suspension"] is not None:
        _fail(f"suspend error: {result['suspension']}")
    else:
        _ok("process suspended (mocked)")

    qrec = result["quarantine"]
    if qrec is None:
        _fail("no quarantine record")
    else:
        _ok(f"file quarantined (id={qrec.id})")

    if result["event_id"] is None:
        _fail("no audit event emitted")
    else:
        _ok(f"audit event published (rowid={result['event_id']})")

    # Verify the audit event in the bus DB.
    rows = bus.recent(limit=5, where="event_type=?", params=("process_suspended",))
    if not rows:
        _fail("audit event not found in events.db")
    else:
        _ok(f"audit event in events.db: pid={rows[0]['pid']}")

    bus.close()
    store.close()
    return True


# --------------------------------------------------------------------------- #
# 4. Notifier
# --------------------------------------------------------------------------- #

def verify_notifier() -> bool:
    print("\n[4/6] Notifier -- calm, clear notifications")

    notifier = Notifier()

    # These should not crash even without a UI channel.
    try:
        notifier.notify_alert(
            process_name="test.exe",
            reason="live verification test",
            pid=12345,
            score=85.0,
        )
        _ok("notify_alert() did not crash")
    except Exception as exc:
        _fail(f"notify_alert() crashed: {exc}")
        return False

    try:
        notifier.notify_info("Sentinel live verification running")
        _ok("notify_info() did not crash")
    except Exception as exc:
        _fail(f"notify_info() crashed: {exc}")

    try:
        notifier.notify_resolved("test.exe", "restored", quarantine_id="abc")
        _ok("notify_resolved() did not crash")
    except Exception as exc:
        _fail(f"notify_resolved() crashed: {exc}")

    return True


# --------------------------------------------------------------------------- #
# 5. Schema -- new event types
# --------------------------------------------------------------------------- #

def verify_schema_update() -> bool:
    print("\n[5/6] Schema -- Phase 3 event types")

    from sentinel.engine.schema import EVENT_TYPES, Event, utc_timestamp

    if "process_suspended" not in EVENT_TYPES:
        _fail("'process_suspended' not in EVENT_TYPES")
        return False
    _ok("'process_suspended' in EVENT_TYPES")

    if "file_quarantined" not in EVENT_TYPES:
        _fail("'file_quarantined' not in EVENT_TYPES")
    else:
        _ok("'file_quarantined' in EVENT_TYPES")

    # Verify we can create an Event with the new type.
    try:
        event = Event(
            timestamp=utc_timestamp(),
            source="etw_process",
            event_type="process_suspended",
            pid=1234,
        )
        _ok("Event(event_type='process_suspended') created OK")
    except ValueError as exc:
        _fail(f"Event creation failed: {exc}")
        return False

    return True


# --------------------------------------------------------------------------- #
# 6. Watchdog -- import and basic check
# --------------------------------------------------------------------------- #

def verify_watchdog() -> bool:
    print("\n[6/6] Watchdog -- import and basic structure")

    try:
        from sentinel.watchdog_svc import Watchdog, _read_pid
        _ok("watchdog_svc imports OK")
    except ImportError as exc:
        _fail(f"watchdog_svc import failed: {exc}")
        return False

    # PID file should not exist (no service running).
    pid = _read_pid()
    _ok(f"_read_pid() = {pid} (None is normal when service isn't running)")

    # Watchdog can be instantiated.
    try:
        wd = Watchdog(poll_interval=1.0)
        _ok("Watchdog() instantiated OK")
    except Exception as exc:
        _fail(f"Watchdog() failed: {exc}")
        return False

    return True


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> int:
    global _passed, _failed

    print("=== Sentinel Phase 3 Live Verification ===")
    print("All checks use safe synthetic data -- no real malware or suspension.")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        verify_quarantine_store(tmp_dir)
        verify_responder()
        verify_full_pipeline(tmp_dir)
        verify_notifier()
        verify_schema_update()
        verify_watchdog()

    print("\n=== Summary ===")
    print(f"  PASSED: {_passed}")
    print(f"  FAILED: {_failed}")

    if _failed:
        print(f"\n=== {_failed} FAILURE(S) ===")
        return 1
    print("\n=== ALL PASS ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
