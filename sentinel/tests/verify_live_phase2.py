"""Phase 2 live-verification script.

Run this to validate that every Phase 2 detector fires correctly against
its matching test harness in plan.md Section 7. This is the Phase 2
equivalent of ``verify_live.py`` (Phase 1).

Usage (no admin required for most checks):
    cd "C:\\Users\\littlemukti\\OneDrive\\Documents\\pgt app\\antivirus"
    .venv\\Scripts\\python.exe -m sentinel.tests.verify_live_phase2

This runs each harness in sequence and reports PASS/FAIL for each
detector. All harnesses use safe, synthetic data — no real malware.

Detectors validated:
    1. Static classifier: EICAR hash → vt_positive signal
    2. Brute-force heuristic: synthetic login failures → failed_login_burst
    3. Ransomware heuristic: file burst → entropy_spike + mass_modification
    4. DLL self-injection: CreateRemoteThread on self → correctly ignored
    5. Scoring integration: corroborated signals → should_respond()
    6. Scoring integration: single weak signal → should NOT respond

Note:
    The cryptomining CPU heuristic (cpu_sustained) is NOT tested live here
    because it requires sustaining >85% CPU for >60s. Use the separate
    cpu_busy_loop.py harness for manual validation. See PROGRESS.md for
    the psutil WindowsApps quirk that affects automated CPU testing.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

from sentinel.engine.heuristics_bruteforce import BruteForceHeuristic
from sentinel.engine.heuristics_ransomware import RansomwareHeuristic
from sentinel.engine.schema import Event, utc_timestamp
from sentinel.engine.scoring import (
    DllLoadContext,
    DllReputationCache,
    Scorer,
    Signal,
    score_dll_load,
)
from sentinel.engine.static_classifier import StaticClassifier
from sentinel.intel.virustotal_client import HashVerdict


def _ok(msg: str) -> None:
    print(f"  [PASS] {msg}")


def _fail(msg: str) -> None:
    print(f"  [FAIL] {msg}")


# ---------------------------------------------------------------------------
# 1. Static classifier: EICAR
# ---------------------------------------------------------------------------
def verify_eicar() -> bool:
    print("\n[1/6] Static Classifier — EICAR test file")
    eicar = (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
        b"ANTIVIRUS-TEST-FILE!$H+H*"
    )
    eicar_sha256 = hashlib.sha256(eicar).hexdigest()

    with tempfile.NamedTemporaryFile(suffix=".com", delete=False) as f:
        f.write(eicar)
        path = Path(f.name)

    vt = MagicMock()
    vt.lookup.return_value = HashVerdict(
        sha256=eicar_sha256, verdict="malicious",
        positives=55, total=70, from_cache=False,
    )
    classifier = StaticClassifier(vt_client=vt)
    event = Event(
        timestamp=utc_timestamp(), source="fs",
        event_type="file_write", image_path=str(path),
    )
    signals = classifier.classify_file_event(event)
    path.unlink(missing_ok=True)

    if signals and signals[0].kind == "vt_positive":
        _ok(f"vt_positive signal for EICAR (weight {signals[0].effective_weight})")
        return True
    _fail("no vt_positive signal for EICAR")
    return False


# ---------------------------------------------------------------------------
# 2. Brute-force heuristic
# ---------------------------------------------------------------------------
def verify_brute_force() -> bool:
    print("\n[2/6] Brute-Force Heuristic — synthetic login failures")
    heuristic = BruteForceHeuristic(failed_login_count=5, window_seconds=120.0)
    fired = False
    for i in range(8):
        sig = heuristic.process_login_event(Event(
            timestamp=utc_timestamp(), source="eventlog",
            event_type="login_failed",
            extra={"event_id": 4625, "source_host": "10.0.0.1"},
        ))
        if sig:
            fired = True
    if fired:
        _ok("failed_login_burst fired after 5+ failures from same source")
        return True
    _fail("no failed_login_burst signal after 8 failures")
    return False


# ---------------------------------------------------------------------------
# 3. Ransomware heuristic
# ---------------------------------------------------------------------------
def verify_ransomware() -> bool:
    print("\n[3/6] Ransomware Heuristic — file burst with random data")
    base = Path(tempfile.mkdtemp(prefix="sentinel_test_"))
    heuristic = RansomwareHeuristic(
        entropy_alert=6.0,
        write_rate_per_min=10,
    )
    kinds = set()
    try:
        for i in range(60):
            f = base / f"dummy_{i:04d}.dat"
            f.write_bytes(os.urandom(4096))
            signals = heuristic.process_fs_event(Event(
                timestamp=utc_timestamp(), source="fs",
                event_type="file_write", image_path=str(f),
                extra={"entropy": 7.9, "action": "modified"},
            ))
            for sig in signals:
                kinds.add(sig.kind)
    finally:
        for f in base.iterdir():
            f.unlink()
        base.rmdir()

    ok = True
    if "entropy_spike" in kinds:
        _ok("entropy_spike fired")
    else:
        _fail("entropy_spike did NOT fire")
        ok = False
    if "mass_modification" in kinds:
        _ok("mass_modification fired")
    else:
        _fail("mass_modification did NOT fire")
        ok = False
    return ok


# ---------------------------------------------------------------------------
# 4. DLL self-injection → correctly ignored
# ---------------------------------------------------------------------------
def verify_dll_self_load() -> bool:
    print("\n[4/6] DLL Handling — self-injection correctly ignored")
    ctx = DllLoadContext(
        dll_hash="deadbeef" * 8,
        loader_pid=os.getpid(),
        target_pid=os.getpid(),
        signed=False,
        reflective=False,
    )
    signals = score_dll_load(ctx, DllReputationCache())
    if not signals:
        _ok("self-injection produced 0 signals (correctly ignored)")
        return True
    _fail(f"self-injection produced {len(signals)} signals (should be 0)")
    return False


# ---------------------------------------------------------------------------
# 5. Scoring: corroborated → should_respond
# ---------------------------------------------------------------------------
def verify_corroborated_response() -> bool:
    print("\n[5/6] Scoring — corroborated signals trigger response")
    scorer = Scorer()
    subject = "test:integration"
    scorer.add_signal(Signal(
        kind="vt_positive", subject=subject,
        engine="static_classifier", reason="VirusTotal: 20/70 detections",
    ))
    scorer.add_signal(Signal(
        kind="rule_match_high", subject=subject,
        engine="rule_engine", reason="LOLBin pattern matched",
    ))
    total = scorer.get(subject).total
    responds = scorer.should_respond(subject)
    if responds:
        _ok(f"vt_positive (50) + rule_match_high (40) = {total:.0f} -> respond")
        return True
    _fail(f"score {total:.0f} should respond but should_respond() returned False")
    return False


# ---------------------------------------------------------------------------
# 6. Scoring: single weak signal → no response
# ---------------------------------------------------------------------------
def verify_single_weak_no_response() -> bool:
    print("\n[6/6] Scoring — single weak signal does NOT trigger response")
    scorer = Scorer()
    subject = "test:single_weak"
    scorer.add_signal(Signal(
        kind="vt_positive", subject=subject,
        engine="static_classifier", reason="VirusTotal: 5/70 detections",
    ))
    responds = scorer.should_respond(subject)
    if not responds:
        score = scorer.get(subject).total
        _ok(f"vt_positive alone ({score:.0f}) correctly did NOT trigger response")
        return True
    _fail("single vt_positive should NOT trigger response")
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    print("=== Sentinel Phase 2 Live Verification ===")
    print("All checks use safe synthetic data — no real malware.")

    results = []
    results.append(("Static Classifier (EICAR)", verify_eicar()))
    results.append(("Brute-Force Heuristic", verify_brute_force()))
    results.append(("Ransomware Heuristic", verify_ransomware()))
    results.append(("DLL Self-Injection", verify_dll_self_load()))
    results.append(("Scoring: Corroborated", verify_corroborated_response()))
    results.append(("Scoring: Single Weak", verify_single_weak_no_response()))

    print("\n=== Summary ===")
    all_ok = True
    for name, ok in results:
        status = "PASS" if ok else "FAIL"
        print(f"  {name}: {status}")
        all_ok = all_ok and ok

    print(f"\n  Note: cryptomining CPU heuristic requires manual validation")
    print(f"        via cpu_busy_loop.py harness (>60s sustained CPU needed)")
    print("=== " + ("ALL PASS" if all_ok else "INCOMPLETE — see notes above") + " ===")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())

