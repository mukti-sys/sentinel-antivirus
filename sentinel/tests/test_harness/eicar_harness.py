"""EICAR test-file harness — validates the static classifier scanning pipeline.

Simulates:
    A new file appearing in a watched folder that VT recognizes as
    malicious (the EICAR test string is the industry-standard harmless AV
    test — every AV on earth recognizes its SHA-256).

What it exercises:
    1. File write to a temp directory (simulates a download arriving)
    2. Static classifier hashes the file (SHA-256)
    3. VT lookup returns "malicious" (or is mocked to return it)
    4. ``vt_positive`` signal emitted into scorer

Safety:
    The EICAR string is NOT malware. It is a specially crafted 68-byte
    ASCII string designed specifically for AV testing. It does nothing
    when executed. See https://www.eicar.org/download-anti-malware-testfile/

Usage:
    # Unit-test mode (no live system needed):
    cd "C:\\Users\\littlemukti\\OneDrive\\Documents\\pgt app\\antivirus"
    .venv\\Scripts\\python.exe -m sentinel.tests.test_harness.eicar_harness

    # With live VT key (requires settings.yaml virustotal_api_key):
    .venv\\Scripts\\python.exe -m sentinel.tests.test_harness.eicar_harness --live
"""
from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from sentinel.engine.schema import Event, utc_timestamp
from sentinel.engine.scoring import Scorer, Signal
from sentinel.engine.static_classifier import StaticClassifier
from sentinel.intel.virustotal_client import HashVerdict, VirusTotalClient

# The EICAR test string — 68 bytes, completely harmless.
# https://www.eicar.org/download-anti-malware-testfile/
EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
    b"ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_SHA256 = hashlib.sha256(EICAR).hexdigest()


def run_mocked() -> bool:
    """Run the EICAR harness with a mocked VT client (no network)."""
    print("=== EICAR Harness (mocked VT) ===")

    # 1. Drop EICAR to temp file.
    with tempfile.NamedTemporaryFile(suffix=".com", delete=False) as f:
        f.write(EICAR)
        eicar_path = Path(f.name)
    print(f"  [1] Wrote EICAR to {eicar_path} ({len(EICAR)} bytes)")
    print(f"      SHA-256: {EICAR_SHA256}")

    # 2. Create a mocked VT client that returns "malicious".
    vt = MagicMock(spec=VirusTotalClient)
    vt.lookup.return_value = HashVerdict(
        sha256=EICAR_SHA256,
        verdict="malicious",
        positives=55,
        total=70,
        from_cache=False,
    )

    # 3. Run the static classifier.
    classifier = StaticClassifier(vt_client=vt)
    event = Event(
        timestamp=utc_timestamp(),
        source="fs",
        event_type="file_write",
        image_path=str(eicar_path),
    )
    signals = classifier.classify_file_event(event)
    print(f"  [2] Static classifier returned {len(signals)} signal(s)")

    # 4. Feed into scorer.
    scorer = Scorer()
    for sig in signals:
        scorer.add_signal(sig)
        print(f"      -> {sig.kind} (weight {sig.effective_weight}): {sig.reason}")

    # 5. Verify.
    passed = True
    if not signals:
        print("  [FAIL] No signals emitted — expected vt_positive")
        passed = False
    elif signals[0].kind != "vt_positive":
        print(f"  [FAIL] Expected vt_positive, got {signals[0].kind}")
        passed = False
    else:
        subject = signals[0].subject
        score = scorer.get(subject)
        print(f"  [3] Subject '{subject}' score: {score.total:.0f} "
              f"(threshold: {scorer.threshold:.0f})")
        print(f"  [PASS] vt_positive signal emitted with weight "
              f"{signals[0].effective_weight:.0f}")

    # Cleanup.
    eicar_path.unlink(missing_ok=True)
    return passed


def main() -> int:
    if "--live" in sys.argv:
        print("Live VT mode not implemented — use mocked mode for now")
        print("(live mode requires the full event bus + sensor pipeline)")
        return 1

    ok = run_mocked()
    print(f"\n{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

