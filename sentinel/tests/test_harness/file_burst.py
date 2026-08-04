"""File-burst harness — validates the ransomware entropy/rate heuristic.

Simulates:
    A process rapidly rewriting a batch of dummy files with high-entropy
    random data in a test folder — the observable pattern ransomware
    exhibits (architecture.md Example B: write-entropy spike +
    mass-modification rate).

What it exercises:
    1. Creates a temp folder with N dummy files
    2. Rapidly rewrites each with random bytes (high entropy ≈ 7.99)
    3. The ransomware heuristic should fire both ``entropy_spike`` and
       ``mass_modification`` signals for this burst

Safety:
    All files are created in a temporary directory inside the project's
    data/ folder. Only dummy files are affected — no user data is touched.
    The directory is cleaned up after the test.

Usage:
    cd "C:\\Users\\littlemukti\\OneDrive\\Documents\\pgt app\\antivirus"
    .venv\\Scripts\\python.exe -m sentinel.tests.test_harness.file_burst

    # Custom parameters:
    .venv\\Scripts\\python.exe -m sentinel.tests.test_harness.file_burst --files 100 --size 4096
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from sentinel.engine.heuristics_ransomware import RansomwareHeuristic
from sentinel.engine.schema import Event, utc_timestamp
from sentinel.engine.scoring import Scorer


def run_burst(
    num_files: int = 80,
    file_size: int = 4096,
) -> bool:
    """Rapidly rewrite dummy files with random data and check that the
    ransomware heuristic fires."""
    print("=== File Burst Harness (ransomware entropy/rate) ===")

    # Create a temp directory inside the project data/ folder.
    base = Path(__file__).resolve().parent.parent.parent / "data" / "_test_burst"
    base.mkdir(parents=True, exist_ok=True)

    # 1. Create dummy files.
    files = []
    for i in range(num_files):
        f = base / f"dummy_{i:04d}.dat"
        f.write_bytes(b"\\x00" * file_size)  # starts as low-entropy zeros
        files.append(f)
    print(f"  [1] Created {num_files} dummy files in {base}")
    print(f"      File size: {file_size} bytes each")

    # 2. Set up the heuristic with aggressive thresholds (for test speed).
    heuristic = RansomwareHeuristic(
        entropy_alert=7.0,
        write_rate_per_min=20,   # 20 writes/min window -- easy to trigger
    )
    scorer = Scorer()
    all_signals = []

    # 3. Rapidly rewrite each file with random data (high entropy ≈ 7.99).
    print(f"  [2] Rapidly rewriting {num_files} files with random data...")
    start = time.time()
    for f in files:
        random_data = os.urandom(file_size)
        f.write_bytes(random_data)

        # Feed the file_write event into the heuristic.
        # The heuristic expects entropy in event.extra (computed by the
        # fs_sensor in the live pipeline); here we compute it ourselves.
        from sentinel.engine.static_classifier import _file_entropy
        ent = _file_entropy(random_data)
        event = Event(
            timestamp=utc_timestamp(),
            source="fs",
            event_type="file_write",
            image_path=str(f),
            extra={"entropy": ent, "action": "modified"},
        )
        signals = heuristic.process_fs_event(event)
        for sig in signals:
            all_signals.append(sig)
            scorer.add_signal(sig)
    elapsed = time.time() - start
    rate = num_files / max(elapsed, 0.001)
    print(f"      Rewrote {num_files} files in {elapsed:.2f}s ({rate:.0f} files/s)")

    # 4. Report signals.
    print(f"  [3] Heuristic emitted {len(all_signals)} signal(s):")
    kinds = {}
    for sig in all_signals:
        kinds[sig.kind] = kinds.get(sig.kind, 0) + 1
        print(f"      -> {sig.kind} (weight {sig.effective_weight}): "
              f"{sig.reason[:80]}...")

    # 5. Verify.
    passed = True
    has_entropy = "entropy_spike" in kinds
    has_rate = "mass_modification" in kinds

    if has_entropy:
        print(f"  [PASS] entropy_spike fired ({kinds['entropy_spike']} times)")
    else:
        print("  [FAIL] entropy_spike did NOT fire")
        passed = False

    if has_rate:
        print(f"  [PASS] mass_modification fired ({kinds['mass_modification']} times)")
    else:
        print("  [FAIL] mass_modification did NOT fire")
        passed = False

    # 6. Cleanup.
    for f in files:
        f.unlink(missing_ok=True)
    base.rmdir()
    print(f"  [4] Cleaned up {base}")

    return passed


def main() -> int:
    num_files = 80
    file_size = 4096
    args = sys.argv[1:]
    if "--files" in args:
        num_files = int(args[args.index("--files") + 1])
    if "--size" in args:
        file_size = int(args[args.index("--size") + 1])

    ok = run_burst(num_files=num_files, file_size=file_size)
    print(f"\n{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

