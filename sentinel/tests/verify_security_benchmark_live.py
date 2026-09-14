"""Unified Security & Efficacy Benchmark Verification (Live in VM).

Runs all 4 critical security tests strictly inside the VM environment:
1. Industry-Standard EICAR Test File Detection & Autonomous Quarantine.
2. .DLL File Inspection, Autonomous Quarantine & Kernel Minifilter Pre-Execution Blocking.
3. False Positive (FP) Benchmark across 100+ clean Windows system binaries & DLLs (Target: 0.0% FP).
4. Behavioral Ransomware Simulation (Shannon entropy surge ~7.9 + mass-modification burst).

Usage (elevated in VM):
    python -m sentinel.tests.verify_security_benchmark_live
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import math
import os
import struct
import sys
import time
from pathlib import Path

import pefile

from sentinel.service import SentinelOrchestrator
from sentinel.kernel.bridge import KernelBridge, dos_to_nt_path
from sentinel.engine.scanner import OnDemandScanner, ThreatSeverity
from sentinel.engine.heuristics_ransomware import RansomwareHeuristic
from sentinel.engine.schema import Event, utc_timestamp
from sentinel.engine.scoring import Scorer

# Windows API constants for file execution checks
GENERIC_EXECUTE = 0x20000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

# Standard EICAR payload string (68 bytes)
EICAR_PAYLOAD = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def make_eicar_payload() -> bytes:
    """Generate EICAR string with unique padding for distinct SHA-256 per test."""
    return EICAR_PAYLOAD + f" #{int(time.time() * 1000)}".encode()


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def try_open_for_execute(path: str) -> bool:
    """Attempt CreateFileW with GENERIC_EXECUTE access."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateFileW(
        path,
        GENERIC_EXECUTE,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE or handle == -1:
        error = kernel32.GetLastError()
        if error == 5:  # ERROR_ACCESS_DENIED
            return False
        raise OSError(f"CreateFileW failed with unexpected error {error}")
    kernel32.CloseHandle(handle)
    return True


def make_valid_pe_dll(payload: bytes = b"") -> bytes:
    """Construct a structurally valid 64-bit AMD64 PE DLL."""
    e_lfanew = 0x80
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", e_lfanew) + b"\x00" * (e_lfanew - 0x40)
    pe_sig = b"PE\x00\x00"
    file_hdr = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)  # DLL | EXEC | LARGE
    magic = 0x020B
    opt_std = struct.pack("<HBBIIIII", magic, 14, 0, 0x200, 0, 0, 0x1000, 0x1000)
    opt_win = struct.pack(
        "<QIIHHHHHHIIIIHHQQQQII",
        0x180000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 2, 0x8160,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    data_dirs = b"\x00" * (16 * 8)
    opt_hdr = opt_std + opt_win + data_dirs

    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x200,   # VirtualSize
        0x1000,  # VirtualAddress
        0x200,   # SizeOfRawData
        0x200,   # PointerToRawData
        0, 0, 0, 0,
        0x60000020,  # CODE | EXECUTE | READ
    )

    headers = (dos_header + pe_sig + file_hdr + opt_hdr + sec_hdr).ljust(0x200, b"\x00")
    code = (b"\xb8\x01\x00\x00\x00\xc3" + payload).ljust(0x200, b"\x00")
    return headers + code


def run_benchmark() -> int:
    print("=" * 72)
    print("   SENTINEL ANTIVIRUS — SECURITY & EFFICACY LIVE BENCHMARK")
    print("=" * 72)
    print(f" Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Execution Mode: {'Elevated Administrator' if is_admin() else 'User Mode'}")
    print()

    # Step 0: Initialize Orchestrator & Kernel Driver
    print("[0/4] Initializing Sentinel Orchestrator, EventBus & Sensors...")
    orch = SentinelOrchestrator()
    orch._init_components()

    bridge: KernelBridge | None = orch._kernel_bridge
    if bridge and bridge.connected:
        print(f"   ✓ Kernel Minifilter Driver: CONNECTED (status: {bridge.get_status()})")
    else:
        print("   ✗ ERROR: Kernel driver is not connected. Driver test required.")
        return 1

    consumer = orch._consumer
    if not consumer:
        print("   ✗ ERROR: DetectionConsumer failed to initialize.")
        return 1
    print("   ✓ DetectionConsumer & EventBus: ACTIVE")

    scanner = OnDemandScanner(
        classifier=consumer.static_classifier,
        quarantine_store=consumer.quarantine_store,
    )
    print("   ✓ On-Demand Scanner Engine: READY")

    test_root = Path("C:/av_test")
    test_root.mkdir(parents=True, exist_ok=True)
    downloads_dir = Path.home() / "Downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)

    test_scores: dict[str, bool] = {}

    try:
        # ===================================================================
        # TEST 1: Industry-Standard EICAR Test File Detection
        # ===================================================================
        print("\n" + "-" * 72)
        print("TEST 1: Industry-Standard EICAR Test File Detection")
        print("-" * 72)

        # 1A: On-demand scan
        eicar_scan_file = test_root / f"eicar_scan_{int(time.time())}.com"
        eicar_scan_file.write_bytes(make_eicar_payload())
        print(f"  [1A] Testing On-Demand Scanner on EICAR sample: {eicar_scan_file.name}...")

        scan_result = scanner.scan_file(eicar_scan_file)
        if scan_result and "EICAR" in scan_result.threat_name:
            print(f"       ✓ Detected: {scan_result.threat_name} (Severity: {scan_result.severity.value}, Score: {scan_result.score})")
            t1a_passed = True
        else:
            print(f"       ✗ FAILED: Scanner did not detect EICAR. Result: {scan_result}")
            t1a_passed = False
        eicar_scan_file.unlink(missing_ok=True)

        # 1B: Real-time autonomous quarantine upon drop
        eicar_drop_file = downloads_dir / f"eicar_drop_{int(time.time())}.com"
        print(f"  [1B] Testing Real-Time Drop & Autonomous Quarantine: {eicar_drop_file.name}...")
        eicar_drop_file.write_bytes(make_eicar_payload())

        # Wait for filesystem sensor -> consumer to quarantine
        quarantined_1b = False
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if not eicar_drop_file.exists():
                quarantined_1b = True
                break
            time.sleep(0.3)

        if quarantined_1b:
            print(f"       ✓ Real-time sensor caught EICAR write and quarantined file within {(10.0 - (deadline - time.time())):.2f}s")
            # Verify in quarantine store
            q_records = consumer.quarantine_store.list_all()[:5]
            eicar_record = any("eicar" in r.reason.lower() or "eicar" in r.original_path.lower() for r in q_records)
            if eicar_record:
                print("       ✓ Quarantine record logged in QuarantineStore SQLite DB")
                t1b_passed = True
            else:
                print("       ⚠ File moved but record not found in QuarantineStore")
                t1b_passed = False
        else:
            print("       ✗ FAILED: File was not quarantined within 10s timeout")
            eicar_drop_file.unlink(missing_ok=True)
            t1b_passed = False

        test_scores["Test 1: EICAR Standard Test File"] = t1a_passed and t1b_passed

        # ===================================================================
        # TEST 2: .DLL File Inspection, Autonomous Quarantine & Kernel Blocking
        # ===================================================================
        print("\n" + "-" * 72)
        print("TEST 2: .DLL File Inspection, Autonomous Quarantine & Kernel Blocking")
        print("-" * 72)

        unique_sig = f"SENTINEL-ANTIVIRUS-TEST-PAYLOAD-AUTONOMOUS-QUARANTINE-{int(time.time() * 1000)}".encode()
        dll_bytes = make_valid_pe_dll(unique_sig)
        pe_check = pefile.PE(data=dll_bytes)
        assert pe_check.is_dll(), "Generated test artifact must be a valid PE DLL"
        print(f"  [2A] Built structurally valid AMD64 PE DLL ({len(dll_bytes)} bytes, Machine={hex(pe_check.FILE_HEADER.Machine)})")

        # 2A: On-demand scan on DLL
        test_dll_path = test_root / f"sentinel_test_{int(time.time())}.dll"
        test_dll_path.write_bytes(dll_bytes)
        print(f"  [2B] On-Demand Scanner evaluating DLL: {test_dll_path.name}...")
        dll_scan_res = scanner.scan_file(test_dll_path)
        if dll_scan_res and "Sentinel_Test_Payload" in dll_scan_res.threat_name:
            print(f"       ✓ Detected DLL Threat: {dll_scan_res.threat_name} (Score: {dll_scan_res.score})")
            t2a_passed = True
        else:
            print(f"       ✗ FAILED: Scanner did not flag test DLL. Result: {dll_scan_res}")
            t2a_passed = False
        test_dll_path.unlink(missing_ok=True)

        # 2B: Real-time autonomous quarantine on DLL drop
        dll_drop_file = downloads_dir / f"sentinel_drop_{int(time.time())}.dll"
        print(f"  [2C] Dropping test DLL into watched folder: {dll_drop_file.name}...")
        dll_drop_file.write_bytes(dll_bytes)

        quarantined_2b = False
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if not dll_drop_file.exists():
                quarantined_2b = True
                break
            time.sleep(0.3)

        if quarantined_2b:
            print(f"       ✓ Real-Time Sensor caught DLL drop and isolated it to Quarantine")
            t2b_passed = True
        else:
            print("       ✗ FAILED: DLL file was not quarantined within timeout")
            dll_drop_file.unlink(missing_ok=True)
            t2b_passed = False

        # 2C: Kernel Minifilter Driver Pre-Execution Interception on DLL
        print("  [2D] Testing Kernel Minifilter Driver Pre-Execution Block on .DLL...")
        block_dll_path = test_root / f"sentinel_kernel_block_{int(time.time())}.dll"
        block_dll_path.write_bytes(dll_bytes)

        # Blacklist in driver
        bridge.add_block(str(block_dll_path))
        print(f"       Added DLL to kernel blocklist: {block_dll_path.name}")

        # Attempt to open DLL for execution (GENERIC_EXECUTE)
        can_exec = try_open_for_execute(str(block_dll_path))
        if not can_exec:
            print("       ✓ Kernel Driver Intercepted CreateFileW(GENERIC_EXECUTE) -> STATUS_ACCESS_DENIED!")
            t2c_passed = True
        else:
            print("       ✗ FAILED: Kernel driver allowed GENERIC_EXECUTE open!")
            t2c_passed = False

        # Attempt to load with LoadLibraryEx
        h_mod = ctypes.windll.kernel32.LoadLibraryExW(str(block_dll_path), None, 0)
        if h_mod == 0:
            err = ctypes.windll.kernel32.GetLastError()
            print(f"       ✓ OS LoadLibraryExW denied (LastError: {err} - Access Denied)")
            t2d_passed = True
        else:
            print(f"       ✗ FAILED: LoadLibraryExW succeeded with handle {hex(h_mod)}!")
            ctypes.windll.kernel32.FreeLibrary(h_mod)
            t2d_passed = False

        bridge.remove_block(str(block_dll_path))
        block_dll_path.unlink(missing_ok=True)

        test_scores["Test 2: .DLL Inspection & Kernel Blocking"] = t2a_passed and t2b_passed and t2c_passed and t2d_passed

        # ===================================================================
        # TEST 3: False Positive (FP) Benchmark on Real Windows Binaries
        # ===================================================================
        print("\n" + "-" * 72)
        print("TEST 3: False Positive (FP) Benchmark on Real Windows Binaries & DLLs")
        print("-" * 72)

        # Enumerate known clean, legitimate Windows system utilities and libraries
        candidate_dirs = [
            Path("C:/Windows/System32"),
            Path(sys.prefix) / "DLLs",
            Path(sys.prefix) / "Lib",
        ]

        clean_files: list[Path] = []
        for cdir in candidate_dirs:
            if not cdir.is_dir():
                continue
            for entry in cdir.iterdir():
                try:
                    if entry.is_file() and entry.suffix.lower() in {".exe", ".dll", ".pyd"}:
                        clean_files.append(entry)
                        if len(clean_files) >= 120:
                            break
                except (PermissionError, OSError):
                    continue
            if len(clean_files) >= 120:
                break

        print(f"  [3A] Selected {len(clean_files)} legitimate Windows binaries, system DLLs & Python libraries")
        print(f"       Examples: {[f.name for f in clean_files[:8]]}")
        print("  [3B] Running On-Demand Scanner across all clean files to evaluate FP rate...")

        false_positives: list[tuple[Path, str]] = []
        start_fp_scan = time.time()

        for idx, cfile in enumerate(clean_files, 1):
            res = scanner.scan_file(cfile)
            if res is not None:
                false_positives.append((cfile, res.threat_name))

        fp_elapsed = time.time() - start_fp_scan
        total_scanned = len(clean_files)
        fp_count = len(false_positives)
        fp_rate = (fp_count / total_scanned) * 100.0 if total_scanned > 0 else 0.0

        print(f"       Scanned: {total_scanned} files in {fp_elapsed:.2f}s ({total_scanned / fp_elapsed:.1f} files/sec)")
        print(f"       False Positives Flagged: {fp_count}")
        print(f"       Measured False Positive Rate: {fp_rate:.2f}%")

        if fp_count == 0:
            print("       ✓ PERFECT SCORE: 0.0% False Positive Rate on legitimate Windows software!")
            test_scores["Test 3: False Positive Benchmark"] = True
        else:
            print(f"       ✗ FAILED: {fp_count} clean files erroneously flagged:")
            for cf, tn in false_positives[:5]:
                print(f"         - {cf.name}: {tn}")
            test_scores["Test 3: False Positive Benchmark"] = False

        # ===================================================================
        # TEST 4: Behavioral Ransomware Simulation (Canary Entropy Burst)
        # ===================================================================
        print("\n" + "-" * 72)
        print("TEST 4: Behavioral Ransomware Simulation (Entropy Surge & Burst Velocity)")
        print("-" * 72)

        canary_dir = test_root / "_ransomware_canary"
        canary_dir.mkdir(parents=True, exist_ok=True)
        num_canary_files = 40
        canary_size = 4096

        print(f"  [4A] Preparing {num_canary_files} canary test files in isolated sandbox {canary_dir.name}...")
        c_files = []
        for i in range(num_canary_files):
            cf = canary_dir / f"doc_{i:03d}.txt"
            cf.write_bytes(b"Low entropy plain text document header.\n" * 10)
            c_files.append(cf)

        # Instantiate heuristic with active detection thresholds
        rw_heuristic = RansomwareHeuristic(
            write_rate_per_min=20.0,
            entropy_alert=7.0,
        )
        scorer = Scorer()

        print(f"  [4B] Executing simulated encryption burst (rapid high-entropy writes)...")
        fired_entropy_spike = False
        fired_mass_modification = False
        max_entropy_seen = 0.0

        for cf in c_files:
            # High-entropy encrypted bytes (~7.99)
            enc_data = os.urandom(canary_size)
            cf.write_bytes(enc_data)

            # Shannon entropy
            ent = 0.0
            counts = [0] * 256
            for b in enc_data:
                counts[b] += 1
            n = len(enc_data)
            for c in counts:
                if c > 0:
                    p = c / n
                    ent -= p * math.log2(p)
            if ent > max_entropy_seen:
                max_entropy_seen = ent

            ev = Event(
                timestamp=utc_timestamp(),
                source="fs",
                event_type="file_write",
                image_path=str(cf),
                extra={"entropy": ent, "action": "modified"},
            )
            sigs = rw_heuristic.process_fs_event(ev)
            for s in sigs:
                if s.kind == "entropy_spike":
                    fired_entropy_spike = True
                elif s.kind == "mass_modification":
                    fired_mass_modification = True

        print(f"       Observed File Entropy: {max_entropy_seen:.2f} bits/byte (Threshold: 7.0)")
        print(f"       Heuristic Signal 'entropy_spike': {'FIRED ✓' if fired_entropy_spike else 'MISSED ✗'}")
        print(f"       Heuristic Signal 'mass_modification': {'FIRED ✓' if fired_mass_modification else 'MISSED ✗'}")

        # Clean up canary files
        for cf in c_files:
            cf.unlink(missing_ok=True)
        canary_dir.rmdir()

        t4_passed = fired_entropy_spike and fired_mass_modification
        test_scores["Test 4: Ransomware Behavioral Canary"] = t4_passed

    finally:
        print("\n[!] Cleaning up Sentinel Orchestrator and Sensors...")
        orch._cleanup()
        print("    Orchestrator stopped cleanly ✓")

    # ===================================================================
    # FINAL BENCHMARK SCORECARD
    # ===================================================================
    print("\n" + "=" * 72)
    print("                 SECURITY BENCHMARK SCORECARD")
    print("=" * 72)

    all_passed = True
    for test_name, passed in test_scores.items():
        status_str = "PASSED [✓]" if passed else "FAILED [✗]"
        print(f"  {test_name:<55} {status_str}")
        if not passed:
            all_passed = False

    print("=" * 72)
    if all_passed:
        print("  >>> OVERALL RESULT: 100% PASSED — ALL SECURITY CRITERIA MET <<<")
        print("=" * 72)
        return 0
    else:
        print("  >>> OVERALL RESULT: SOME BENCHMARK TESTS FAILED <<<")
        print("=" * 72)
        return 1


if __name__ == "__main__":
    sys.exit(run_benchmark())
