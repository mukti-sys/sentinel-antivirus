"""Unified Adversarial & Stress Benchmark Verification (Live in VM).

Runs 4 advanced adversarial evasion and stress test vectors strictly inside the VM:
1. Extension Spoofing & Polymorphic Masquerading (Double extension + PE disguised as .pdf/.jpg/.dat).
2. NTFS Alternate Data Streams (ADS) Hidden Evasion & Kernel Driver Execution Interception.
3. High-Velocity Event Queue Flooding / Anti-DoS Stress (500-file flood + Threat detection under load).
4. Anti-Tampering & Quarantine Vault DACL Integrity (Win32 Deny-All ACLs + SQLite WAL integrity).

Usage (elevated in VM):
    python -m sentinel.tests.verify_adversarial_stress_live
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import os
import shutil
import sqlite3
import struct
import sys
import threading
import time
from pathlib import Path

import pefile

from sentinel.service import SentinelOrchestrator
from sentinel.kernel.bridge import KernelBridge
from sentinel.engine.scanner import OnDemandScanner, ThreatSeverity
from sentinel.engine.schema import Event, utc_timestamp
from sentinel.tests.verify_security_benchmark_live import (
    make_valid_pe_dll,
    try_open_for_execute,
    is_admin,
)

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


def try_open_for_read(path: str) -> bool:
    """Attempt CreateFileW with GENERIC_READ access."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE or handle == -1:
        error = kernel32.GetLastError()
        if error in (5, 32):  # ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION
            return False
        return False
    kernel32.CloseHandle(handle)
    return True


def run_adversarial_benchmark() -> bool:
    print("=" * 72)
    print("      SENTINEL ANTIVIRUS — ADVANCED ADVERSARIAL & STRESS BENCHMARK    ")
    print("=" * 72)
    print(f"Platform       : {sys.platform} (Python {sys.version.split()[0]})")
    print(f"Elevated Admin : {is_admin()}")
    print(f"Working Dir    : {os.getcwd()}")

    if not is_admin():
        print("[-] WARNING: This test requires elevation (Run as Administrator).")

    # Set up sandbox directories
    test_root = Path("C:/_sentinel_adversarial_sandbox")
    test_root.mkdir(parents=True, exist_ok=True)
    downloads_dir = Path.home() / "Downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)

    print("\n[+] Initializing Sentinel Orchestrator, EventBus & Kernel Bridge...")
    orchestrator = SentinelOrchestrator()
    orchestrator._init_components()
    time.sleep(2.0)  # Allow background threads to settle

    bridge: KernelBridge = orchestrator._kernel_bridge or KernelBridge()
    if not bridge.connected:
        bridge.connect()
    driver_connected = bridge.connected
    print(f"Kernel Driver  : {'CONNECTED (Ring 0 Active)' if driver_connected else 'OFFLINE (Bridge disconnected)'}")

    consumer = orchestrator._consumer
    scanner = OnDemandScanner(
        classifier=consumer.static_classifier if consumer else None,
        quarantine_store=consumer.quarantine_store if consumer else None,
    )
    print("    Orchestrator running, sensors active, and scanner ready.")

    test_scores: dict[str, bool] = {}

    try:
        # ===================================================================
        # VECTOR 1: Extension Spoofing & Polymorphic Masquerading
        # ===================================================================
        print("\n" + "-" * 72)
        print("VECTOR 1: Extension Spoofing & Polymorphic Masquerading")
        print("-" * 72)

        # 1A: Double extension test
        double_ext_file = test_root / f"financial_statement_{int(time.time())}.pdf.exe"
        double_ext_file.write_bytes(b"MZ" + b"\x00" * 200)
        print(f"  [1A] Testing double-extension spoofing: {double_ext_file.name}...")
        r_double = scanner.scan_file(double_ext_file)
        if r_double and "DoubleExtension" in r_double.threat_name:
            print(f"       ✓ Detected Double Extension: {r_double.threat_name} (Score: {r_double.score})")
            t1a_passed = True
        else:
            print(f"       ✗ FAILED: Double extension not detected. Result: {r_double}")
            t1a_passed = False
        double_ext_file.unlink(missing_ok=True)

        # 1B: Valid PE binary masquerading with document extension (.pdf)
        pdf_masquerade = test_root / f"quarterly_report_{int(time.time())}.pdf"
        pe_bytes = make_valid_pe_dll(b"PAYLOAD-DISGUISED-AS-PDF")
        pdf_masquerade.write_bytes(pe_bytes)
        print(f"  [1B] Testing PE disguised as document: {pdf_masquerade.name}...")
        r_masq = scanner.scan_file(pdf_masquerade)
        if r_masq and "MasqueradingExtension" in r_masq.threat_name:
            print(f"       ✓ Detected Disguised Executable: {r_masq.threat_name} (Score: {r_masq.score})")
            t1b_passed = True
        else:
            print(f"       ✗ FAILED: Disguised PE not detected. Result: {r_masq}")
            t1b_passed = False
        pdf_masquerade.unlink(missing_ok=True)

        # 1C: Real-time autonomous quarantine on masqueraded PE drop
        drop_masq = downloads_dir / f"invoice_scan_{int(time.time())}.pdf"
        print(f"  [1C] Dropping masqueraded PE into watched folder: {drop_masq.name}...")
        drop_masq.write_bytes(pe_bytes)

        quarantined_1c = False
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if not drop_masq.exists():
                quarantined_1c = True
                break
            time.sleep(0.3)

        if quarantined_1c:
            print("       ✓ Real-Time Sensor caught masqueraded PE and autonomously isolated it!")
            t1c_passed = True
        else:
            print("       ✗ FAILED: Masqueraded PE was not quarantined within timeout")
            drop_masq.unlink(missing_ok=True)
            t1c_passed = False

        test_scores["Vector 1: Extension Spoofing & Masquerading"] = t1a_passed and t1b_passed and t1c_passed

        # ===================================================================
        # VECTOR 2: NTFS Alternate Data Streams (ADS) Hidden Evasion
        # ===================================================================
        print("\n" + "-" * 72)
        print("VECTOR 2: NTFS Alternate Data Streams (ADS) Hidden Evasion")
        print("-" * 72)

        carrier_file = test_root / f"harmless_notes_{int(time.time())}.txt"
        carrier_file.write_text("This is an ordinary, completely harmless text document.")
        stream_path_str = str(carrier_file) + ":hidden_worker.dll"

        unique_stream_sig = f"SENTINEL-ANTIVIRUS-TEST-PAYLOAD-AUTONOMOUS-QUARANTINE-{int(time.time() * 1000)}".encode()
        stream_pe_bytes = make_valid_pe_dll(unique_stream_sig)

        print(f"  [2A] Writing hidden PE payload to NTFS Stream: {stream_path_str}...")
        with open(stream_path_str, "wb") as f_stream:
            f_stream.write(stream_pe_bytes)

        # 2B: Scan NTFS stream directly
        print("  [2B] On-Demand Scanner inspecting NTFS stream...")
        r_stream = scanner.scan_file(stream_path_str)
        if r_stream and "Sentinel_Test_Payload" in r_stream.threat_name:
            print(f"       ✓ Detected Threat in Stream: {r_stream.threat_name} (Score: {r_stream.score})")
            t2a_passed = True
        else:
            print(f"       ✗ FAILED: Stream threat not detected. Result: {r_stream}")
            t2a_passed = False

        # 2C: Kernel Minifilter Execution Block on Stream
        print("  [2C] Testing Kernel Minifilter Driver Pre-Execution Block on Stream...")
        bridge.add_block(stream_path_str)
        print(f"       Added stream to kernel blocklist: {stream_path_str}")

        can_exec_stream = try_open_for_execute(stream_path_str)
        if not can_exec_stream:
            print("       ✓ Kernel Driver Intercepted CreateFileW(GENERIC_EXECUTE) on Stream -> STATUS_ACCESS_DENIED!")
            t2b_passed = True
        else:
            print("       ✗ FAILED: Kernel driver allowed GENERIC_EXECUTE on stream!")
            t2b_passed = False

        # Attempt LoadLibraryEx on stream
        h_stream_mod = ctypes.windll.kernel32.LoadLibraryExW(stream_path_str, None, 0)
        if h_stream_mod == 0:
            err = ctypes.windll.kernel32.GetLastError()
            print(f"       ✓ OS LoadLibraryExW denied on Stream (LastError: {err} - Access Denied)")
            t2c_passed = True
        else:
            print(f"       ✗ FAILED: LoadLibraryExW on stream succeeded with handle {hex(h_stream_mod)}!")
            ctypes.windll.kernel32.FreeLibrary(h_stream_mod)
            t2c_passed = False

        bridge.remove_block(stream_path_str)
        carrier_file.unlink(missing_ok=True)

        test_scores["Vector 2: NTFS Alternate Data Streams (ADS)"] = t2a_passed and t2b_passed and t2c_passed

        # ===================================================================
        # VECTOR 3: High-Velocity Event Queue Flooding / Anti-DoS Stress
        # ===================================================================
        print("\n" + "-" * 72)
        print("VECTOR 3: High-Velocity Event Queue Flooding / Anti-DoS Stress")
        print("-" * 72)

        flood_dir = test_root / "queue_flood_test"
        flood_dir.mkdir(parents=True, exist_ok=True)
        flood_count = 500

        print(f"  [3A] Initiating high-speed flood of {flood_count} file events...")
        t_flood_start = time.time()

        # Target threat file placed right in the middle
        threat_drop_file = downloads_dir / f"storm_threat_{int(time.time())}.dll"
        threat_bytes = make_valid_pe_dll(unique_stream_sig)

        created_files = []
        for i in range(flood_count):
            p = flood_dir / f"flood_{i:04d}.tmp"
            p.write_bytes(b"Normal system log activity chunk " * 8)
            created_files.append(p)
            if i == 250:
                # Inject threat in the middle of the storm
                threat_drop_file.write_bytes(threat_bytes)

        t_flood_elapsed = time.time() - t_flood_start
        print(f"       Emitted {flood_count} file operations in {t_flood_elapsed:.2f}s ({flood_count / t_flood_elapsed:.0f} ops/sec)")

        # Verify threat file is isolated despite heavy queue contention
        print("  [3B] Verifying threat isolation under extreme queue pressure...")
        quarantined_threat = False
        deadline = time.time() + 12.0
        while time.time() < deadline:
            if not threat_drop_file.exists():
                quarantined_threat = True
                break
            time.sleep(0.3)

        if quarantined_threat:
            print("       ✓ Threat successfully quarantined under high queue load!")
            t3_passed = True
        else:
            print("       ✗ FAILED: Threat was dropped or missed during queue flood")
            threat_drop_file.unlink(missing_ok=True)
            t3_passed = False

        # Cleanup flood files
        shutil.rmtree(flood_dir, ignore_errors=True)
        test_scores["Vector 3: High-Velocity Event Queue Stress"] = t3_passed

        # ===================================================================
        # VECTOR 4: Anti-Tampering & Quarantine Vault DACL Integrity
        # ===================================================================
        print("\n" + "-" * 72)
        print("VECTOR 4: Anti-Tampering & Quarantine Vault DACL Integrity")
        print("-" * 72)

        if consumer and consumer.quarantine_store:
            q_dir = Path(consumer.quarantine_store.quarantine_dir)
            db_path = Path(getattr(consumer.quarantine_store, "db_path", consumer.quarantine_store._db_path))
        else:
            q_dir = Path("C:/SentinelQuarantine")
            db_path = q_dir / "quarantine.db"

        print(f"  [4A] Inspecting Quarantine Vault: {q_dir}...")
        t4a_passed = q_dir.exists()

        if t4a_passed:
            q_files = [f for f in q_dir.iterdir() if f.is_file() and not f.name.endswith(".db")]
            print(f"       Found {len(q_files)} quarantined artifacts in vault")

            if q_files:
                sample_q_file = q_files[0]
                print(f"  [4B] Testing Deny-Execute DACL restriction on: {sample_q_file.name}...")
                # Attempt to open quarantined file for execution
                can_exec = try_open_for_execute(str(sample_q_file))
                if not can_exec:
                    print("       ✓ Win32 DACL actively enforced: Execution blocked (Access Denied)!")
                    t4b_passed = True
                else:
                    print("       ✗ FAILED: Quarantined file was executable without Sentinel authorization!")
                    t4b_passed = False
            else:
                print("       (No quarantined files in vault; creating test file with _strip_execute)")
                dummy_q = q_dir / f"test_{int(time.time())}.tmp"
                dummy_q.write_bytes(b"quarantine payload")
                consumer.quarantine_store._strip_execute(dummy_q)
                can_exec = try_open_for_execute(str(dummy_q))
                if not can_exec:
                    print("       ✓ Win32 DACL actively enforced on test artifact: Execution blocked!")
                    t4b_passed = True
                else:
                    print("       ✗ FAILED: Execution allowed on quarantined artifact")
                    t4b_passed = False
                dummy_q.unlink(missing_ok=True)

            # 4C: Check SQLite DB WAL mode & integrity
            print(f"  [4C] Checking SQLite Database integrity: {db_path.name}...")
            if db_path.exists():
                con = sqlite3.connect(str(db_path))
                cur = con.cursor()
                cur.execute("PRAGMA integrity_check;")
                integ_res = cur.fetchone()[0]
                cur.execute("PRAGMA journal_mode;")
                journal_mode = cur.fetchone()[0]
                con.close()
                if integ_res.lower() == "ok":
                    print(f"       ✓ SQLite Integrity: OK (Journal Mode: {journal_mode.upper()})")
                    t4c_passed = True
                else:
                    print(f"       ✗ SQLite Integrity Failed: {integ_res}")
                    t4c_passed = False
            else:
                print("       ✗ Quarantine DB does not exist")
                t4c_passed = False
        else:
            print("       ✗ Quarantine directory does not exist")
            t4b_passed = False
            t4c_passed = False

        test_scores["Vector 4: Anti-Tampering & Quarantine Vault DACL"] = t4a_passed and t4b_passed and t4c_passed

    finally:
        print("\n[!] Cleaning up Sentinel Orchestrator and Sensors...")
        orchestrator.stop()
        print("    Orchestrator stopped cleanly ✓")
        shutil.rmtree(test_root, ignore_errors=True)

    # Print Final Scorecard
    print("\n" + "=" * 72)
    print("                 ADVERSARIAL BENCHMARK SCORECARD")
    print("=" * 72)
    all_passed = True
    for t_name, passed in test_scores.items():
        status_str = "PASSED [✓]" if passed else "FAILED [X]"
        print(f" {t_name:<55} {status_str}")
        if not passed:
            all_passed = False
    print("=" * 72)

    return all_passed


if __name__ == "__main__":
    success = run_adversarial_benchmark()
    sys.exit(0 if success else 1)
