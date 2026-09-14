"""Live Verification Script: Deep Threat Model & Real PE Machine Learning.

Validates the expanded Sentinel threat model inside the live Windows VM:
- Vector 1: Real ML Model Inference (Real trained weights vs 10-line scaffolding)
- Vector 2: Memory Malware (Unbacked RWX memory, reflective DLL, shellcode stubs)
- Vector 3: Command & Control (C2) Detection (Statistical jitter beaconing & C2 threat intel blocking)
- Vector 4: Behavioral Execution Sandbox (Windows Job Object containment, dropped payload trapping)

Run elevated inside the SentinelDriver VM:
    cd "C:\\Users\\User\\sentinel_test"
    .venv\\Scripts\\python.exe -m sentinel.tests.verify_deep_threat_model_live
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import logging
import os
import sys
import time
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel.verify_live")


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_all_checks() -> bool:
    print()
    print("=" * 78)
    print("       SENTINEL ANTIVIRUS — DEEP THREAT MODEL & REAL ML VERIFICATION")
    print("=" * 78)
    print(f"  OS Platform:     Windows {sys.getwindowsversion().major}.{sys.getwindowsversion().minor}")
    print(f"  Python Process:  PID {os.getpid()} ({sys.executable})")
    print(f"  Elevated Admin:  {'YES [Admin]' if is_admin() else 'NO (Standard User)'}")
    print("=" * 78)
    print()

    all_passed = True
    results: list[tuple[str, bool, str]] = []

    # -----------------------------------------------------------------------
    # VECTOR 1: Real ML Model Inference (Trained on 350+ Real Binaries)
    # -----------------------------------------------------------------------
    print("[VECTOR 1] Real PE Machine Learning Anomaly Detection...")
    v1_passed = False
    v1_detail = ""
    try:
        from sentinel.engine.static_classifier import PEFeatureModel, PEFeatures
        model = PEFeatureModel()

        is_real = model._fitted and bool(model.metadata)
        sample_count = model.metadata.get("num_samples", len(model._BASELINE))

        # Test Clean Binary Profile (e.g. system utility)
        clean_pe = PEFeatures(
            file_size=205000,
            num_sections=6,
            entry_point=0x1500,
            file_entropy=6.1,
            has_debug=True,
            has_signature=True,
            num_imports=85,
            num_exports=0,
            suspicious_section_count=0,
            avg_section_entropy=5.8,
            max_section_entropy=6.5,
            min_section_raw_size=512,
        )
        clean_suspicious = model.is_suspicious(clean_pe)

        # Test Anomalous Packed PE Profile (high entropy, UPX sections, tiny raw size)
        mal_pe = PEFeatures(
            file_size=85000,
            num_sections=3,
            entry_point=0x14000,
            file_entropy=7.92,
            has_debug=False,
            has_signature=False,
            num_imports=2,
            num_exports=0,
            suspicious_section_count=2,
            avg_section_entropy=7.4,
            max_section_entropy=7.98,
            min_section_raw_size=256,
        )
        mal_suspicious = model.is_suspicious(mal_pe)

        if is_real and sample_count >= 100 and not clean_suspicious and mal_suspicious:
            v1_passed = True
            v1_detail = f"Model loaded with {sample_count} real samples; Clean=Inlier, Packed=Outlier"
        else:
            v1_detail = f"Fitted={model._fitted}, Samples={sample_count}, CleanSusp={clean_suspicious}, MalSusp={mal_suspicious}"
    except Exception as exc:
        v1_detail = f"Exception: {exc}"

    print(f"  Result: {'PASSED [OK]' if v1_passed else 'FAILED [X]'} — {v1_detail}")
    results.append(("Real PE Machine Learning Model", v1_passed, v1_detail))
    all_passed = all_passed and v1_passed
    print()

    # -----------------------------------------------------------------------
    # VECTOR 2: Memory Malware & Shellcode Detection (Unbacked RWX)
    # -----------------------------------------------------------------------
    print("[VECTOR 2] Memory Malware & Shellcode Inspection (VirtualQueryEx)...")
    v2_passed = False
    v2_detail = ""
    try:
        from sentinel.engine.memory_scanner import MemoryScanner
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.VirtualAlloc.restype = ctypes.c_void_p
        k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]

        # Allocate simulated unbacked PAGE_EXECUTE_READWRITE memory page
        rwx_addr = k32.VirtualAlloc(None, 4096, 0x1000, 0x40)
        assert rwx_addr is not None

        try:
            # Write reflective DLL MZ header + Cobalt Strike shellcode pattern
            # \xfc\xe8... (cld; call)
            payload = b"MZ\x90\x00\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64"
            ctypes.memmove(rwx_addr, payload, len(payload))

            scanner = MemoryScanner()
            threats = scanner.scan_process(os.getpid(), process_name="live_target.exe")

            caught_types = [t.threat_type for t in threats]
            signals = [t.to_signal() for t in threats]
            sig_kinds = [s.kind for s in signals]

            has_reflective = "reflective_pe" in caught_types
            has_unbacked = "unbacked_executable" in caught_types
            has_signal = "memory_shellcode" in sig_kinds

            if has_reflective and has_unbacked and has_signal:
                v2_passed = True
                v2_detail = f"Caught unbacked RWX @ 0x{rwx_addr:x}: {caught_types} (signals: {sig_kinds})"
            else:
                v2_detail = f"Threats: {caught_types}, Signals: {sig_kinds}"
        finally:
            k32.VirtualFree.restype = wintypes.BOOL
            k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
            k32.VirtualFree(ctypes.c_void_p(rwx_addr), 0, 0x8000)

    except Exception as exc:
        v2_detail = f"Exception: {exc}"

    print(f"  Result: {'PASSED [OK]' if v2_passed else 'FAILED [X]'} — {v2_detail}")
    results.append(("Memory Malware & Shellcode Detector", v2_passed, v2_detail))
    all_passed = all_passed and v2_passed
    print()

    # -----------------------------------------------------------------------
    # VECTOR 3: Command & Control (C2) Detection & Threat Intel Blocking
    # -----------------------------------------------------------------------
    print("[VECTOR 3] Command & Control (C2) Beaconing & Threat Intel Blocking...")
    v3_passed = False
    v3_detail = ""
    try:
        from sentinel.engine.heuristics_c2 import C2BeaconDetector, C2Blocklist
        from sentinel.engine.schema import Event, utc_timestamp

        # 1. Threat Intel Blocklist Match
        blocklist = C2Blocklist()
        ev_threat = Event(
            timestamp=utc_timestamp(),
            source="network",
            event_type="connection",
            pid=7788,
            image_path=r"C:\Windows\Temp\mal.exe",
            extra={"remote_ip": "194.38.20.15", "dest_port": 443},
        )
        sig_intel = blocklist.check_connection(ev_threat)

        # 2. Periodic Machine Beaconing (Jitter CV < 0.20)
        detector = C2BeaconDetector(cv_threshold=0.20, cooldown_seconds=0.0)
        sig_beacon = None
        now_base = 1000.0
        # 5 periodic connections with 5.0s delta ± 0.05s jitter
        for dt in [0.0, 5.02, 10.01, 15.04, 20.02]:
            ev_beacon = Event(
                timestamp=utc_timestamp(),
                source="network",
                event_type="connection",
                pid=8899,
                image_path=r"C:\Windows\System32\rundll32.exe",
                extra={"remote_ip": "198.51.100.77", "dest_port": 443},
            )
            import unittest.mock as mock
            with mock.patch("time.time", return_value=now_base + dt):
                sig = detector.process_connection(ev_beacon)
                if sig:
                    sig_beacon = sig

        intel_ok = sig_intel is not None and sig_intel.kind == "c2_threat_intel" and sig_intel.effective_weight == 85.0
        beacon_ok = sig_beacon is not None and sig_beacon.kind == "c2_beaconing" and sig_beacon.effective_weight == 40.0

        if intel_ok and beacon_ok:
            v3_passed = True
            v3_detail = "C2 Intel matched (score 85.0) & Periodic Beaconing detected (score 40.0)"
        else:
            v3_detail = f"Intel_ok={intel_ok}, Beacon_ok={beacon_ok}"

    except Exception as exc:
        v3_detail = f"Exception: {exc}"

    print(f"  Result: {'PASSED [OK]' if v3_passed else 'FAILED [X]'} — {v3_detail}")
    results.append(("C2 Beaconing & Threat Intel Blocking", v3_passed, v3_detail))
    all_passed = all_passed and v3_passed
    print()

    # -----------------------------------------------------------------------
    # VECTOR 4: Behavioral Sandbox (Windows Job Objects Containment)
    # -----------------------------------------------------------------------
    print("[VECTOR 4] Behavioral Sandbox Containment (Windows Job Objects)...")
    v4_passed = False
    v4_detail = ""
    try:
        from sentinel.sandbox.runner import SandboxRunner
        runner = SandboxRunner(max_duration_seconds=5.0, max_memory_mb=128, cpu_percent_limit=20)
        cmd_path = Path(os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"))

        # Test 1: Benign program execution in sandbox
        benign_rep = runner.run_binary(cmd_path, args=["/c", "exit 0"])

        # Test 2: Malicious dropper simulation (spawns dropped executable)
        dropper_rep = runner.run_binary(cmd_path, args=["/c", "echo malicious > dropped_payload.exe"])

        benign_clean = not benign_rep.is_malicious and benign_rep.exit_code == 0
        dropper_caught = dropper_rep.is_malicious and "dropped_payload.exe" in dropper_rep.dropped_executables
        dropper_sigs = dropper_rep.to_signals()
        sig_ok = len(dropper_sigs) > 0 and dropper_sigs[0].kind == "sandbox_malicious" and dropper_sigs[0].effective_weight == 85.0

        if benign_clean and dropper_caught and sig_ok:
            v4_passed = True
            v4_detail = f"Job Object contained execution; Dropper trapped: {dropper_rep.dropped_executables} (score 85.0)"
        else:
            v4_detail = f"BenignClean={benign_clean}, DropperCaught={dropper_caught}, SigOk={sig_ok}"

    except Exception as exc:
        v4_detail = f"Exception: {exc}"

    print(f"  Result: {'PASSED [OK]' if v4_passed else 'FAILED [X]'} — {v4_detail}")
    results.append(("Behavioral Job Object Sandbox", v4_passed, v4_detail))
    all_passed = all_passed and v4_passed
    print()

    # -----------------------------------------------------------------------
    # SCORECARD SUMMARY
    # -----------------------------------------------------------------------
    print("=" * 78)
    print("                   DEEP THREAT MODEL VERIFICATION SCORECARD")
    print("=" * 78)
    print(f"{'Vector':<38} | {'Status':<10} | {'Details'}")
    print("-" * 78)
    for name, ok, detail in results:
        status_str = "PASSED [OK]" if ok else "FAILED [X]"
        print(f"{name:<38} | {status_str:<10} | {detail[:26]}")
    print("=" * 78)
    verdict = "100% COMPLIANT -- ALL VECTORS DEFEATED" if all_passed else "VERIFICATION FAILED"
    print(f"OVERALL VERDICT: {verdict}")
    print("=" * 78)
    print()

    return all_passed


if __name__ == "__main__":
    success = run_all_checks()
    sys.exit(0 if success else 1)
