"""CreateRemoteThread-on-self harness — validates the DLL/behavioral detector.

Simulates:
    A process calling CreateRemoteThread on ITSELF (self-injection). This
    exercises the DLL / image-load handling pipeline WITHOUT injecting into
    any other process.

What it exercises:
    1. Calls ``kernel32.CreateRemoteThread`` targeting its own process handle
    2. The thread runs a trivial function (no-op) and exits immediately
    3. The ETW sensor (if running elevated) captures the thread creation event
    4. The DLL scoring pipeline should classify this as a SELF-LOAD (ignored,
       per architecture.md Section 5.3: "a process loading its own DLL from
       its own directory is routine and ignored")

Safety:
    - The target is ALWAYS the calling process itself (``GetCurrentProcess()``)
    - The thread function is a no-op (``ExitThread(0)``)
    - No code is injected into any other process
    - No DLL is loaded — it's a bare thread creation
    - On non-Windows or if ctypes fails, the script prints a diagnostic and exits

Usage:
    cd "C:\\Users\\littlemukti\\OneDrive\\Documents\\pgt app\\antivirus"
    .venv\\Scripts\\python.exe -m sentinel.tests.test_harness.inject_self

Note:
    Per architecture.md Section 5.3, self-loads/self-threads are routine and
    IGNORED. This harness validates that the detector correctly identifies
    self-injection and does NOT produce a cross-process signal (false positive).
"""
from __future__ import annotations

import os
import sys

from sentinel.engine.scoring import DllLoadContext, Scorer, score_dll_load, DllReputationCache


def run_ctypes_self_inject() -> bool:
    """Call CreateRemoteThread on the current process (self-injection)."""
    print("=== CreateRemoteThread-on-Self Harness ===")
    print(f"  PID: {os.getpid()}")
    print(f"  Safety: targets only this process (GetCurrentProcess)")
    print()

    if sys.platform != "win32":
        print("  [SKIP] Not on Windows — CreateRemoteThread is a Win32 API")
        return True

    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # Get a handle to the current process.
        handle = kernel32.GetCurrentProcess()
        print(f"  [1] GetCurrentProcess() handle: {handle}")

        # Create a remote thread in our OWN process that calls ExitThread(0).
        # This is a no-op: the thread is created, runs ExitThread, and dies.
        exit_thread = kernel32.ExitThread
        thread_id = wintypes.DWORD(0)
        thread_handle = kernel32.CreateRemoteThread(
            handle,           # hProcess — our own process
            None,             # lpThreadAttributes
            0,                # dwStackSize (default)
            exit_thread,      # lpStartAddress — just ExitThread
            0,                # lpParameter — exit code 0
            0,                # dwCreationFlags
            ctypes.byref(thread_id),
        )

        if thread_handle:
            print(f"  [2] CreateRemoteThread succeeded (thread ID: {thread_id.value})")
            kernel32.CloseHandle(thread_handle)
        else:
            error = ctypes.get_last_error()
            print(f"  [2] CreateRemoteThread failed (error: {error})")
            print("      This is OK — some security software blocks self-CRT")
    except Exception as exc:
        print(f"  [2] ctypes call failed: {exc!r}")
        print("      This is expected on some locked-down systems")

    # Now validate the SCORING side: a self-load should produce NO signals.
    print()
    print("  [3] Validating scoring: self-injection should be ignored...")
    ctx = DllLoadContext(
        dll_hash="deadbeef" * 8,
        publisher=None,
        loader_pid=os.getpid(),
        target_pid=os.getpid(),    # SELF — same PID
        loader_image="python.exe",
        dll_path=None,
        signed=False,
        reflective=False,
    )
    reputation = DllReputationCache()
    signals = score_dll_load(ctx, reputation)

    if not signals:
        print(f"  [PASS] Self-injection produced 0 signals (correctly ignored)")
        return True
    else:
        print(f"  [FAIL] Self-injection produced {len(signals)} signals "
              f"(should be 0): {[s.kind for s in signals]}")
        return False


def main() -> int:
    ok = run_ctypes_self_inject()
    print(f"\n{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

