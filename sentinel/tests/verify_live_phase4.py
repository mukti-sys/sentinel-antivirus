"""Phase 4 Definition-of-Done live verification test.

⚠️  REQUIREMENTS (all in VM only):
    - Elevated terminal (Run as Administrator)
    - Test signing enabled (bcdedit /set testsigning on + reboot)
    - SentinelFilter.sys loaded (fltmc load SentinelFilter)
    - Python + sentinel package available

This test:
1. Creates a test .exe in a temp directory
2. Adds its path to the kernel blocklist via the bridge
3. Attempts to open the file with FILE_EXECUTE access
4. Verifies that the open returns STATUS_ACCESS_DENIED
5. Removes the path from the blocklist
6. Verifies the open now succeeds
7. Cleans up

If all steps pass, Phase 4 Definition of Done is MET.
"""
from __future__ import annotations

import ctypes
import os
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path

from sentinel.kernel.bridge import KernelBridge

# Windows constants for CreateFileW.
GENERIC_EXECUTE   = 0x20000000
FILE_SHARE_READ   = 0x00000001
OPEN_EXISTING     = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE  = wintypes.HANDLE(-1).value

# Minimal PE stub (MZ header + "This program cannot be run in DOS mode").
MINIMAL_EXE = (
    b"MZ" + b"\x90" * 58 +                              # DOS header
    b"\x50\x45\x00\x00" +                                # PE\0\0 signature
    b"\x64\x86" +                                        # Machine: AMD64
    b"\x00" * 100                                        # Minimal PE fields
)


def create_test_exe(directory: Path) -> Path:
    """Create a minimal test .exe file."""
    exe_path = directory / "sentinel_phase4_dod_test.exe"
    exe_path.write_bytes(MINIMAL_EXE)
    return exe_path


def try_open_for_execute(path: str) -> bool:
    """Try to open a file with GENERIC_EXECUTE access.

    Returns True if the open succeeded, False if access was denied.
    Raises on unexpected errors.
    """
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

    # Success — close the handle.
    kernel32.CloseHandle(handle)
    return True


def main():
    print("=" * 60)
    print("  Phase 4 — Definition of Done Verification")
    print("  (Run in VM only, elevated, with driver loaded)")
    print("=" * 60)
    print()

    # Step 0: Check prerequisites.
    print("[0] Checking prerequisites...")
    bridge = KernelBridge()
    if not bridge.connect():
        print("   FAIL: Cannot connect to SentinelFilter driver.")
        print("   Is the driver loaded? (fltmc load SentinelFilter)")
        sys.exit(1)
    print("   Connected to SentinelFilter ✓")

    status = bridge.get_status()
    print(f"   Driver status: {status}")

    with tempfile.TemporaryDirectory(prefix="sentinel_dod_") as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Step 1: Create test exe.
        print("\n[1] Creating test executable...")
        exe_path = create_test_exe(tmpdir_path)
        print(f"   Created: {exe_path}")

        # Step 2: Verify the file can be opened BEFORE blocking.
        print("\n[2] Opening file with GENERIC_EXECUTE (should succeed)...")
        if try_open_for_execute(str(exe_path)):
            print("   Open succeeded ✓ (file is NOT blocked)")
        else:
            print("   FAIL: File is already blocked before we added it!")
            bridge.disconnect()
            sys.exit(1)

        # Step 3: Add to blocklist.
        print("\n[3] Adding to kernel blocklist...")
        if bridge.add_block(str(exe_path)):
            print(f"   Blocked: {exe_path} ✓")
        else:
            print("   FAIL: bridge.add_block returned False")
            bridge.disconnect()
            sys.exit(1)

        # Step 4: Try to open — should be DENIED.
        print("\n[4] Opening file with GENERIC_EXECUTE (should FAIL)...")
        if try_open_for_execute(str(exe_path)):
            print("   FAIL: File was NOT blocked by the driver!")
            print("   The kernel minifilter did not deny the access.")
            bridge.remove_block(str(exe_path))
            bridge.disconnect()
            sys.exit(1)
        else:
            print("   Access DENIED ✓ (driver blocked the file)")

        # Step 5: Remove from blocklist.
        print("\n[5] Removing from kernel blocklist...")
        bridge.remove_block(str(exe_path))
        print("   Unblocked ✓")

        # Step 6: Try to open again — should succeed.
        print("\n[6] Opening file with GENERIC_EXECUTE (should succeed)...")
        if try_open_for_execute(str(exe_path)):
            print("   Open succeeded ✓ (file is no longer blocked)")
        else:
            print("   FAIL: File is still blocked after removal!")
            bridge.disconnect()
            sys.exit(1)

    bridge.disconnect()

    print()
    print("=" * 60)
    print("  ✓ PHASE 4 DEFINITION OF DONE: VERIFIED")
    print("  A test file was blocked from executing at all,")
    print("  not just suspended after starting.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
