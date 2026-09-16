"""Unit tests for memory_scanner.py — unbacked executable memory and shellcode detection."""
import ctypes
import os
import sys
from ctypes import wintypes
import pytest

from sentinel.engine.memory_scanner import (
    MEM_COMMIT,
    MEM_IMAGE,
    MEM_PRIVATE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE,
    MemoryRegion,
    MemoryScanner,
    MemoryThreat,
)


def test_memory_region_properties():
    """Verify dataclass calculation for unbacked executable regions."""
    # Legitimate mapped image code
    legit = MemoryRegion(
        base_address=0x10000,
        size=4096,
        state=MEM_COMMIT,
        protect=PAGE_EXECUTE_READ,
        mem_type=MEM_IMAGE,
    )
    assert legit.is_executable is True
    assert legit.is_private is False
    assert legit.is_unbacked_executable is False

    # Normal private heap/stack data (non-executable)
    heap = MemoryRegion(
        base_address=0x20000,
        size=4096,
        state=MEM_COMMIT,
        protect=PAGE_READWRITE,
        mem_type=MEM_PRIVATE,
    )
    assert heap.is_executable is False
    assert heap.is_private is True
    assert heap.is_unbacked_executable is False

    # Injected unbacked executable memory
    injected = MemoryRegion(
        base_address=0x30000,
        size=4096,
        state=MEM_COMMIT,
        protect=PAGE_EXECUTE_READWRITE,
        mem_type=MEM_PRIVATE,
    )
    assert injected.is_executable is True
    assert injected.is_private is True
    assert injected.is_unbacked_executable is True


def test_memory_threat_to_signal():
    """Verify Signal mapping and weights."""
    threat = MemoryThreat(
        pid=1234,
        process_name="svchost.exe",
        base_address=0x7FFF1000,
        size=4096,
        threat_type="reflective_pe",
        description="Reflective DLL injection",
        confidence=0.95,
    )
    sig = threat.to_signal()
    assert sig.kind == "memory_shellcode"
    assert sig.subject == "pid:1234"
    assert sig.effective_weight == 80.0
    assert "reflective_pe" in sig.reason


@pytest.mark.skipif(sys.platform != "win32", reason="Requires Windows")
def test_live_memory_scanner_catches_simulated_rwx():
    """Simulate in-process memory injection and verify that MemoryScanner detects it."""
    import struct
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]

    # Allocate a PAGE_EXECUTE_READWRITE block (MEM_PRIVATE)
    addr = k32.VirtualAlloc(None, 4096, 0x1000, 0x40)
    assert addr is not None

    try:
        scanner = MemoryScanner()

        # Step 1: Arbitrary buffer with MZ text prefix should NOT trigger reflective_pe (false positive resistance)
        ctypes.memmove(addr, b"MZ arbitrary non-PE buffer data for testing", 40)
        threats = scanner.scan_process(os.getpid(), process_name="test_target.exe")
        types = [t.threat_type for t in threats]
        assert "reflective_pe" not in types
        # But still caught as unbacked RWX in non-JIT process
        assert "unbacked_executable" in types

        # Step 2: Write simulated verified reflective DLL (valid DOS + NT headers)
        pe_header = bytearray(
            b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80) + b"\x00" * 0x40 + b"PE\0\0" + struct.pack("<H", 0x8664) + b"\x00" * 100
        )
        ctypes.memmove(addr, bytes(pe_header), len(pe_header))
        threats = scanner.scan_process(os.getpid(), process_name="test_target.exe")
        types = [t.threat_type for t in threats]
        assert "reflective_pe" in types
        assert "unbacked_executable" in types

        # Check address and confidence
        match = next(t for t in threats if t.threat_type == "reflective_pe")
        assert match.base_address == addr
        assert match.confidence >= 0.95

        # Step 3: Write genuine adversary shellcode (x64 PEB walk)
        shellcode = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00" + b"\x90" * 20
        ctypes.memmove(addr, shellcode, len(shellcode))
        threats = scanner.scan_process(os.getpid(), process_name="test_target.exe")
        types = [t.threat_type for t in threats]
        assert "shellcode_signature" in types

        # Step 4: Verify JIT process exemption from raw unbacked RWX
        # Normal data in JIT process should not trigger unbacked_executable
        ctypes.memmove(addr, b"\xcc" * 64, 64)
        jit_threats = scanner.scan_process(os.getpid(), process_name="powershell.exe")
        jit_types = [t.threat_type for t in jit_threats]
        assert "unbacked_executable" not in jit_types

    finally:
        k32.VirtualFree.restype = wintypes.BOOL
        k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
        k32.VirtualFree(ctypes.c_void_p(addr), 0, 0x8000)

