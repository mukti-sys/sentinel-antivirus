"""Unit tests for sentinel/sandbox/emulator.py and dynamic analysis."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
import pytest

from sentinel.sandbox.emulator import (
    DynamicEmulator,
    VirtualMemory,
    ror13,
    KNOWN_API_ROR13_HASHES,
)
from sentinel.sandbox.isolation import SandboxIsolation
from sentinel.sandbox.runner import SandboxRunner, SandboxReport


def test_virtual_memory_operations():
    """Verify virtual memory page allocation, read/write, and page modification tracking."""
    vm = VirtualMemory(is_64bit=True)
    base = 0x400000

    vm.alloc(base, 8192, "RWX")
    assert base in vm.pages
    assert (base + 4096) in vm.pages

    # Write & read bytes
    test_data = b"Hello Sentinel Virtual Memory"
    vm.write_bytes(base + 0x50, test_data)
    assert vm.read_bytes(base + 0x50, len(test_data)) == test_data

    # Integers
    vm.write_u32(base + 0x100, 0x12345678)
    assert vm.read_u32(base + 0x100) == 0x12345678

    vm.write_u64(base + 0x200, 0x1122334455667788)
    assert vm.read_u64(base + 0x200) == 0x1122334455667788

    # Modified buffers
    buffers = vm.get_modified_buffers()
    assert len(buffers) >= 1
    assert b"Hello Sentinel" in buffers[0]


def test_ror13_hash_calculation():
    """Verify ROR13 API hash computation matches known shellcode signatures."""
    assert ror13("LoadLibraryA") == 0xEC0E4E8E
    assert ror13("GetProcAddress") == 0x7C0DFCAA
    assert ror13("VirtualAlloc") == 0x91AFCA54
    assert ror13("IsDebuggerPresent") == 0xA36DC676


def test_emulator_detects_anti_debug_rdtsc():
    """Verify emulator detects RDTSC timing evasion."""
    emulator = DynamicEmulator(max_instructions=50)

    # Shellcode: 0x0F 0x31 (RDTSC), 0x90 (NOP), 0xC3 (RET)
    shellcode = b"\x0F\x31\x90\xC3"
    result = emulator.emulate("test_rdtsc.bin", raw_data=shellcode)

    assert "AntiAnalysis:RDTSCTimingCheck" in result.evasion_techniques
    assert result.instructions_executed >= 2
    assert result.is_suspicious is True


def test_emulator_detects_peb_walk():
    """Verify emulator detects direct PEB walking (fs:[0x30])."""
    emulator = DynamicEmulator(max_instructions=50)

    # Shellcode: mov eax, fs:[0x30] (0x64 0xA1 0x30 0x00 0x00 0x00), RET (0xC3)
    shellcode = b"\x64\xA1\x30\x00\x00\x00\xC3"
    result = emulator.emulate("test_peb.bin", raw_data=shellcode)

    assert "AntiAnalysis:DirectPEBWalk" in result.evasion_techniques
    assert result.instructions_executed >= 1
    assert result.is_suspicious is True


def test_emulator_detects_api_hashing():
    """Verify emulator intercepts ROR13 API resolution loops."""
    emulator = DynamicEmulator(max_instructions=50)

    # Shellcode setting EAX to ROR13 hash of VirtualAlloc (0x91AFCA54),
    # followed by ror eax, 13 (0xC1 0xC8 0x0D), then ret (0xC3)
    # 0xB8 0x54 0xCA 0xAF 0x91 = mov eax, 0x91AFCA54
    # 0xC1 0xC8 0x0D          = ror eax, 13
    # 0xC3                   = ret
    shellcode = b"\xB8\x54\xCA\xAF\x91\xC1\xC8\x0D\xC3"
    result = emulator.emulate("test_api_hash.bin", raw_data=shellcode)

    assert any("ApiHashing:ROR13(VirtualAlloc)" in ev for ev in result.evasion_techniques)
    assert any(c.api_name == "VirtualAlloc" for c in result.api_calls)
    assert result.rwx_allocations >= 1


def test_emulator_unpacking_and_yara_rescan(tmp_path):
    """Verify emulator extracts unpacked memory and triggers YARA rescan."""
    emulator = DynamicEmulator(max_instructions=200, enable_yara_rescan=True)

    # Self-modifying / unpacking pattern:
    # Set EDI to stack/destination, perform repeated STOSB (0xAA) writing into destination
    # 0xBF 0x00 0x00 0x0F 0x00 = mov edi, 0x000F0000
    # 0xB0 0x58                = mov al, 0x58 ('X')
    # 0xAA 0xAA 0xAA 0xAA ...  = stosb (write bytes)
    # 0xC3                     = ret
    shellcode = b"\xBF\x00\x00\x0F\x00\xB0\x58" + (b"\xAA" * 128) + b"\xC3"
    result = emulator.emulate("test_unpack.bin", raw_data=shellcode)

    assert len(result.unpacked_payload_sizes) > 0
    assert any("Self-decrypting" in r for r in result.threat_reasons)
    assert result.is_suspicious is True


def test_sandbox_runner_unified_analyze(tmp_path):
    """Verify SandboxRunner analyze() dispatches correctly and produces rich report."""
    runner = SandboxRunner(max_duration_seconds=2.0)

    # Create dummy benign shellcode file
    dummy = tmp_path / "benign.bin"
    dummy.write_bytes(b"\x90\x90\x90\x90\xC3")

    report = runner.analyze(dummy, mode="emulation")
    assert report.target_path == str(dummy)
    assert report.is_malicious is False
    assert report.analysis_mode == "emulation"
    assert report.instructions_executed > 0


def test_sandbox_signals_conversion():
    """Verify SandboxReport correctly converts dynamic analysis findings into signals."""
    report = SandboxReport(
        target_path="sample.exe",
        duration_seconds=0.5,
        unpacked_yara_matches=["Trojan.Generic", "CobaltStrike.Beacon"],
        evasion_techniques=["AntiDebug:IsDebuggerPresent"],
        threat_reasons=["Unpacked memory matched YARA signature"],
        risk_score=90.0,
    )

    assert report.is_malicious is True
    signals = report.to_signals()
    assert len(signals) >= 2

    # Should have unpacked yara signal (weight 90) and evasion signal (weight 35)
    kinds = {s.kind: s.effective_weight for s in signals}
    assert "sandbox_unpacked_yara" in kinds
    assert kinds["sandbox_unpacked_yara"] == 90.0
    assert "sandbox_evasion_detected" in kinds
    assert kinds["sandbox_evasion_detected"] == 35.0


def test_sandbox_isolation_lifecycle(tmp_path):
    """Verify cross-platform SandboxIsolation executes command with resource containment."""
    isolation = SandboxIsolation(max_memory_mb=64, cpu_percent_limit=20, max_duration_seconds=3.0)
    py_exe = sys.executable

    exit_code, timed_out = isolation.run_isolated(
        cmd=[py_exe, "-c", "import sys; sys.exit(0)"],
        work_dir=tmp_path,
        timeout=3.0,
    )
    assert exit_code == 0
    assert timed_out is False
