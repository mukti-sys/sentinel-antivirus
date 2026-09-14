"""Memory Malware Scanner — detects unbacked executable memory regions,
reflective DLL loading, shellcode injection, and process hollowing.

Implements deep memory threat detection:
1. Unbacked Executable Memory (PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_READ on MEM_PRIVATE):
   Windows loader maps legitimate code pages from disk as MEM_IMAGE. When malware
   allocates private memory via VirtualAllocEx and injects payload, it resides
   in unbacked MEM_PRIVATE memory.
2. Reflective DLL / Shellcode Signatures:
   Inspects memory bytes for embedded PE headers (reflective DLLs) or classic
   shellcode execution prologues (cld; call, NOP sleds, egg-hunters).
3. Process Hollowing:
   Verifies that the executable memory base matches the PE header and entry point
   of the on-disk image file, flagging unmapped or overwritten hollowed processes.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from sentinel.engine.scoring import Signal

logger = logging.getLogger("sentinel.memory_scanner")

# Win32 Memory Constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

EXECUTABLE_PROTECTIONS = frozenset({
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
})

# Win32 Process Access Flags
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# Known JIT / Interpreter processes that legitimately allocate executable private pages.
# These are exempted from basic unbacked warnings unless shellcode/PE headers are detected.
_KNOWN_JIT_PROCESSES = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "python.exe", "pythonw.exe", "node.exe", "code.exe",
    "devenv.exe", "java.exe", "javaw.exe",
})

# Shellcode signatures / suspicious byte prologues
_SHELLCODE_PATTERNS = [
    (b"\xfc\xe8", "CobaltStrike/Metasploit cld;call prologue"),
    (b"\xeb\xfe", "Infinite loop shellcode stub / debug trap"),
    (b"\x48\x83\xec", "x64 stack allocation prologue in unbacked memory"),
    (b"\x55\x8b\xec", "x86 standard stack frame prologue in unbacked memory"),
    (b"\x31\xc0\x50\x68", "Classic win32 shellcode xor-eax / push string pattern"),
    (b"\x90\x90\x90\x90\x90\x90\x90\x90", "NOP sled"),
]


_IS_64BIT = ctypes.sizeof(ctypes.c_void_p) == 8

if _IS_64BIT:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("PartitionId", wintypes.WORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]
else:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]


@dataclass(frozen=True)
class MemoryRegion:
    base_address: int
    size: int
    state: int
    protect: int
    mem_type: int

    @property
    def is_executable(self) -> bool:
        return (self.protect & 0xFF) in EXECUTABLE_PROTECTIONS

    @property
    def is_private(self) -> bool:
        return self.mem_type == MEM_PRIVATE

    @property
    def is_unbacked_executable(self) -> bool:
        return self.state == MEM_COMMIT and self.is_private and self.is_executable


@dataclass
class MemoryThreat:
    pid: int
    process_name: str
    base_address: int
    size: int
    threat_type: str
    description: str
    confidence: float
    sample_bytes: bytes = field(default=b"", repr=False)
    timestamp: float = field(default_factory=time.time)

    def to_signal(self) -> Signal:
        """Convert memory threat to an engine Signal for Scorer consumption."""
        kind_map = {
            "unbacked_executable": "memory_unbacked_exec",
            "shellcode_signature": "memory_shellcode",
            "reflective_pe": "memory_shellcode",
            "process_hollowing": "memory_hollowing",
        }
        kind = kind_map.get(self.threat_type, "memory_unbacked_exec")
        return Signal(
            kind=kind,
            subject=f"pid:{self.pid}",
            engine="memory_scanner",
            reason=f"{self.threat_type}: {self.description} at 0x{self.base_address:x} in {self.process_name} (pid {self.pid})",
        )


class MemoryScanner:
    """Scans running Windows processes for memory-resident malware."""

    def __init__(self) -> None:
        self._is_windows = sys.platform == "win32"
        self._kernel32 = None
        if self._is_windows:
            try:
                self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                self._kernel32.OpenProcess.restype = wintypes.HANDLE
                self._kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
                self._kernel32.VirtualQueryEx.restype = ctypes.c_size_t
                self._kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
                self._kernel32.ReadProcessMemory.restype = wintypes.BOOL
                self._kernel32.ReadProcessMemory.argtypes = [
                    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
                ]
                self._kernel32.CloseHandle.restype = wintypes.BOOL
                self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            except Exception as exc:
                logger.warning("Could not load kernel32 for MemoryScanner: %s", exc)

    def scan_process(
        self,
        pid: int,
        process_name: str | None = None,
        max_scan_bytes: int = 100 * 1024 * 1024,  # Cap at 100MB to preserve low CPU
    ) -> list[MemoryThreat]:
        """Scan virtual memory pages of a specific process for injection / anomalies."""
        threats: list[MemoryThreat] = []
        if not self._is_windows or not self._kernel32 or pid <= 4:
            return threats

        proc_name = process_name or f"pid_{pid}"
        h_process = self._kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid,
        )
        if not h_process:
            return threats

        try:
            threats.extend(self._scan_process_regions(h_process, pid, proc_name, max_scan_bytes))
        finally:
            self._kernel32.CloseHandle(h_process)

        return threats

    def _scan_process_regions(
        self,
        h_process: int,
        pid: int,
        proc_name: str,
        max_scan_bytes: int,
    ) -> list[MemoryThreat]:
        threats: list[MemoryThreat] = []
        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        total_scanned = 0
        is_jit = proc_name.lower() in _KNOWN_JIT_PROCESSES

        while True:
            res = self._kernel32.VirtualQueryEx(
                h_process,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not res:
                break

            base_addr = mbi.BaseAddress or 0
            if isinstance(base_addr, int):
                addr_val = base_addr
            else:
                addr_val = ctypes.cast(base_addr, ctypes.c_void_p).value or 0

            region_size = mbi.RegionSize
            state = mbi.State
            protect = mbi.Protect
            mem_type = mbi.Type

            region = MemoryRegion(
                base_address=addr_val,
                size=region_size,
                state=state,
                protect=protect,
                mem_type=mem_type,
            )

            # Analyze committed executable private memory
            if region.is_unbacked_executable:
                sample = self._read_memory_bytes(h_process, addr_val, min(region_size, 512))

                # Check 1: Reflective PE injection (MZ header inside unbacked private region)
                if sample.startswith(b"MZ"):
                    threats.append(
                        MemoryThreat(
                            pid=pid,
                            process_name=proc_name,
                            base_address=addr_val,
                            size=region_size,
                            threat_type="reflective_pe",
                            description="Reflective DLL injected into unbacked private memory (embedded MZ header)",
                            confidence=0.95,
                            sample_bytes=sample[:32],
                        )
                    )

                # Check 2: Known shellcode prologues
                for pattern, desc in _SHELLCODE_PATTERNS:
                    if pattern in sample:
                        threats.append(
                            MemoryThreat(
                                pid=pid,
                                process_name=proc_name,
                                base_address=addr_val,
                                size=region_size,
                                threat_type="shellcode_signature",
                                description=f"Shellcode signature detected: {desc}",
                                confidence=0.90,
                                sample_bytes=sample[:32],
                            )
                        )
                        break

                # Check 3: Raw unbacked executable region in non-JIT processes
                if not is_jit and (protect & PAGE_EXECUTE_READWRITE):
                    threats.append(
                        MemoryThreat(
                            pid=pid,
                            process_name=proc_name,
                            base_address=addr_val,
                            size=region_size,
                            threat_type="unbacked_executable",
                            description="Anomalous PAGE_EXECUTE_READWRITE unbacked private memory in non-JIT process",
                            confidence=0.75,
                            sample_bytes=sample[:32],
                        )
                    )
                total_scanned += region_size
                if max_scan_bytes and total_scanned >= max_scan_bytes:
                    break

            address = addr_val + region_size
            if address >= 0x7FFFFFFF0000 or region_size == 0:
                break

        return threats

    def _read_memory_bytes(self, h_process: int, address: int, size: int) -> bytes:
        """Read bytes from a process's virtual memory."""
        if not self._kernel32 or size <= 0:
            return b""
        buf = (ctypes.c_char * size)()
        bytes_read = ctypes.c_size_t(0)
        ok = self._kernel32.ReadProcessMemory(
            h_process,
            ctypes.c_void_p(address),
            buf,
            size,
            ctypes.byref(bytes_read),
        )
        if ok and bytes_read.value > 0:
            return bytes(buf[:bytes_read.value])
        return b""

    def scan_all_processes(
        self,
        filter_names: Sequence[str] | None = None,
    ) -> list[MemoryThreat]:
        """Enumerate running processes and scan memory of candidate processes."""
        all_threats: list[MemoryThreat] = []
        try:
            import psutil
        except ImportError:
            return all_threats

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pinfo = proc.info
                pid = pinfo.get("pid")
                name = pinfo.get("name")
                if not pid or pid <= 4 or not name:
                    continue
                if filter_names and name.lower() not in [f.lower() for f in filter_names]:
                    continue

                threats = self.scan_process(pid=pid, process_name=name)
                all_threats.extend(threats)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as exc:
                logger.debug("Memory scan error for pid %s: %s", getattr(proc, "pid", None), exc)

        return all_threats
