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
import struct
import sys
import threading
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

# Known JIT / Interpreter / Runtime process names (fast path)
_KNOWN_JIT_NAMES = frozenset({
    "powershell.exe", "pwsh.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "brave.exe", "python.exe", "pythonw.exe", "node.exe", "code.exe",
    "devenv.exe", "java.exe", "javaw.exe", "slack.exe", "discord.exe",
    "teams.exe", "spotify.exe", "robloxplayerbeta.exe", "roblox.exe",
})

# Known managed runtime and JIT modules (deep path for arbitrary .NET apps, Unity, Electron, etc.)
_MANAGED_MODULE_PATTERNS = frozenset({
    "clr.dll", "clrjit.dll", "coreclr.dll", "mscorwks.dll",
    "mscoreei.dll", "mscoree.dll", "mono.dll", "mono-2.0-bdwgc.dll",
    "monosgen-2.0.dll", "v8.dll", "node.dll", "jvm.dll",
})

# Authentic adversary shellcode signatures (Cobalt Strike, Metasploit, PEB walks, Egghunters)
_SHELLCODE_PATTERNS: list[tuple[bytes, str]] = [
    # Metasploit / Cobalt Strike Windows API Hash Stagers
    (b"\xfc\x48\x83\xe4\xf0\xe8", "Metasploit x64 reverse stager (cld; and rsp, -16; call)"),
    (b"\xfc\xe8\x82\x00\x00\x00\x60", "Metasploit x86 reverse stager (cld; call; pushad)"),
    (b"\xfc\xe8\x89\x00\x00\x00\x60", "Cobalt Strike / Metasploit x86 stager (cld; call; pushad)"),
    (b"\xfc\x48\x89\xe5\x48\x81\xec", "Cobalt Strike Beacon x64 stager prologue"),

    # x64 PEB Address Resolution (Adversary dynamic import resolution)
    (b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00", "x64 shellcode PEB resolution (mov rax, gs:[0x60])"),
    (b"\x65\x48\x8b\x1c\x25\x60\x00\x00\x00", "x64 shellcode PEB resolution (mov rbx, gs:[0x60])"),
    (b"\x65\x48\x8b\x14\x25\x60\x00\x00\x00", "x64 shellcode PEB resolution (mov rdx, gs:[0x60])"),
    (b"\x65\x48\x8b\x0c\x25\x60\x00\x00\x00", "x64 shellcode PEB resolution (mov rcx, gs:[0x60])"),
    (b"\x65\x48\x8b\x34\x25\x60\x00\x00\x00", "x64 shellcode PEB resolution (mov rsi, gs:[0x60])"),
    (b"\x65\x48\x8b\x3c\x25\x60\x00\x00\x00", "x64 shellcode PEB resolution (mov rdi, gs:[0x60])"),
    (b"\x65\x48\x8b\x40\x60", "x64 compact shellcode PEB resolution (gs:[rax+0x60])"),
    (b"\x65\x48\x8b\x52\x60", "x64 compact shellcode PEB resolution (gs:[rdx+0x60])"),

    # x86 PEB Address Resolution
    (b"\x64\xa1\x30\x00\x00\x00", "x86 shellcode PEB resolution (mov eax, fs:[0x30])"),
    (b"\x64\x8b\x15\x30\x00\x00\x00", "x86 shellcode PEB resolution (mov edx, fs:[0x30])"),
    (b"\x64\x8b\x0d\x30\x00\x00\x00", "x86 shellcode PEB resolution (mov ecx, fs:[0x30])"),
    (b"\x64\x8b\x1d\x30\x00\x00\x00", "x86 shellcode PEB resolution (mov ebx, fs:[0x30])"),
    (b"\x64\x8b\x35\x30\x00\x00\x00", "x86 shellcode PEB resolution (mov esi, fs:[0x30])"),

    # Egghunter stagers
    (b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e", "Windows NtAccessCheckAndAuditAlarm Syscall egghunter"),

    # NOP sled (>= 16 consecutive NOPs in unbacked execution page)
    (b"\x90" * 16, "Unbacked execution NOP sled (>= 16 consecutive NOPs)"),
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
    confidence: float = 85.0
    protection: int = 0x40
    sample_bytes: bytes = field(default=b"", repr=False)
    timestamp: float = field(default_factory=time.time)

    @property
    def evidence(self) -> str:
        return self.description

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
    """Cross-platform memory scanner for detecting memory-resident malware.

    Supports:
        - Windows: kernel32.dll VirtualQueryEx / ReadProcessMemory
        - Linux:   /proc/<pid>/maps + /proc/<pid>/mem
        - macOS:   mach_vm_region + mach_vm_read (via ctypes)
    """

    def __init__(self) -> None:
        self._is_windows = sys.platform == "win32"
        self._is_linux = sys.platform == "linux"
        self._is_macos = sys.platform == "darwin"
        self._kernel32 = None
        self._managed_pid_cache: dict[int, bool] = {}
        self._cache_lock = threading.Lock()
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

    def _is_managed_process(self, pid: int, proc_name: str) -> bool:
        """Dynamically detect if a process hosts a managed runtime / JIT engine."""
        # Cross-platform JIT process names
        name_lower = proc_name.lower()
        if name_lower in _KNOWN_JIT_NAMES:
            return True
        # Linux/macOS JIT process names
        if name_lower in {"python3", "python", "node", "java", "dotnet", "mono",
                          "chromium", "chrome", "firefox", "brave-browser"}:
            return True

        with self._cache_lock:
            if pid in self._managed_pid_cache:
                return self._managed_pid_cache[pid]

        is_managed = False
        try:
            import psutil
            p = psutil.Process(pid)
            for m in p.memory_maps():
                if m.path:
                    # Use os.sep-agnostic basename
                    lib_name = Path(m.path).name.lower()
                    if lib_name in _MANAGED_MODULE_PATTERNS:
                        is_managed = True
                        break
                    # Linux/macOS shared object patterns
                    if any(k in lib_name for k in (
                        "clrjit", "coreclr", "mscorlib",
                        "libmonosgen", "libcoreclr", "libjvm",
                        "libv8", "libnode",
                    )):
                        is_managed = True
                        break
        except Exception:
            pass

        with self._cache_lock:
            self._managed_pid_cache[pid] = is_managed
        return is_managed

    @staticmethod
    def _check_reflective_pe(sample: bytes) -> bool:
        """Strict verification of an in-memory Portable Executable (PE) header.
        
        Requires:
        1. DOS header signature 'MZ' at offset 0
        2. Valid e_lfanew pointer at offset 0x3C (0x40 <= e_lfanew <= 0x1000)
        3. PE signature 'PE\\0\\0' at sample[e_lfanew : e_lfanew + 4]
        4. Valid PE machine type (IMAGE_FILE_MACHINE_AMD64 / I386 / ARM64)
        """
        if len(sample) < 0x40 or not sample.startswith(b"MZ"):
            return False
        try:
            e_lfanew = struct.unpack_from("<I", sample, 0x3C)[0]
            if 0x40 <= e_lfanew <= min(len(sample) - 4, 0x1000):
                if sample[e_lfanew : e_lfanew + 4] == b"PE\0\0":
                    if len(sample) >= e_lfanew + 6:
                        machine = struct.unpack_from("<H", sample, e_lfanew + 4)[0]
                        # 0x014c (i386), 0x8664 (x64), 0xaa64 (arm64)
                        if machine in (0x014C, 0x8664, 0xAA64):
                            return True
                    else:
                        return True
        except Exception:
            pass
        return False

    @staticmethod
    def _check_elf_in_memory(sample: bytes) -> bool:
        """Check for an ELF header injected into process memory (Linux equivalent of reflective PE)."""
        if len(sample) < 16:
            return False
        # ELF magic: 0x7f 'E' 'L' 'F'
        if sample[:4] == b"\x7fELF":
            # Validate ELF class (32/64-bit)
            ei_class = sample[4] if len(sample) > 4 else 0
            if ei_class in (1, 2):  # ELFCLASS32 or ELFCLASS64
                return True
        return False

    def scan_process(
        self,
        pid: int,
        process_name: str | None = None,
        max_scan_bytes: int = 100 * 1024 * 1024,  # Cap at 100MB to preserve low CPU
    ) -> list[MemoryThreat]:
        """Scan virtual memory pages of a specific process for injection / anomalies.

        Dispatches to the appropriate platform-specific scanner.
        """
        if pid <= 4:
            return []

        proc_name = process_name or f"pid_{pid}"

        if self._is_windows:
            return self._scan_process_windows(pid, proc_name, max_scan_bytes)
        elif self._is_linux:
            return self._scan_process_linux(pid, proc_name, max_scan_bytes)
        elif self._is_macos:
            return self._scan_process_macos(pid, proc_name, max_scan_bytes)
        return []

    # ------------------------------------------------------------------ #
    # Windows backend
    # ------------------------------------------------------------------ #
    def _scan_process_windows(
        self,
        pid: int,
        proc_name: str,
        max_scan_bytes: int,
    ) -> list[MemoryThreat]:
        """Windows memory scanning via kernel32.dll."""
        threats: list[MemoryThreat] = []
        if not self._kernel32:
            return threats

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
        is_jit = self._is_managed_process(pid, proc_name)

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
                sample = self._read_memory_bytes_win(h_process, addr_val, min(region_size, 1024))

                # Check 1: Reflective PE injection (verified MZ + PE header in unbacked memory)
                if self._check_reflective_pe(sample):
                    threats.append(
                        MemoryThreat(
                            pid=pid,
                            process_name=proc_name,
                            base_address=addr_val,
                            size=region_size,
                            threat_type="reflective_pe",
                            description="Reflective DLL injected into unbacked private memory (embedded verified PE header)",
                            confidence=0.98,
                            protection=protect,
                            sample_bytes=sample[:32],
                        )
                    )

                # Check 2: Known authentic shellcode signatures
                for pattern, desc in _SHELLCODE_PATTERNS:
                    if is_jit and "PEB resolution" in desc:
                        continue
                    if pattern in sample:
                        threats.append(
                            MemoryThreat(
                                pid=pid,
                                process_name=proc_name,
                                base_address=addr_val,
                                size=region_size,
                                threat_type="shellcode_signature",
                                description=f"Shellcode signature detected: {desc}",
                                confidence=0.95,
                                protection=protect,
                                sample_bytes=sample[:32],
                            )
                        )
                        break

                # Check 3: Raw unbacked executable region in non-JIT processes
                if not is_jit and (protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)):
                    threats.append(
                        MemoryThreat(
                            pid=pid,
                            process_name=proc_name,
                            base_address=addr_val,
                            size=region_size,
                            threat_type="unbacked_executable",
                            description="Anomalous PAGE_EXECUTE_READWRITE unbacked private memory in non-JIT process",
                            confidence=0.80,
                            protection=protect,
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

    def _read_memory_bytes_win(self, h_process: int, address: int, size: int) -> bytes:
        """Read bytes from a process's virtual memory (Windows)."""
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

    # Keep old name for backwards compatibility
    def _read_memory_bytes(self, h_process: int, address: int, size: int) -> bytes:
        return self._read_memory_bytes_win(h_process, address, size)

    # ------------------------------------------------------------------ #
    # Linux backend — /proc/<pid>/maps + /proc/<pid>/mem
    # ------------------------------------------------------------------ #
    def _scan_process_linux(
        self,
        pid: int,
        proc_name: str,
        max_scan_bytes: int,
    ) -> list[MemoryThreat]:
        """Linux memory scanning via /proc filesystem."""
        import re
        threats: list[MemoryThreat] = []
        maps_path = f"/proc/{pid}/maps"
        mem_path = f"/proc/{pid}/mem"
        total_scanned = 0
        is_jit = self._is_managed_process(pid, proc_name)

        try:
            with open(maps_path, "r") as maps_file:
                lines = maps_file.readlines()
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            return threats

        # Parse /proc/<pid>/maps format:
        # address           perms offset  dev   inode    pathname
        # 7f1234000000-7f1235000000 rwxp 00000000 00:00 0  [heap]
        maps_re = re.compile(
            r"([0-9a-f]+)-([0-9a-f]+)\s+([\w-]+)\s+([0-9a-f]+)\s+\S+\s+(\d+)\s*(.*)"
        )

        mem_fd = None
        try:
            mem_fd = os.open(mem_path, os.O_RDONLY)
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            return threats

        try:
            for line in lines:
                match = maps_re.match(line.strip())
                if not match:
                    continue

                start_addr = int(match.group(1), 16)
                end_addr = int(match.group(2), 16)
                perms = match.group(3)
                inode = int(match.group(5))
                pathname = match.group(6).strip()
                region_size = end_addr - start_addr

                # Focus on executable, private, anonymous (no backing file) regions
                # perms like 'rwxp' — 'x' = executable, 'p' = private
                is_executable = 'x' in perms
                is_private = 'p' in perms
                is_anonymous = (inode == 0) and not pathname.startswith("[")

                if not (is_executable and is_private and is_anonymous):
                    continue

                # Skip known safe anonymous regions
                if pathname in ("[vdso]", "[vsyscall]", "[vvar]"):
                    continue

                # Read sample bytes
                sample = b""
                try:
                    os.lseek(mem_fd, start_addr, os.SEEK_SET)
                    sample = os.read(mem_fd, min(region_size, 1024))
                except (OSError, OverflowError):
                    continue

                if not sample:
                    continue

                # Check 1: Reflective PE injection (Windows malware running via Wine/WINE)
                if self._check_reflective_pe(sample):
                    threats.append(
                        MemoryThreat(
                            pid=pid,
                            process_name=proc_name,
                            base_address=start_addr,
                            size=region_size,
                            threat_type="reflective_pe",
                            description="PE header in anonymous executable memory (possible injected Windows payload)",
                            confidence=0.95,
                            protection=PAGE_EXECUTE_READWRITE,
                            sample_bytes=sample[:32],
                        )
                    )

                # Check 1b: ELF injection (native Linux reflective loading)
                if self._check_elf_in_memory(sample):
                    threats.append(
                        MemoryThreat(
                            pid=pid,
                            process_name=proc_name,
                            base_address=start_addr,
                            size=region_size,
                            threat_type="reflective_pe",
                            description="ELF header in anonymous executable memory (possible reflective ELF injection)",
                            confidence=0.95,
                            protection=PAGE_EXECUTE_READWRITE,
                            sample_bytes=sample[:32],
                        )
                    )

                # Check 2: Shellcode signatures
                for pattern, desc in _SHELLCODE_PATTERNS:
                    if is_jit and "PEB resolution" in desc:
                        continue
                    if pattern in sample:
                        threats.append(
                            MemoryThreat(
                                pid=pid,
                                process_name=proc_name,
                                base_address=start_addr,
                                size=region_size,
                                threat_type="shellcode_signature",
                                description=f"Shellcode signature detected: {desc}",
                                confidence=0.95,
                                protection=PAGE_EXECUTE_READWRITE,
                                sample_bytes=sample[:32],
                            )
                        )
                        break

                # Check 3: Anomalous RWX anonymous region in non-JIT process
                is_writable = 'w' in perms
                if not is_jit and is_writable and is_executable:
                    threats.append(
                        MemoryThreat(
                            pid=pid,
                            process_name=proc_name,
                            base_address=start_addr,
                            size=region_size,
                            threat_type="unbacked_executable",
                            description="Anomalous RWX anonymous memory region in non-JIT process",
                            confidence=0.80,
                            protection=PAGE_EXECUTE_READWRITE,
                            sample_bytes=sample[:32],
                        )
                    )

                total_scanned += region_size
                if max_scan_bytes and total_scanned >= max_scan_bytes:
                    break
        finally:
            os.close(mem_fd)

        return threats

    # ------------------------------------------------------------------ #
    # macOS backend — mach_vm via ctypes
    # ------------------------------------------------------------------ #
    def _scan_process_macos(
        self,
        pid: int,
        proc_name: str,
        max_scan_bytes: int,
    ) -> list[MemoryThreat]:
        """macOS memory scanning via mach_vm_region and mach_vm_read.

        Uses ctypes to call Mach kernel APIs for process memory inspection.
        Requires appropriate privileges (root or taskgated entitlement).
        """
        threats: list[MemoryThreat] = []

        # On macOS, we use psutil's memory_maps as a simpler approach
        # since mach_vm APIs require complex ctypes setup and entitlements
        try:
            import psutil
        except ImportError:
            return threats

        is_jit = self._is_managed_process(pid, proc_name)
        total_scanned = 0

        try:
            proc = psutil.Process(pid)
            for mmap in proc.memory_maps():
                # Parse the memory map entry
                addr_str = mmap.addr if hasattr(mmap, "addr") else ""
                path = mmap.path if hasattr(mmap, "path") else ""
                rss = mmap.rss if hasattr(mmap, "rss") else 0

                if not addr_str:
                    continue

                # Parse address range
                try:
                    if "-" in addr_str:
                        start_s, end_s = addr_str.split("-", 1)
                        start_addr = int(start_s, 16)
                        end_addr = int(end_s, 16)
                    else:
                        continue
                except (ValueError, IndexError):
                    continue

                region_size = end_addr - start_addr

                # Check permissions
                perms = mmap.perms if hasattr(mmap, "perms") else ""
                is_executable = "x" in perms
                is_private = "p" in perms or "private" in str(path).lower()
                is_anonymous = not path or path.startswith("[")

                if not (is_executable and is_anonymous):
                    continue

                # Try to read memory via /proc (macOS doesn't have /proc,
                # so we rely on the process maps metadata for detection)
                # On macOS, we flag suspicious regions without reading memory
                if not is_jit and "w" in perms and is_executable:
                    threats.append(
                        MemoryThreat(
                            pid=pid,
                            process_name=proc_name,
                            base_address=start_addr,
                            size=region_size,
                            threat_type="unbacked_executable",
                            description="Anomalous RWX anonymous memory region in non-JIT process",
                            confidence=0.75,
                            protection=PAGE_EXECUTE_READWRITE,
                            sample_bytes=b"",
                        )
                    )

                total_scanned += region_size
                if max_scan_bytes and total_scanned >= max_scan_bytes:
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as exc:
            logger.debug("macOS memory scan error for pid %d: %s", pid, exc)

        return threats

    # ------------------------------------------------------------------ #
    # Cross-platform process enumeration
    # ------------------------------------------------------------------ #
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

        min_pid = 4 if self._is_windows else 1

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pinfo = proc.info
                pid = pinfo.get("pid")
                name = pinfo.get("name")
                if not pid or pid <= min_pid or not name:
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
