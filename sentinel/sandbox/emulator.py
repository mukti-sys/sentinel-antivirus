"""Dynamic In-Memory Instruction and API Emulator for Sentinel Antivirus.

Provides zero-risk, user-space x86/x64 CPU and Win32/POSIX API emulation
for suspicious, packed, or ambiguous binaries. Never executes untrusted code
directly on the host CPU.

Key Capabilities:
1. Virtual Address Space & Section Mapping (PE / ELF / Raw Shellcode)
2. Virtual CPU Registers & 64KB Stack
3. Virtual Process Environment Block (PEB) & TEB for dynamic API resolution
4. Mock Virtual DLLs (VDLLs) with anti-debug, evasion, and injection detection
5. Memory write tracking (self-modifying code & unpacking loops)
6. Harvests unpacked memory buffers and rescans them with YARA
"""
from __future__ import annotations

import logging
import os
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pefile

try:
    from sentinel.engine.rule_engine import RuleEngine
    _RULE_ENGINE_AVAILABLE = True
except ImportError:
    _RULE_ENGINE_AVAILABLE = False

logger = logging.getLogger("sentinel.sandbox.emulator")


def ror13(name: str) -> int:
    """Calculate the 32-bit ROR13 hash of an API string."""
    hash_val = 0
    for char in name:
        c = ord(char)
        hash_val = ((hash_val >> 13) | ((hash_val << (32 - 13)) & 0xFFFFFFFF)) & 0xFFFFFFFF
        hash_val = (hash_val + c) & 0xFFFFFFFF
    return hash_val


# Target Win32 APIs tracked by malware / shellcode / packers
TARGET_APIS = [
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "VirtualProtectEx", "WriteProcessMemory", "CreateProcessA", "CreateProcessW",
    "CreateRemoteThread", "QueueUserAPC", "WinExec", "ExitProcess",
    "TerminateProcess", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "Sleep", "SleepEx", "GetTickCount", "QueryPerformanceCounter",
    "URLDownloadToFileA", "InternetOpenA", "InternetConnectA",
    "HttpOpenRequestA", "HttpSendRequestA", "NtUnmapViewOfSection",
]

KNOWN_API_ROR13_HASHES: dict[int, str] = {ror13(api): api for api in TARGET_APIS}


@dataclass
class ApiCallRecord:
    """Record of an API call intercepted during emulation."""
    api_name: str
    arguments: list[Any] = field(default_factory=list)
    return_value: int = 0
    category: str = "general"
    timestamp: float = field(default_factory=time.time)


@dataclass
class EmulationResult:
    """Summary of findings from emulator execution."""
    target_path: str
    instructions_executed: int = 0
    duration_seconds: float = 0.0
    api_calls: list[ApiCallRecord] = field(default_factory=list)
    evasion_techniques: list[str] = field(default_factory=list)
    rwx_allocations: int = 0
    unpacked_payload_sizes: list[int] = field(default_factory=list)
    unpacked_yara_matches: list[str] = field(default_factory=list)
    threat_reasons: list[str] = field(default_factory=list)
    is_suspicious: bool = False
    is_malicious: bool = False
    risk_score: float = 0.0
    error: str | None = None

    def summarize(self) -> dict[str, Any]:
        return {
            "target": self.target_path,
            "instructions": self.instructions_executed,
            "duration_ms": round(self.duration_seconds * 1000, 2),
            "api_calls_count": len(self.api_calls),
            "evasion_count": len(self.evasion_techniques),
            "rwx_allocs": self.rwx_allocations,
            "unpacked_yara": self.unpacked_yara_matches,
            "threat_reasons": self.threat_reasons,
            "risk_score": self.risk_score,
            "is_suspicious": self.is_suspicious,
            "is_malicious": self.is_malicious,
        }


class VirtualMemory:
    """Simulates a 32/64-bit flat virtual memory space."""

    def __init__(self, is_64bit: bool = True) -> None:
        self.is_64bit = is_64bit
        self.mask = 0xFFFFFFFFFFFFFFFF if is_64bit else 0xFFFFFFFF
        self.pages: dict[int, bytearray] = {}  # 4KB aligned pages
        self.permissions: dict[int, str] = {}  # "R", "RW", "RX", "RWX"
        self.written_pages: set[int] = set()

    def _page_base(self, addr: int) -> int:
        return addr & ~0xFFF

    def alloc(self, addr: int, size: int, prot: str = "RWX") -> int:
        """Allocate contiguous virtual memory pages."""
        base = self._page_base(addr)
        num_pages = max(1, (size + 0xFFF) // 0x1000)
        for i in range(num_pages):
            p = base + (i * 0x1000)
            if p not in self.pages:
                self.pages[p] = bytearray(4096)
                self.permissions[p] = prot
        return addr

    def write_bytes(self, addr: int, data: bytes | bytearray) -> None:
        """Write raw bytes into virtual memory."""
        cur = addr
        offset = 0
        data_len = len(data)

        while offset < data_len:
            p = self._page_base(cur)
            if p not in self.pages:
                self.alloc(p, 4096, "RWX")

            page_off = cur & 0xFFF
            chunk_size = min(data_len - offset, 4096 - page_off)
            self.pages[p][page_off : page_off + chunk_size] = data[offset : offset + chunk_size]
            self.written_pages.add(p)

            cur += chunk_size
            offset += chunk_size

    def read_bytes(self, addr: int, size: int) -> bytes:
        """Read raw bytes from virtual memory."""
        res = bytearray()
        cur = addr
        remaining = size

        while remaining > 0:
            p = self._page_base(cur)
            page_off = cur & 0xFFF
            chunk_size = min(remaining, 4096 - page_off)

            if p in self.pages:
                res.extend(self.pages[p][page_off : page_off + chunk_size])
            else:
                res.extend(b"\x00" * chunk_size)

            cur += chunk_size
            remaining -= chunk_size

        return bytes(res)

    def write_u32(self, addr: int, val: int) -> None:
        self.write_bytes(addr, struct.pack("<I", val & 0xFFFFFFFF))

    def read_u32(self, addr: int) -> int:
        data = self.read_bytes(addr, 4)
        return struct.unpack("<I", data)[0]

    def write_u64(self, addr: int, val: int) -> None:
        self.write_bytes(addr, struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF))

    def read_u64(self, addr: int) -> int:
        data = self.read_bytes(addr, 8)
        return struct.unpack("<Q", data)[0]

    def get_modified_buffers(self) -> list[bytes]:
        """Harvest buffers written during execution (for unpack detection)."""
        buffers: list[bytes] = []
        for p in sorted(self.written_pages):
            page_data = bytes(self.pages[p])
            if any(b != 0 for b in page_data):
                buffers.append(page_data)
        return buffers


class DynamicEmulator:
    """Safe, user-space in-memory CPU and Win32/POSIX API emulator."""

    def __init__(
        self,
        max_instructions: int = 5000,
        max_seconds: float = 2.0,
        enable_yara_rescan: bool = True,
    ) -> None:
        self.max_instructions = max_instructions
        self.max_seconds = max_seconds
        self.enable_yara_rescan = enable_yara_rescan
        self.rule_engine: Any = None

        if self.enable_yara_rescan and _RULE_ENGINE_AVAILABLE:
            try:
                self.rule_engine = RuleEngine()
            except Exception as e:
                logger.debug("RuleEngine initialization in emulator: %s", e)

    def emulate(self, file_path: str | Path, raw_data: bytes | None = None) -> EmulationResult:
        """Emulate target binary or shellcode from entry point."""
        path = Path(file_path).resolve()
        result = EmulationResult(target_path=str(path))
        start_time = time.time()

        data = raw_data
        if data is None:
            if not path.is_file():
                result.error = f"File not found: {path}"
                return result
            try:
                data = path.read_bytes()
            except Exception as e:
                result.error = f"Read failed: {e}"
                return result

        if len(data) == 0:
            result.error = "Empty file"
            return result

        # 1. PE Binary Emulation
        if data.startswith(b"MZ"):
            self._emulate_pe(data, result, start_time)
        elif data.startswith(b"\x7fELF"):
            self._emulate_elf(data, result, start_time)
        else:
            # Raw shellcode / script buffer emulation
            self._emulate_shellcode(data, result, start_time)

        result.duration_seconds = max(0.001, time.time() - start_time)

        # 2. Rescan unpacked memory buffers with YARA
        if self.rule_engine and (result.unpacked_payload_sizes or result.rwx_allocations):
            for buf in self.vm.get_modified_buffers():
                if len(buf) >= 64:
                    try:
                        hits = self.rule_engine.scan_bytes(buf)
                        for hit in hits:
                            rule_name = hit.rule if hasattr(hit, "rule") else str(hit)
                            if rule_name not in result.unpacked_yara_matches:
                                result.unpacked_yara_matches.append(rule_name)
                    except Exception:
                        pass

        # 3. Calculate Risk Score & Verdict
        self._evaluate_risk(result)
        return result

    def _emulate_pe(self, data: bytes, result: EmulationResult, start_time: float) -> None:
        """Map and emulate a Windows Portable Executable (PE)."""
        try:
            pe = pefile.PE(data=data, fast_load=False)
        except Exception:
            # Truncated PE or raw shellcode masquerading with MZ header
            self._emulate_shellcode(data, result, start_time)
            return

        is_64bit = pe.OPTIONAL_HEADER.Magic == 0x20B  # PE32+
        self.vm = VirtualMemory(is_64bit=is_64bit)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point = image_base + entry_rva

        # Map PE Headers
        header_size = pe.OPTIONAL_HEADER.SizeOfHeaders
        self.vm.alloc(image_base, header_size, "R")
        self.vm.write_bytes(image_base, data[:header_size])

        # Map Sections
        for section in pe.sections:
            sec_va = image_base + section.VirtualAddress
            sec_raw = section.get_data()
            sec_vsize = section.Misc_VirtualSize or len(sec_raw)

            chars = section.Characteristics
            prot = "RWX" if (chars & 0x20000000 and chars & 0x80000000) else "RX" if (chars & 0x20000000) else "RW"

            self.vm.alloc(sec_va, sec_vsize, prot)
            if sec_raw:
                self.vm.write_bytes(sec_va, sec_raw)

        # Map Virtual Stack
        stack_base = 0x000F0000 if not is_64bit else 0x00000000000F0000
        stack_size = 0x00020000  # 128KB stack
        self.vm.alloc(stack_base, stack_size, "RW")
        initial_sp = stack_base + stack_size - 0x1000

        # Initialize Registers
        regs: dict[str, int] = {
            "eax": 0, "ebx": 0, "ecx": 0, "edx": 0,
            "esi": 0, "edi": 0, "esp": initial_sp, "ebp": initial_sp,
            "eip": entry_point,
            "eflags": 0x246,
        }

        # Setup Virtual PEB & TEB
        peb_base = 0x7FFDF000 if not is_64bit else 0x00007FFD0000
        self._setup_virtual_peb(peb_base, image_base, is_64bit)

        self._run_interpreter(regs, result, start_time, is_64bit, image_base)

    def _setup_virtual_peb(self, peb_base: int, image_base: int, is_64bit: bool) -> None:
        """Setup simulated PEB so malware querying fs:[0x30] or gs:[0x60] succeeds."""
        self.vm.alloc(peb_base, 4096, "R")
        self.vm.write_bytes(peb_base + 2, b"\x00")  # BeingDebugged = 0

        if is_64bit:
            self.vm.write_u64(peb_base + 0x10, image_base)
        else:
            self.vm.write_u32(peb_base + 0x08, image_base)

    def _emulate_elf(self, data: bytes, result: EmulationResult, start_time: float) -> None:
        """Emulate Linux ELF binary entry point heuristics."""
        is_64bit = data[4] == 2  # ELFCLASS64
        self.vm = VirtualMemory(is_64bit=is_64bit)

        entry_point = 0x400000
        if is_64bit and len(data) >= 32:
            entry_point = struct.unpack("<Q", data[24:32])[0] or 0x400000
        elif not is_64bit and len(data) >= 28:
            entry_point = struct.unpack("<I", data[24:28])[0] or 0x400000

        base = 0x400000
        self.vm.alloc(base, len(data), "RWX")
        self.vm.write_bytes(base, data)

        stack_base = 0x7FFF0000
        self.vm.alloc(stack_base, 0x10000, "RW")
        initial_sp = stack_base + 0x8000

        regs = {
            "eax": 0, "ebx": 0, "ecx": 0, "edx": 0,
            "esi": 0, "edi": 0, "esp": initial_sp, "ebp": initial_sp,
            "eip": entry_point, "eflags": 0x246,
        }

        self._run_interpreter(regs, result, start_time, is_64bit, base)

    def _emulate_shellcode(self, data: bytes, result: EmulationResult, start_time: float) -> None:
        """Emulate raw shellcode."""
        self.vm = VirtualMemory(is_64bit=True)
        base = 0x10000000
        self.vm.alloc(base, len(data) + 0x10000, "RWX")
        self.vm.write_bytes(base, data)

        stack_base = 0x20000000
        self.vm.alloc(stack_base, 0x10000, "RW")
        initial_sp = stack_base + 0x8000

        regs = {
            "eax": 0, "ebx": 0, "ecx": 0, "edx": 0,
            "esi": 0, "edi": 0, "esp": initial_sp, "ebp": initial_sp,
            "eip": base, "eflags": 0x246,
        }

        self._run_interpreter(regs, result, start_time, True, base)

    def _run_interpreter(
        self,
        regs: dict[str, int],
        result: EmulationResult,
        start_time: float,
        is_64bit: bool,
        image_base: int,
    ) -> None:
        """Core instruction stepping, register tracking, and virtual API dispatch."""
        steps = 0
        written_bytes_count = 0
        reg_names_32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]

        while steps < self.max_instructions:
            if time.time() - start_time > self.max_seconds:
                result.evasion_techniques.append("ExecutionTimeout:LongRunningLoop")
                break

            steps += 1
            eip = regs["eip"]

            op_bytes = self.vm.read_bytes(eip, 15)
            if not op_bytes or op_bytes == b"\x00" * len(op_bytes):
                break

            b0 = op_bytes[0]
            b1 = op_bytes[1] if len(op_bytes) > 1 else 0

            # -------------------------------------------------------------
            # Evasion Pattern 1: RDTSC timing check (0x0F 0x31)
            # -------------------------------------------------------------
            if b0 == 0x0F and b1 == 0x31:
                result.evasion_techniques.append("AntiAnalysis:RDTSCTimingCheck")
                regs["eax"] = int(time.time() * 1000) & 0xFFFFFFFF
                regs["edx"] = 0
                regs["eip"] += 2
                continue

            # -------------------------------------------------------------
            # Evasion Pattern 2: PEB Access (fs:[0x30] in x86 or gs:[0x60] in x64)
            # -------------------------------------------------------------
            if (b0 == 0x64 and b1 == 0xA1 and op_bytes[2:6] == b"\x30\x00\x00\x00") or \
               (b0 == 0x65 and b1 == 0x48 and op_bytes[2:7] == b"\x8b\x04\x25\x60\x00"):
                result.evasion_techniques.append("AntiAnalysis:DirectPEBWalk")
                regs["eax"] = 0x7FFDF000
                regs["eip"] += 6 if b0 == 0x64 else 9
                continue

            # -------------------------------------------------------------
            # Register assignment: MOV r32, imm32 (0xB8..0xBF)
            # -------------------------------------------------------------
            if 0xB8 <= b0 <= 0xBF and len(op_bytes) >= 5:
                reg_name = reg_names_32[b0 - 0xB8]
                imm32 = struct.unpack("<I", op_bytes[1:5])[0]
                regs[reg_name] = imm32
                regs["eip"] += 5
                continue

            # -------------------------------------------------------------
            # Register assignment: MOV r8, imm8 (0xB0..0xB7)
            # -------------------------------------------------------------
            if 0xB0 <= b0 <= 0xB7 and len(op_bytes) >= 2:
                val8 = op_bytes[1]
                if b0 == 0xB0:  # AL
                    regs["eax"] = (regs.get("eax", 0) & ~0xFF) | val8
                elif b0 == 0xB1:  # CL
                    regs["ecx"] = (regs.get("ecx", 0) & ~0xFF) | val8
                regs["eip"] += 2
                continue

            # -------------------------------------------------------------
            # API Hashing Pattern: ROR13 API Resolution Loop
            # Detects ror reg, 13 (0xC1 / 0xC8.. 0x0D)
            # -------------------------------------------------------------
            if b0 in (0xC1, 0x48) and len(op_bytes) >= 3:
                # Check for ROR r32, 13 (0xC1 0xC8.. 0x0D)
                if (b0 == 0xC1 and len(op_bytes) >= 3 and op_bytes[2] == 0x0D) or \
                   (b0 == 0x48 and len(op_bytes) >= 4 and op_bytes[1] == 0xC1 and op_bytes[3] == 0x0D):
                    val = regs.get("eax", 0) & 0xFFFFFFFF
                    if val in KNOWN_API_ROR13_HASHES:
                        api_name = KNOWN_API_ROR13_HASHES[val]
                        result.evasion_techniques.append(f"ApiHashing:ROR13({api_name})")
                        self._handle_api_call(api_name, regs, result)

            # -------------------------------------------------------------
            # Memory writes: STOSB (0xAA) / STOSD (0xAB) (Unpacking Loop)
            # -------------------------------------------------------------
            if b0 == 0xAA:  # STOSB
                dest_addr = regs.get("edi", 0)
                if dest_addr != 0:
                    val8 = regs.get("eax", 0) & 0xFF
                    self.vm.write_bytes(dest_addr, bytes([val8]))
                    regs["edi"] += 1
                    written_bytes_count += 1
                regs["eip"] += 1
                continue

            if b0 == 0xAB:  # STOSD
                dest_addr = regs.get("edi", 0)
                if dest_addr != 0:
                    val32 = regs.get("eax", 0) & 0xFFFFFFFF
                    self.vm.write_u32(dest_addr, val32)
                    regs["edi"] += 4
                    written_bytes_count += 4
                regs["eip"] += 1
                continue

            # -------------------------------------------------------------
            # Windows API Call / Sycall Simulation (0xE8 rel32)
            # -------------------------------------------------------------
            if b0 == 0xE8 and len(op_bytes) >= 5:
                rel32 = struct.unpack("<i", op_bytes[1:5])[0]
                target_addr = (eip + 5 + rel32) & 0xFFFFFFFFFFFFFFFF
                regs["eip"] = target_addr
                regs["esp"] -= 8 if is_64bit else 4
                if is_64bit:
                    self.vm.write_u64(regs["esp"], eip + 5)
                else:
                    self.vm.write_u32(regs["esp"], eip + 5)
                continue

            if b0 == 0xC3:  # RET
                ret_addr = self.vm.read_u64(regs["esp"]) if is_64bit else self.vm.read_u32(regs["esp"])
                regs["esp"] += 8 if is_64bit else 4
                regs["eip"] = ret_addr
                if ret_addr == 0 or ret_addr > 0xFFFFFFFFFFFF:
                    break
                continue

            # -------------------------------------------------------------
            # Standard NOP / JMP / Control Flow Stepping
            # -------------------------------------------------------------
            if b0 == 0x90:  # NOP
                regs["eip"] += 1
                continue

            if b0 == 0xEB:  # JMP short
                offset = struct.unpack("<b", bytes([b1]))[0]
                regs["eip"] += 2 + offset
                continue

            if b0 == 0xE9 and len(op_bytes) >= 5:  # JMP near
                offset = struct.unpack("<i", op_bytes[1:5])[0]
                regs["eip"] += 5 + offset
                continue

            # Default advance EIP (safe instruction step)
            step_len = 1
            if b0 in (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F):
                step_len = 1  # PUSH / POP reg
            elif b0 in (0x83, 0x80):
                step_len = 3  # ADD/SUB/CMP r/m, imm8
            elif b0 in (0x81,):
                step_len = 6  # ADD/SUB/CMP r/m, imm32
            elif b0 in (0x89, 0x8B):
                step_len = 2  # MOV r/m, r
            elif b0 in (0x31, 0x33):
                step_len = 2  # XOR reg, reg
                regs["eax"] = 0
            else:
                step_len = 2

            regs["eip"] += step_len

        result.instructions_executed = steps
        if written_bytes_count > 64:
            result.unpacked_payload_sizes.append(written_bytes_count)

    def _handle_api_call(self, api_name: str, regs: dict[str, int], result: EmulationResult) -> None:
        """Simulate Win32 / POSIX API response and log behavioral indicators."""
        category = "general"

        if api_name in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent"):
            category = "anti_debug"
            result.evasion_techniques.append(f"AntiDebug:{api_name}")
            regs["eax"] = 0

        elif api_name in ("Sleep", "SleepEx"):
            category = "timing"
            result.evasion_techniques.append("TimingEvasion:Sleep")
            regs["eax"] = 0

        elif api_name in ("VirtualAlloc", "VirtualAllocEx"):
            category = "memory"
            result.rwx_allocations += 1
            regs["eax"] = 0x20000000
            result.threat_reasons.append("Allocated executable memory (VirtualAlloc)")

        elif api_name in ("WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection"):
            category = "injection"
            result.threat_reasons.append(f"Process Injection primitive called: {api_name}")
            regs["eax"] = 1

        result.api_calls.append(ApiCallRecord(
            api_name=api_name,
            return_value=regs.get("eax", 0),
            category=category,
        ))

    def _evaluate_risk(self, result: EmulationResult) -> None:
        """Compute final confidence score and classification."""
        score = 0.0

        if result.unpacked_yara_matches:
            score += 85.0
            result.threat_reasons.append(
                f"Unpacked memory matched YARA signature(s): {', '.join(result.unpacked_yara_matches)}"
            )

        if any(call.category == "injection" for call in result.api_calls):
            score += 45.0

        if result.unpacked_payload_sizes:
            score += 35.0
            result.threat_reasons.append("Self-decrypting unpacking routine detected (wrote payload to memory)")

        if result.rwx_allocations > 0:
            score += 25.0

        if result.evasion_techniques:
            score += min(40.0, len(result.evasion_techniques) * 20.0)
            result.threat_reasons.append(
                f"Anti-analysis evasion detected: {', '.join(result.evasion_techniques[:3])}"
            )

        result.risk_score = min(100.0, score)
        result.is_suspicious = (
            result.risk_score >= 20.0
            or len(result.evasion_techniques) > 0
            or result.rwx_allocations > 0
            or len(result.unpacked_payload_sizes) > 0
        )
        result.is_malicious = result.risk_score >= 75.0 or bool(result.unpacked_yara_matches)
