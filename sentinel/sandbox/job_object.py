"""Windows Job Object wrapper for sandbox containment.

Configures resource limits (CPU rate cap, process memory limit, active process limit),
UI isolation (desktop/atom restrictions), and guaranteed cleanup
(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE).
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import logging
import sys
from typing import Any

logger = logging.getLogger("sentinel.sandbox.job_object")

# Job Object Limit Flags
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x0100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x0200
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x0008
JOB_OBJECT_LIMIT_PRIORITY_CLASS = 0x0020

# UI Restrictions Flags
JOB_OBJECT_UILIMIT_HANDLES = 0x0001
JOB_OBJECT_UILIMIT_GLOBALATOMS = 0x0020
JOB_OBJECT_UILIMIT_DESKTOP = 0x0040
JOB_OBJECT_UILIMIT_DISPLAYSETTINGS = 0x0080
JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x0008

# CPU Rate Control Flags
JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x0001
JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x0004

# Info Classes
JobObjectExtendedLimitInformation = 9
JobObjectBasicUIRestrictions = 4
JobObjectCpuRateControlInformation = 15


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class JOBOBJECT_BASIC_UI_RESTRICTIONS(ctypes.Structure):
    _fields_ = [
        ("UIRestrictionsClass", wintypes.DWORD),
    ]


class JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ControlFlags", wintypes.DWORD),
        ("CpuRate", wintypes.DWORD),
    ]


class SandboxJobObject:
    """Manages an isolated Windows Job Object sandbox container."""

    def __init__(
        self,
        name: str | None = None,
        max_memory_mb: int = 128,
        max_processes: int = 5,
        cpu_percent_limit: int = 20,
    ) -> None:
        self.name = name
        self.max_memory_mb = max_memory_mb
        self.max_processes = max_processes
        self.cpu_percent_limit = cpu_percent_limit
        self._handle: int | None = None
        self._is_windows = sys.platform == "win32"
        self._kernel32 = None

        if self._is_windows:
            try:
                self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                self._init_api()
                self._create_job()
            except Exception as exc:
                logger.warning("SandboxJobObject initialization error: %s", exc)

    def _init_api(self) -> None:
        if not self._kernel32:
            return
        self._kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self._kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]

        self._kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self._kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
        ]

        self._kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self._kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]

        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    def _create_job(self) -> None:
        if not self._kernel32:
            return

        h_job = self._kernel32.CreateJobObjectW(None, self.name)
        if not h_job:
            err = ctypes.get_last_error()
            raise OSError(f"CreateJobObjectW failed with error code {err}")
        self._handle = h_job

        # 1. Extended limits (memory cap, process count, kill on close)
        ext_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        ext_info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            JOB_OBJECT_LIMIT_PROCESS_MEMORY |
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        )
        ext_info.BasicLimitInformation.ActiveProcessLimit = self.max_processes
        ext_info.ProcessMemoryLimit = self.max_memory_mb * 1024 * 1024

        ok = self._kernel32.SetInformationJobObject(
            self._handle,
            JobObjectExtendedLimitInformation,
            ctypes.byref(ext_info),
            ctypes.sizeof(ext_info),
        )
        if not ok:
            logger.warning("Could not set JobObject extended limits: %d", ctypes.get_last_error())

        # 2. UI Restrictions (isolate desktop, clipboard, global atoms)
        ui = JOBOBJECT_BASIC_UI_RESTRICTIONS()
        ui.UIRestrictionsClass = (
            JOB_OBJECT_UILIMIT_HANDLES |
            JOB_OBJECT_UILIMIT_GLOBALATOMS |
            JOB_OBJECT_UILIMIT_DESKTOP |
            JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
        )
        self._kernel32.SetInformationJobObject(
            self._handle,
            JobObjectBasicUIRestrictions,
            ctypes.byref(ui),
            ctypes.sizeof(ui),
        )

        # 3. CPU Rate Control (hard cap at cpu_percent_limit)
        if self.cpu_percent_limit > 0:
            cpu_info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION()
            cpu_info.ControlFlags = (
                JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
                JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
            )
            # CpuRate is expressed in units of 0.01% (e.g. 20% = 2000)
            cpu_info.CpuRate = self.cpu_percent_limit * 100
            self._kernel32.SetInformationJobObject(
                self._handle,
                JobObjectCpuRateControlInformation,
                ctypes.byref(cpu_info),
                ctypes.sizeof(cpu_info),
            )

    def assign_process(self, process_handle: int) -> bool:
        """Assign an active or suspended process to this sandbox Job Object."""
        if not self._handle or not self._kernel32:
            return False
        ok = self._kernel32.AssignProcessToJobObject(self._handle, process_handle)
        if not ok:
            logger.warning("AssignProcessToJobObject failed with error %d", ctypes.get_last_error())
        return bool(ok)

    def close(self) -> None:
        """Close the job object handle. Kills all processes within the job."""
        if self._handle and self._kernel32:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self) -> SandboxJobObject:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
