"""Cross-Platform Process Isolation and Containment for Sentinel Antivirus.

Provides operating-system-level isolation mechanisms when executing untrusted
binaries for dynamic behavioral detonation:
- Windows: Job Objects (CPU cap, memory quota, active process limits, UI limits)
- Linux: Resource limits (setrlimit CPU/RAM/processes) + PR_SET_NO_NEW_PRIVS
- macOS: POSIX resource limits (setrlimit)
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from sentinel.platform import IS_WINDOWS, IS_LINUX, IS_MACOS

logger = logging.getLogger("sentinel.sandbox.isolation")

if IS_WINDOWS:
    from sentinel.sandbox.job_object import SandboxJobObject
else:
    SandboxJobObject = None  # type: ignore


class SandboxIsolation:
    """Manages cross-platform process isolation and resource containment."""

    def __init__(
        self,
        max_memory_mb: int = 128,
        cpu_percent_limit: int = 20,
        max_duration_seconds: float = 5.0,
    ) -> None:
        self.max_memory_mb = max_memory_mb
        self.cpu_percent_limit = cpu_percent_limit
        self.max_duration_seconds = max_duration_seconds

    def run_isolated(
        self,
        cmd: list[str],
        work_dir: Path,
        timeout: float | None = None,
    ) -> tuple[int | None, bool]:
        """Execute command in isolated container.
        Returns (exit_code, timed_out).
        """
        effective_timeout = timeout if timeout is not None else self.max_duration_seconds

        if IS_WINDOWS:
            return self._run_windows(cmd, work_dir, effective_timeout)
        elif IS_LINUX:
            return self._run_linux(cmd, work_dir, effective_timeout)
        else:
            return self._run_posix(cmd, work_dir, effective_timeout)

    def _run_windows(
        self,
        cmd: list[str],
        work_dir: Path,
        timeout: float,
    ) -> tuple[int | None, bool]:
        """Windows Job Object isolation."""
        timed_out = False
        exit_code: int | None = None

        with SandboxJobObject(
            max_memory_mb=self.max_memory_mb,
            cpu_percent_limit=self.cpu_percent_limit,
        ) as job:
            try:
                proc = subprocess.Popen(
                    cmd,
                    cwd=str(work_dir),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as exc:
                logger.error("Failed to spawn Windows isolated process: %s", exc)
                return -1, False

            # Assign to Job Object for automatic kernel-level resource enforcement
            try:
                job.assign_process(int(proc._handle))
            except Exception as e:
                logger.debug("Failed to assign process to Job Object: %s", e)

            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                exit_code = -1
            except Exception:
                proc.kill()
                exit_code = -1

        return exit_code, timed_out

    def _run_linux(
        self,
        cmd: list[str],
        work_dir: Path,
        timeout: float,
    ) -> tuple[int | None, bool]:
        """Linux isolation using setrlimit and prctl no-new-privs."""
        timed_out = False
        exit_code: int | None = None

        def _linux_preexec() -> None:
            # 1. Prevent privilege escalation (PR_SET_NO_NEW_PRIVS)
            try:
                import ctypes
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                PR_SET_NO_NEW_PRIVS = 38
                libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            except Exception:
                pass

            # 2. Enforce memory and CPU limits via resource
            try:
                import resource
                mem_bytes = self.max_memory_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                cpu_secs = max(1, int(self.max_duration_seconds))
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_secs, cpu_secs + 1))
                resource.setrlimit(resource.RLIMIT_NPROC, (5, 5))
            except Exception:
                pass

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(work_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=_linux_preexec,
            )
            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                exit_code = -1
        except Exception as exc:
            logger.error("Failed to spawn Linux isolated process: %s", exc)
            return -1, False

        return exit_code, timed_out

    def _run_posix(
        self,
        cmd: list[str],
        work_dir: Path,
        timeout: float,
    ) -> tuple[int | None, bool]:
        """macOS / generic POSIX containment."""
        timed_out = False
        exit_code: int | None = None

        def _posix_preexec() -> None:
            try:
                import resource
                mem_bytes = self.max_memory_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                cpu_secs = max(1, int(self.max_duration_seconds))
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_secs, cpu_secs + 1))
            except Exception:
                pass

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(work_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=_posix_preexec,
            )
            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                exit_code = -1
        except Exception as exc:
            logger.error("Failed to spawn POSIX isolated process: %s", exc)
            return -1, False

        return exit_code, timed_out
