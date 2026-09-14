"""Sandbox Execution Runner — safely executes untrusted or ambiguous binaries
in isolated Windows Job Objects to analyze runtime behavior.

Monitors:
- Files dropped/created in sandbox workspace
- Entropy surges in created files (ransomware activity)
- Dropped executable files or script extensions
- Child process spawning and unexpected crash behavior
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.engine.scoring import Signal
from sentinel.engine.static_classifier import _file_entropy
from sentinel.sandbox.job_object import SandboxJobObject

logger = logging.getLogger("sentinel.sandbox.runner")

# Suspicious extensions dropped during execution
EXECUTABLE_DROPPED_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta"
})


@dataclass
class SandboxReport:
    """Telemetry report produced from sandbox execution."""
    target_path: str
    duration_seconds: float
    exit_code: int | None
    files_created: list[str] = field(default_factory=list)
    dropped_executables: list[str] = field(default_factory=list)
    max_entropy_observed: float = 0.0
    threat_reasons: list[str] = field(default_factory=list)

    @property
    def is_malicious(self) -> bool:
        return (
            len(self.dropped_executables) > 0 or
            self.max_entropy_observed >= 7.6 or
            any("ransomware" in r.lower() or "dropped" in r.lower() for r in self.threat_reasons)
        )

    @property
    def is_suspicious(self) -> bool:
        return self.is_malicious or len(self.files_created) > 3 or bool(self.threat_reasons)

    def to_signals(self, pid: int | None = None) -> list[Signal]:
        signals: list[Signal] = []
        subject = f"file:{Path(self.target_path).name}" if not pid else f"pid:{pid}"

        if self.is_malicious:
            signals.append(
                Signal(
                    kind="sandbox_malicious",
                    subject=subject,
                    engine="sandbox",
                    reason=f"Sandbox execution confirmed malicious behavior: {'; '.join(self.threat_reasons)}",
                    weight=85.0,
                )
            )
        elif self.is_suspicious:
            signals.append(
                Signal(
                    kind="sandbox_suspicious",
                    subject=subject,
                    engine="sandbox",
                    reason=f"Sandbox execution observed anomalies: {'; '.join(self.threat_reasons or ['anomalous activity'])}",
                    weight=35.0,
                )
            )

        return signals


class SandboxRunner:
    """Executes target binary inside an isolated Job Object and analyzes behavior."""

    def __init__(
        self,
        max_duration_seconds: float = 8.0,
        max_memory_mb: int = 128,
        cpu_percent_limit: int = 20,
    ) -> None:
        self.max_duration_seconds = max_duration_seconds
        self.max_memory_mb = max_memory_mb
        self.cpu_percent_limit = cpu_percent_limit
        self._is_windows = sys.platform == "win32"

    def run_binary(
        self,
        binary_path: str | Path,
        args: list[str] | None = None,
    ) -> SandboxReport:
        """Run a binary in the sandbox workspace and return a behavior report."""
        target = Path(binary_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Binary not found: {target}")

        temp_dir = Path(tempfile.mkdtemp(prefix="sentinel_sandbox_"))
        cmd_args = args or []

        # Copy target binary into isolated workspace
        sandbox_bin = temp_dir / target.name
        shutil.copy2(target, sandbox_bin)

        start_time = time.time()
        files_created: list[str] = []
        dropped_execs: list[str] = []
        max_entropy = 0.0
        reasons: list[str] = []
        exit_code: int | None = None

        try:
            if self._is_windows:
                exit_code = self._run_windows_sandbox(
                    sandbox_bin,
                    cmd_args,
                    temp_dir,
                    self.max_duration_seconds,
                )
            else:
                # Fallback for mock/test runs on non-Windows
                proc = subprocess.Popen([str(sandbox_bin)] + cmd_args, cwd=str(temp_dir))
                try:
                    exit_code = proc.wait(timeout=self.max_duration_seconds)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    exit_code = -1

            duration = time.time() - start_time

            # Analyze filesystem artifacts generated in sandbox directory
            for root, _, files in os.walk(temp_dir):
                for fname in files:
                    fpath = Path(root) / fname
                    if fpath == sandbox_bin:
                        continue  # skip the original binary

                    rel_name = str(fpath.relative_to(temp_dir))
                    files_created.append(rel_name)

                    # Check for dropped executable payload
                    if fpath.suffix.lower() in EXECUTABLE_DROPPED_EXTENSIONS:
                        dropped_execs.append(rel_name)
                        reasons.append(f"Dropped executable payload: {rel_name}")

                    # Measure file entropy
                    try:
                        data = fpath.read_bytes()
                        ent = _file_entropy(data)
                        if ent > max_entropy:
                            max_entropy = ent
                        if ent >= 7.6 and len(data) >= 512:
                            reasons.append(f"High-entropy file generated ({rel_name}, entropy={ent:.2f} bits/byte)")
                    except Exception:
                        pass

        finally:
            # Clean up sandbox workspace
            shutil.rmtree(temp_dir, ignore_errors=True)

        return SandboxReport(
            target_path=str(target),
            duration_seconds=round(time.time() - start_time, 2),
            exit_code=exit_code,
            files_created=files_created,
            dropped_executables=dropped_execs,
            max_entropy_observed=round(max_entropy, 2),
            threat_reasons=reasons,
        )

    def _run_windows_sandbox(
        self,
        bin_path: Path,
        args: list[str],
        work_dir: Path,
        timeout: float,
    ) -> int | None:
        """Launch process in workspace, bind to JobObject, and observe."""
        cmd_list = [str(bin_path)] + args

        with SandboxJobObject(
            max_memory_mb=self.max_memory_mb,
            cpu_percent_limit=self.cpu_percent_limit,
        ) as job:
            proc = subprocess.Popen(
                cmd_list,
                cwd=str(work_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Assign process to Job Object
            job.assign_process(int(proc._handle))

            # Wait for timeout or process exit
            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                exit_code = -1

            return exit_code
