"""Unit tests for sandbox/job_object.py and sandbox/runner.py."""
import os
import sys
from pathlib import Path
import pytest

from sentinel.sandbox.job_object import SandboxJobObject
from sentinel.sandbox.runner import SandboxReport, SandboxRunner


def test_sandbox_report_evaluation():
    """Verify SandboxReport threat categorization and signal mapping."""
    # Clean report
    clean = SandboxReport(
        target_path="clean.exe",
        duration_seconds=1.2,
        exit_code=0,
        files_created=["temp.txt"],
        max_entropy_observed=4.5,
    )
    assert clean.is_malicious is False
    assert clean.is_suspicious is False
    assert clean.to_signals() == []

    # Dropper malware report
    dropper = SandboxReport(
        target_path="dropper.exe",
        duration_seconds=0.8,
        exit_code=0,
        files_created=["sub\\payload.dll"],
        dropped_executables=["sub\\payload.dll"],
        threat_reasons=["Dropped executable payload: sub\\payload.dll"],
    )
    assert dropper.is_malicious is True
    sigs = dropper.to_signals()
    assert len(sigs) == 1
    assert sigs[0].kind == "sandbox_malicious"
    assert sigs[0].effective_weight == 85.0
    assert "payload.dll" in sigs[0].reason

    # High entropy ransomware report
    ransom = SandboxReport(
        target_path="crypt.exe",
        duration_seconds=2.1,
        exit_code=0,
        files_created=["encrypted.dat"],
        max_entropy_observed=7.89,
        threat_reasons=["High-entropy file generated (encrypted.dat)"],
    )
    assert ransom.is_malicious is True
    sigs = ransom.to_signals()
    assert len(sigs) == 1
    assert sigs[0].kind == "sandbox_malicious"


@pytest.mark.skipif(sys.platform != "win32", reason="Requires Windows Job Objects")
def test_sandbox_job_object_lifecycle():
    """Verify Job Object creation, limits, and cleanup."""
    with SandboxJobObject(max_memory_mb=64, max_processes=3, cpu_percent_limit=15) as job:
        assert job._handle is not None
        assert job.max_memory_mb == 64
        assert job.cpu_percent_limit == 15

    # Should be closed outside context manager
    assert job._handle is None


@pytest.mark.skipif(sys.platform != "win32", reason="Requires Windows")
def test_sandbox_runner_executes_benign_command(tmp_path):
    """Execute benign command in sandbox and verify clean execution and report."""
    runner = SandboxRunner(max_duration_seconds=4.0)
    cmd_exe = Path(os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"))

    report = runner.run_binary(cmd_exe, args=["/c", "exit 0"])
    assert report.exit_code == 0
    assert report.is_malicious is False
    assert report.duration_seconds < 4.0
