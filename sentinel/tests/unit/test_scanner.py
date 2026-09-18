"""Unit tests for OnDemandScanner (sentinel.engine.scanner)."""
from __future__ import annotations

import time
from pathlib import Path
import pytest

from sentinel.engine.scanner import (
    OnDemandScanner,
    ScanType,
    ScanStatus,
    ThreatSeverity,
    ThreatDetection,
    ScanProgress,
)
from sentinel.response.quarantine_store import QuarantineStore

# Sentinel-specific test payload (registered in rules/eicar.yar as Sentinel_Test_Payload)
# Using this prevents Windows Defender on the host from interfering with unit test temp files
SENTINEL_PAYLOAD = b"MZ\x90\x00SENTINEL-ANTIVIRUS-TEST-PAYLOAD-AUTONOMOUS-QUARANTINE\x00"
CLEAN_PAYLOAD = b"This is a perfectly safe text document for testing.\n"


@pytest.fixture
def scanner(tmp_path):
    """Fixture providing an OnDemandScanner instance without quarantine."""
    return OnDemandScanner()


@pytest.fixture
def quarantine_scanner(tmp_path):
    """Fixture providing an OnDemandScanner instance with auto-quarantine enabled."""
    store = QuarantineStore(
        quarantine_dir=tmp_path / "quarantine",
        db_path=tmp_path / "quarantine.db",
    )
    return OnDemandScanner(quarantine_store=store, auto_quarantine=True)


def test_scan_benign_file_returns_none(scanner, tmp_path):
    clean_file = tmp_path / "notes.txt"
    clean_file.write_bytes(CLEAN_PAYLOAD)

    detection = scanner.scan_file(clean_file)
    assert detection is None


def test_scan_nonexistent_file_returns_none(scanner, tmp_path):
    non_file = tmp_path / "ghost.exe"
    assert scanner.scan_file(non_file) is None


def test_scan_payload_detected(scanner, tmp_path):
    test_file = tmp_path / "suspicious.exe"
    test_file.write_bytes(SENTINEL_PAYLOAD)

    detection = scanner.scan_file(test_file)
    assert detection is not None
    assert "Sentinel_Test_Payload" in detection.threat_name
    assert detection.score >= 85.0
    assert detection.quarantined is False


def test_scan_with_auto_quarantine(quarantine_scanner, tmp_path):
    test_file = tmp_path / "malware.exe"
    test_file.write_bytes(SENTINEL_PAYLOAD)

    detection = quarantine_scanner.scan_file(test_file)
    assert detection is not None
    assert detection.quarantined is True
    assert detection.quarantine_id is not None
    # Original file was moved into quarantine
    assert not test_file.exists()


def test_execute_scan_directory(scanner, tmp_path):
    # Setup files in folder
    clean1 = tmp_path / "doc1.txt"
    clean1.write_bytes(CLEAN_PAYLOAD)

    sub = tmp_path / "subfolder"
    sub.mkdir()
    clean2 = sub / "doc2.txt"
    clean2.write_bytes(CLEAN_PAYLOAD)

    bad = sub / "threat.exe"
    bad.write_bytes(SENTINEL_PAYLOAD)

    progress_reports: list[ScanProgress] = []

    def on_prog(p: ScanProgress):
        progress_reports.append(p)

    summary = scanner.execute_scan(
        targets=[tmp_path],
        scan_type=ScanType.CUSTOM,
        progress_callback=on_prog,
    )

    assert summary.status == ScanStatus.COMPLETED
    assert summary.files_scanned >= 3
    assert summary.threats_found == 1
    assert len(summary.threats) == 1
    assert "Sentinel_Test_Payload" in summary.threats[0].threat_name
    assert len(progress_reports) >= 3


def test_scan_cancellation(scanner, tmp_path):
    # Create 50 files
    for i in range(50):
        (tmp_path / f"file_{i}.txt").write_bytes(b"content\n")

    cancelled_early = False

    def on_prog(p: ScanProgress):
        nonlocal cancelled_early
        if p.files_scanned >= 5:
            scanner.cancel()
            cancelled_early = True

    summary = scanner.execute_scan(
        targets=[tmp_path],
        scan_type=ScanType.CUSTOM,
        progress_callback=on_prog,
    )

    assert cancelled_early is True
    assert summary.status == ScanStatus.CANCELLED
    assert summary.files_scanned < 50


def test_scan_pause_and_resume(scanner, tmp_path):
    # Create 10 files
    for i in range(10):
        (tmp_path / f"test_{i}.txt").write_bytes(b"data\n")

    paused = False
    resumed = False

    def on_prog(p: ScanProgress):
        nonlocal paused, resumed
        if p.files_scanned == 2 and not paused:
            paused = True
            scanner.pause()
            assert scanner.status == ScanStatus.PAUSED
            # Schedule resume
            def do_resume():
                time.sleep(0.1)
                scanner.resume()

            import threading
            threading.Thread(target=do_resume).start()
            resumed = True

    summary = scanner.execute_scan(
        targets=[tmp_path],
        scan_type=ScanType.CUSTOM,
        progress_callback=on_prog,
    )

    assert summary.status == ScanStatus.COMPLETED
    assert summary.files_scanned == 10
    assert paused is True
    assert resumed is True


def test_quick_scan_targets_collection():
    targets = OnDemandScanner.get_quick_scan_targets()
    assert isinstance(targets, list)
    # Should at least find Desktop or Downloads or Temp
    assert len(targets) > 0


def test_full_scan_targets_collection():
    targets = OnDemandScanner.get_full_scan_targets()
    assert isinstance(targets, list)
    assert len(targets) >= 1
    assert any("C:" in str(t).upper() for t in targets)


def test_scan_triggers_dynamic_emulation(tmp_path):
    """Verify OnDemandScanner invokes dynamic emulation for evasive/packing binaries."""
    scanner = OnDemandScanner(read_only_mode=True, dynamic_analysis=True)

    # Create dummy executable with self-decrypting loop / API hashing
    sample = tmp_path / "packed_evasion.exe"
    # Shellcode setting EAX to ROR13 VirtualAlloc hash, then ROR EAX 13, RDTSC, RET
    shellcode = b"\xB8\x54\xCA\xAF\x91\xC1\xC8\x0D\x0F\x31\xC3"
    sample.write_bytes(shellcode)

    threat = scanner.scan_file(sample)
    assert threat is not None
    assert threat.engine == "dynamic_sandbox"
    assert "Sandbox" in threat.threat_name

