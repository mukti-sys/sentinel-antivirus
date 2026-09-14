"""Unit tests for SentinelDashboard GUI components and controllers."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from sentinel.engine.memory_scanner import MemoryThreat
from sentinel.response.quarantine_store import QuarantineStore
from sentinel.sandbox.runner import DroppedFile, SandboxReport
from sentinel.ui.dashboard import SentinelDashboard


@pytest.fixture
def test_dashboard(tmp_path):
    """Fixture providing a headless-friendly SentinelDashboard instance."""
    store = QuarantineStore(
        quarantine_dir=tmp_path / "quarantine",
        db_path=tmp_path / "quarantine.db",
    )
    app = SentinelDashboard(quarantine_store=store)
    app.withdraw()  # keep invisible
    yield app
    try:
        app.destroy()
    except Exception:
        pass


def test_dashboard_tabs_exist(test_dashboard):
    """Ensure all required consumer navigation tabs and frame views exist."""
    required_tabs = [
        "overview",
        "scan",
        "sandbox",
        "memory",
        "network",
        "quarantine",
        "logs",
        "settings",
    ]
    for tab in required_tabs:
        assert tab in test_dashboard._tab_frames
        assert tab in test_dashboard._nav_buttons


def test_dashboard_tab_switching(test_dashboard):
    """Verify switching tabs activates frames and updates button highlight."""
    test_dashboard._switch_tab("sandbox")
    assert test_dashboard._current_tab == "sandbox"

    test_dashboard._switch_tab("memory")
    assert test_dashboard._current_tab == "memory"

    test_dashboard._switch_tab("network")
    assert test_dashboard._current_tab == "network"


def test_sandbox_report_handling(test_dashboard, tmp_path):
    """Verify sandbox completion populates telemetry tiles and audit treeview."""
    report = SandboxReport(
        target_path=str(tmp_path / "payload.exe"),
        exit_code=0,
        duration_seconds=3.2,
        peak_memory_mb=24.5,
        max_memory_mb=128,
        cpu_rate_pct=20,
        timed_out=False,
        threat_reasons=["Dropped high entropy binary"],
        findings=[{"category": "Heuristic", "detail": "Dropped high entropy binary", "severity": "HIGH"}],
        dropped_files=[DroppedFile(path=str(tmp_path / "dropped.dat"), size_bytes=1024, entropy=7.65, is_high_entropy=True)],
        pids_spawned=[4012, 4016],
    )

    test_dashboard._on_sandbox_finished(report, report.target_path)

    assert "MALICIOUS" in test_dashboard.lbl_tile_verdict.cget("text")
    assert "24.5 MB" in test_dashboard.lbl_tile_memory.cget("text")
    children = test_dashboard.tree_sandbox.get_children()
    assert len(children) >= 3


def test_memory_scan_handling(test_dashboard):
    """Verify memory scan completion populates memory threat treeview."""
    threat = MemoryThreat(
        pid=1337,
        process_name="bad_injector.exe",
        base_address=0x7FF60000,
        size=4096,
        threat_type="UNBACKED_RWX",
        description="Executable private memory region unbacked by filesystem image",
        confidence=95.0,
        protection=0x40,  # PAGE_EXECUTE_READWRITE
    )

    test_dashboard._on_memory_scan_finished(scanned_count=25, threats=[(1337, "bad_injector.exe", threat)], rwx_count=1)

    assert "THREATS DETECTED" in test_dashboard.lbl_tile_mem_status.cget("text")
    assert test_dashboard.lbl_tile_mem_threats.cget("text") == "1"
    children = test_dashboard.tree_memory.get_children()
    assert len(children) == 1
    values = test_dashboard.tree_memory.item(children[0])["values"]
    assert values[0] == 1337
    assert values[1] == "bad_injector.exe"
    assert "UNBACKED_RWX" in str(values[4])


def test_network_scan_handling(test_dashboard):
    """Verify network scan completion flags C2 indicators with badges."""
    sample_connections = [
        (4500, "malware.exe", "TCP", "192.168.1.50:50234", "185.106.94.13:4444", "ESTABLISHED", "🚨 Known C2 Threat Intel IP"),
        (1000, "chrome.exe", "TCP", "192.168.1.50:50235", "142.250.190.46:443", "ESTABLISHED", "Clean"),
    ]

    test_dashboard._on_network_scan_finished(sample_connections, c2_threat_count=1)

    assert test_dashboard.lbl_tile_net_threats.cget("text") == "1"
    children = test_dashboard.tree_network.get_children()
    assert len(children) == 2

    # Suspicious connection should be sorted to top
    first_item = test_dashboard.tree_network.item(children[0])["values"]
    assert "🚨" in str(first_item[6])
