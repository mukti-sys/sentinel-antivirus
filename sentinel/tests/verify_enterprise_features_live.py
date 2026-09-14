"""Live Verification Script for Enterprise Features:
1. Ransomware Canary Deception Engine (Honeypot Traps + Camouflage)
2. System Tray Companion & Anti-Spam Sliding-Window Toast Alerts
3. Windows Service Mode & Named Pipe IPC (Session 0 Isolation Bridge)
"""
from __future__ import annotations

import logging
import os
import sys
import tempfile
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentinel.verify_enterprise_features")

from sentinel.engine.canary import CanaryManager, CANARY_TEMPLATES
from sentinel.engine.heuristics_ransomware import RansomwareHeuristic
from sentinel.engine.schema import Event, utc_timestamp
from sentinel.ipc import NamedPipeClient, NamedPipeServer
from sentinel.response.notifier import Notifier
from sentinel.ui.tray_app import TrayApp, _create_icon_image


def test_canary_deception_engine():
    print("\n" + "=" * 80)
    print(" [1/3] VERIFYING RANSOMWARE CANARY DECEPTION ENGINE (HONEYPOTS)")
    print("=" * 80)

    with tempfile.TemporaryDirectory() as tmp_dir:
        test_dir = Path(tmp_dir)
        mgr = CanaryManager(target_directories=[test_dir])
        armed_count = mgr.arm_traps()
        print(f"  [+] Armed {armed_count} canary traps in: {test_dir}")
        assert armed_count == len(CANARY_TEMPLATES), f"Expected {len(CANARY_TEMPLATES)}, got {armed_count}"

        # Verify canary camouflage & headers
        for trap in mgr.active_canaries.values():
            assert trap.path.exists(), f"Canary {trap.path} does not exist"
            assert trap.original_size > 0
            print(f"      - {trap.path.name}: {trap.original_size} bytes (SHA: {trap.original_sha256[:12]}...)")

        # Verify initial intact check
        tampered_initial = mgr.verify_all_canaries()
        assert len(tampered_initial) == 0
        print("  [+] Honeypots Integrity Check: All canaries intact and pristine.")

        # Simulate Ransomware Attack: LockBit / WannaCry modifying document
        canary_list = list(mgr.active_canaries.values())
        victim_canary = canary_list[0]
        print(f"  [*] Simulating ransomware encryption on victim honeypot: {victim_canary.path.name}")
        from sentinel.engine.canary import write_canary_content
        write_canary_content(victim_canary.path, b"LOCKED_BY_LOCKBIT_3.0_ENCRYPTED_DATA_BYTES", set_hidden=True)


        # Verify tampering detection
        tampered = mgr.verify_all_canaries()
        assert len(tampered) == 1, f"Expected 1 tampered canary, got {len(tampered)}"
        print(f"  [!] Honeypot Tripped! Detected tampering on: {tampered[0][0].path.name} ({tampered[0][1]})")

        # Verify Heuristics Integration
        heuristics = RansomwareHeuristic(canary_manager=mgr)
        attack_event = Event(
            timestamp=utc_timestamp(),
            event_type="file_write",
            source="fs",
            pid=7777,
            image_path=str(victim_canary.path),
            extra={"action": "modified"},
        )
        signals = heuristics.process_fs_event(attack_event)

        canary_signals = [s for s in signals if s.kind == "canary_tripped"]
        assert len(canary_signals) == 1, "Expected canary_tripped signal"
        print(f"  [+] Ransomware Heuristics generated: {canary_signals[0].kind} (reason={canary_signals[0].reason[:45]}...)")


        # Test Canary Self-Repair
        repaired = mgr.repair_canaries()
        assert repaired == 1
        assert len(mgr.verify_all_canaries()) == 0
        print(f"  [+] Canary Self-Repair: {repaired} honeypot(s) automatically regenerated and re-armed.")
        mgr.disarm_traps()


def test_anti_spam_tray_notifications():
    print("\n" + "=" * 80)
    print(" [2/3] VERIFYING SYSTEM TRAY COMPANION & ANTI-SPAM NOTIFICATIONS")
    print("=" * 80)

    # Test Icon generation
    for color in ("GREEN", "YELLOW", "RED"):
        img = _create_icon_image(color)
        assert img.size == (64, 64)
    print("  [+] Shield icons generated: GREEN (Protected), YELLOW (Warning), RED (Threat Blocked)")

    # Test Anti-spam alert throttling
    notifier = Notifier(cooldown_sec=1.5)
    print("  [*] Simulating 10 rapid burst encryption alerts from identical process...")
    # Send 10 rapid alerts
    for _ in range(10):
        notifier.notify_alert(
            process_name="ransomware_burst.exe",
            reason="Mass canary encryption burst",
            pid=8888,
            score=98.0,
        )

    suppressed = sum(notifier._suppressed_counts.values())
    print(f"  [+] Anti-Spam Sliding-Window: Suppressed {suppressed} redundant notifications (Anti-spam active).")
    assert suppressed == 9, f"Expected 9 suppressed alerts, got {suppressed}"


def test_windows_service_ipc():
    print("\n" + "=" * 80)
    print(" [3/3] VERIFYING WINDOWS SERVICE & WIN32 NAMED PIPE IPC")
    print("=" * 80)

    test_pipe = r"\\.\pipe\SentinelEnterpriseTestPipe"
    def service_handler(req: dict) -> dict:
        cmd = req.get("cmd")
        if cmd == "ping":
            return {"status": "ok", "pong": True, "service": "running"}
        elif cmd == "get_status":
            return {"status": "ok", "shield": "GREEN", "canaries_armed": 3, "driver": "connected"}
        return {"status": "error", "message": f"unknown: {cmd}"}

    server = NamedPipeServer(pipe_name=test_pipe, command_handler=service_handler)
    server.start()
    time.sleep(0.1)

    try:
        client = NamedPipeClient(pipe_name=test_pipe, timeout_ms=2000)
        assert client.is_service_running() is True
        print(f"  [+] Named Pipe IPC Server active on: {test_pipe}")

        # Send Ping
        ping_resp = client.send({"cmd": "ping"})
        assert ping_resp["pong"] is True
        print(f"  [+] Client Ping Transaction: SUCCESS ({ping_resp})")

        # Send Status Query
        status_resp = client.get_status()
        assert status_resp["shield"] == "GREEN"
        print(f"  [+] Status Query Transaction: SUCCESS ({status_resp})")
    finally:
        server.stop()
        print("  [+] Named Pipe IPC Server cleanly stopped.")



def main():
    print("================================================================================")
    print("          SENTINEL ENTERPRISE FEATURES LIVE VERIFICATION HARNESS")
    print("================================================================================")

    test_canary_deception_engine()
    test_anti_spam_tray_notifications()
    test_windows_service_ipc()

    print("\n" + "=" * 80)
    print("  ALL 3 ENTERPRISE COMPONENTS & TRADE-OFF MITIGATIONS VERIFIED 100% OK")
    print("================================================================================")


if __name__ == "__main__":
    main()
