"""Sentinel Antivirus — Master Application Launcher.

Provides a unified double-clickable entrypoint for Sentinel:
- Background protection service (Sensors + EventBus + DetectionConsumer + KernelBridge)
- Modern consumer Desktop GUI Dashboard
- System tray minimization
- Explorer context menu registration

Usage:
    python sentinel_main.py             # Start background protection + open GUI
    python sentinel_main.py --service   # Run background protection headless
    python sentinel_main.py --gui       # Open GUI dashboard only
    python sentinel_main.py --scan PATH # Scan specific file or folder in GUI
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time
from pathlib import Path

# Configure top-level logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel.app")


def run_all(scan_target: str | None = None) -> int:
    """Run both background protection service and the GUI dashboard."""
    logger.info("Starting Sentinel Antivirus Engine...")

    # 1. Start background orchestrator in a daemon thread
    orchestrator = None
    try:
        from sentinel.service import SentinelOrchestrator
        orchestrator = SentinelOrchestrator()

        def service_thread():
            try:
                orchestrator.start()
            except Exception as exc:
                logger.error("Sentinel service loop terminated: %s", exc)

        t = threading.Thread(target=service_thread, name="sentinel-core-service", daemon=True)
        t.start()
        logger.info("Real-time background protection active")
    except Exception as exc:
        logger.warning("Could not start background service (running UI-only mode): %s", exc)

    # 2. Automatically register Windows Explorer context menu if needed
    try:
        from sentinel.ui.context_menu import install_context_menu, is_context_menu_installed
        if not is_context_menu_installed():
            install_context_menu()
    except Exception as exc:
        logger.debug("Context menu setup skipped: %s", exc)

    # 3. Launch the desktop GUI
    try:
        from sentinel.ui.dashboard import SentinelDashboard
        app = SentinelDashboard(
            quarantine_store=orchestrator._consumer.quarantine_store if orchestrator and orchestrator._consumer else None,
            auto_scan_target=scan_target,
        )
        logger.info("Sentinel Dashboard opened")
        app.mainloop()
    except Exception as exc:
        logger.exception("Error running Sentinel Dashboard: %s", exc)
    finally:
        if orchestrator:
            logger.info("Stopping Sentinel background engine...")
            orchestrator.stop()

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel Antivirus Master Launcher")
    parser.add_argument("--service", action="store_true", help="Run background protection service only (headless)")
    parser.add_argument("--gui", action="store_true", help="Launch GUI dashboard only")
    parser.add_argument("--scan", type=str, help="Scan target file or directory upon launch", default=None)

    args = parser.parse_args()

    if args.service:
        from sentinel.service import SentinelOrchestrator
        orch = SentinelOrchestrator()
        orch.start()
        return 0

    if args.gui:
        from sentinel.ui.dashboard import SentinelDashboard
        app = SentinelDashboard(auto_scan_target=args.scan)
        app.mainloop()
        return 0

    return run_all(scan_target=args.scan)


if __name__ == "__main__":
    sys.exit(main())
