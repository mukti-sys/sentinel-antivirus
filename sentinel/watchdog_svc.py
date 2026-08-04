"""Watchdog process -- monitors the core Sentinel service and restarts it
if it dies unexpectedly.

Implements architecture.md Section 6:
    A lightweight watchdog process checks the core service is alive and
    restarts it if not -- and logs unexpected termination as a signal in
    its own right (a killed security service is itself suspicious)

Design:
- Polls for the core service PID (from sentinel.pid) or queries the
  Windows SCM (Service Control Manager) every N seconds.
- If the core service is not running:
  1. Log the unexpected termination as a detection signal
  2. Attempt to restart it
  3. Emit a toast notification
- Can run as a separate Windows service or standalone.

Usage:
    python -m sentinel.watchdog_svc --standalone
    python -m sentinel.watchdog_svc install   (elevated)
"""
from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_PID_FILE = Path(__file__).resolve().parent / "data" / "sentinel.pid"
_POLL_INTERVAL = 10.0  # seconds
_RESTART_COOLDOWN = 30.0  # minimum seconds between restart attempts


def _pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running."""
    try:
        import psutil
        return psutil.pid_exists(pid)
    except Exception:
        return False


def _read_pid() -> int | None:
    """Read the core service PID from the PID file."""
    try:
        if _PID_FILE.exists():
            text = _PID_FILE.read_text().strip()
            return int(text) if text else None
    except (ValueError, OSError):
        pass
    return None


def _service_running() -> bool:
    """Check if SentinelCoreSvc is running via the SCM."""
    try:
        import win32service
        scm = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_CONNECT,
        )
        try:
            svc = win32service.OpenService(
                scm, "SentinelCoreSvc", win32service.SERVICE_QUERY_STATUS,
            )
            try:
                status = win32service.QueryServiceStatus(svc)
                return status[1] == win32service.SERVICE_RUNNING
            finally:
                win32service.CloseServiceHandle(svc)
        except Exception:
            return False
        finally:
            win32service.CloseServiceHandle(scm)
    except Exception:
        return False


def _restart_service() -> bool:
    """Attempt to restart the core service via the SCM."""
    try:
        import win32service
        scm = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_ALL_ACCESS,
        )
        try:
            svc = win32service.OpenService(
                scm, "SentinelCoreSvc", win32service.SERVICE_START,
            )
            try:
                win32service.StartService(svc, None)
                logger.info("watchdog: restarted SentinelCoreSvc")
                return True
            finally:
                win32service.CloseServiceHandle(svc)
        except Exception as exc:
            logger.error("watchdog: failed to restart service: %s", exc)
            return False
        finally:
            win32service.CloseServiceHandle(scm)
    except Exception as exc:
        logger.error("watchdog: SCM error: %s", exc)
        return False


def _notify_termination() -> None:
    """Send a notification about unexpected core service termination."""
    try:
        from sentinel.response.notifier import Notifier
        notifier = Notifier()
        notifier.notify_info(
            "Core detection service stopped unexpectedly. "
            "Attempting restart. A killed security service is itself "
            "suspicious -- check recent activity."
        )
    except Exception as exc:
        logger.warning("watchdog: notification failed: %s", exc)


class Watchdog:
    """Monitors the core Sentinel service and restarts it if needed."""

    def __init__(self, poll_interval: float = _POLL_INTERVAL) -> None:
        self._poll_interval = poll_interval
        self._running = False
        self._last_restart = 0.0

    def start(self) -> None:
        """Start the watchdog loop (blocking)."""
        logger.info("watchdog started (poll every %.0fs)", self._poll_interval)
        self._running = True

        while self._running:
            try:
                alive = self._check_alive()
                if not alive:
                    self._handle_death()
            except Exception:
                logger.exception("watchdog poll error")

            time.sleep(self._poll_interval)

    def stop(self) -> None:
        self._running = False

    def _check_alive(self) -> bool:
        """Check if the core service is alive via PID file or SCM."""
        # Try PID file first (works without admin).
        pid = _read_pid()
        if pid is not None and _pid_alive(pid):
            return True

        # Fall back to SCM query (needs admin).
        if _service_running():
            return True

        # If no PID file and no service, assume it hasn't been started yet.
        if pid is None:
            return True  # nothing to watch yet

        return False

    def _handle_death(self) -> None:
        """Handle an unexpected core service termination."""
        now = time.time()
        logger.warning("watchdog: core service appears dead")

        # Rate-limit restarts.
        if now - self._last_restart < _RESTART_COOLDOWN:
            logger.info("watchdog: cooldown active, skipping restart")
            return

        # Notify.
        _notify_termination()

        # Try to restart.
        if _restart_service():
            self._last_restart = now
            logger.info("watchdog: service restarted")
        else:
            logger.error("watchdog: restart failed -- manual intervention needed")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if "--standalone" in sys.argv:
        wd = Watchdog()
        try:
            wd.start()
        except KeyboardInterrupt:
            wd.stop()
        return 0

    print("Sentinel Watchdog")
    print()
    print("  python -m sentinel.watchdog_svc --standalone")
    return 0


if __name__ == "__main__":
    sys.exit(main())
