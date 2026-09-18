"""Cross-platform service/daemon management for Sentinel Antivirus.

Provides:
    - Windows: pywin32 service wrapper (delegates to sentinel.service)
    - Linux:   systemd unit file generation + systemctl management
    - macOS:   launchd plist generation + launchctl management
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger("sentinel.platform.service_runner")

_PLATFORM = sys.platform

# ---------------------------------------------------------------------------
# systemd (Linux)
# ---------------------------------------------------------------------------
_SYSTEMD_UNIT_TEMPLATE = """\
[Unit]
Description=Sentinel Antivirus Core Detection Service
Documentation=https://github.com/mukti-sys/sentinel-antivirus
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart={python_path} -m sentinel.service --standalone
WorkingDirectory={install_dir}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinel

# Security hardening
ProtectSystem=strict
ReadWritePaths={data_dir} /var/run/sentinel
ProtectHome=read-only
NoNewPrivileges=false
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN
AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
"""

# ---------------------------------------------------------------------------
# launchd (macOS)
# ---------------------------------------------------------------------------
_LAUNCHD_PLIST_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sentinel.antivirus</string>

    <key>ProgramArguments</key>
    <array>
        <string>{python_path}</string>
        <string>-m</string>
        <string>sentinel.service</string>
        <string>--standalone</string>
    </array>

    <key>WorkingDirectory</key>
    <string>{install_dir}</string>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>{log_dir}/sentinel.log</string>

    <key>StandardErrorPath</key>
    <string>{log_dir}/sentinel.err.log</string>
</dict>
</plist>
"""


class ServiceManager:
    """Cross-platform service/daemon lifecycle management."""

    def __init__(
        self,
        install_dir: str = "",
        data_dir: str = "",
        log_dir: str = "",
        python_path: str = "",
    ) -> None:
        from sentinel.platform import (
            DEFAULT_INSTALL_DIR, DEFAULT_DATA_DIR, DEFAULT_LOG_DIR,
        )
        self.install_dir = install_dir or DEFAULT_INSTALL_DIR
        self.data_dir = data_dir or DEFAULT_DATA_DIR
        self.log_dir = log_dir or DEFAULT_LOG_DIR
        self.python_path = python_path or sys.executable

    # ------------------------------------------------------------------ #
    # Installation
    # ------------------------------------------------------------------ #
    def install(self) -> bool:
        """Install the service/daemon for the current platform."""
        if _PLATFORM == "win32":
            return self._install_windows()
        elif _PLATFORM == "linux":
            return self._install_systemd()
        elif _PLATFORM == "darwin":
            return self._install_launchd()
        else:
            logger.error("Unsupported platform for service installation: %s", _PLATFORM)
            return False

    def uninstall(self) -> bool:
        """Uninstall the service/daemon."""
        if _PLATFORM == "win32":
            return self._uninstall_windows()
        elif _PLATFORM == "linux":
            return self._uninstall_systemd()
        elif _PLATFORM == "darwin":
            return self._uninstall_launchd()
        return False

    def start(self) -> bool:
        """Start the service/daemon."""
        if _PLATFORM == "win32":
            return self._run_cmd(["sc", "start", "SentinelCoreSvc"])
        elif _PLATFORM == "linux":
            return self._run_cmd(["systemctl", "start", "sentinel"])
        elif _PLATFORM == "darwin":
            return self._run_cmd(["launchctl", "load", self._plist_path()])
        return False

    def stop(self) -> bool:
        """Stop the service/daemon."""
        if _PLATFORM == "win32":
            return self._run_cmd(["sc", "stop", "SentinelCoreSvc"])
        elif _PLATFORM == "linux":
            return self._run_cmd(["systemctl", "stop", "sentinel"])
        elif _PLATFORM == "darwin":
            return self._run_cmd(["launchctl", "unload", self._plist_path()])
        return False

    def status(self) -> str:
        """Return service status as a human-readable string."""
        try:
            if _PLATFORM == "win32":
                result = subprocess.run(
                    ["sc", "query", "SentinelCoreSvc"],
                    capture_output=True, text=True, timeout=5,
                )
                if "RUNNING" in result.stdout:
                    return "running"
                elif "STOPPED" in result.stdout:
                    return "stopped"
                return "unknown"
            elif _PLATFORM == "linux":
                result = subprocess.run(
                    ["systemctl", "is-active", "sentinel"],
                    capture_output=True, text=True, timeout=5,
                )
                return result.stdout.strip()
            elif _PLATFORM == "darwin":
                result = subprocess.run(
                    ["launchctl", "list", "com.sentinel.antivirus"],
                    capture_output=True, text=True, timeout=5,
                )
                return "running" if result.returncode == 0 else "stopped"
        except Exception as exc:
            logger.debug("Status check failed: %s", exc)
        return "unknown"

    # ------------------------------------------------------------------ #
    # Linux — systemd
    # ------------------------------------------------------------------ #
    def _install_systemd(self) -> bool:
        unit_content = _SYSTEMD_UNIT_TEMPLATE.format(
            python_path=self.python_path,
            install_dir=self.install_dir,
            data_dir=self.data_dir,
        )
        unit_path = Path("/etc/systemd/system/sentinel.service")
        try:
            unit_path.write_text(unit_content)
            self._run_cmd(["systemctl", "daemon-reload"])
            self._run_cmd(["systemctl", "enable", "sentinel"])
            logger.info("systemd service installed: %s", unit_path)
            return True
        except PermissionError:
            logger.error("Root privileges required to install systemd service")
            return False
        except Exception as exc:
            logger.error("systemd install failed: %s", exc)
            return False

    def _uninstall_systemd(self) -> bool:
        self._run_cmd(["systemctl", "stop", "sentinel"])
        self._run_cmd(["systemctl", "disable", "sentinel"])
        unit_path = Path("/etc/systemd/system/sentinel.service")
        try:
            unit_path.unlink(missing_ok=True)
            self._run_cmd(["systemctl", "daemon-reload"])
            return True
        except Exception as exc:
            logger.error("systemd uninstall failed: %s", exc)
            return False

    # ------------------------------------------------------------------ #
    # macOS — launchd
    # ------------------------------------------------------------------ #
    def _plist_path(self) -> str:
        return str(Path.home() / "Library" / "LaunchAgents" / "com.sentinel.antivirus.plist")

    def _install_launchd(self) -> bool:
        plist_content = _LAUNCHD_PLIST_TEMPLATE.format(
            python_path=self.python_path,
            install_dir=self.install_dir,
            log_dir=self.log_dir,
        )
        plist_path = Path(self._plist_path())
        try:
            plist_path.parent.mkdir(parents=True, exist_ok=True)
            plist_path.write_text(plist_content)
            logger.info("launchd plist installed: %s", plist_path)
            return True
        except Exception as exc:
            logger.error("launchd install failed: %s", exc)
            return False

    def _uninstall_launchd(self) -> bool:
        self.stop()
        try:
            Path(self._plist_path()).unlink(missing_ok=True)
            return True
        except Exception as exc:
            logger.error("launchd uninstall failed: %s", exc)
            return False

    # ------------------------------------------------------------------ #
    # Windows — pywin32 (delegates to existing code)
    # ------------------------------------------------------------------ #
    def _install_windows(self) -> bool:
        return self._run_cmd([sys.executable, "-m", "sentinel.service", "install"])

    def _uninstall_windows(self) -> bool:
        self._run_cmd([sys.executable, "-m", "sentinel.service", "stop"])
        return self._run_cmd([sys.executable, "-m", "sentinel.service", "remove"])

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _run_cmd(cmd: list[str]) -> bool:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.returncode == 0
        except Exception as exc:
            logger.debug("Command %s failed: %s", cmd, exc)
            return False
