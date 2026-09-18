"""Linux systemd journal sensor — replacement for Windows Event Log sensor.

Monitors security-relevant events from the systemd journal:
    - Failed login attempts (SSH, PAM)
    - sudo invocations
    - Service start/stop/crash events
    - Package manager activity (apt, dnf)
    - Firewall/iptables log entries

Uses ``systemd.journal`` Python bindings when available, falls back
to ``journalctl --follow`` subprocess.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import threading
import time
from typing import Optional

from sentinel.engine.event_bus import EventBus
from sentinel.engine.schema import Event, utc_timestamp

logger = logging.getLogger("sentinel.sensors.journald")

# Security-relevant syslog identifiers
_SECURITY_UNITS = frozenset({
    "sshd", "sudo", "su", "login", "passwd",
    "systemd-logind", "polkitd", "pkexec",
    "ufw", "iptables", "nftables", "firewalld",
    "apt", "apt-get", "dpkg", "dnf", "yum", "rpm",
    "cron", "at", "anacron",
})

# Patterns that indicate security-relevant events
_SECURITY_PATTERNS = [
    (re.compile(r"Failed password", re.IGNORECASE), "auth_failure", "warning"),
    (re.compile(r"Accepted (?:password|publickey)", re.IGNORECASE), "auth_success", "info"),
    (re.compile(r"authentication failure", re.IGNORECASE), "auth_failure", "warning"),
    (re.compile(r"session opened", re.IGNORECASE), "session_open", "info"),
    (re.compile(r"session closed", re.IGNORECASE), "session_close", "info"),
    (re.compile(r"COMMAND=", re.IGNORECASE), "sudo_command", "info"),
    (re.compile(r"(Started|Stopped|Failed)\s+", re.IGNORECASE), "service_event", "info"),
    (re.compile(r"(install|remove|upgrade|purge)\s+", re.IGNORECASE), "package_event", "info"),
    (re.compile(r"(BLOCK|DROP|REJECT)", re.IGNORECASE), "firewall_event", "warning"),
    (re.compile(r"segfault|coredump|oom-kill", re.IGNORECASE), "crash_event", "critical"),
]


class JournaldSensor:
    """Systemd journal security event sensor.

    Continuously monitors the journal for security-relevant events and
    publishes them to the Sentinel EventBus.
    """

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        """Start monitoring the systemd journal."""
        if sys.platform != "linux":
            raise RuntimeError("JournaldSensor is Linux-only")

        self._running = True

        # Try native systemd.journal first, fall back to journalctl
        try:
            import systemd.journal  # noqa: F401
            target = self._monitor_native
            mode = "systemd.journal"
        except ImportError:
            target = self._monitor_journalctl
            mode = "journalctl"

        self._thread = threading.Thread(
            target=target,
            name="sentinel-journald",
            daemon=True,
        )
        self._thread.start()
        logger.info("journald sensor started (mode=%s)", mode)

    def stop(self) -> None:
        """Stop the journal monitor."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("journald sensor stopped")

    def _monitor_native(self) -> None:
        """Monitor journal using systemd.journal Python bindings."""
        try:
            import systemd.journal
            import select

            journal = systemd.journal.Reader()
            journal.log_level(logging.INFO)

            # Only follow security-relevant units
            for unit in _SECURITY_UNITS:
                try:
                    journal.add_match(SYSLOG_IDENTIFIER=unit)
                    journal.add_disjunction()
                except Exception:
                    pass

            # Seek to tail (only process new entries)
            journal.seek_tail()
            journal.get_previous()

            poller = select.poll()
            poller.register(journal, journal.get_events())

            while self._running:
                if poller.poll(1000):
                    if journal.process() == systemd.journal.APPEND:
                        for entry in journal:
                            self._process_journal_entry(entry)
        except Exception as exc:
            logger.error("Native journal monitor failed: %s — falling back", exc)
            self._monitor_journalctl()

    def _monitor_journalctl(self) -> None:
        """Monitor journal using journalctl subprocess."""
        try:
            cmd = [
                "journalctl", "-f", "--no-pager",
                "--output", "json",
                "-p", "info",  # priority info and above
            ]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )

            while self._running and proc.poll() is None:
                line = proc.stdout.readline()
                if not line:
                    continue

                try:
                    entry = json.loads(line.strip())
                    self._process_journal_entry(entry)
                except json.JSONDecodeError:
                    # Non-JSON output from journalctl — parse as plain text
                    self._process_plain_line(line.strip())

            proc.terminate()
        except FileNotFoundError:
            logger.warning("journalctl not found — journald sensor disabled")
        except Exception as exc:
            logger.error("journalctl monitor failed: %s", exc)

    def _process_journal_entry(self, entry: dict) -> None:
        """Process a structured journal entry."""
        message = str(entry.get("MESSAGE", ""))
        syslog_id = str(entry.get("SYSLOG_IDENTIFIER", ""))
        unit = str(entry.get("_SYSTEMD_UNIT", ""))
        pid = entry.get("_PID", 0)

        # Check if this is from a security-relevant source
        source_name = syslog_id or unit.replace(".service", "")
        if source_name not in _SECURITY_UNITS and not self._matches_security_pattern(message):
            return

        # Classify the event
        event_type, severity = self._classify_message(message)

        event = Event(
            timestamp=utc_timestamp(),
            source="journald",
            event_type=event_type,
            severity=severity,
            description=f"[{source_name}] {message[:300]}",
            extra={
                "syslog_identifier": syslog_id,
                "unit": unit,
                "pid": int(pid) if str(pid).isdigit() else 0,
                "message": message[:1000],
            },
        )
        self._bus.publish(event)

    def _process_plain_line(self, line: str) -> None:
        """Process a plain-text journal line (fallback)."""
        if not self._matches_security_pattern(line):
            return

        event_type, severity = self._classify_message(line)

        event = Event(
            timestamp=utc_timestamp(),
            source="journald",
            event_type=event_type,
            severity=severity,
            description=line[:300],
            extra={"raw": line[:1000]},
        )
        self._bus.publish(event)

    @staticmethod
    def _matches_security_pattern(message: str) -> bool:
        """Check if a message matches any security-relevant pattern."""
        return any(pattern.search(message) for pattern, _, _ in _SECURITY_PATTERNS)

    @staticmethod
    def _classify_message(message: str) -> tuple[str, str]:
        """Classify a journal message by type and severity."""
        for pattern, event_type, severity in _SECURITY_PATTERNS:
            if pattern.search(message):
                return event_type, severity
        return "system_event", "info"
