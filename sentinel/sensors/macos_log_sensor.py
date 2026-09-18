"""macOS Unified Logging sensor — replacement for ETW/Event Log on macOS.

Monitors process creation, network activity, and security events via
macOS Unified Logging (``log stream``). This provides similar telemetry
to Windows ETW without requiring EndpointSecurity entitlements.

Captures:
    - Process creation/exit events
    - Network connection events
    - Security and authentication events (sudo, login, Gatekeeper)
    - Kernel security events

Note: Full EndpointSecurity framework requires a paid Apple Developer
Program membership ($99/year) for the entitlement. This sensor uses the
free ``log stream`` approach which provides read-only event monitoring.
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

logger = logging.getLogger("sentinel.sensors.macos_log")

# log stream predicates for security-relevant events
_LOG_PREDICATES = [
    # Process events
    '(subsystem == "com.apple.securityd")',
    '(subsystem == "com.apple.authd")',
    '(subsystem == "com.apple.sandbox")',
    '(category == "process")',
    # Security events
    '(subsystem == "com.apple.ManagedClient")',
    '(subsystem == "com.apple.securityd")',
    # Gatekeeper
    '(subsystem == "com.apple.syspolicy")',
]

# Patterns for classifying log messages
_CLASSIFICATION_PATTERNS = [
    (re.compile(r"exec\w*\s+of\s+", re.IGNORECASE), "process_create", "info"),
    (re.compile(r"process\s+\d+\s+(?:started|launched)", re.IGNORECASE), "process_create", "info"),
    (re.compile(r"process\s+\d+\s+(?:exited|terminated)", re.IGNORECASE), "process_exit", "info"),
    (re.compile(r"(?:authentication|login)\s+(?:success|accepted)", re.IGNORECASE), "auth_success", "info"),
    (re.compile(r"(?:authentication|login)\s+(?:fail|denied|reject)", re.IGNORECASE), "auth_failure", "warning"),
    (re.compile(r"sudo", re.IGNORECASE), "sudo_command", "info"),
    (re.compile(r"sandbox\s+violation", re.IGNORECASE), "sandbox_violation", "warning"),
    (re.compile(r"gatekeeper|notarization|quarantine", re.IGNORECASE), "gatekeeper_event", "warning"),
    (re.compile(r"(?:denied|blocked|rejected)", re.IGNORECASE), "security_block", "warning"),
    (re.compile(r"connection\s+(?:to|from)", re.IGNORECASE), "network_event", "info"),
    (re.compile(r"(?:keychain|certificate)", re.IGNORECASE), "keychain_event", "info"),
]


class MacOSLogSensor:
    """macOS Unified Logging sensor.

    Monitors the system log stream for security-relevant events and
    publishes them to the Sentinel EventBus.
    """

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._thread: Optional[threading.Thread] = None
        self._proc: Optional[subprocess.Popen] = None
        self._running = False

    def start(self) -> None:
        """Start monitoring the macOS log stream."""
        if sys.platform != "darwin":
            raise RuntimeError("MacOSLogSensor is macOS-only")

        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_log_stream,
            name="sentinel-macos-log",
            daemon=True,
        )
        self._thread.start()
        logger.info("macOS log sensor started")

    def stop(self) -> None:
        """Stop the log stream monitor."""
        self._running = False
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("macOS log sensor stopped")

    def _monitor_log_stream(self) -> None:
        """Run ``log stream`` and process output."""
        # Build predicate combining all security-relevant filters
        predicate = " OR ".join(_LOG_PREDICATES)

        cmd = [
            "log", "stream",
            "--style", "json",
            "--level", "info",
            "--predicate", predicate,
        ]

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )

            # Skip the header line
            buffer = ""
            while self._running and self._proc.poll() is None:
                line = self._proc.stdout.readline()
                if not line:
                    continue

                line = line.strip()
                if not line:
                    continue

                # Try to parse as JSON
                try:
                    entry = json.loads(line)
                    self._process_log_entry(entry)
                except json.JSONDecodeError:
                    # Some lines aren't valid JSON — try to extract info
                    self._process_plain_line(line)

        except FileNotFoundError:
            logger.error("'log' command not found — macOS log sensor disabled")
        except Exception as exc:
            logger.error("macOS log stream failed: %s", exc)

    def _process_log_entry(self, entry: dict) -> None:
        """Process a structured JSON log entry."""
        message = entry.get("eventMessage", "")
        subsystem = entry.get("subsystem", "")
        category = entry.get("category", "")
        process = entry.get("processImagePath", "")
        pid = entry.get("processID", 0)

        if not message:
            return

        # Classify the event
        event_type, severity = self._classify_message(message)
        if event_type == "unknown":
            return

        event = Event(
            timestamp=utc_timestamp(),
            source="macos_log",
            event_type=event_type,
            severity=severity,
            description=f"[{subsystem}/{category}] {message[:300]}",
            extra={
                "subsystem": subsystem,
                "category": category,
                "process": process,
                "pid": pid,
                "message": message[:1000],
            },
        )
        self._bus.publish(event)

    def _process_plain_line(self, line: str) -> None:
        """Process a plain-text log line (fallback)."""
        event_type, severity = self._classify_message(line)
        if event_type == "unknown":
            return

        event = Event(
            timestamp=utc_timestamp(),
            source="macos_log",
            event_type=event_type,
            severity=severity,
            description=line[:300],
            extra={"raw": line[:1000]},
        )
        self._bus.publish(event)

    @staticmethod
    def _classify_message(message: str) -> tuple[str, str]:
        """Classify a log message by type and severity."""
        for pattern, event_type, severity in _CLASSIFICATION_PATTERNS:
            if pattern.search(message):
                return event_type, severity
        return "unknown", "info"
