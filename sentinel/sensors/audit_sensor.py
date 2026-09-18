"""Linux Audit subsystem sensor — replacement for ETW on Linux.

Monitors process creation, file access, and network events via the
Linux Audit framework (auditd). This provides similar telemetry to
Windows ETW but through the Linux kernel's audit infrastructure.

Modes of operation (in order of preference):
1. ``auditd`` + ``ausearch`` — parses structured audit records
2. Direct ``/var/log/audit/audit.log`` tailing — fallback if ausearch unavailable
3. ``/var/log/syslog`` / ``journalctl`` — last resort

Requirements:
    - ``auditd`` package installed and running (optional but recommended)
    - Read access to ``/var/log/audit/audit.log`` (root or audit group)
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from sentinel.engine.event_bus import EventBus
from sentinel.engine.schema import Event, utc_timestamp

logger = logging.getLogger("sentinel.sensors.audit")

# Audit record types we care about
_AUDIT_TYPES = {
    "SYSCALL",
    "EXECVE",
    "CWD",
    "PATH",
    "PROCTITLE",
    "SOCKADDR",
    "USER_AUTH",
    "USER_LOGIN",
    "USER_START",
    "ANOM_PROMISCUOUS",
}

# Regex patterns for parsing audit log lines
_RE_TYPE = re.compile(r'type=(\w+)')
_RE_MSG = re.compile(r'msg=audit\((\d+\.\d+):(\d+)\)')
_RE_KEY_VALUE = re.compile(r'(\w+)=("[^"]*"|\S+)')
_RE_EXECVE_ARG = re.compile(r'a(\d+)=(".*?"|\S+)')


class AuditSensor:
    """Linux Audit subsystem sensor.

    Emits process creation (``process_create``), file access
    (``file_access``), and authentication (``auth_event``) events
    into the Sentinel EventBus.
    """

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._last_serial: int = 0

    def start(self) -> None:
        """Start monitoring audit events."""
        if sys.platform != "linux":
            raise RuntimeError("AuditSensor is Linux-only")

        self._running = True

        # Determine monitoring mode
        if self._auditd_available():
            target = self._tail_audit_log
            mode = "audit.log"
        else:
            target = self._poll_journalctl
            mode = "journalctl"

        self._thread = threading.Thread(
            target=target,
            name="sentinel-audit",
            daemon=True,
        )
        self._thread.start()
        logger.info("audit sensor started (mode=%s)", mode)

    def stop(self) -> None:
        """Stop the audit sensor."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("audit sensor stopped")

    @staticmethod
    def _auditd_available() -> bool:
        """Check if auditd is running and log is readable."""
        log_path = Path("/var/log/audit/audit.log")
        return log_path.exists() and os.access(str(log_path), os.R_OK)

    def _tail_audit_log(self) -> None:
        """Tail /var/log/audit/audit.log for new events."""
        log_path = "/var/log/audit/audit.log"
        try:
            with open(log_path, "r") as f:
                # Seek to end
                f.seek(0, 2)
                while self._running:
                    line = f.readline()
                    if line:
                        self._process_audit_line(line.strip())
                    else:
                        time.sleep(0.1)
        except Exception as exc:
            logger.error("audit log tail failed: %s", exc)

    def _poll_journalctl(self) -> None:
        """Fall back to journalctl for audit events."""
        try:
            proc = subprocess.Popen(
                [
                    "journalctl", "-f", "--no-pager",
                    "-t", "audit",
                    "--output", "short",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )

            while self._running and proc.poll() is None:
                line = proc.stdout.readline()
                if line:
                    self._process_audit_line(line.strip())

            proc.terminate()
        except FileNotFoundError:
            logger.warning("journalctl not found — audit sensor disabled")
        except Exception as exc:
            logger.error("journalctl audit monitor failed: %s", exc)

    def _process_audit_line(self, line: str) -> None:
        """Parse a single audit log line and emit appropriate events."""
        type_match = _RE_TYPE.search(line)
        if not type_match:
            return

        audit_type = type_match.group(1)
        if audit_type not in _AUDIT_TYPES:
            return

        # Parse key-value pairs
        fields = dict(_RE_KEY_VALUE.findall(line))
        # Strip quotes from values
        fields = {k: v.strip('"') for k, v in fields.items()}

        # Deduplicate by serial
        msg_match = _RE_MSG.search(line)
        if msg_match:
            serial = int(msg_match.group(2))
            if serial <= self._last_serial:
                return
            self._last_serial = serial

        if audit_type == "EXECVE":
            self._emit_process_create(fields, line)
        elif audit_type == "SYSCALL" and fields.get("syscall") in ("59", "322"):
            # execve(59) or execveat(322)
            self._emit_process_create(fields, line)
        elif audit_type in ("USER_AUTH", "USER_LOGIN", "USER_START"):
            self._emit_auth_event(audit_type, fields)
        elif audit_type == "PATH":
            self._emit_file_access(fields)

    def _emit_process_create(self, fields: dict, raw: str) -> None:
        """Emit a process_create event."""
        exe = fields.get("exe", "unknown")
        pid = fields.get("pid", "0")
        ppid = fields.get("ppid", "0")
        uid = fields.get("uid", "-1")
        comm = fields.get("comm", "unknown")

        event = Event(
            timestamp=utc_timestamp(),
            source="audit",
            event_type="process_create",
            severity="info",
            description=f"Process created: {comm} (pid={pid})",
            extra={
                "exe": exe,
                "pid": int(pid) if pid.isdigit() else 0,
                "ppid": int(ppid) if ppid.isdigit() else 0,
                "uid": int(uid) if uid.lstrip("-").isdigit() else -1,
                "comm": comm,
                "raw": raw[:500],
            },
        )
        self._bus.publish(event)

    def _emit_auth_event(self, audit_type: str, fields: dict) -> None:
        """Emit an authentication event."""
        user = fields.get("acct", fields.get("uid", "unknown"))
        result = fields.get("res", "unknown")
        terminal = fields.get("terminal", "")

        severity = "warning" if result != "success" else "info"

        event = Event(
            timestamp=utc_timestamp(),
            source="audit",
            event_type="auth_event",
            severity=severity,
            description=f"{audit_type}: user={user} result={result}",
            extra={
                "audit_type": audit_type,
                "user": user,
                "result": result,
                "terminal": terminal,
            },
        )
        self._bus.publish(event)

    def _emit_file_access(self, fields: dict) -> None:
        """Emit a file access event from PATH audit records."""
        name = fields.get("name", "")
        if not name or name in (".", "/"):
            return

        event = Event(
            timestamp=utc_timestamp(),
            source="audit",
            event_type="file_access",
            severity="info",
            description=f"File accessed: {name}",
            extra={
                "path": name,
                "mode": fields.get("mode", ""),
                "ouid": fields.get("ouid", ""),
            },
        )
        self._bus.publish(event)
