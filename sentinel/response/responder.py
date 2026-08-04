"""Responder — suspends processes, quarantines files, and emits response
events back to the event bus.

Implements phases.md Phase 3:
    responder.py: suspend process (NtSuspendProcess), move file to
    data/quarantine/, strip execute permission

Design:
- suspend_process(pid) uses NtSuspendProcess via ctypes/win32 API to freeze
  a process without killing it (reversible).
- resume_process(pid) uses NtResumeProcess to unfreeze.
- quarantine_process() combines suspend + file quarantine + notification
  emission in one atomic-ish step.
- Every response action emits a schema-shaped Event back into the EventBus
  for the audit trail (FR-11: "local, structured log of Sentinel's own
  activity, separate from alerts").
- Errors are logged and returned, never crash the orchestrator.
"""
from __future__ import annotations

import logging
import sys
from ctypes import (
    POINTER,
    Structure,
    WinDLL,
    byref,
    c_int,
    c_uint32,
    c_void_p,
    sizeof,
)
from pathlib import Path
from typing import Any

from sentinel.engine.schema import Event, utc_timestamp

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# NtSuspendProcess / NtResumeProcess via ntdll
#
# These are undocumented NT API functions. They're stable across all modern
# Windows versions (10/11) and widely used by legitimate system tools.
# Signature (from NT API):
#   NTSTATUS NtSuspendProcess(HANDLE ProcessHandle);
#   NTSTATUS NtResumeProcess(HANDLE ProcessHandle);
# ---------------------------------------------------------------------------

_ntdll = WinDLL("ntdll", use_last_error=True)

_SuspendProcess = _ntdll.NtSuspendProcess
_SuspendProcess.restype = c_int  # NTSTATUS
_SuspendProcess.argtypes = [c_void_p]

_ResumeProcess = _ntdll.NtResumeProcess
_ResumeProcess.restype = c_int
_ResumeProcess.argtypes = [c_void_p]

# STATUS_SUCCESS = 0 — the NT API success code.
_STATUS_SUCCESS = 0

# win32 API for OpenProcess / CloseHandle
_OpenProcess = WinDLL("kernel32", use_last_error=True).OpenProcess
_OpenProcess.restype = c_void_p
_OpenProcess.argtypes = [c_uint32, c_int, c_uint32]

_CloseHandle = WinDLL("kernel32", use_last_error=True).CloseHandle
_CloseHandle.restype = c_int
_CloseHandle.argtypes = [c_void_p]

# PROCESS_SUSPEND_RESUME (0x0800) — needed for NtSuspendProcess handle.
_PROCESS_SUSPEND_RESUME = 0x0800
# PROCESS_QUERY_INFORMATION (0x0400) — needed for NtResumeProcess.
_PROCESS_QUERY_INFORMATION = 0x0400


def suspend_process(pid: int) -> str | None:
    """Suspend a process by PID using NtSuspendProcess.

    Returns None on success, or an error string on failure. This is a
    reversible operation — resume_process() can unfreeze it.
    """
    if pid is None or pid <= 0:
        return "invalid pid"

    handle = _OpenProcess(_PROCESS_SUSPEND_RESUME, 0, pid)
    if not handle:
        err = c_int.in_dll(WinDLL("kernel32"), "GetLastError").value
        return f"OpenProcess failed (pid={pid}, error={err})"

    try:
        status = _SuspendProcess(handle)
        if status != _STATUS_SUCCESS:
            return f"NtSuspendProcess returned status {status} (pid={pid})"
        logger.info("suspended pid %d", pid)
        return None  # success
    finally:
        _CloseHandle(handle)


def resume_process(pid: int) -> str | None:
    """Resume a previously-suspended process.

    Returns None on success, or an error string on failure.
    """
    if pid is None or pid <= 0:
        return "invalid pid"

    handle = _OpenProcess(
        _PROCESS_SUSPEND_RESUME | _PROCESS_QUERY_INFORMATION, 0, pid
    )
    if not handle:
        err = c_int.in_dll(WinDLL("kernel32"), "GetLastError").value
        return f"OpenProcess failed (pid={pid}, error={err})"

    try:
        status = _ResumeProcess(handle)
        if status != _STATUS_SUCCESS:
            return f"NtResumeProcess returned status {status} (pid={pid})"
        logger.info("resumed pid %d", pid)
        return None  # success
    finally:
        _CloseHandle(handle)


# ---------------------------------------------------------------------------
# High-level quarantine action
# ---------------------------------------------------------------------------

def quarantine_process(
    pid: int,
    reason: str,
    source_signals: list[dict[str, Any]] | None = None,
    scorer=None,
    quarantine_store=None,
    bus=None,
    image_path: str | None = None,
    kernel_bridge=None,
) -> dict[str, Any]:
    """Suspend a process and quarantine its image file.

    This is the high-level action that the orchestrator calls when
    scorer.should_respond() returns True.

    Steps:
    1. Suspend the process (reversible).
    2. Quarantine the image file (move to quarantine dir, strip exec).
    3. Push image path to kernel blocklist (if bridge connected).
    4. Emit a ``process_suspended`` event back to the EventBus for audit.
    5. Return a result dict with status and details.

    Returns a dict with keys:
        success: bool
        error: str | None
        suspension: str | None (error from suspend, None = success)
        quarantine: QuarantineRecord | None
        event_id: int | None (rowid from EventBus)
    """
    result: dict[str, Any] = {
        "success": False,
        "error": None,
        "suspension": None,
        "quarantine": None,
        "event_id": None,
    }

    # Step 1: Suspend the process.
    suspend_err = suspend_process(pid)
    result["suspension"] = suspend_err
    if suspend_err:
        result["error"] = f"suspend failed: {suspend_err}"
        logger.error("quarantine_process: %s", result["error"])
        return result

    # Step 2: Find and quarantine the image file.
    image_path_resolved = image_path
    if not image_path_resolved:
        # Try to resolve from the process itself.
        try:
            import psutil
            proc = psutil.Process(pid)
            image_path_resolved = proc.exe()
        except Exception:
            pass

    qrec = None
    if image_path_resolved and quarantine_store is not None:
        qrec = quarantine_store.add(
            source_path=image_path_resolved,
            subject=f"pid:{pid}",
            reason=reason,
            score=scorer.get(f"pid:{pid}").total if scorer else 0.0,
            source_signals=source_signals,
        )
        if qrec is None:
            logger.warning(
                "quarantine_process: file quarantine failed for %s (pid %d) — "
                "process is still suspended",
                image_path_resolved, pid,
            )

    result["quarantine"] = qrec
    if qrec is None and image_path_resolved:
        result["error"] = ("process suspended but file could not be "
                           "quarantined (check permissions)")
    else:
        result["success"] = True

    # Step 3: Push to kernel blocklist (Phase 4).
    # Best-effort — bridge failure does not affect quarantine success.
    if kernel_bridge and image_path_resolved:
        try:
            kernel_bridge.add_block(image_path_resolved)
        except Exception as exc:
            logger.warning(
                "quarantine_process: kernel bridge add_block failed: %s", exc
            )

    # Step 4: Emit audit event.
    if bus is not None:
        event = Event(
            timestamp=utc_timestamp(),
            source="etw_process",
            event_type="process_suspended",
            pid=pid,
            image_path=image_path_resolved or "",
            extra={
                "reason": reason,
                "quarantine_id": qrec.id if qrec else None,
                "quarantine_path": str(qrec.quarantined_path) if qrec else None,
                "score": float(result.get("score", 0.0)),
            },
        )
        try:
            result["event_id"] = bus.publish(event)
        except Exception as exc:
            logger.warning("quarantine_process: audit event publish failed: %s", exc)

    logger.info(
        "quarantine_process: pid=%d suspended=%s quarantined=%s",
        pid, suspend_err is None, qrec is not None,
    )
    return result


def resolve_process_image(pid: int) -> str | None:
    """Resolve the image path for a given PID using psutil."""
    try:
        import psutil
        proc = psutil.Process(pid)
        return proc.exe()
    except Exception:
        return None