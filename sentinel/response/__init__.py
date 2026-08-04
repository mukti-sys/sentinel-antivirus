"""Response module — process suspension, file quarantine, notifications.

Implements phases.md Phase 3:
- responder.py: NtSuspendProcess + file quarantine
- quarantine_store.py: metadata DB, restore/delete
- notifier.py: calm Windows toast notifications
"""
from sentinel.response.quarantine_store import (
    DELETED,
    PENDING,
    RESTORED,
    QuarantineRecord,
    QuarantineStore,
)
from sentinel.response.responder import (
    quarantine_process,
    resume_process,
    suspend_process,
)
from sentinel.response.notifier import Notification, Notifier

__all__ = [
    "QuarantineStore",
    "QuarantineRecord",
    "PENDING",
    "RESTORED",
    "DELETED",
    "suspend_process",
    "resume_process",
    "quarantine_process",
    "Notifier",
    "Notification",
]