"""Response module — process suspension, file quarantine, notifications.

Implements phases.md Phase 3:
- responder.py: NtSuspendProcess + file quarantine
- quarantine_store.py: metadata DB, restore/delete
- notifier.py: calm Windows toast notifications

NOTE: responder.py imports ctypes.WinDLL (ntdll) at module level, which
fails on non-Windows platforms.  We lazy-import it here behind a platform
guard so that ``sentinel.response`` (and by extension quarantine_store
and notifier) can be imported on Linux for CI / cross-platform testing.
"""
import sys

from sentinel.response.quarantine_store import (
    DELETED,
    PENDING,
    RESTORED,
    QuarantineRecord,
    QuarantineStore,
)
from sentinel.response.notifier import Notification, Notifier

__all__ = [
    "QuarantineStore",
    "QuarantineRecord",
    "PENDING",
    "RESTORED",
    "DELETED",
    "Notifier",
    "Notification",
]

# Lazy-import responder only on Windows (it needs ctypes.WinDLL / ntdll).
if sys.platform == "win32":
    from sentinel.response.responder import (
        quarantine_process,
        resume_process,
        suspend_process,
    )
    __all__ += ["suspend_process", "resume_process", "quarantine_process"]