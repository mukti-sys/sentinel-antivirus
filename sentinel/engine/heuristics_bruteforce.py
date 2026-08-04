"""Brute-force heuristic — N failed logins from the same source in a window.

Implements FR-3 and architecture.md Section 5.3 heuristics (failed-login
rate). Consumes `login_failed` events from the eventlog sensor (Event ID
4625) and emits `failed_login_burst` when the count from one source crosses
the configured threshold within `failed_login_window_seconds`.

Design (consistent with "no single weak signal"):
- One burst signal per source (deduped) so scoring is not spammed.
- Subject is `source:<host-or-ip>` — login events rarely carry a meaningful
  pid; the attacker identity is the source host/IP in `extra.source_host`.
- The signal weight (25) alone is below the default response threshold (80),
  so corroboration from other engines is required unless thresholds change.

Thresholds come from config/settings.yaml (`failed_login_count`,
`failed_login_window_seconds`) per plan.md Section 3. Passive only.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque

from sentinel.engine.schema import Event
from sentinel.engine.scoring import Signal

logger = logging.getLogger(__name__)

DEFAULT_FAILED_LOGIN_COUNT = 5
DEFAULT_WINDOW_SECONDS = 120.0


class BruteForceHeuristic:
    """Tracks failed logins per source and emits burst signals."""

    def __init__(
        self,
        failed_login_count: int = DEFAULT_FAILED_LOGIN_COUNT,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self.count_threshold = failed_login_count
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._emitted: set[str] = set()

    @staticmethod
    def _source_of(event: Event) -> str | None:
        if event.event_type != "login_failed" or event.source != "eventlog":
            return None
        source = event.extra.get("source_host")
        if source is None or str(source).strip() == "":
            return None
        return str(source)

    @staticmethod
    def subject_for_source(source: str) -> str:
        return f"source:{source}"

    def process_login_event(
        self, event: Event, now: float | None = None
    ) -> Signal | None:
        """Examine one `login_failed` event; return a burst signal when the
        sliding-window count for that source reaches the threshold."""
        if now is None:
            now = time.time()
        source = self._source_of(event)
        if source is None:
            return None

        subject = self.subject_for_source(source)
        dq = self._attempts[source]
        dq.append(now)
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) < self.count_threshold:
            return None
        if subject in self._emitted:
            return None

        self._emitted.add(subject)
        target_user = event.extra.get("target_user") or "unknown"
        logon_type = event.extra.get("logon_type")
        logon_note = f", logon_type={logon_type}" if logon_type is not None else ""
        return Signal(
            kind="failed_login_burst",
            subject=subject,
            engine="bruteforce_heuristic",
            reason=(
                f"{len(dq)} failed logins from {source} in "
                f"{self.window_seconds:.0f}s (target={target_user}{logon_note})"
            ),
        )

    def current_count(self, source: str, now: float | None = None) -> int:
        """Failed-login count for `source` in the current window."""
        if now is None:
            now = time.time()
        dq = self._attempts.get(source)
        if not dq:
            return 0
        cutoff = now - self.window_seconds
        return sum(1 for t in dq if t >= cutoff)

    def clear_source_flag(self, source: str) -> None:
        """Reset burst emission for a source (e.g. after resolution)."""
        self._emitted.discard(self.subject_for_source(source))
