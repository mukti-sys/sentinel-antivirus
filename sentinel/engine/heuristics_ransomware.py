"""Ransomware heuristic — mass rapid file modification + high-entropy writes
on watched folders (FR-4, architecture.md Section 5.3 heuristics, Example B).

Design (consistent with "no single weak signal"):
- `entropy_spike` fires when a written file's content entropy >=
  file_entropy_alert (encryption/compression spikes entropy, prd.md glossary).
- `mass_modification` fires when the write rate in a watched folder exceeds
  file_write_rate_per_min.
- architecture.md Example B: the ransomware verdict is rate + entropy + a
  rule-engine match TOGETHER, fast-tracked. This heuristic emits the rate and
  entropy signals; scoring.py combines them (and any rule match) and decides.

Signals are attributed to the responsible process when the fs event carries
one (the schema's pid is usually None for fs events — the OS doesn't tell
watchdog which process wrote). When pid is unknown we attribute to the
folder scope so scoring can still combine rate+entropy for that folder.
This heuristic is passive: it never suspends or deletes anything.

Thresholds come from config/settings.yaml (file_write_rate_per_min,
file_entropy_alert) per plan.md Section 3.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque

from sentinel.engine.schema import Event
from sentinel.engine.scoring import Signal

logger = logging.getLogger(__name__)

DEFAULT_WRITE_RATE_PER_MIN = 50.0
DEFAULT_ENTROPY_ALERT = 7.5

# How far back (seconds) we keep write timestamps for the rate window.
_RATE_WINDOW_SECONDS = 60.0


class RansomwareHeuristic:
    """Consumes fs `file_write` events and emits entropy_spike /
    mass_modification signals.

    The heuristic keeps a per-scope deque of recent write timestamps to
    compute the write rate. Scope = the responsible pid if known, else the
    watched folder (so folder-level rate+entropy can still combine).
    """

    def __init__(
        self,
        write_rate_per_min: float = DEFAULT_WRITE_RATE_PER_MIN,
        entropy_alert: float = DEFAULT_ENTROPY_ALERT,
    ) -> None:
        self.write_rate = write_rate_per_min
        self.entropy_alert = entropy_alert
        # scope -> deque[timestamp]
        self._writes: dict[str, deque] = defaultdict(deque)
        self._emitted_rate: set[str] = set()
        self._emitted_entropy: set[str] = set()  # per file path (dedupe)

    @staticmethod
    def _scope_of(event: Event) -> str:
        if event.pid is not None:
            return f"pid:{event.pid}"
        # Fall back to the watched folder so folder-level signals combine.
        root = event.extra.get("watched_root") or "unknown_folder"
        return f"folder:{root}"

    def process_fs_event(self, event: Event, now: float | None = None) -> list[Signal]:
        """Examine one fs `file_write` event; return any signals it triggers.
        Returns an empty list for non-write events or benign writes."""
        if now is None:
            now = time.time()
        if event.event_type != "file_write" or event.source != "fs":
            return []

        signals: list[Signal] = []
        scope = self._scope_of(event)
        action = event.extra.get("action")
        entropy = event.extra.get("entropy")
        path = event.image_path or "unknown"

        # Record the write for the rate window (created/modified/moved all
        # count as mass-modification candidates; deletions count too since
        # ransomware deletes originals after making encrypted copies).
        dq = self._writes[scope]
        dq.append(now)
        cutoff = now - _RATE_WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()

        # --- entropy_spike (per written file) ---
        if entropy is not None and float(entropy) >= self.entropy_alert:
            if path not in self._emitted_entropy:
                self._emitted_entropy.add(path)
                signals.append(
                    Signal(
                        kind="entropy_spike",
                        subject=scope,
                        engine="ransomware_heuristic",
                        reason=(
                            f"high-entropy write ({float(entropy):.2f} bits/byte "
                            f">= {self.entropy_alert:.1f}) to {path}"
                        ),
                    )
                )

        # --- mass_modification (per scope, over the rate window) ---
        rate_per_min = len(dq) * (60.0 / _RATE_WINDOW_SECONDS)
        if rate_per_min >= self.write_rate and scope not in self._emitted_rate:
            self._emitted_rate.add(scope)
            signals.append(
                Signal(
                    kind="mass_modification",
                    subject=scope,
                    engine="ransomware_heuristic",
                    reason=(
                        f"rapid file modification: {len(dq)} writes in "
                        f"{_RATE_WINDOW_SECONDS:.0f}s (~{rate_per_min:.0f}/min >= "
                        f"{self.write_rate:.0f}/min) in scope {scope}"
                    ),
                )
            )

        return signals

    def clear_scope_flag(self, scope: str) -> None:
        """Reset rate-emission for a scope (e.g. after resolution)."""
        self._emitted_rate.discard(scope)

    def current_rate(self, scope: str, now: float | None = None) -> float:
        """Current write rate (writes/min) for a scope — for observability."""
        if now is None:
            now = time.time()
        dq = self._writes.get(scope)
        if not dq:
            return 0.0
        cutoff = now - _RATE_WINDOW_SECONDS
        n = sum(1 for t in dq if t >= cutoff)
        return n * (60.0 / _RATE_WINDOW_SECONDS)
