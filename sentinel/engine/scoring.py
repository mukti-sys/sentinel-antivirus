"""Scoring — combines signals from all detection engines into one confidence
score per process/file, and decides whether the score crosses the response
threshold.

Implements architecture.md Section 5.4 ("Scoring") and the DLL / Image-Load
Handling rules in Section 5.3 (the anti-Defender-false-positive design).
This is the main lever for false-positive tuning (NFR-1 in prd.md).

Model
-----
Each detection engine contributes typed **signals** (a `(kind, weight,
subject, reason)` record). A single weak signal is never enough — response
only triggers when the *combined* score crosses `threshold`. This is the
"no single weak signal causes a suspend/quarantine on its own" guarantee
(architecture.md Section 5.3, plan.md sample rule `sentinel-0002`).

DLL / Image-Load handling (Section 5.3) is implemented here, exactly as
designed:
- **Self-load vs cross-process injection** — a process loading its own DLL
  from its own directory is routine and ignored; only a DLL loaded *into an
  unrelated process* counts.
- **Reflective/manual mapping >> normal LoadLibrary** — unbacked executable
  memory / no matching image-load event is weighted much higher than a
  routine (signed or unsigned) LoadLibrary.
- **Unsigned ≠ guilty** — an unsigned DLL alone never triggers; it only adds
  score when paired with cross-process injection into an abnormal host OR an
  accompanying CPU/network anomaly.
- **Local reputation cache** — a DLL hash / publisher that loaded cleanly
  many times stops contributing.
- **Publisher/hash allowlist** — surgical, not folder-wide (per settings.yaml
  `dll_handling`). Folder-wide exclusions are NOT implemented, by design.

Threshold
---------
Response triggers only when the per-subject score >= `threshold`. The
default is conservative (NFR-1). All engines feed the same scorer so the
user has ONE place to tune.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signal kinds and base weights. Weak signals have low weights so a single one
# never crosses the threshold alone — corroboration is required.
# ---------------------------------------------------------------------------
WEIGHTS: dict[str, float] = {
    # Rule engine (Sigma) — a single high-level rule match.
    "rule_match_high": 40.0,
    "rule_match_medium": 20.0,
    "rule_match_low": 10.0,
    # DLL / image-load layered signals (Section 5.3).
    "dll_cross_process": 25.0,        # cross-process injection into a host
    "dll_reflective": 45.0,           # reflective/manual mapping (rare, high)
    "dll_unsigned": 10.0,             # unsigned — WEAK alone, by design
    "dll_abnormal_host": 15.0,        # injected into a process that doesn't
                                        # normally host injected code
    # Cryptomining heuristic (FR-2).
    "cpu_sustained": 30.0,
    "stratum_network": 30.0,
    # Ransomware heuristic (FR-4).
    "entropy_spike": 30.0,
    "mass_modification": 30.0,
    # Brute-force heuristic (FR-3).
    "failed_login_burst": 25.0,
    # YARA content scan — a rule match is a high-confidence indicator.
    "yara_match": 85.0,               # YARA rule matched file content (fires alone)
    # Static classifier (FR-5).
    "vt_positive": 50.0,              # VirusTotal flags the hash
    "vt_unknown_suspicious_pe": 15.0, # unknown hash + suspicious PE features
    "pe_masquerade": 85.0,            # Executable disguised as document/media (fires alone)
    "pe_double_extension": 85.0,      # Deceptive double extension (fires alone)
    # Process-behavior rules (LOLBin / parent-child) — covered by rule engine,
    # but a direct suspicious-parent signal is allowed too.
    "suspicious_parent_child": 20.0,
}

# The DLL signals that, *alone*, must never trigger a response
# (architecture.md Section 5.3 "unsigned DLL alone is not sufficient").
_WEAK_DLL_SIGNALS = {"dll_unsigned", "dll_cross_process", "dll_abnormal_host"}


@dataclass(frozen=True)
class Signal:
    """A single detection contribution from an engine."""

    kind: str            # key into WEIGHTS
    subject: str         # process/file identifier the signal is about
    reason: str          # human-readable "what and why" (for notifier)
    weight: float | None = None   # override default weight
    engine: str = "unknown"       # which engine produced it (observability)
    timestamp: float | None = None

    def __post_init__(self) -> None:
        if self.timestamp is None:
            object.__setattr__(self, "timestamp", time.time())

    @property
    def effective_weight(self) -> float:
        if self.weight is not None:
            return self.weight
        return WEIGHTS.get(self.kind, 0.0)


def format_pid_subject(pid: int, start_time: float | int | None = None) -> str:
    """Format a process subject key.
    When start_time is known, keys as 'pid:<pid>:<start_time>' to prevent PID
    reuse collision. Otherwise falls back to 'pid:<pid>'.
    """
    if start_time is not None:
        return f"pid:{pid}:{int(start_time)}"
    return f"pid:{pid}"


@dataclass
class SubjectScore:
    """Aggregate score for one subject (process or file)."""

    subject: str
    total: float = 0.0
    signals: list[Signal] = field(default_factory=list)
    dll_components: set[str] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)

    def add(self, sig: Signal) -> None:
        self.signals.append(sig)
        self.total += sig.effective_weight
        if sig.kind.startswith("dll_"):
            self.dll_components.add(sig.kind)
        self.last_updated = sig.timestamp if sig.timestamp is not None else time.time()

    @property
    def top_reasons(self) -> list[str]:
        return [f"{s.kind} ({s.effective_weight:.0f}): {s.reason}" for s in self.signals]



# ---------------------------------------------------------------------------
# DLL / Image-Load layered handling (architecture.md Section 5.3)
# ---------------------------------------------------------------------------
class DllReputationCache:
    """Local reputation cache: a DLL hash/publisher that has loaded cleanly
    many times on this machine stops contributing to the score (Section 5.3).
    In-memory for v1; a future phase can persist it to disk.
    """

    def __init__(self, clean_threshold: int = 20) -> None:
        self._clean_loads: dict[str, int] = {}
        self._clean_threshold = clean_threshold

    def record_clean_load(self, key: str) -> None:
        self._clean_loads[key] = self._clean_loads.get(key, 0) + 1

    def is_reputable(self, key: str) -> bool:
        """True if `key` (dll hash or publisher) has loaded cleanly enough
        times that it stops contributing to the score."""
        return self._clean_loads.get(key, 0) >= self._clean_threshold


@dataclass(frozen=True)
class DllLoadContext:
    """The facts about one image-load, as gathered by the detector that built
    this context (cross_process detection uses the loader vs target pid).

    These map to the architecture.md Section 5.3 questions.
    """

    dll_hash: str | None = None
    publisher: str | None = None
    loader_pid: int | None = None       # process that caused the load
    target_pid: int | None = None       # process the DLL landed in
    loader_image: str | None = None
    dll_path: str | None = None
    signed: bool | None = None
    reflective: bool = False            # reflective/manual mapping (no valid
                                        # on-disk path / unbacked exec memory)
    host_normally_injected: bool = True # does the target normally host
                                        # injected code (e.g. browser plugin)?
    has_cpu_anomaly: bool = False       # accompanying CPU/network anomaly
    has_network_anomaly: bool = False

    @property
    def is_cross_process(self) -> bool:
        """Section 5.3: only a DLL loaded *into an unrelated process* counts.
        A process loading its own DLL from its own directory is routine."""
        if self.loader_pid is None or self.target_pid is None:
            return False
        return self.loader_pid != self.target_pid


def score_dll_load(
    ctx: DllLoadContext,
    reputation: DllReputationCache,
    trusted_publishers: set[str] | None = None,
    trusted_hashes: set[str] | None = None,
) -> list[Signal]:
    """Apply the architecture.md Section 5.3 layered DLL rules to one load.

    Returns the list of signals this load contributes (possibly empty).
    NO single weak signal is sufficient by itself — the caller aggregates
    these with everything else before comparing to the threshold.
    """
    trusted_publishers = trusted_publishers or set()
    trusted_hashes = trusted_hashes or set()
    signals: list[Signal] = []

    subject = f"pid:{ctx.target_pid}" if ctx.target_pid is not None else "unknown"

    # Publisher/hash allowlist — surgical, not folder-wide (Section 5.3).
    if ctx.publisher and ctx.publisher in trusted_publishers:
        reputation.record_clean_load(f"pub:{ctx.publisher}")
        return []
    if ctx.dll_hash and ctx.dll_hash in trusted_hashes:
        reputation.record_clean_load(f"hash:{ctx.dll_hash}")
        return []

    # Local reputation cache — stops contributing after many clean loads.
    if ctx.dll_hash and reputation.is_reputable(f"hash:{ctx.dll_hash}"):
        return []
    if ctx.publisher and reputation.is_reputable(f"pub:{ctx.publisher}"):
        return []

    # Self-load vs cross-process (Section 5.3): self-loads are routine/ignored.
    if not ctx.is_cross_process:
        # Record a clean self-load toward reputation.
        if ctx.dll_hash:
            reputation.record_clean_load(f"hash:{ctx.dll_hash}")
        if ctx.publisher:
            reputation.record_clean_load(f"pub:{ctx.publisher}")
        return []

    # Reflective/manual mapping >> normal LoadLibrary (Section 5.3).
    if ctx.reflective:
        signals.append(
            Signal(
                kind="dll_reflective",
                subject=subject,
                engine="dll_handling",
                reason=(
                    f"reflective/manually-mapped injection of "
                    f"{ctx.dll_path or ctx.dll_hash} into pid {ctx.target_pid} "
                    f"(unbacked executable memory / no valid on-disk image)"
                ),
            )
        )

    # Cross-process injection into a host.
    signals.append(
        Signal(
            kind="dll_cross_process",
            subject=subject,
            engine="dll_handling",
            reason=(
                f"{ctx.loader_image or ctx.loader_pid} injected "
                f"{ctx.dll_path or ctx.dll_hash} into unrelated process "
                f"{ctx.target_pid}"
            ),
        )
    )

    # Injection into a host that doesn't normally host injected code.
    if not ctx.host_normally_injected:
        signals.append(
            Signal(
                kind="dll_abnormal_host",
                subject=subject,
                engine="dll_handling",
                reason=(
                    f"target pid {ctx.target_pid} does not normally host "
                    f"injected code"
                ),
            )
        )

    # Unsigned ≠ guilty (Section 5.3): unsigned ONLY adds score when paired
    # with an abnormal host OR an accompanying CPU/network anomaly.
    if ctx.signed is False:
        if (not ctx.host_normally_injected) or ctx.has_cpu_anomaly or ctx.has_network_anomaly:
            signals.append(
                Signal(
                    kind="dll_unsigned",
                    subject=subject,
                    engine="dll_handling",
                    reason=(
                        f"unsigned DLL {ctx.dll_path or ctx.dll_hash} injected "
                        f"cross-process with corroborating anomaly"
                    ),
                )
            )

    return signals


# ---------------------------------------------------------------------------
# The scorer
# ---------------------------------------------------------------------------
class Scorer:
    """Aggregates signals per subject and decides whether the score crosses
    the response threshold. One Scorer for the whole process; every engine
    feeds it.

    Supports time-decay of aging signals (NFR-1 false-positive suppression),
    stale subject eviction, bounded memory footprint, and PID-safe reset.
    """

    def __init__(
        self,
        threshold: float = 80.0,
        signal_ttl: float = 600.0,
        max_subjects: int = 10000,
    ) -> None:
        self.threshold = threshold
        self.signal_ttl = signal_ttl
        self.max_subjects = max_subjects
        self._subjects: dict[str, SubjectScore] = {}
        self._lock = __import__("threading").Lock()

    def add_signal(self, sig: Signal) -> SubjectScore:
        with self._lock:
            # Enforce bounded capacity (evict oldest updated subject if full)
            if len(self._subjects) >= self.max_subjects and sig.subject not in self._subjects:
                oldest_key = min(
                    self._subjects,
                    key=lambda k: getattr(self._subjects[k], "last_updated", 0),
                )
                self._subjects.pop(oldest_key, None)

            subj = self._subjects.setdefault(sig.subject, SubjectScore(sig.subject))
            subj.add(sig)
            return subj

    def add_signals(self, sigs: list[Signal]) -> SubjectScore | None:
        last = None
        for s in sigs:
            last = self.add_signal(s)
        return last

    def get(self, subject: str) -> SubjectScore | None:
        with self._lock:
            return self._subjects.get(subject)

    def crosses_threshold(self, subject: str) -> bool:
        with self._lock:
            subj = self._subjects.get(subject)
            return bool(subj and subj.total >= self.threshold)

    def should_respond(self, subject: str) -> bool:
        """The single decision point: respond only when the combined score
        crosses the threshold AND the DLL weak-signal rule holds.

        architecture.md Section 5.3: if the *entire* score is composed only
        of weak DLL signals (dll_unsigned / dll_cross_process /
        dll_abnormal_host), do NOT respond — those need corroboration from a
        non-DLL signal or a strong reflective signal.
        """
        with self._lock:
            subj = self._subjects.get(subject)
            if subj is None or subj.total < self.threshold:
                return False
            non_dll = [s for s in subj.signals if not s.kind.startswith("dll_")]
            strong_dll = [s for s in subj.signals if s.kind == "dll_reflective"]
            # Respond if there's a non-DLL corroborating signal OR a strong
            # reflective-mapping signal. Weak-DLL-signals-only never responds.
            return bool(non_dll or strong_dll)

    def reset(self, subject: str | None = None) -> None:
        """Reset score for a subject, or all subjects if None.
        If subject starts with 'pid:<id>', also clears 'pid:<id>:<start_time>'.
        """
        with self._lock:
            if subject is None:
                self._subjects.clear()
            else:
                self._subjects.pop(subject, None)
                if subject.startswith("pid:"):
                    prefix = subject + ":"
                    matching = [k for k in self._subjects if k.startswith(prefix)]
                    for k in matching:
                        self._subjects.pop(k, None)

    def reset_pid(self, pid: int) -> None:
        """Purge all scores associated with a process ID (clears both
        'pid:<pid>' and 'pid:<pid>:<start_time>').
        """
        self.reset(f"pid:{pid}")

    def decay(self, ttl_seconds: float | None = None, now: float | None = None) -> list[str]:
        """Prune signals older than ttl_seconds from all subjects.
        Recomputes total scores and deletes subjects that have no remaining signals.
        Returns list of pruned subject keys.
        """
        ttl = ttl_seconds if ttl_seconds is not None else self.signal_ttl
        now_ts = now if now is not None else time.time()
        cutoff = now_ts - ttl
        pruned_subjects = []

        with self._lock:
            dead_keys = []
            for subj_key, subj in self._subjects.items():
                active_signals = [
                    s for s in subj.signals
                    if s.timestamp is not None and s.timestamp >= cutoff
                ]
                if len(active_signals) != len(subj.signals):
                    subj.signals = active_signals
                    subj.total = sum(s.effective_weight for s in active_signals)
                    subj.dll_components = {
                        s.kind for s in active_signals if s.kind.startswith("dll_")
                    }
                    subj.last_updated = now_ts
                if not subj.signals or subj.total <= 0:
                    dead_keys.append(subj_key)

            for k in dead_keys:
                self._subjects.pop(k, None)
                pruned_subjects.append(k)

        return pruned_subjects

    def evict_stale(self, max_age_seconds: float = 3600.0, now: float | None = None) -> int:
        """Evict subjects that have not received any new signal in max_age_seconds."""
        now_ts = now if now is not None else time.time()
        cutoff = now_ts - max_age_seconds
        evicted = 0

        with self._lock:
            dead_keys = [
                k for k, subj in self._subjects.items()
                if getattr(subj, "last_updated", getattr(subj, "created_at", 0)) < cutoff
            ]
            for k in dead_keys:
                self._subjects.pop(k, None)
                evicted += 1

        return evicted

    def subjects(self) -> list[str]:
        with self._lock:
            return list(self._subjects.keys())

