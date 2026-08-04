"""Cryptomining heuristic — sustained CPU/GPU usage + stratum-protocol
network traffic (FR-2, architecture.md Section 5.3 heuristics, Example A).

Design (consistent with the project-wide "no single weak signal" rule):
- `cpu_sustained` fires only after a process holds >= cpu_sustained_percent
  for >= cpu_sustained_seconds.
- `stratum_network` fires when a process connects to a mining-pool/stratum
  endpoint (common stratum ports / pool IP, via the network events the bus
  already captures).
- The SCORING engine combines both signals for the same subject (pid). Per
  architecture.md Example A, the cryptominer verdict is CPU + stratum TOGETHER
  — this heuristic emits the two signals; scoring.py decides the response.

Thresholds come from config/settings.yaml (cpu_sustained_percent,
cpu_sustained_seconds) per plan.md Section 3. This module does NOT block or
kill anything — it only emits signals into scoring.py.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import psutil

from sentinel.engine.schema import Event
from sentinel.engine.scoring import Signal

logger = logging.getLogger(__name__)

# Common stratum/mining-pool destination ports (not exhaustive — Phase 2
# tuning will refine against real pool IPs / abuse.ch feeds). Mining pools
# commonly use these; an unexpected connection to one is a stratum signal.
_STRATUM_PORTS = frozenset({3333, 4444, 5555, 7777, 8333, 9999, 14433, 45700})
# Stratum JSON-RPC markers we may see in connection metadata later. v1 keys
# on ports only (we don't capture payloads), refined in later phases.

# Default thresholds mirror plan.md sample settings; the caller passes the
# actual values from settings.yaml.
DEFAULT_CPU_PERCENT = 85.0
DEFAULT_CPU_SECONDS = 60.0


@dataclass
class CpuWindow:
    """Rolling view of a process's recent CPU usage."""
    samples: list[tuple[float, float]] = field(default_factory=list)  # (ts, percent)

    def add(self, ts: float, percent: float, max_age: float) -> None:
        self.samples.append((ts, percent))
        cutoff = ts - max_age
        self.samples = [(t, p) for (t, p) in self.samples if t >= cutoff]

    def sustained_above(self, threshold: float, seconds: float, now: float) -> bool:
        """True if every sample in the last `seconds` window is >= threshold
        AND the window spans at least `seconds`."""
        cutoff = now - seconds
        window = [(t, p) for (t, p) in self.samples if t >= cutoff]
        if not window:
            return False
        if window[0][0] > cutoff + (seconds * 0.25):
            # Not enough history to claim a full sustained window.
            return False
        return all(p >= threshold for (_, p) in window)


class CryptominingHeuristic:
    """Tracks per-process CPU and stratum-network connections, emitting
    signals into scoring.py.

    This is intentionally passive: it reads CPU from psutil and consumes
    network events from the bus. It never suspends or kills a process.
    """

    def __init__(
        self,
        cpu_percent_threshold: float = DEFAULT_CPU_PERCENT,
        cpu_seconds_threshold: float = DEFAULT_CPU_SECONDS,
        sample_interval: float = 2.0,
        stratum_ports: frozenset[int] = _STRATUM_PORTS,
    ) -> None:
        self.cpu_percent = cpu_percent_threshold
        self.cpu_seconds = cpu_seconds_threshold
        self.sample_interval = sample_interval
        self.stratum_ports = stratum_ports
        self._cpu_windows: dict[int, CpuWindow] = {}
        self._procs: dict[int, psutil.Process] = {}
        self._emitted_cpu: set[int] = set()   # avoid re-firing cpu_sustained
        self._emitted_stratum: set[int] = set()

    # ------------------------------------------------------------------ #
    # CPU signal
    # ------------------------------------------------------------------ #
    def _get_proc(self, pid: int) -> psutil.Process | None:
        """Return a cached psutil.Process for `pid`, creating+priming it on
        first sight. psutil's cpu_percent(None) returns 0.0 on the FIRST call
        for a given Process object (it measures since the last call), so we
        must keep the object around and prime it once before trusting values.
        """
        proc = self._procs.get(pid)
        if proc is None or not proc.is_running():
            try:
                proc = psutil.Process(pid)
                proc.cpu_percent(None)  # prime: first call returns 0.0
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                return None
            self._procs[pid] = proc
        return proc

    def sample_cpu(self, now: float | None = None) -> list[Signal]:
        """Sample CPU across processes and return cpu_sustained signals for
        any process that has held >= threshold for >= the configured window.
        Call this on a timer (every sample_interval seconds). The first call
        primes each Process (0.0 readings); real values appear from the second
        call onward. CPU % can exceed 100 on multi-core (psutil reports
        per-process CPU across cores), so the threshold is applied as given.
        """
        if now is None:
            now = time.time()
        signals: list[Signal] = []
        try:
            pids = psutil.pids()
        except Exception:
            return signals
        for pid in pids:
            proc = self._get_proc(pid)
            if proc is None:
                continue
            try:
                pct = proc.cpu_percent(None)
                name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                self._procs.pop(pid, None)
                continue
            win = self._cpu_windows.setdefault(pid, CpuWindow())
            win.add(now, pct, max_age=self.cpu_seconds * 2)
            if pid in self._emitted_cpu:
                continue
            if win.sustained_above(self.cpu_percent, self.cpu_seconds, now):
                self._emitted_cpu.add(pid)
                signals.append(
                    Signal(
                        kind="cpu_sustained",
                        subject=f"pid:{pid}",
                        engine="cryptomining_heuristic",
                        reason=(
                            f"{name or 'pid %d' % pid} sustained "
                            f">={self.cpu_percent:.0f}% CPU for "
                            f">={self.cpu_seconds:.0f}s"
                        ),
                    )
                )
        return signals

    def clear_cpu_flag(self, pid: int) -> None:
        """Reset the emitted flag for a pid (e.g. after it's resolved)."""
        self._emitted_cpu.discard(pid)

    # ------------------------------------------------------------------ #
    # Stratum-network signal
    # ------------------------------------------------------------------ #
    def check_network_event(self, event: Event) -> Signal | None:
        """Examine a network `connection` event; return a stratum_network
        signal if the destination looks like a mining pool/stratum endpoint.
        Returns None otherwise (and for non-connection events)."""
        if event.event_type != "connection":
            return None
        pid = event.pid
        if pid is None:
            return None
        dest_port = event.extra.get("dest_port")
        remote_ip = event.extra.get("remote_ip")
        if dest_port is None:
            return None
        if int(dest_port) in self.stratum_ports:
            if pid in self._emitted_stratum:
                return None
            self._emitted_stratum.add(pid)
            return Signal(
                kind="stratum_network",
                subject=f"pid:{pid}",
                engine="cryptomining_heuristic",
                reason=(
                    f"connection to mining-pool/stratum endpoint "
                    f"{remote_ip}:{dest_port} (pid {pid})"
                ),
            )
        return None

    def clear_stratum_flag(self, pid: int) -> None:
        self._emitted_stratum.discard(pid)
