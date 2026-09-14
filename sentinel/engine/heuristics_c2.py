"""Command & Control (C2) heuristics — beaconing detection, jitter analysis,
and threat intelligence blocking.

Implements detection for automated malware communication:
1. Beaconing Analysis (Low-Jitter Periodic Connections):
   Unlike interactive human network traffic (which is bursty and irregular),
   automated C2 malware agents (Cobalt Strike, Sliver, Metasploit, AsyncRAT)
   reach out to their command servers at periodic intervals (heartbeats).
   By tracking inter-arrival connection times and computing the coefficient
   of variation (CV = std_dev / mean), Sentinel flags connections with CV < 0.20.
2. Threat Intelligence Blocklist:
   Matches outbound remote endpoints against high-confidence C2 infrastructure
   and standard listener ports.
3. Active Containment:
   Emits high-confidence signals (c2_threat_intel, c2_beaconing) triggering
   immediate process suspension and socket isolation.
"""
from __future__ import annotations

import logging
import math
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from sentinel.engine.schema import Event
from sentinel.engine.scoring import Signal

logger = logging.getLogger("sentinel.heuristics_c2")

# Maximum time delta to consider as part of the same beacon stream (e.g. 15 minutes)
_MAX_INTERVAL_SECONDS = 900.0
# Minimum connection samples required to calculate statistical beaconing
_MIN_BEACON_SAMPLES = 4
# Coefficient of variation threshold (std / mean). < 0.20 indicates highly periodic beaconing
_MAX_CV_THRESHOLD = 0.20


# Curated high-confidence C2 threat intel indicators
# Includes known Cobalt Strike, Sliver, Metasploit teamservers and sinkholes
DEFAULT_C2_IPS = frozenset({
    "185.106.94.13",
    "194.38.20.15",
    "45.154.255.88",
    "193.106.191.162",
    "91.240.118.172",
    "195.123.245.101",
    "185.220.101.5",
    "194.26.29.114",
    # Reserved loopback testing C2 indicator
    "127.0.0.99",
})

# Suspicious high-risk C2 default listener ports
DEFAULT_C2_PORTS = frozenset({
    50050,  # Cobalt Strike teamserver default
    31337,  # Sliver / Back Orifice default
    4444,   # Metasploit default handler
    6606,   # AsyncRAT default
    7707,   # AsyncRAT secondary
    8888,   # Common staging proxy
})


@dataclass
class BeaconStream:
    """Tracks connection arrival timestamps for a (pid, remote_ip) stream."""
    pid: int
    remote_ip: str
    timestamps: deque[float] = field(default_factory=lambda: deque(maxlen=20))
    last_signal_time: float = 0.0

    def add_connection(self, ts: float) -> None:
        self.timestamps.append(ts)

    def calculate_jitter(self) -> tuple[float, float, float] | None:
        """Calculate mean interval, standard deviation, and coefficient of variation (CV).
        Returns (mean, std, cv) or None if insufficient samples.
        """
        if len(self.timestamps) < _MIN_BEACON_SAMPLES:
            return None

        # Compute adjacent intervals
        ts_list = list(self.timestamps)
        intervals = [ts_list[i] - ts_list[i - 1] for i in range(1, len(ts_list))]

        # Exclude negative intervals (clock skew) or huge gaps
        valid_intervals = [dt for dt in intervals if 0.1 <= dt <= _MAX_INTERVAL_SECONDS]
        if len(valid_intervals) < _MIN_BEACON_SAMPLES - 1:
            return None

        mean_dt = sum(valid_intervals) / len(valid_intervals)
        if mean_dt <= 0.0:
            return None

        variance = sum((dt - mean_dt) ** 2 for dt in valid_intervals) / len(valid_intervals)
        std_dt = math.sqrt(variance)
        cv = std_dt / mean_dt

        return mean_dt, std_dt, cv


class C2BeaconDetector:
    """Stateful detector that analyzes outbound network connections for C2 beaconing."""

    def __init__(
        self,
        cv_threshold: float = _MAX_CV_THRESHOLD,
        cooldown_seconds: float = 60.0,
    ) -> None:
        self.cv_threshold = cv_threshold
        self.cooldown_seconds = cooldown_seconds
        self._streams: dict[tuple[int, str], BeaconStream] = {}
        self._lock = threading.Lock()

    def process_connection(self, event: Event) -> Signal | None:
        """Inspect a network connection event and evaluate beaconing metrics."""
        if event.event_type != "connection" or not event.pid:
            return None

        extra = event.extra or {}
        remote_ip = extra.get("remote_ip")
        if not remote_ip or remote_ip in ("127.0.0.1", "::1", "0.0.0.0"):
            return None

        now = time.time()
        key = (event.pid, remote_ip)

        with self._lock:
            if key not in self._streams:
                self._streams[key] = BeaconStream(pid=event.pid, remote_ip=remote_ip)

            stream = self._streams[key]
            stream.add_connection(now)

            # Prevent alert storming during ongoing beaconing
            if now - stream.last_signal_time < self.cooldown_seconds:
                return None

            metrics = stream.calculate_jitter()
            if metrics is None:
                return None

            mean_dt, std_dt, cv = metrics
            if cv <= self.cv_threshold:
                stream.last_signal_time = now
                proc_str = event.command_line or event.image_path or f"PID {event.pid}"
                logger.warning(
                    "C2 BEACON DETECTED: pid=%d remote=%s mean=%.2fs std=%.2fs cv=%.3f (threshold=%.2f)",
                    event.pid, remote_ip, mean_dt, std_dt, cv, self.cv_threshold,
                )
                return Signal(
                    kind="c2_beaconing",
                    subject=f"pid:{event.pid}",
                    engine="heuristics_c2",
                    reason=(
                        f"Periodic C2 beaconing detected to {remote_ip}: "
                        f"interval={mean_dt:.1f}s (jitter cv={cv:.3f} <= {self.cv_threshold:.2f}) "
                        f"by {proc_str}"
                    ),
                    weight=40.0,
                )

        return None

    def reset_pid(self, pid: int) -> None:
        """Clean up state on process termination."""
        with self._lock:
            keys_to_del = [k for k in self._streams if k[0] == pid]
            for k in keys_to_del:
                del self._streams[k]


class C2Blocklist:
    """In-memory high-confidence C2 threat intelligence feed matcher."""

    def __init__(
        self,
        blocked_ips: set[str] | None = None,
        blocked_ports: set[int] | None = None,
    ) -> None:
        self.blocked_ips = set(blocked_ips or DEFAULT_C2_IPS)
        self.blocked_ports = set(blocked_ports or DEFAULT_C2_PORTS)

    def check(self, ip: str, port: int | None = None) -> tuple[bool, str]:
        """Check an IP and optional port directly against the C2 blocklist."""
        if ip in self.blocked_ips:
            return True, f"Known C2 Threat Intel IP ({ip})"
        if port and int(port) in self.blocked_ports and not ip.startswith(("10.", "192.168.", "172.16.")):
            return True, f"Known C2 Staging Port ({port})"
        return False, ""

    def check_connection(self, event: Event) -> Signal | None:
        """Match connection against known C2 indicators."""
        if event.event_type != "connection" or not event.pid:
            return None

        extra = event.extra or {}
        remote_ip = extra.get("remote_ip")
        dest_port = extra.get("dest_port")

        if not remote_ip:
            return None

        matched_reason = None
        if remote_ip in self.blocked_ips:
            matched_reason = f"Outbound connection to known C2 infrastructure IP: {remote_ip}"
        elif dest_port and int(dest_port) in self.blocked_ports and not remote_ip.startswith(("10.", "192.168.", "172.16.")):
            matched_reason = f"Outbound connection to known C2 staging/listener port {dest_port} at {remote_ip}"

        if matched_reason:
            proc_str = event.command_line or event.image_path or f"PID {event.pid}"
            logger.warning("C2 THREAT INTEL MATCH: pid=%d remote=%s:%s (%s)",
                           event.pid, remote_ip, dest_port, matched_reason)
            return Signal(
                kind="c2_threat_intel",
                subject=f"pid:{event.pid}",
                engine="heuristics_c2",
                reason=f"{matched_reason} by {proc_str}",
                weight=85.0,  # Critical: triggers autonomous containment immediately
            )

        return None
