"""Network sensor — raw connection logging.

Implements architecture.md Section 5.1 (`network_sensor.py` — "outbound
connections, stratum-protocol traffic") and phases.md Phase 1 ("raw
connection logging (no detection logic yet — just capture)").

PHASE 1 SCOPE: capture only. We log outbound connections as shared-schema
`connection` events (pid, image_path, remote_ip, dest_port in extra). The
stratum/mining-pool *detection* is the cryptomining heuristic in Phase 2
(`engine/scoring.py`) and the abuse.ch blocklist sync — neither lives here.

Implementation note: rather than a raw packet hook (which needs a kernel
capture driver / Npcap), v1 polls per-process connections via psutil. This
gives us pid + remote ip:port for every outbound socket without elevated
privileges and without touching the kernel, which matches the "OS-level
mechanism independent of Defender" constraint (NFR-5) and the modest idle
footprint (NFR-6). The abuse.ch blocklist and stratum signature matching in
Phase 2 consume the same fields.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import psutil

from sentinel.engine.event_bus import EventBus
from sentinel.engine.schema import Event, utc_timestamp

logger = logging.getLogger(__name__)

# Outbound states we treat as "a connection". Established + SYN_SENT (an
# attempted connection, still informative for brute-force/beaconing later).
_INTERESTING_STATUSES = frozenset({"ESTABLISHED", "SYN_SENT", "SYN_RECV"})


@dataclass(frozen=True)
class ConnKey:
    """Dedup key so the same live connection isn't re-logged every poll."""

    pid: int
    local: str
    remote: str
    status: str


def _safe_addr(addr) -> tuple[str, int | None]:
    """Return (ip, port) for a psutil addr tuple, tolerating empties."""
    if not addr:
        return "", None
    try:
        return addr.ip, addr.port
    except AttributeError:
        return "", None


class NetworkSensor:
    """Polls per-process outbound connections and publishes `connection`
    events for new ones. One instance drives its own poll loop on a thread.
    """

    def __init__(
        self,
        bus: EventBus,
        poll_interval: float = 5.0,
        baseline_on_start: bool = False,
    ) -> None:
        self._bus = bus
        self._poll_interval = poll_interval
        self._baseline_on_start = baseline_on_start
        self._seen: set[ConnKey] = set()
        self._running = False
        self._thread: None | __import__("threading").Thread = None

    def establish_baseline(self) -> int:
        """Silently populate self._seen with currently active connections
        without publishing events. Prevents a burst of startup events for
        pre-existing sockets on the machine.
        Returns number of baseline connections recorded.
        """
        initial_count = len(self._seen)
        self._snapshot()
        count = len(self._seen) - initial_count
        logger.info("network_sensor: baselined %d pre-existing connection(s)", count)
        return count

    # ------------------------------------------------------------------ #
    def _snapshot(self) -> list[Event]:
        """Collect one snapshot of new outbound connections as events."""
        events: list[Event] = []
        try:
            conns = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, PermissionError):
            logger.warning(
                "network_sensor: access denied enumerating connections; "
                "run with appropriate privileges for full visibility."
            )
            return events

        for c in conns:
            if c.status not in _INTERESTING_STATUSES:
                continue
            remote_ip, remote_port = _safe_addr(c.raddr)
            if not remote_ip:
                continue  # listening sockets / no remote endpoint
            local_ip, local_port = _safe_addr(c.laddr)
            pid = c.pid
            key = ConnKey(pid=pid, local=f"{local_ip}:{local_port}",
                          remote=f"{remote_ip}:{remote_port}", status=c.status)
            if key in self._seen:
                continue
            self._seen.add(key)

            # Best-effort process name/path for image_path (may be None for
            # system processes we can't query without admin).
            image_path = None
            proc_name = None
            if pid:
                try:
                    p = psutil.Process(pid)
                    proc_name = p.name()
                    image_path = p.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        psutil.ZombieProcess):
                    pass

            events.append(
                Event(
                    timestamp=utc_timestamp(),
                    source="network",
                    event_type="connection",
                    pid=pid if pid else None,
                    image_path=image_path,
                    command_line=proc_name,
                    extra={
                        "remote_ip": remote_ip,
                        "dest_port": remote_port,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "status": c.status,
                        "process_name": proc_name,
                    },
                )
            )
        return events

    def poll_once(self) -> int:
        """One snapshot + publish. Returns number of new events published.
        Exposed separately so tests can call it deterministically."""
        events = self._snapshot()
        for ev in events:
            try:
                self._bus.publish(ev)
            except Exception:
                logger.exception("network_sensor: failed to publish event")
        return len(events)

    def _loop(self) -> None:
        while self._running:
            try:
                self.poll_once()
            except Exception:  # never let the poll loop die
                logger.exception("network_sensor poll error")
            time.sleep(self._poll_interval)

    def start(self) -> None:
        import threading

        if self._running:
            return
        if self._baseline_on_start:
            try:
                self.establish_baseline()
            except Exception as exc:
                logger.debug("network_sensor baseline error: %s", exc)
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="sentinel-network", daemon=True
        )
        self._thread.start()
        logger.info("network_sensor started (poll_interval=%ss)", self._poll_interval)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=self._poll_interval + 2)
            self._thread = None

    @property
    def seen_count(self) -> int:
        return len(self._seen)


def run() -> None:
    """Standalone run: poll for ~30s and report captured connections.
    Useful for a quick live spot-check (Phase 1 DoD) without the full
    service harness."""
    bus = EventBus()
    sensor = NetworkSensor(bus, poll_interval=3.0)
    sensor.start()
    print("network_sensor: polling outbound connections for 30s. "
          "Open a webpage or ping something to generate traffic.")
    time.sleep(30)
    sensor.stop()
    rows = bus.recent(limit=20, where="source=?", params=("network",))
    print(f"network_sensor: {len(rows)} connection event(s) captured:")
    for r in rows:
        e = r.get("extra", {})
        print("  ", r["timestamp"], r["event_type"],
              f"pid={r['pid']}", r.get("command_line") or r.get("image_path") or "?",
              "->", e.get("remote_ip"), e.get("dest_port"))
    bus.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    run()
