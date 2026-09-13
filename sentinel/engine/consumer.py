"""DetectionConsumer — pulls events from EventBus and routes them to detection engines.

Implements the central detection pipeline connecting:
    Sensors -> EventBus -> DetectionConsumer -> (
        RuleEngine,
        StaticClassifier (YARA + VT + PE features),
        RansomwareHeuristic,
        CryptominingHeuristic,
        BruteForceHeuristic,
    ) -> Scorer -> Responder + KernelBridge + Notifier

Also handles:
    - PID recycling prevention: resets process scores on process_exit events.
    - Full-loop response: suspends processes, moves files to quarantine, adds to
      kernel minifilter blocklist, and sends calm desktop notifications.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any

from sentinel.engine.event_bus import EventBus
from sentinel.engine.heuristics_bruteforce import BruteForceHeuristic
from sentinel.engine.heuristics_cryptomining import CryptominingHeuristic
from sentinel.engine.heuristics_ransomware import RansomwareHeuristic
from sentinel.engine.rule_engine import RuleEngine
from sentinel.engine.schema import Event, utc_timestamp
from sentinel.engine.scoring import (
    DllLoadContext,
    DllReputationCache,
    Scorer,
    Signal,
    score_dll_load,
)
from sentinel.engine.static_classifier import StaticClassifier
from sentinel.response.notifier import Notification, Notifier
from sentinel.response.quarantine_store import QuarantineStore
from sentinel.response.responder import quarantine_process

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config" / "settings.yaml"
_DEFAULT_RULES = Path(__file__).resolve().parent.parent / "config" / "rules"


def _load_settings(path: str | Path) -> dict[str, Any]:
    try:
        import yaml
        p = Path(path)
        if p.exists():
            with p.open(encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
    except Exception as exc:
        logger.warning("failed to load settings from %s: %s", path, exc)
    return {}


class DetectionConsumer:
    """Consumes events from EventBus and dispatches them across all detection engines."""

    def __init__(
        self,
        bus: EventBus,
        scorer: Scorer | None = None,
        quarantine_store: QuarantineStore | None = None,
        kernel_bridge: Any | None = None,
        notifier: Notifier | None = None,
        config_path: str | Path = _DEFAULT_CONFIG,
        rules_dir: str | Path = _DEFAULT_RULES,
        auto_respond: bool = True,
    ) -> None:
        self.bus = bus
        self.scorer = scorer or Scorer()
        self.kernel_bridge = kernel_bridge
        self.quarantine_store = quarantine_store or QuarantineStore(kernel_bridge=kernel_bridge)
        if getattr(self.quarantine_store, "kernel_bridge", None) is None and kernel_bridge:
            self.quarantine_store.kernel_bridge = kernel_bridge
        self.notifier = notifier or Notifier()
        self.auto_respond = auto_respond

        self.rules_dir = Path(rules_dir)
        settings = _load_settings(config_path)

        # Thresholds
        thresholds = settings.get("thresholds", {})
        write_rate = thresholds.get("file_write_rate_per_min", 50.0)
        entropy_alert = thresholds.get("file_entropy_alert", 7.5)
        cpu_percent = thresholds.get("cpu_sustained_percent", 85.0)
        cpu_seconds = thresholds.get("cpu_sustained_seconds", 60.0)
        login_count = thresholds.get("failed_login_count", 5)
        login_window = thresholds.get("failed_login_window_seconds", 120.0)

        # Threat intel (VirusTotal)
        intel = settings.get("intel", {})
        vt_api_key = intel.get("virustotal_api_key", "").strip() or None
        vt_client = None
        if vt_api_key:
            try:
                from sentinel.intel.virustotal import VTClient
                vt_client = VTClient(api_key=vt_api_key)
            except Exception as exc:
                logger.warning("VTClient init failed: %s", exc)

        # DLL handling allowlist
        dll_handling = settings.get("dll_handling", {})
        self.trusted_publishers = set(dll_handling.get("trusted_publishers", []))
        self.trusted_hashes = set(dll_handling.get("trusted_hashes", []))

        # Instantiate detection engines
        self.rule_engine = RuleEngine.from_dir(self.rules_dir)
        self.static_classifier = StaticClassifier(
            vt_client=vt_client,
            yara_rules_dir=self.rules_dir,
        )
        self.ransomware_heuristic = RansomwareHeuristic(
            write_rate_per_min=write_rate,
            entropy_alert=entropy_alert,
        )
        self.cryptomining_heuristic = CryptominingHeuristic(
            cpu_percent_threshold=cpu_percent,
            cpu_seconds_threshold=cpu_seconds,
        )
        self.bruteforce_heuristic = BruteForceHeuristic(
            failed_login_count=login_count,
            window_seconds=login_window,
        )
        self.dll_reputation = DllReputationCache()

        # Lifecycle & state
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._responded_subjects: set[str] = set()
        self._proc_start_times: dict[int, float] = {}
        self._last_cpu_sample = 0.0

    def start(self) -> None:
        """Start the background consumer thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_consumer,
            name="DetectionConsumerThread",
            daemon=True,
        )
        self._thread.start()
        logger.info("DetectionConsumer started")

    def stop(self, timeout: float = 3.0) -> None:
        """Signal the consumer thread to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("DetectionConsumer stopped")

    def _run_consumer(self) -> None:
        """Main loop: dequeue events, dispatch, score, and respond."""
        while not self._stop_event.is_set():
            try:
                # 1. Pull events from the bus
                item = self.bus.consume(timeout=0.2)
                if item is not None:
                    if isinstance(item, list):
                        for ev in item:
                            self.process_event(ev)
                    else:
                        self.process_event(item)

                # 2. Periodic background checks (e.g. CPU sampling every 10s)
                now = time.time()
                if now - self._last_cpu_sample >= 10.0:
                    self._last_cpu_sample = now
                    self._periodic_checks(now)

            except Exception:
                logger.exception("unexpected error in DetectionConsumer loop")

    def process_event(self, event: Event) -> list[Signal]:
        """Process a single event through all applicable detectors.

        Returns all generated Signals.
        """
        # 1. Handle process_exit / process_terminate — reset subject score to prevent PID recycling issues
        if event.event_type in ("process_exit", "process_terminate") and event.pid is not None:
            pid = event.pid
            self.scorer.reset_pid(pid)
            self.cryptomining_heuristic.clear_cpu_flag(pid)
            self._proc_start_times.pop(pid, None)
            prefix = f"pid:{pid}"
            self._responded_subjects = {
                s for s in self._responded_subjects
                if not (s == prefix or s.startswith(prefix + ":"))
            }
            return []

        # Track start time if available
        if event.pid is not None:
            st = event.extra.get("create_time") or event.extra.get("process_start_time")
            if st is not None and event.pid not in self._proc_start_times:
                try:
                    self._proc_start_times[event.pid] = float(st)
                except (ValueError, TypeError):
                    pass

        signals: list[Signal] = []

        # 2. Rule Engine (Sigma YAML patterns)
        try:
            matched = self.rule_engine.match(event)
            if matched:
                signals.extend(matched)
        except Exception as exc:
            logger.debug("rule engine error: %s", exc)

        # 3. File Events (YARA, Static Classifier, Ransomware Heuristics)
        if event.event_type in ("file_write", "file_create", "file_modified"):
            try:
                rw_sigs = self.ransomware_heuristic.process_fs_event(event)
                if rw_sigs:
                    signals.extend(rw_sigs)
            except Exception as exc:
                logger.debug("ransomware heuristic error: %s", exc)

            try:
                sc_sigs = self.static_classifier.classify_file_event(event)
                if sc_sigs:
                    signals.extend(sc_sigs)
            except Exception as exc:
                logger.debug("static classifier error: %s", exc)

        # 4. Network Connections (Cryptomining Stratum Heuristics)
        elif event.event_type == "connection":
            try:
                net_sig = self.cryptomining_heuristic.check_network_event(event)
                if net_sig:
                    signals.append(net_sig)
            except Exception as exc:
                logger.debug("cryptomining network check error: %s", exc)

        # 5. Failed Logins (Brute Force Heuristics)
        elif event.event_type == "login_failed":
            try:
                bf_sig = self.bruteforce_heuristic.process_login_event(event)
                if bf_sig:
                    signals.append(bf_sig)
            except Exception as exc:
                logger.debug("bruteforce heuristic error: %s", exc)

        # 6. Image Loads (DLL / Injection Handling)
        elif event.event_type == "image_load":
            try:
                ctx = DllLoadContext(
                    dll_hash=event.hash_sha256,
                    loader_pid=event.extra.get("loader_pid", event.pid),
                    target_pid=event.pid,
                    loader_image=event.extra.get("loader_image"),
                    dll_path=event.image_path,
                    signed=event.extra.get("signed"),
                    reflective=bool(event.extra.get("reflective", False)),
                    host_normally_injected=bool(event.extra.get("host_normally_injected", True)),
                    has_cpu_anomaly=bool(event.extra.get("has_cpu_anomaly", False)),
                    has_network_anomaly=bool(event.extra.get("has_network_anomaly", False)),
                )
                dll_sigs = score_dll_load(
                    ctx,
                    self.dll_reputation,
                    trusted_publishers=self.trusted_publishers,
                    trusted_hashes=self.trusted_hashes,
                )
                if dll_sigs:
                    signals.extend(dll_sigs)
            except Exception as exc:
                logger.debug("dll scoring error: %s", exc)

        # 7. Feed all signals into Scorer and check for response triggers
        for sig in signals:
            self.scorer.add_signal(sig)
            if self.auto_respond and self.scorer.should_respond(sig.subject):
                if sig.subject not in self._responded_subjects:
                    self._responded_subjects.add(sig.subject)
                    self._execute_response(sig.subject, sig, event)

        return signals

    def _periodic_checks(self, now: float) -> None:
        """Run periodic sampling such as cryptomining CPU usage, signal decay, and subject eviction."""
        try:
            cpu_sigs = self.cryptomining_heuristic.sample_cpu(now=now)
            for sig in cpu_sigs:
                self.scorer.add_signal(sig)
                if self.auto_respond and self.scorer.should_respond(sig.subject):
                    if sig.subject not in self._responded_subjects:
                        self._responded_subjects.add(sig.subject)
                        self._execute_response(sig.subject, sig, None)
        except Exception as exc:
            logger.debug("periodic check error: %s", exc)

        # Decay aging signals and evict stale subjects (NFR-1 false-positive lever)
        try:
            self.scorer.decay(ttl_seconds=600.0, now=now)
            self.scorer.evict_stale(max_age_seconds=3600.0, now=now)
        except Exception as exc:
            logger.debug("scorer decay error: %s", exc)

    def _execute_response(self, subject: str, sig: Signal, event: Event | None) -> None:
        """Execute autonomous response when score crosses threshold."""
        score = self.scorer.get(subject)
        score_val = score.total if score else 0.0
        source_signals = [s.kind for s in score.signals] if score else [sig.kind]

        logger.warning(
            "AUTONOMOUS RESPONSE TRIGGERED: subject=%s score=%.1f reason=%s signals=%s",
            subject, score_val, sig.reason, source_signals,
        )

        # Case A: Process subject
        if subject.startswith("pid:"):
            try:
                pid = int(subject[4:])
            except ValueError:
                pid = None

            if pid:
                image_path = None
                if event and event.pid == pid and event.image_path:
                    image_path = event.image_path

                res = quarantine_process(
                    pid=pid,
                    image_path=image_path,
                    reason=sig.reason,
                    scorer=self.scorer,
                    quarantine_store=self.quarantine_store,
                    kernel_bridge=self.kernel_bridge,
                    bus=self.bus,
                    source_signals=source_signals,
                )

                qrec = res.get("quarantine")
                self.notifier.notify_alert(
                    process_name=image_path or f"PID {pid}",
                    reason=sig.reason,
                    pid=pid,
                    quarantine_id=qrec.id if qrec else None,
                    score=score_val,
                )
                return

        # Case B: File subject
        file_path = None
        if event:
            if event.image_path and Path(event.image_path).is_file():
                file_path = event.image_path
            elif "path" in event.extra and Path(event.extra["path"]).is_file():
                file_path = event.extra["path"]

        if file_path:
            # Check if user previously restored this file (FP feedback)
            if self.quarantine_store:
                try:
                    p = Path(file_path)
                    if p.is_file():
                        sha = self.quarantine_store._sha256_of(p)
                        if self.quarantine_store.is_restored(sha):
                            logger.info(
                                "Skipping autonomous response for user-restored file %s (sha256=%s)",
                                file_path,
                                sha,
                            )
                            return
                except Exception:
                    pass

            qrec = self.quarantine_store.add(
                source_path=str(file_path),
                subject=subject,
                reason=sig.reason,
                score=score_val,
                source_signals=source_signals,
            )

            # Phase 4: Pre-block in kernel driver
            if self.kernel_bridge:
                try:
                    self.kernel_bridge.add_block(str(file_path))
                except Exception as exc:
                    logger.warning("kernel bridge add_block failed: %s", exc)

            self.notifier.notify_alert(
                process_name=Path(file_path).name,
                reason=sig.reason,
                quarantine_id=qrec.id if qrec else None,
                score=score_val,
            )
