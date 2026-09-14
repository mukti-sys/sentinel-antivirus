"""On-demand file and directory scanner for Sentinel Antivirus.

Provides recursive scanning capabilities for files, folders, quick scans
(memory / startup / high-risk directories), and full disk scans.
Leverages YARA rule engine, StaticClassifier PE feature heuristics,
and QuarantineStore for optional autonomous isolation.
"""
from __future__ import annotations

import enum
import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

from sentinel.engine.static_classifier import StaticClassifier, _read_and_hash
from sentinel.response.quarantine_store import QuarantineStore

logger = logging.getLogger("sentinel.scanner")

# Default extensions prioritized for deeper analysis
EXECUTABLE_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".scr", ".cpl", ".drv", ".ocx",
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".msi", ".msp", ".com", ".pif",
})

# System-level folders and files to bypass during recursive full scans
SYSTEM_IGNORE_FOLDERS = frozenset({
    "$recycle.bin",
    "system volume information",
    "$windows.~bt",
    "$windows.~ws",
    "$winreagent",
    "recovery",
})

SYSTEM_IGNORE_FILES = frozenset({
    "pagefile.sys",
    "swapfile.sys",
    "hiberfil.sys",
    "dumpstack.log.tmp",
})


class ScanType(enum.Enum):
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"


class ScanStatus(enum.Enum):
    IDLE = "idle"
    SCANNING = "scanning"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ERROR = "error"


class ThreatSeverity(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatDetection:
    file_path: Path
    sha256: str
    threat_name: str
    score: float
    severity: ThreatSeverity
    engine: str
    description: str
    timestamp: float = field(default_factory=time.time)
    quarantined: bool = False
    quarantine_id: str | None = None


@dataclass
class ScanProgress:
    files_scanned: int = 0
    threats_found: int = 0
    current_file: str = ""
    start_time: float = 0.0
    elapsed_seconds: float = 0.0
    bytes_scanned: int = 0
    total_files_estimate: int = 0


@dataclass
class ScanSummary:
    scan_type: ScanType
    status: ScanStatus
    files_scanned: int
    threats_found: int
    threats: list[ThreatDetection]
    start_time: float
    end_time: float
    duration_seconds: float
    error_message: str | None = None


# Progress callback signature: on_progress(progress: ScanProgress)
ProgressCallback = Callable[[ScanProgress], None]
# Threat callback signature: on_threat(threat: ThreatDetection)
ThreatCallback = Callable[[ThreatDetection], None]
# Completion callback signature: on_complete(summary: ScanSummary)
CompletionCallback = Callable[[ScanSummary], None]


class OnDemandScanner:
    """Multi-threaded on-demand scanner for files, directories, and system presets."""

    def __init__(
        self,
        classifier: StaticClassifier | None = None,
        quarantine_store: QuarantineStore | None = None,
        rules_dir: str | Path | None = None,
        auto_quarantine: bool = False,
    ) -> None:
        self.classifier = classifier or StaticClassifier(yara_rules_dir=rules_dir)
        self.quarantine_store = quarantine_store
        self.auto_quarantine = auto_quarantine

        self._status = ScanStatus.IDLE
        self._cancel_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # set = unpaused
        self._lock = threading.Lock()
        self._active_thread: threading.Thread | None = None
        self._last_summary: ScanSummary | None = None

    # ------------------------------------------------------------------ #
    # State control
    # ------------------------------------------------------------------ #

    @property
    def status(self) -> ScanStatus:
        with self._lock:
            return self._status

    @property
    def last_summary(self) -> ScanSummary | None:
        with self._lock:
            return self._last_summary

    def cancel(self) -> None:
        """Signal the running scan to stop."""
        self._cancel_event.set()
        self._pause_event.set()  # resume so thread can notice cancel

    def pause(self) -> None:
        """Pause the current scan."""
        with self._lock:
            if self._status == ScanStatus.SCANNING:
                self._status = ScanStatus.PAUSED
                self._pause_event.clear()

    def resume(self) -> None:
        """Resume a paused scan."""
        with self._lock:
            if self._status == ScanStatus.PAUSED:
                self._status = ScanStatus.SCANNING
                self._pause_event.set()

    # ------------------------------------------------------------------ #
    # Single File Scanning
    # ------------------------------------------------------------------ #

    def scan_file(self, path: str | Path) -> ThreatDetection | None:
        """Scan an individual file against YARA and PE feature models.
        Returns a ThreatDetection object if suspicious or malicious, else None.
        """
        file_path = Path(path).resolve()
        if not file_path.is_file():
            return None

        # Check ignore list
        if file_path.name.lower() in SYSTEM_IGNORE_FILES:
            return None

        result = _read_and_hash(file_path)
        if result is None:
            return None
        sha256, file_data = result

        threat: ThreatDetection | None = None

        # 1. YARA rules content match (checks all files)
        yara_hits = self.classifier._yara_scan(file_data, file_path.name)
        if yara_hits:
            rule_name = yara_hits[0]
            threat = ThreatDetection(
                file_path=file_path,
                sha256=sha256,
                threat_name=f"YARA:{rule_name}",
                score=90.0,
                severity=ThreatSeverity.CRITICAL if "eicar" in rule_name.lower() or "ransom" in rule_name.lower() else ThreatSeverity.HIGH,
                engine="yara_scanner",
                description=f"Matched YARA signature: '{rule_name}'",
            )

        # 2. VirusTotal cloud check (if configured)
        if not threat and self.classifier.vt is not None:
            vt_verdict = self.classifier.vt.lookup(sha256)
            if vt_verdict is not None and vt_verdict.verdict == "malicious":
                threat = ThreatDetection(
                    file_path=file_path,
                    sha256=sha256,
                    threat_name="VirusTotal:Malicious",
                    score=85.0,
                    severity=ThreatSeverity.HIGH,
                    engine="virustotal",
                    description=f"VirusTotal flagged {vt_verdict.positives}/{vt_verdict.total} detections",
                )

        # 3. PE Feature anomaly model (for executable binaries)
        if not threat and file_path.suffix.lower() in {".exe", ".dll", ".sys", ".scr"}:
            features = self.classifier.pe_model.extract_features(file_path)
            if features is not None:
                prob = self.classifier.pe_model.predict_proba(features)
                if prob >= 0.70:
                    threat = ThreatDetection(
                        file_path=file_path,
                        sha256=sha256,
                        threat_name="Heuristic:PE.Anomaly",
                        score=float(prob * 100.0),
                        severity=ThreatSeverity.HIGH if prob >= 0.85 else ThreatSeverity.MEDIUM,
                        engine="pe_classifier",
                        description=f"PE anomaly model confidence: {prob:.1%}",
                    )

        # Optional auto-quarantine
        if threat and self.auto_quarantine and self.quarantine_store:
            try:
                rec = self.quarantine_store.add(
                    source_path=file_path,
                    subject=f"file:{sha256[:16]}",
                    reason=f"Scanner: {threat.threat_name} ({threat.description})",
                    score=threat.score,
                )
                if rec is not None:
                    threat.quarantined = True
                    threat.quarantine_id = rec.id
                    logger.info("Scanner auto-quarantined: %s (ID: %s)", file_path, rec.id)
            except Exception as exc:
                logger.error("Failed to auto-quarantine %s: %s", file_path, exc)

        return threat

    # ------------------------------------------------------------------ #
    # Directory Traversal
    # ------------------------------------------------------------------ #

    def _collect_files(
        self,
        targets: Sequence[Path],
        quick_mode: bool = False,
    ) -> Iterable[Path]:
        """Generator yielding file paths from targets, respecting ignore lists."""
        for target in targets:
            if self._cancel_event.is_set():
                break

            try:
                target = target.resolve()
            except Exception:
                continue

            if target.is_file():
                yield target
                continue

            if not target.is_dir():
                continue

            # Walk directory
            for root, dirs, files in os.walk(str(target), followlinks=False):
                if self._cancel_event.is_set():
                    break

                # Filter out system and ignored folders in place
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in SYSTEM_IGNORE_FOLDERS
                    and not d.startswith(".")
                ]

                for fname in files:
                    if self._cancel_event.is_set():
                        break

                    if fname.lower() in SYSTEM_IGNORE_FILES:
                        continue

                    fpath = Path(root) / fname
                    # In quick mode, prioritize executable/script files + archives
                    if quick_mode and fpath.suffix.lower() not in EXECUTABLE_EXTENSIONS:
                        continue

                    yield fpath

    # ------------------------------------------------------------------ #
    # Preset Target Collectors
    # ------------------------------------------------------------------ #

    @staticmethod
    def get_quick_scan_targets() -> list[Path]:
        """Collect paths for high-risk locations and running processes."""
        targets: list[Path] = []
        home = Path.home()

        # 1. User common download/drop locations
        for rel in ["Downloads", "Desktop"]:
            p = home / rel
            if p.is_dir():
                targets.append(p)

        # 2. Temp folders
        for env_var in ["TEMP", "TMP"]:
            val = os.environ.get(env_var)
            if val and Path(val).is_dir():
                targets.append(Path(val))

        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            local_temp = Path(local_app_data) / "Temp"
            if local_temp.is_dir():
                targets.append(local_temp)

        # 3. Startup directories
        appdata = os.environ.get("APPDATA")
        if appdata:
            startup = Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup"
            if startup.is_dir():
                targets.append(startup)

        progdata = os.environ.get("PROGRAMDATA")
        if progdata:
            cstartup = Path(progdata) / r"Microsoft\Windows\Start Menu\Programs\Startup"
            if cstartup.is_dir():
                targets.append(cstartup)

        # 4. Running process executable paths
        try:
            import psutil
            seen_exes: set[str] = set()
            for proc in psutil.process_iter(["exe"]):
                try:
                    exe_path = proc.info.get("exe")
                    if exe_path and exe_path not in seen_exes:
                        seen_exes.add(exe_path)
                        p = Path(exe_path)
                        if p.is_file():
                            targets.append(p)
                except Exception:
                    continue
        except Exception as exc:
            logger.debug("Scanner: could not enumerate running processes: %s", exc)

        return targets

    @staticmethod
    def get_full_scan_targets() -> list[Path]:
        """Collect all local fixed drive roots for a full system scan."""
        targets: list[Path] = []
        try:
            import psutil
            for part in psutil.disk_partitions(all=False):
                if "fixed" in part.opts.lower() or part.fstype != "":
                    mount = Path(part.mountpoint)
                    if mount.exists():
                        targets.append(mount)
        except Exception:
            # Fallback to C:\
            targets = [Path("C:\\")]
        return targets or [Path("C:\\")]

    # ------------------------------------------------------------------ #
    # Core Scan Loop
    # ------------------------------------------------------------------ #

    def execute_scan(
        self,
        targets: Sequence[Path],
        scan_type: ScanType = ScanType.CUSTOM,
        progress_callback: ProgressCallback | None = None,
        threat_callback: ThreatCallback | None = None,
    ) -> ScanSummary:
        """Run scan synchronously over target paths."""
        with self._lock:
            if self._status == ScanStatus.SCANNING:
                raise RuntimeError("Scan is already in progress")
            self._status = ScanStatus.SCANNING
            self._cancel_event.clear()
            self._pause_event.set()

        start_time = time.time()
        threats: list[ThreatDetection] = []
        progress = ScanProgress(start_time=start_time)
        quick_mode = (scan_type == ScanType.QUICK)

        final_status = ScanStatus.COMPLETED
        error_msg: str | None = None

        try:
            file_generator = self._collect_files(targets, quick_mode=quick_mode)

            for file_path in file_generator:
                # Handle pause
                self._pause_event.wait()

                # Handle cancel
                if self._cancel_event.is_set():
                    final_status = ScanStatus.CANCELLED
                    break

                progress.current_file = str(file_path)
                progress.files_scanned += 1
                progress.elapsed_seconds = time.time() - start_time

                try:
                    size = file_path.stat().st_size
                    progress.bytes_scanned += size
                except Exception:
                    pass

                # Perform scan
                try:
                    detection = self.scan_file(file_path)
                    if detection:
                        threats.append(detection)
                        progress.threats_found += 1
                        if threat_callback:
                            try:
                                threat_callback(detection)
                            except Exception as cb_exc:
                                logger.debug("threat_callback error: %s", cb_exc)
                except Exception as scan_exc:
                    logger.debug("Error scanning %s: %s", file_path, scan_exc)

                # Report progress every file
                if progress_callback:
                    try:
                        progress_callback(progress)
                    except Exception as cb_exc:
                        logger.debug("progress_callback error: %s", cb_exc)

        except Exception as exc:
            final_status = ScanStatus.ERROR
            error_msg = str(exc)
            logger.exception("Scanner error during scan: %s", exc)

        if self._cancel_event.is_set():
            final_status = ScanStatus.CANCELLED

        end_time = time.time()
        summary = ScanSummary(
            scan_type=scan_type,
            status=final_status,
            files_scanned=progress.files_scanned,
            threats_found=len(threats),
            threats=threats,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=end_time - start_time,
            error_message=error_msg,
        )

        with self._lock:
            self._status = final_status
            self._last_summary = summary

        return summary

    # ------------------------------------------------------------------ #
    # Asynchronous Launchers
    # ------------------------------------------------------------------ #

    def _start_async(
        self,
        targets: Sequence[Path],
        scan_type: ScanType,
        progress_callback: ProgressCallback | None = None,
        threat_callback: ThreatCallback | None = None,
        completion_callback: CompletionCallback | None = None,
    ) -> threading.Thread:
        """Internal helper to start scan on a background thread."""
        def worker() -> None:
            summary = self.execute_scan(
                targets=targets,
                scan_type=scan_type,
                progress_callback=progress_callback,
                threat_callback=threat_callback,
            )
            if completion_callback:
                try:
                    completion_callback(summary)
                except Exception as cb_exc:
                    logger.error("completion_callback error: %s", cb_exc)

        thread = threading.Thread(
            target=worker,
            name=f"sentinel-scanner-{scan_type.value}",
            daemon=True,
        )
        self._active_thread = thread
        thread.start()
        return thread

    def start_quick_scan(
        self,
        progress_callback: ProgressCallback | None = None,
        threat_callback: ThreatCallback | None = None,
        completion_callback: CompletionCallback | None = None,
    ) -> threading.Thread:
        """Start Quick Scan in background."""
        targets = self.get_quick_scan_targets()
        return self._start_async(
            targets=targets,
            scan_type=ScanType.QUICK,
            progress_callback=progress_callback,
            threat_callback=threat_callback,
            completion_callback=completion_callback,
        )

    def start_full_scan(
        self,
        progress_callback: ProgressCallback | None = None,
        threat_callback: ThreatCallback | None = None,
        completion_callback: CompletionCallback | None = None,
    ) -> threading.Thread:
        """Start Full Scan in background."""
        targets = self.get_full_scan_targets()
        return self._start_async(
            targets=targets,
            scan_type=ScanType.FULL,
            progress_callback=progress_callback,
            threat_callback=threat_callback,
            completion_callback=completion_callback,
        )

    def start_custom_scan(
        self,
        targets: Sequence[str | Path],
        progress_callback: ProgressCallback | None = None,
        threat_callback: ThreatCallback | None = None,
        completion_callback: CompletionCallback | None = None,
    ) -> threading.Thread:
        """Start Custom Scan in background for specific paths."""
        path_targets = [Path(t) for t in targets]
        return self._start_async(
            targets=path_targets,
            scan_type=ScanType.CUSTOM,
            progress_callback=progress_callback,
            threat_callback=threat_callback,
            completion_callback=completion_callback,
        )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Sentinel On-Demand Scanner")
    parser.add_argument("--quick", action="store_true", help="Run Quick Scan")
    parser.add_argument("--full", action="store_true", help="Run Full Scan")
    parser.add_argument("--target", type=str, help="Specific file or directory to scan")
    parser.add_argument("--quarantine", action="store_true", help="Auto-quarantine detected threats")
    args = parser.parse_args()

    scanner = OnDemandScanner(auto_quarantine=args.quarantine)

    def on_prog(p: ScanProgress):
        display = p.current_file
        if len(display) > 60:
            display = "..." + display[-57:]
        sys.stdout.write(f"\rScanned: {p.files_scanned} files | Threats: {p.threats_found} | {display}")
        sys.stdout.flush()

    def on_threat(t: ThreatDetection):
        print(f"\n[!] THREAT DETECTED: {t.threat_name} in {t.file_path}")

    print("=== Sentinel On-Demand Scanner ===")
    if args.quick:
        summary = scanner.execute_scan(
            scanner.get_quick_scan_targets(),
            scan_type=ScanType.QUICK,
            progress_callback=on_prog,
            threat_callback=on_threat,
        )
    elif args.full:
        summary = scanner.execute_scan(
            scanner.get_full_scan_targets(),
            scan_type=ScanType.FULL,
            progress_callback=on_prog,
            threat_callback=on_threat,
        )
    elif args.target:
        summary = scanner.execute_scan(
            [Path(args.target)],
            scan_type=ScanType.CUSTOM,
            progress_callback=on_prog,
            threat_callback=on_threat,
        )
    else:
        parser.print_help()
        sys.exit(0)

    print(f"\nScan completed in {summary.duration_seconds:.1f}s. Scanned {summary.files_scanned} files. Threats: {summary.threats_found}")

