"""Sentinel Windows service -- runs the core detection loop as a service.

Implements phases.md Phase 3 hardening:
    run core logic as a Windows service

Phase 4 kernel enforcement integration:
    Connects to the SentinelFilter minifilter driver via KernelBridge.
    If the driver is not loaded, the service continues in user-mode-only
    mode (Phase 3 behavior).

Usage (elevated terminal):
    python -m sentinel.service install
    python -m sentinel.service start
    python -m sentinel.service stop
    python -m sentinel.service remove

The service orchestrates sensors -> detection -> response in a single
process, matching the concurrency model in architecture.md Section 8.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Service name and display name.
SERVICE_NAME = "SentinelCoreSvc"
SERVICE_DISPLAY = "Sentinel Core Detection Service"
SERVICE_DESC = (
    "Behavioral security layer: sensors, detection engines, and response. "
    "Independent of Windows Defender."
)

# PID file for watchdog monitoring.
_PID_FILE = Path(__file__).resolve().parent / "data" / "sentinel.pid"


def _write_pid() -> None:
    """Write the current PID to the PID file for watchdog monitoring."""
    _PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    _PID_FILE.write_text(str(os.getpid()))


def _remove_pid() -> None:
    """Remove the PID file on clean shutdown."""
    _PID_FILE.unlink(missing_ok=True)


class SentinelOrchestrator:
    """Core orchestrator that ties sensors -> detection -> response together.

    This is the main loop that the service runs. It can also be run
    standalone for development/testing.
    """

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._sensors = []
        self._bus = None
        self._kernel_bridge = None  # Phase 4: kernel enforcement bridge
        self._consumer = None       # Detection & response pipeline consumer
        self._canary_manager = None # Honeypot canary deception engine
        self._ipc_server = None     # Win32 Named Pipe IPC server (Session 0 bridge)

    def start(self) -> None:
        """Start all sensors and the detection loop."""
        logger.info("Sentinel orchestrator starting (pid=%d)", os.getpid())
        _write_pid()

        try:
            self._init_components()
            self._run_loop()
        except Exception:
            logger.exception("orchestrator crashed")
            raise
        finally:
            self._cleanup()

    def stop(self) -> None:
        """Signal the orchestrator to stop."""
        logger.info("Sentinel orchestrator stopping")
        self._stop_event.set()

    def _init_components(self) -> None:
        """Initialize sensors, detection engines, and response components."""
        from sentinel.engine.event_bus import EventBus

        data_dir = Path(__file__).resolve().parent / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        self._bus = EventBus(db_path=data_dir / "events.db")
        logger.info("event bus initialized (db: %s)", data_dir / "events.db")

        # Phase 4: Connect to kernel minifilter (graceful degradation).
        self._init_kernel_bridge()

        # Start detection consumer pipeline (wire sensors -> engines -> response).
        self._init_detection_consumer()

        # Arm Honeypot Canary Deception Engine
        try:
            from sentinel.engine.canary import CanaryManager
            self._canary_manager = CanaryManager()
            armed = self._canary_manager.arm_traps()
            logger.info("canary deception engine armed (%d traps)", armed)
        except Exception as exc:
            logger.warning("canary deception engine init failed: %s", exc)
            self._canary_manager = None

        # Start Win32 Named Pipe IPC server for desktop session communication
        try:
            from sentinel.ipc import NamedPipeServer
            self._ipc_server = NamedPipeServer(command_handler=self._handle_ipc_command)
            self._ipc_server.start()
            logger.info("named pipe IPC server started")
        except Exception as exc:
            logger.warning("named pipe IPC server init failed: %s", exc)
            self._ipc_server = None

        # Start sensors (each in its own thread per architecture.md Section 8).
        self._start_sensors()


    def _start_sensors(self) -> None:
        """Start all sensors, skipping any that fail to initialize."""
        # FS sensor (no admin required).
        try:
            from sentinel.sensors.fs_sensor import FsSensor
            downloads = str(Path.home() / "Downloads")
            desktop = str(Path.home() / "Desktop")
            fs = FsSensor(self._bus, [downloads, desktop])
            fs.start()
            self._sensors.append(fs)
            logger.info("fs_sensor started")
        except Exception as exc:
            logger.warning("fs_sensor failed to start: %s", exc)

        # Network sensor (no admin required).
        try:
            from sentinel.sensors.network_sensor import NetworkSensor
            net = NetworkSensor(self._bus, baseline_on_start=True)
            net.start()
            self._sensors.append(net)
            logger.info("network_sensor started")
        except Exception as exc:
            logger.warning("network_sensor failed to start: %s", exc)

        # ETW sensor (requires admin).
        try:
            from sentinel.sensors.etw_sensor import EtwSensor
            etw = EtwSensor(self._bus)
            etw.start()
            self._sensors.append(etw)
            logger.info("etw_sensor started")
        except Exception as exc:
            logger.warning("etw_sensor failed to start (admin?): %s", exc)

        # Eventlog sensor (requires admin).
        try:
            from sentinel.sensors.eventlog_sensor import EventLogSensor
            evtlog = EventLogSensor(self._bus)
            evtlog.start()
            self._sensors.append(evtlog)
            logger.info("eventlog_sensor started")
        except Exception as exc:
            logger.warning("eventlog_sensor failed to start (admin?): %s", exc)

    def _run_loop(self) -> None:
        """Main event processing loop."""
        logger.info("orchestrator running (%d sensors active)", len(self._sensors))
        while not self._stop_event.wait(timeout=1.0):
            # In v1, detection engines consume from the bus queue.
            # The loop just keeps the process alive; detection runs in
            # sensor/consumer threads.
            pass

    def _init_kernel_bridge(self) -> None:
        """Connect to the SentinelFilter kernel minifilter (Phase 4).

        Best-effort: if the driver isn't loaded, the bridge enters no-op
        mode and all kernel enforcement calls become silent no-ops.
        The rest of Sentinel works exactly as in Phase 3.
        """
        try:
            from sentinel.kernel.bridge import KernelBridge
            bridge = KernelBridge()
            if bridge.connect():
                status = bridge.get_status()
                logger.info(
                    "kernel bridge connected (blocklist=%s, total_blocks=%s)",
                    status.get("blocklist_count", "?"),
                    status.get("blocks_total", "?"),
                )
            else:
                logger.info(
                    "kernel bridge: driver not loaded — "
                    "running in user-mode-only mode (Phase 3)"
                )
            self._kernel_bridge = bridge
        except Exception as exc:
            logger.warning("kernel bridge init failed: %s — "
                          "running in user-mode-only mode", exc)
            self._kernel_bridge = None

    def _init_detection_consumer(self) -> None:
        """Initialize and start the detection consumer pipeline."""
        try:
            from sentinel.engine.consumer import DetectionConsumer
            from sentinel.response.notifier import Notifier
            from sentinel.response.quarantine_store import QuarantineStore

            data_dir = Path(__file__).resolve().parent / "data"
            quarantine_dir = data_dir / "quarantine"
            quarantine_store = QuarantineStore(
                db_path=data_dir / "quarantine.db",
                quarantine_dir=quarantine_dir,
            )
            notifier = Notifier()

            self._consumer = DetectionConsumer(
                bus=self._bus,
                quarantine_store=quarantine_store,
                kernel_bridge=self._kernel_bridge,
                notifier=notifier,
            )
            self._consumer.start()
            logger.info("detection consumer pipeline started")
        except Exception as exc:
            logger.exception("detection consumer failed to start: %s", exc)
            self._consumer = None

    def _handle_ipc_command(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle incoming commands from desktop applications (Session 1+)."""
        cmd = request.get("cmd")
        if cmd == "ping":
            return {"status": "ok", "pong": True, "service": "running", "version": "1.0.0"}

        elif cmd == "get_status":
            driver_info = {}
            if self._kernel_bridge:
                try:
                    driver_info = self._kernel_bridge.get_status()
                except Exception:
                    pass

            canary_info = {}
            if self._canary_manager:
                try:
                    canary_info = self._canary_manager.get_status()
                except Exception:
                    pass

            quarantine_count = 0
            if self._consumer and getattr(self._consumer, "_quarantine_store", None):
                try:
                    quarantine_count = self._consumer._quarantine_store.count(decision="pending")
                except Exception:
                    pass

            return {
                "status": "ok",
                "service": "running",
                "pid": os.getpid(),
                "shield": "GREEN",
                "kernel_driver": driver_info,
                "canary_traps": canary_info,
                "sensors_active": len(self._sensors),
                "quarantine_pending": quarantine_count,
            }

        elif cmd == "verify_canaries":
            if not self._canary_manager:
                return {"status": "error", "message": "canary engine not active"}
            tampered = self._canary_manager.verify_all_canaries()
            return {
                "status": "ok",
                "tampered_count": len(tampered),
                "tampered": [{"path": str(t.path), "reason": r} for t, r in tampered],
            }

        elif cmd == "rearm_canaries":
            if not self._canary_manager:
                return {"status": "error", "message": "canary engine not active"}
            repaired = self._canary_manager.repair_canaries()
            return {"status": "ok", "repaired_count": repaired}

        return {"status": "error", "message": f"unknown command: {cmd}"}

    def _cleanup(self) -> None:
        """Stop IPC, consumer, sensors, disconnect bridge, disarm canaries, and close bus."""
        # Stop IPC server first
        if self._ipc_server:
            try:
                self._ipc_server.stop()
                logger.info("IPC server stopped")
            except Exception as exc:
                logger.warning("IPC server stop error: %s", exc)

        # Stop detection consumer
        if self._consumer:
            try:
                self._consumer.stop()
                logger.info("detection consumer stopped")
            except Exception as exc:
                logger.warning("consumer stop error: %s", exc)

        for sensor in self._sensors:
            try:
                sensor.stop()
            except Exception as exc:
                logger.warning("sensor stop error: %s", exc)

        # Disconnect kernel bridge
        if self._kernel_bridge:
            try:
                self._kernel_bridge.disconnect()
                logger.info("kernel bridge disconnected")
            except Exception as exc:
                logger.warning("kernel bridge disconnect error: %s", exc)

        # Disarm canaries if shutting down cleanly
        if self._canary_manager:
            try:
                self._canary_manager.disarm_traps()
                logger.info("canary traps disarmed")
            except Exception as exc:
                logger.warning("canary disarm error: %s", exc)

        if self._bus:
            self._bus.close()
        _remove_pid()
        logger.info("orchestrator stopped")



# --------------------------------------------------------------------------- #
# Windows Service wrapper (pywin32)
# --------------------------------------------------------------------------- #

def _run_as_service() -> None:
    """Register and run as a Windows service."""
    try:
        import win32serviceutil
        import win32service
        import win32event
        import servicemanager
    except ImportError:
        print("Error: pywin32 is required for service mode")
        print("  pip install pywin32")
        sys.exit(1)

    class SentinelService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESC

        def __init__(self, args):
            super().__init__(args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._orchestrator = SentinelOrchestrator()

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            # Run orchestrator in a thread so we can respond to stop requests.
            thread = threading.Thread(target=self._orchestrator.start, daemon=True)
            thread.start()
            # Wait for stop signal.
            win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
            self._orchestrator.stop()
            thread.join(timeout=10)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._orchestrator.stop()
            win32event.SetEvent(self._stop_event)

    # Handle install/start/stop/remove commands.
    if len(sys.argv) == 1:
        # Started by the SCM (or fallback to standalone if run directly without SCM).
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(SentinelService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception as exc:
            logger.info("Not running under SCM controller (%s), starting standalone orchestrator.", exc)
            orch = SentinelOrchestrator()
            try:
                orch.start()
            except KeyboardInterrupt:
                orch.stop()
    else:
        win32serviceutil.HandleCommandLine(SentinelService)


def main() -> int:
    """Entry point: run as service if invoked by SCM or with service commands,
    otherwise run standalone."""
    if "--standalone" in sys.argv:
        # Run the orchestrator directly (for development/testing).
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        )
        orch = SentinelOrchestrator()
        try:
            orch.start()
        except KeyboardInterrupt:
            orch.stop()
        return 0

    if "--help" in sys.argv or "-h" in sys.argv:
        print(f"Sentinel Service ({SERVICE_NAME})")
        print()
        print("Service commands (elevated terminal required):")
        print(f"  python -m sentinel.service install")
        print(f"  python -m sentinel.service start")
        print(f"  python -m sentinel.service stop")
        print(f"  python -m sentinel.service remove")
        print()
        print("Development mode:")
        print(f"  python -m sentinel.service --standalone")
        return 0

    _run_as_service()
    return 0


if __name__ == "__main__":
    sys.exit(main())
