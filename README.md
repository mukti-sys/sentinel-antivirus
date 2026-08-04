# 🛡️ Sentinel Antivirus

A lightweight, open-source antivirus engine for Windows built in Python with a Windows kernel minifilter driver for pre-execution blocking.

## Features

### User-Mode Protection Engine
- **YARA Content Scanner** — Real-time file scanning with custom YARA rules
- **PE Static Classifier** — Machine learning anomaly detection on PE headers using Isolation Forest
- **VirusTotal Integration** — Hash-based cloud lookup with local caching (optional, works offline)
- **Ransomware Detection** — Entropy spike analysis + mass file modification rate monitoring
- **Cryptomining Detection** — Sustained CPU usage + stratum mining pool connection detection
- **Brute-Force Detection** — Failed login burst monitoring via Windows Event Log (Event ID 4625)
- **Sigma Rule Engine** — Sigma-style YAML detection rules with recursive-descent condition parser
- **Real-Time File Monitoring** — Watchdog-based filesystem sensor for Downloads/Desktop/Temp
- **ETW Process Telemetry** — Live process creation, image loads, and registry writes via Event Tracing for Windows
- **Network Connection Logging** — Per-process outbound connection tracking with deduplication
- **Quarantine System** — SQLite-backed quarantine with restore/delete capability and SHA-256 integrity verification
- **System Tray App** — `pystray`-based tray icon with quarantine management UI
- **Watchdog Service** — Monitors core service health and auto-restarts on unexpected termination

### Kernel-Mode Driver (`driver/SentinelFilter/`)
- **Windows Minifilter Driver** — Intercepts `IRP_MJ_CREATE` with `FILE_EXECUTE` access to block malicious files before execution
- **Path-Based Blocklist** — Zero disk I/O in the hot path (fast string comparison, no SHA-256 in kernel)
- **User-Mode Communication Port** — Bidirectional messaging between driver and Python service
- **Graceful Degradation** — Full user-mode protection works without the kernel driver loaded

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  System Tray UI                  │
│              (pystray + Pillow)                  │
├─────────────────────────────────────────────────┤
│                Sentinel Service                  │
│         (Orchestrator / Windows Service)         │
├──────────┬──────────┬──────────┬────────────────┤
│  Scoring │  YARA    │  Rule    │  Heuristics    │
│  Engine  │  Scanner │  Engine  │ (ransom/crypto │
│          │          │  (Sigma) │  /brute-force) │
├──────────┴──────────┴──────────┴────────────────┤
│              Event Bus (SQLite + Queue)           │
├──────────┬──────────┬──────────┬────────────────┤
│   ETW    │    FS    │ Network  │   EventLog     │
│  Sensor  │  Sensor  │  Sensor  │   Sensor       │
├──────────┴──────────┴──────────┴────────────────┤
│          Kernel Bridge (ctypes/fltlib)            │
├─────────────────────────────────────────────────┤
│     SentinelFilter.sys (Windows Minifilter)       │
│        Altitude 328100 · FSFilter Anti-Virus      │
└─────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Windows 10/11
- Python 3.11+

### Installation

```bash
git clone https://github.com/yourusername/sentinel-antivirus.git
cd sentinel-antivirus
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### Run (Standalone Mode)
```bash
python -m sentinel.service --standalone
```

### Run (System Tray)
```bash
python -m sentinel.ui.tray_app
```

### Test with EICAR
Drop the [EICAR test file](https://www.eicar.org/) into your Downloads folder — Sentinel will detect and quarantine it automatically.

## Project Structure

```
sentinel/
├── config/
│   ├── rules/          # Sigma YAML rules + YARA .yar rules
│   └── settings.yaml   # Detection thresholds, watched folders, API keys
├── engine/
│   ├── event_bus.py    # Normalize + persist events to SQLite
│   ├── schema.py       # Shared event dataclass
│   ├── scoring.py      # Signal aggregation + response threshold
│   ├── rule_engine.py  # Sigma-style YAML rule matching
│   ├── static_classifier.py  # YARA + VT hash + PE anomaly detection
│   └── heuristics_*.py # Ransomware, cryptomining, brute-force
├── sensors/
│   ├── etw_sensor.py   # ETW process/image/registry telemetry
│   ├── fs_sensor.py    # Watchdog filesystem monitoring
│   ├── network_sensor.py  # psutil connection logging
│   └── eventlog_sensor.py # Windows Security Event Log (4625)
├── response/
│   ├── responder.py    # Process suspend/resume via NtSuspendProcess
│   ├── quarantine_store.py  # SQLite quarantine DB + file isolation
│   └── notifier.py     # Windows toast notifications
├── kernel/
│   ├── bridge.py       # fltlib.dll ctypes bridge to minifilter
│   └── messages.py     # Shared message structures
├── intel/
│   └── virustotal_client.py  # VT API v3 with rate limiting + cache
├── ui/
│   └── tray_app.py     # System tray with quarantine management
├── service.py          # Windows service + standalone orchestrator
└── watchdog_svc.py     # Core service health monitor

driver/
├── SentinelFilter/
│   ├── SentinelFilter.c    # Minifilter driver (IRP_MJ_CREATE hook)
│   ├── blocklist.c         # Sorted path-based blocklist
│   ├── communication.c     # Filter communication port
│   ├── SentinelFilter.inf  # Driver installation INF
│   └── SentinelFilter.vcxproj  # WDK build project
├── scripts/            # Driver signing, installation, test-signing scripts
├── test/               # User-mode C blocklist tests (16 tests)
└── VM_SETUP.md         # VM setup guide for driver testing
```

## Testing

```bash
# Run all tests (251 pass, 1 skipped)
python -m pytest sentinel/tests/ -v

# Run specific test suites
python -m pytest sentinel/tests/unit/test_scoring.py -v
python -m pytest sentinel/tests/unit/test_static_classifier.py -v
python -m pytest sentinel/tests/unit/test_quarantine_store.py -v
```

## Configuration

Edit `sentinel/config/settings.yaml`:

```yaml
watched_folders:
  - "~/Downloads"
  - "~/Desktop"
  - "~/AppData/Local/Temp"

thresholds:
  cpu_sustained_percent: 85
  file_write_rate_per_min: 50
  file_entropy_alert: 7.5
  failed_login_count: 5

intel:
  virustotal_api_key: ""  # Optional: free tier VT API key
```

## Kernel Driver (Advanced)

The minifilter driver requires:
- Visual Studio 2022 + Windows Driver Kit (WDK)
- Test signing enabled (`bcdedit /set testsigning on`)
- **Must be tested in a VM** — never load unsigned drivers on your host machine

See [VM_SETUP.md](driver/VM_SETUP.md) for complete setup instructions.

## License

[MIT](LICENSE)
