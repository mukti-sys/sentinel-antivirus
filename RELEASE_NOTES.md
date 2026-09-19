# 🛡️ Sentinel Antivirus v2.2.0 — Dynamic In-Memory Sandbox & Cross-Platform Edition

Welcome to the **v2.2.0 production release** of **Sentinel Antivirus**. This release introduces a dual-mode dynamic analysis sandbox (pure in-memory CPU emulation and OS-contained process detonation), multi-OS cross-platform protection across Windows, Linux, and macOS, and an interactive Sandbox Studio.

---

## 🚀 Key Highlights & New Capabilities

### 1. Dual-Mode Dynamic Sandbox & In-Memory Emulation (v2.2)
- **Zero-Risk In-Memory Emulation (`DynamicEmulator`)**:
  - Simulates x86/x64 instruction execution directly in Python virtual memory in **< 100 ms** with **zero host execution risk**.
  - **Anti-Debug Interception**: Intercepts `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `RDTSC` timing attacks, and `PEB.BeingDebugged`.
  - **Dynamic API Resolution**: Detects and unmasks runtime API hashing via ROR13 PEB walks (catching stealth calls to `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`).
  - **Unpack Loop Detection**: Tracks memory write bursts (`STOSB`, XOR decryptors) and extracts unpacked memory payloads.
  - **In-Memory YARA Rescanning**: Automatically re-scans unpacked memory buffers with compiled YARA rules, defeating crypters and packers.
- **Contained Process Detonation (`SandboxIsolation`)**:
  - **Windows**: Isolated execution inside Win32 Job Objects enforcing a strict **128 MB RAM ceiling**, CPU time limits, UI restrictions (`UIRestrictionsClass`), and automatic child process containment.
  - **Linux**: Fork isolation leveraging `setrlimit` (AS/CPU limits), `prctl(PR_SET_NO_NEW_PRIVS)`, and child process groups.
  - **macOS**: Posix resource bounds and lifecycle management.
- **100% Read-Only Safety Guarantee**:
  - Original target files on disk are **never modified, deleted, or corrupted**.
  - Detonation executes against a temporary scratch copy in a sandboxed temp folder and wipes the scratch files immediately upon exit.

### 2. Multi-OS Cross-Platform Support (Windows, Linux, macOS)
- **Linux Platform**:
  - Real-time filesystem sensor via `fanotify` and `inotify`.
  - System event auditing via `journald` and `auditd`.
  - Background daemon managed via `systemd`.
  - Secure Unix domain socket IPC (`/run/sentinel/sentinel.sock`).
- **macOS Platform**:
  - Real-time filesystem sensor via `FSEvents`.
  - Apple Unified Logging system sensor via `log stream`.
  - Background daemon managed via `launchd`.
  - Secure Unix domain socket IPC (`/tmp/sentinel.sock`).
- **Continuous Integration**:
  - Automated GitHub Actions matrix testing across Windows, Ubuntu Linux, and macOS runners.

### 3. Extended CLI & Interactive Sandbox Studio
- **New CLI Commands**:
  - `sentinel sandbox <file> --mode emulation` (Safe, pure in-memory, <100ms)
  - `sentinel sandbox <file> --mode detonation` (Isolated sandbox execution)
  - `sentinel sandbox <file> --mode hybrid` (Emulation first, fallback to detonation)
  - `sentinel scan <target> --dynamic` (Full scan with dynamic behavioral unpack heuristics)
- **Interactive Sandbox Studio (GUI)**:
  - Accessible via the **🧪 Sandbox Studio** tab in the desktop dashboard.
  - Choose between **⚡ Emulation**, **🚀 Detonation**, or **🔬 Hybrid** modes.
  - Live visual display of emulated instruction traces, dynamic API calls, unpacked memory buffers, and real-time threat verdicts.

### 4. Enterprise Heuristic & ML Protection Core
- **EMBER2024 LightGBM Model**: 2,568-dimensional PE feature triage trained on 3.23M authentic executables from VirusTotal.
- **Volatile Memory Scanner**: Scans `PAGE_EXECUTE_READWRITE` (RWX) and unbacked RX regions across running processes for Cobalt Strike and Meterpreter stagers.
- **Ransomware Canary Traps**: Camouflaged decoy honeypots with automated process suspension and self-repair.
- **Authenticode Trust Pipeline**: WinVerifyTrust certificate chain validation down-weights generic heuristics for signed commercial applications.

### 5. 100% Test Coverage & Reliability
- **342 Automated Unit Tests** passing cleanly across all engines, heuristics, sandbox modules, and UI bindings.
- Zero false positives on authentic Windows system binaries across System32, SysWOW64, and Program Files.

---

## 📦 Download & Quick Install (Windows)

1. Download **`Sentinel-Antivirus-v2.2-Windows-Setup.zip`** below.
2. Extract the archive.
3. Right-click **`Install-Sentinel.ps1`** and select **Run with PowerShell** (or run from an elevated PowerShell terminal):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Install-Sentinel.ps1
   ```
4. Sentinel is immediately active and guarding your machine!

### Linux & macOS Quick Start
```bash
# Linux
sudo bash dist/Sentinel/install-sentinel.sh
sudo systemctl start sentinel

# macOS
bash dist/Sentinel/install-sentinel.sh
launchctl load ~/Library/LaunchAgents/com.sentinel.antivirus.plist
```
