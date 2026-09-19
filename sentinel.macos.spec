# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller Multi-Binary Specification for Sentinel Antivirus — macOS Build.

Builds 3 native Mach-O executables sharing a unified dependency bundle:
  1. sentinel_service  : Background daemon (runs via launchd)
  2. sentinel_gui      : Full desktop GUI management dashboard (Tk)
  3. sentinel_cli      : Administrative command-line scanning & control utility
"""

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

PROJECT_ROOT = Path.cwd()

# Core hidden imports — macOS build (no win32 modules)
hidden_imports = [
    "lightgbm",
    "pyarrow",
    "pyarrow.parquet",
    "pyarrow.compute",
    "sklearn",
    "sklearn.ensemble",
    "sklearn.ensemble._isolation_forest",
    "sklearn.tree",
    "sklearn.feature_extraction",
    "sklearn.feature_extraction._hashing_fast",
    "yara",
    "pefile",
    "pystray",
    "pystray._darwin",
    "PIL",
    "PIL.Image",
    "watchdog",
    "watchdog.observers",
    "watchdog.observers.fsevents",
    "sentinel",
    "sentinel.engine",
    "sentinel.engine.static_classifier",
    "sentinel.engine.ember_extractor",
    "sentinel.engine.canary",
    "sentinel.engine.scoring",
    "sentinel.engine.scanner",
    "sentinel.engine.consumer",
    "sentinel.platform",
    "sentinel.platform.ipc",
    "sentinel.platform.signature",
    "sentinel.platform.service_runner",
    "sentinel.sensors.fsevents_sensor",
    "sentinel.sensors.macos_log_sensor",
    "sentinel.service",
    "sentinel.response.notifier",
    "sentinel.response.quarantine_store",
    "sentinel.ui.dashboard",
    "sentinel.ui.tray_app",
    "sentinel.sandbox",
    "sentinel.sandbox.emulator",
    "sentinel.sandbox.isolation",
    "sentinel.sandbox.runner",
]

# Bundled data assets
datas = [
    ("sentinel/data/pe_model_ember.model", "sentinel/data"),
    ("sentinel/data/pe_model_v2.joblib", "sentinel/data"),
    ("sentinel/data/large_scale_model_metrics.json", "sentinel/data"),
    ("sentinel/config/rules/*.yar", "sentinel/config/rules"),
]

# Filter datas — only include files that exist
datas = [(src, dst) for src, dst in datas if any(Path(PROJECT_ROOT).glob(src))]

# Native Rust acceleration shared library (if compiled)
native_lib = PROJECT_ROOT / "sentinel" / "engine" / "libsentinel_core.dylib"
binaries = [(str(native_lib), "sentinel/engine")] if native_lib.exists() else []

# 1. Service/Daemon
a_service = Analysis(
    ["sentinel/service.py"],
    pathex=[str(PROJECT_ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["win32api", "win32com", "win32service", "win32serviceutil",
              "win32event", "win32pipe", "win32file", "win32security",
              "pywintypes", "win32timezone", "pystray._win32",
              "plyer.platforms.win"],
    noarchive=False,
)
pyz_service = PYZ(a_service.pure, a_service.zipped_data)
exe_service = EXE(
    pyz_service,
    a_service.scripts,
    [],
    exclude_binaries=True,
    name="sentinel_service",
    debug=False,
    strip=True,
    upx=False,
    console=True,
)

# 2. GUI Dashboard
a_gui = Analysis(
    ["sentinel/ui/dashboard.py"],
    pathex=[str(PROJECT_ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["win32api", "win32com", "win32service", "win32serviceutil",
              "win32event", "win32pipe", "win32file", "win32security",
              "pywintypes", "win32timezone"],
    noarchive=False,
)
pyz_gui = PYZ(a_gui.pure, a_gui.zipped_data)
exe_gui = EXE(
    pyz_gui,
    a_gui.scripts,
    [],
    exclude_binaries=True,
    name="sentinel_gui",
    debug=False,
    strip=True,
    upx=False,
    console=False,
)

# 3. CLI Entry Point
a_cli = Analysis(
    ["sentinel/cli_entry.py"],
    pathex=[str(PROJECT_ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["win32api", "win32com", "win32service", "win32serviceutil",
              "win32event", "win32pipe", "win32file", "win32security",
              "pywintypes", "win32timezone"],
    noarchive=False,
)
pyz_cli = PYZ(a_cli.pure, a_cli.zipped_data)
exe_cli = EXE(
    pyz_cli,
    a_cli.scripts,
    [],
    exclude_binaries=True,
    name="sentinel_cli",
    debug=False,
    strip=True,
    upx=False,
    console=True,
)

# Unified collection into dist/Sentinel
coll = COLLECT(
    exe_service, a_service.binaries, a_service.zipfiles, a_service.datas,
    exe_gui, a_gui.binaries, a_gui.zipfiles, a_gui.datas,
    exe_cli, a_cli.binaries, a_cli.zipfiles, a_cli.datas,
    strip=True,
    upx=False,
    upx_exclude=[],
    name="Sentinel",
)
