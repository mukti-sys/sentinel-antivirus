# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller Multi-Binary Specification for Sentinel Antivirus.

Builds 4 native executables sharing a unified C-runtime / dependency bundle:
  1. sentinel_service.exe : Headless background security service (NT AUTHORITY\SYSTEM)
  2. sentinel_tray.exe    : Lightweight system tray companion with live shield & toast alerts
  3. sentinel_gui.exe     : Full desktop GUI management dashboard
  4. sentinel_cli.exe     : Administrative command-line scanning & control utility
"""

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

PROJECT_ROOT = Path.cwd()

# Core hidden imports required by dynamic loaders & C-extensions
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
    "win32timezone",
    "win32service",
    "win32serviceutil",
    "win32event",
    "win32pipe",
    "win32file",
    "win32process",
    "win32security",
    "pystray",
    "pystray._win32",
    "PIL",
    "PIL.Image",
    "plyer",
    "plyer.platforms.win.notification",
    "watchdog",
    "watchdog.observers",
    "watchdog.observers.winapi",
    "signify",
    "signify.authenticode",
    "signify.authenticode.signed_file",
    "sentinel",
    "sentinel.engine",
    "sentinel.engine.static_classifier",
    "sentinel.engine.ember_extractor",
    "sentinel.engine.harvest_system_pes",
    "sentinel.engine.canary",
    "sentinel.engine.authenticode",
    "sentinel.engine.scoring",
    "sentinel.engine.scanner",
    "sentinel.engine.consumer",
    "sentinel.ipc",
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
    ("sentinel/data/system_pe_benchmark.json", "sentinel/data"),
    ("sentinel/config/rules/*.yar", "sentinel/config/rules"),
]

# 1. Service Analysis & Executable
a_service = Analysis(
    ["sentinel/service.py"],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
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
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,  # Service runs as console subsystem
    disable_windowed_traceback=False,
)

# 2. Tray App Analysis & Executable (noconsole=True)
a_tray = Analysis(
    ["sentinel/ui/tray_app.py"],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz_tray = PYZ(a_tray.pure, a_tray.zipped_data)
exe_tray = EXE(
    pyz_tray,
    a_tray.scripts,
    [],
    exclude_binaries=True,
    name="sentinel_tray",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # No black terminal window for tray app
    disable_windowed_traceback=False,
)

# 3. GUI Dashboard Analysis & Executable (noconsole=True)
a_gui = Analysis(
    ["sentinel/ui/dashboard.py"],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
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
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # Clean windowed GUI application
    disable_windowed_traceback=False,
)

# 4. CLI Entry Point Executable
a_cli = Analysis(
    ["sentinel/cli_entry.py"],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
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
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,  # Command-line utility
    disable_windowed_traceback=False,
)

# Unified collection into dist/Sentinel
coll = COLLECT(
    exe_service, a_service.binaries, a_service.zipfiles, a_service.datas,
    exe_tray, a_tray.binaries, a_tray.zipfiles, a_tray.datas,
    exe_gui, a_gui.binaries, a_gui.zipfiles, a_gui.datas,
    exe_cli, a_cli.binaries, a_cli.zipfiles, a_cli.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Sentinel",
)
