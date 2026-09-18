"""Sentinel Platform Abstraction Layer.

Detects the current operating system and exports platform-appropriate
adapters for signature verification, IPC, service management, and
sensor selection.

Supported platforms:
    - windows (Win32 / Win64)
    - linux   (Ubuntu 22.04+, Debian 12+, Fedora 39+, RHEL 9+)
    - darwin  (macOS 13 Ventura+)
"""
from __future__ import annotations

import sys

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    PLATFORM = "windows"
elif sys.platform == "linux":
    PLATFORM = "linux"
elif sys.platform == "darwin":
    PLATFORM = "darwin"
else:
    PLATFORM = sys.platform  # fallback — best-effort

IS_WINDOWS = PLATFORM == "windows"
IS_LINUX = PLATFORM == "linux"
IS_MACOS = PLATFORM == "darwin"

# ---------------------------------------------------------------------------
# Platform-specific default paths
# ---------------------------------------------------------------------------
if IS_WINDOWS:
    DEFAULT_INSTALL_DIR = r"C:\Program Files\Sentinel Antivirus"
    DEFAULT_DATA_DIR = r"C:\ProgramData\Sentinel"
    DEFAULT_LOG_DIR = r"C:\ProgramData\Sentinel\logs"
elif IS_LINUX:
    DEFAULT_INSTALL_DIR = "/opt/sentinel"
    DEFAULT_DATA_DIR = "/var/lib/sentinel"
    DEFAULT_LOG_DIR = "/var/log/sentinel"
elif IS_MACOS:
    DEFAULT_INSTALL_DIR = "/usr/local/sentinel"
    DEFAULT_DATA_DIR = "/Library/Application Support/Sentinel"
    DEFAULT_LOG_DIR = "/Library/Logs/Sentinel"
else:
    DEFAULT_INSTALL_DIR = "/opt/sentinel"
    DEFAULT_DATA_DIR = "/var/lib/sentinel"
    DEFAULT_LOG_DIR = "/var/log/sentinel"


# ---------------------------------------------------------------------------
# Platform-specific high-risk scan directories
# ---------------------------------------------------------------------------
def get_default_watch_dirs() -> list[str]:
    """Return the default directories to monitor for real-time protection."""
    from pathlib import Path
    home = Path.home()

    if IS_WINDOWS:
        return [
            str(home / "Downloads"),
            str(home / "Desktop"),
            str(Path(r"C:\Windows\Temp")),
        ]
    elif IS_LINUX:
        dirs = [
            str(home / "Downloads"),
            str(home / "Desktop"),
            "/tmp",
        ]
        # Add XDG_DOWNLOAD_DIR if different
        try:
            import subprocess
            result = subprocess.run(
                ["xdg-user-dir", "DOWNLOAD"],
                capture_output=True, text=True, timeout=2,
            )
            xdg_dl = result.stdout.strip()
            if xdg_dl and xdg_dl not in dirs:
                dirs.append(xdg_dl)
        except Exception:
            pass
        return dirs
    elif IS_MACOS:
        return [
            str(home / "Downloads"),
            str(home / "Desktop"),
            "/tmp",
        ]
    return [str(home / "Downloads"), "/tmp"]


def get_executable_extensions() -> frozenset[str]:
    """Return the set of executable file extensions for the current platform."""
    common = {".py", ".sh", ".pl", ".rb"}

    if IS_WINDOWS:
        return frozenset({
            ".exe", ".dll", ".sys", ".scr", ".cpl", ".drv", ".ocx",
            ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
            ".wsf", ".wsh", ".hta", ".msi", ".msp", ".com", ".pif",
        } | common)
    elif IS_LINUX:
        return frozenset({
            ".so", ".ko", ".elf", ".bin", ".run", ".appimage",
            ".deb", ".rpm", ".snap", ".flatpak",
        } | common)
    elif IS_MACOS:
        return frozenset({
            ".app", ".dylib", ".kext", ".pkg", ".dmg", ".bundle",
        } | common)
    return frozenset(common)


def get_system_ignore_folders() -> frozenset[str]:
    """Return folder names to skip during recursive full-disk scans."""
    common = {".git", ".svn", "__pycache__", "node_modules", ".venv", "venv"}

    if IS_WINDOWS:
        return frozenset({
            "$recycle.bin", "system volume information",
            "$windows.~bt", "$windows.~ws", "$winreagent", "recovery",
        } | common)
    elif IS_LINUX:
        return frozenset({
            "proc", "sys", "dev", "run", "snap",
            "lost+found", ".Trash-1000",
        } | common)
    elif IS_MACOS:
        return frozenset({
            ".Spotlight-V100", ".fseventsd", ".Trashes",
            ".vol", "Volumes",
        } | common)
    return frozenset(common)
