"""Windows Explorer context menu integration for Sentinel Antivirus.

Allows users to right-click any file or directory in Windows Explorer and select:
    "Scan with Sentinel Antivirus"

Registers in HKEY_CURRENT_USER (HKCU) so no Administrator elevation is required.
"""
from __future__ import annotations

import logging
import os
import sys
import winreg
from pathlib import Path

logger = logging.getLogger("sentinel.context_menu")

MENU_TEXT = "Scan with Sentinel Antivirus"
REG_SUBKEY_FILE = r"Software\Classes\*\shell\SentinelScan"
REG_SUBKEY_DIR = r"Software\Classes\Directory\shell\SentinelScan"


def _get_python_command(target_placeholder: str = '"%1"') -> str:
    """Build the command line to execute Sentinel scanner GUI for a target."""
    py_exe = sys.executable
    # Use pythonw if available for windowed GUI launch without console flash
    pyw_exe = Path(py_exe).parent / "pythonw.exe"
    launcher = str(pyw_exe) if pyw_exe.exists() else py_exe

    # If packaged as a standalone binary in the future
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --scan {target_placeholder}'

    return f'"{launcher}" -m sentinel.ui.dashboard --scan {target_placeholder}'


def is_context_menu_installed() -> bool:
    """Check if the context menu entries exist in HKCU."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_SUBKEY_FILE, 0, winreg.KEY_READ):
            return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        logger.debug("Error checking context menu registry: %s", exc)
        return False


def install_context_menu() -> bool:
    """Install 'Scan with Sentinel Antivirus' to Explorer right-click menu."""
    cmd_str = _get_python_command('"%1"')
    ico_path = str(Path(__file__).parent / "shield.ico")

    for subkey_path in [REG_SUBKEY_FILE, REG_SUBKEY_DIR]:
        try:
            # Create shell\SentinelScan
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, subkey_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, MENU_TEXT)
                if Path(ico_path).exists():
                    winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, ico_path)

            # Create shell\SentinelScan\command
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"{subkey_path}\\command") as cmd_key:
                winreg.SetValueEx(cmd_key, "", 0, winreg.REG_SZ, cmd_str)

            logger.info("Context menu installed for: %s", subkey_path)
        except OSError as exc:
            logger.error("Failed to install context menu for %s: %s", subkey_path, exc)
            return False

    return True


def uninstall_context_menu() -> bool:
    """Remove 'Scan with Sentinel Antivirus' from Explorer right-click menu."""
    def _delete_key_tree(root, subkey):
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                while True:
                    try:
                        child = winreg.EnumKey(key, 0)
                        _delete_key_tree(key, child)
                    except OSError:
                        break
            winreg.DeleteKey(root, subkey)
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.debug("Error deleting registry key %s: %s", subkey, exc)

    for subkey_path in [REG_SUBKEY_FILE, REG_SUBKEY_DIR]:
        try:
            _delete_key_tree(winreg.HKEY_CURRENT_USER, subkey_path)
            logger.info("Context menu uninstalled for: %s", subkey_path)
        except Exception as exc:
            logger.error("Failed to uninstall context menu for %s: %s", subkey_path, exc)
            return False

    return True


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Sentinel Windows Explorer Context Menu Manager")
    parser.add_argument("--install", action="store_true", help="Install right-click scan menu")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall right-click scan menu")
    parser.add_argument("--status", action="store_true", help="Check if menu is installed")

    args = parser.parse_args()
    if args.install:
        ok = install_context_menu()
        print("Installed:" if ok else "Failed to install")
        sys.exit(0 if ok else 1)
    elif args.uninstall:
        ok = uninstall_context_menu()
        print("Uninstalled:" if ok else "Failed to uninstall")
        sys.exit(0 if ok else 1)
    else:
        installed = is_context_menu_installed()
        print(f"Context menu installed: {installed}")
