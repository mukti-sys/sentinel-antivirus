"""System tray app -- confirm delete / restore, feeds decision back as
training data.

Implements phases.md Phase 3:
    tray_app.py: confirm delete / restore, feeds decision back as training data

And architecture.md Section 5.6:
    System tray app: live status, alert history, confirm/undo actions.
    Talks to the core service rather than running detection logic itself.

Design:
- Uses ``pystray`` for the system tray icon (lightweight, pure-Python).
- Menu: "Status", "Quarantine (N pending)", "Exit"
- Quarantine submenu: lists pending items, each with "Restore" / "Delete".
- Talks to QuarantineStore directly (same-process for v1).
- User decisions feed back via quarantine_store.restore() / .delete() with
  notes, closing the feedback loop per phases.md Cross-Phase.
- Notifier is used for calm confirmations when the user restores/deletes.

Requirements:
    pip install pystray Pillow
"""
from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Lazy-import pystray so the module can be imported even if pystray isn't
# installed (e.g. in test environments).
_pystray = None
_PIL_Image = None


def _ensure_deps() -> bool:
    """Lazy-load pystray and Pillow. Returns True if available."""
    global _pystray, _PIL_Image
    if _pystray is not None:
        return True
    try:
        import pystray
        from PIL import Image
        _pystray = pystray
        _PIL_Image = Image
        return True
    except ImportError:
        logger.warning(
            "tray_app requires pystray and Pillow: pip install pystray Pillow"
        )
        return False


def _create_icon_image():
    """Create a simple shield icon for the system tray (16x16 green shield)."""
    img = _PIL_Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    # Draw a simple filled shield shape.
    from PIL import ImageDraw
    draw = ImageDraw.Draw(img)
    # Shield outline.
    draw.polygon(
        [(32, 4), (58, 14), (54, 44), (32, 58), (10, 44), (6, 14)],
        fill=(46, 125, 50, 255),   # green
        outline=(27, 94, 32, 255),
    )
    # Inner highlight.
    draw.polygon(
        [(32, 12), (50, 20), (47, 40), (32, 50), (17, 40), (14, 20)],
        fill=(76, 175, 80, 255),
    )
    return img


class TrayApp:
    """System tray application for Sentinel.

    Provides a tray icon with menu items for:
    - Viewing status (running/idle)
    - Managing quarantined items (restore / delete)
    - Exiting the tray app (does NOT stop the core service)
    """

    def __init__(
        self,
        quarantine_store=None,
        notifier=None,
    ) -> None:
        self._store = quarantine_store
        self._notifier = notifier
        self._icon = None
        self._running = False

    def start(self) -> None:
        """Start the tray app (blocking — call from main thread or a
        dedicated thread)."""
        if not _ensure_deps():
            logger.error("Cannot start tray app: missing pystray/Pillow")
            return

        self._running = True
        menu = self._build_menu()
        self._icon = _pystray.Icon(
            name="Sentinel",
            icon=_create_icon_image(),
            title="Sentinel -- Active",
            menu=menu,
        )
        logger.info("tray app started")
        self._icon.run(setup=self._on_setup)

    def stop(self) -> None:
        """Stop the tray app."""
        self._running = False
        if self._icon:
            self._icon.stop()
            logger.info("tray app stopped")

    def _on_setup(self, icon) -> None:
        icon.visible = True

    def _build_menu(self):
        """Build the tray menu dynamically."""
        MenuItem = _pystray.MenuItem
        Menu = _pystray.Menu

        items = [
            MenuItem("Open Sentinel Dashboard", self._on_open_dashboard, default=True),
            MenuItem("Run Quick Scan", self._on_quick_scan),
            Menu.SEPARATOR,
            MenuItem(
                self._quarantine_label(),
                self._quarantine_submenu(),
            ),
            Menu.SEPARATOR,
            MenuItem("Exit Tray", self._on_exit),
        ]
        return Menu(*items)

    def _quarantine_label(self) -> str:
        if self._store is None:
            return "Quarantine (no store)"
        count = self._store.count(decision="pending")
        return f"Quarantine ({count} pending)"

    def _quarantine_submenu(self):
        """Build submenu with pending quarantine items."""
        Menu = _pystray.Menu
        MenuItem = _pystray.MenuItem

        if self._store is None:
            return Menu(MenuItem("No store configured", None, enabled=False))

        pending = self._store.list_pending()
        if not pending:
            return Menu(MenuItem("No pending items", None, enabled=False))

        items = []
        for rec in pending[:10]:  # show at most 10
            name = Path(rec.original_path).name
            label = f"{name} (score: {rec.score:.0f})"
            items.append(MenuItem(
                label,
                Menu(
                    MenuItem(
                        "Restore (false positive)",
                        lambda _, r=rec: self._on_restore(r),
                    ),
                    MenuItem(
                        "Delete (confirm malware)",
                        lambda _, r=rec: self._on_delete(r),
                    ),
                ),
            ))

        if len(pending) > 10:
            items.append(MenuItem(
                f"... and {len(pending) - 10} more",
                None, enabled=False,
            ))
        return Menu(*items)

    def _on_restore(self, rec) -> None:
        """Handle user restore action."""
        result = self._store.restore(rec.id, notes="User restored via tray")
        if result:
            logger.info("restored %s via tray", rec.original_path)
            if self._notifier:
                self._notifier.notify_resolved(
                    process_name=Path(rec.original_path).name,
                    action="restored",
                    quarantine_id=rec.id,
                )
        else:
            logger.error("restore failed for %s", rec.id)
        self._refresh_menu()

    def _on_delete(self, rec) -> None:
        """Handle user delete action."""
        ok = self._store.delete(rec.id, notes="User confirmed delete via tray")
        if ok:
            logger.info("deleted %s via tray", rec.original_path)
            if self._notifier:
                self._notifier.notify_resolved(
                    process_name=Path(rec.original_path).name,
                    action="deleted",
                    quarantine_id=rec.id,
                )
        else:
            logger.error("delete failed for %s", rec.id)
        self._refresh_menu()

    def _on_open_dashboard(self, icon=None, item=None) -> None:
        """Launch the full Sentinel GUI Dashboard."""
        import subprocess, sys
        py_exe = sys.executable
        pyw_exe = Path(py_exe).parent / "pythonw.exe"
        launcher = str(pyw_exe) if pyw_exe.exists() else py_exe
        try:
            subprocess.Popen([launcher, "-m", "sentinel.ui.dashboard"])
        except Exception as exc:
            logger.error("Failed to launch dashboard: %s", exc)

    def _on_quick_scan(self, icon=None, item=None) -> None:
        """Launch Sentinel GUI Dashboard for immediate scan."""
        import subprocess, sys
        py_exe = sys.executable
        pyw_exe = Path(py_exe).parent / "pythonw.exe"
        launcher = str(pyw_exe) if pyw_exe.exists() else py_exe
        try:
            subprocess.Popen([launcher, "-m", "sentinel.ui.dashboard"])
        except Exception as exc:
            logger.error("Failed to launch quick scan: %s", exc)

    def _on_exit(self, icon, item) -> None:
        """Exit the tray app (does NOT stop the core service)."""
        self.stop()

    def _refresh_menu(self) -> None:
        """Refresh the tray menu to reflect current quarantine state."""
        if self._icon:
            self._icon.menu = self._build_menu()
            self._icon.update_menu()


def main() -> int:
    """Run the tray app standalone (for development/testing)."""
    logging.basicConfig(level=logging.INFO)

    if not _ensure_deps():
        print("Error: pip install pystray Pillow")
        return 1

    # Try to connect to an existing quarantine store.
    from sentinel.response.quarantine_store import QuarantineStore
    from sentinel.response.notifier import Notifier

    store = QuarantineStore()
    notifier = Notifier()

    app = TrayApp(quarantine_store=store, notifier=notifier)
    print("Sentinel tray app running. Right-click the tray icon for options.")
    app.start()  # blocks until exit
    return 0


if __name__ == "__main__":
    sys.exit(main())
