"""Notifier — calm, clear Windows toast notifications for Sentinel alerts.

Implements phases.md Phase 3:
    notifier.py: calm, clear toast notification with what/why

Design (NFR-1 driven — "notifications worded clearly and calmly rather than
alarmingly"):

- Windows Toast notifications via the ``winrt`` library (Windows Runtime API —
  the modern notification mechanism, same one Windows Defender uses).
- Fallback to ``win32gui`` balloon tip / system tray message when winrt is
  unavailable or the Windows Runtime is not reachable (e.g. running as a
  service without a user session).
- Never alarmist language: "Sentinel suspended {process} — {reason}" rather
  than "DANGER" or "CRITICAL THREAT".
- Clicking the notification opens the tray UI for review (if installed).

Notification types:
    alert: A detection triggered and the process was suspended/quarantined.
    info: A non-critical status update (watchdog restarted, service started).
    resolved: A quarantined item was restored or deleted by the user.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Notification:
    """A structured notification that the notifier will display."""

    title: str
    body: str
    notification_type: str = "alert"  # "alert" | "info" | "resolved"
    quarantine_id: str | None = None
    pid: int | None = None
    process_name: str | None = None
    extra: dict[str, Any] | None = None


class Notifier:
    """Sends Windows toast/balloon notifications for Sentinel events.

    Uses winrt (Windows Runtime) for modern Toast notifications when available,
    falling back to win32gui balloon tips. All notifications use calm, clear
    language per NFR-1.

    The notifier is designed to degrade gracefully: if neither notification
    mechanism works (e.g. running in a headless service context with no user
    session), notifications are silently logged instead.
    """

    def __init__(self, app_name: str = "Sentinel") -> None:
        self.app_name = app_name
        self._toast_available = _check_toast_available()

    def notify_alert(
        self,
        process_name: str | None,
        reason: str,
        pid: int | None = None,
        quarantine_id: str | None = None,
        score: float | None = None,
    ) -> None:
        """Send a calm, clear alert notification.

        Format: "Sentinel suspended {process} — {reason}"
        No alarmist language (NFR-1).
        """
        proc = process_name or f"pid {pid}" if pid else "a process"
        title = f"Sentinel — Alert"
        body = (
            f"Suspended {proc}"
            f"{f' (score: {score:.0f})' if score is not None else ''}"
            f"\n{reason}"
        )
        self._send(Notification(
            title=title, body=body, notification_type="alert",
            quarantine_id=quarantine_id, pid=pid, process_name=process_name,
        ))

    def notify_info(self, message: str) -> None:
        """Send a non-critical info notification."""
        self._send(Notification(
            title=f"Sentinel — Info",
            body=message,
            notification_type="info",
        ))

    def notify_resolved(
        self,
        process_name: str | None,
        action: str,  # "restored" or "deleted"
        quarantine_id: str | None = None,
    ) -> None:
        """Notify that a quarantined item was resolved (restored or deleted)."""
        proc = process_name or "item"
        title = "Sentinel — Resolved"
        body = f"{proc.capitalize()} {action} successfully."
        self._send(Notification(
            title=title, body=body, notification_type="resolved",
            quarantine_id=quarantine_id, process_name=process_name,
        ))

    def _send(self, notification: Notification) -> bool:
        """Send a notification via the best available channel.

        Returns True if delivered, False if all channels failed.
        """
        sent = False

        if self._toast_available:
            sent = _send_toast(notification, self.app_name)

        if not sent:
            sent = _send_balloon(notification, self.app_name)

        if sent:
            logger.debug(
                "notification sent: type=%s title=%s",
                notification.notification_type, notification.title,
            )
        else:
            logger.info(
                "notification (no UI channel): type=%s title=%s body=%s",
                notification.notification_type,
                notification.title,
                notification.body,
            )
        return sent


# ---------------------------------------------------------------------------
# Toast notification via winrt
# ---------------------------------------------------------------------------

def _check_toast_available() -> bool:
    """Check if the Windows Runtime toast API is available."""
    try:
        import winrt.windows.ui.notifications as notifications  # noqa: F401
        return True
    except Exception:
        return False


def _send_toast(notification: Notification, app_name: str) -> bool:
    """Send via Windows Toast using winrt. Returns True if delivered."""
    try:
        import winrt.windows.ui.notifications as notifications
        import winrt.windows.data.xml.dom as dom
    except Exception:
        return False

    try:
        # Build the toast XML template.
        template = notifications.ToastTemplateType.toast_text02
        toast_xml = notifications.ToastNotificationManager.get_template_content(
            template
        )
        text_nodes = toast_xml.get_elements_by_tag_name("text")
        text_nodes.item(0).append_child(
            toast_xml.create_text_node(notification.title)
        )
        text_nodes.item(1).append_child(
            toast_xml.create_text_node(notification.body)
        )

        # Add a silent audio option (no loud alert sound — calm by design).
        toast_node = toast_xml.select_single_node("/toast")
        if toast_node:
            audio_el = toast_xml.create_element("audio")
            audio_el.set_attribute("silent", "true")
            toast_node.append_child(audio_el)

        toast = notifications.ToastNotification(toast_xml)

        # Show it.
        notifications.ToastNotificationManager.create_toast_notifier(
            app_name
        ).show(toast)
        return True
    except Exception as exc:
        logger.debug("toast failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Balloon fallback via win32gui
# ---------------------------------------------------------------------------

def _send_balloon(notification: Notification, app_name: str) -> bool:
    """Send via win32gui balloon tip. Returns True if delivered."""
    try:
        import win32gui
        import win32api
    except Exception:
        return False

    try:
        # Register a window class for the notification.
        wc = win32gui.WNDCLASS()
        wc.lpfnWndProc = _balloon_wndproc
        wc.lpszClassName = "SentinelNotifier"
        class_atom = win32gui.RegisterClass(wc)
        hwnd = win32gui.CreateWindow(
            class_atom, "SentinelNotifier", 0,
            0, 0, 0, 0, 0, 0, 0, None,
        )
        if not hwnd:
            return False

        # Shell_NotifyIcon data.
        import struct
        import win32con

        # We use a simple approach: create a temporary system tray icon
        # with a balloon tooltip.
        flags = win32con.NIF_INFO | win32con.NIF_TIP
        tip_text = notification.body[:128]
        info_text = notification.body[:256]

        # NIIF_INFO = 1, NIIF_NONE = 0
        icon_info = (
            hwnd,
            0,                         # uid
            flags,
            0,                         # callback msg
            0,                         # hicon
            tip_text,                  # tip
            notification.title,        # info title
            info_text,                 # info text
            1,                         # timeout (in seconds for balloon)
            notification.title,        # balloon title
            0,                         # version
        )

        from win32gui import Shell_NotifyIcon
        Shell_NotifyIcon(0x00000000, icon_info)  # NIM_ADD
        Shell_NotifyIcon(0x00000001, icon_info)  # NIM_MODIFY
        # Clean up the temp icon.
        Shell_NotifyIcon(0x00000002, icon_info)  # NIM_DELETE

        win32gui.DestroyWindow(hwnd)
        return True
    except Exception as exc:
        logger.debug("balloon notification failed: %s", exc)
        return False


def _balloon_wndproc(hwnd, msg, wparam, lparam):
    """Minimal window procedure for the balloon notification window."""
    try:
        import win32con
        if msg == win32con.WM_DESTROY:
            # Post quit to break message loop if one existed.
            pass
    except Exception:
        pass
    return 0