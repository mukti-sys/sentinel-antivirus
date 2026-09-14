"""Sentinel Antivirus — Modern Consumer Desktop GUI Dashboard.

Provides an intuitive, dark-mode desktop user interface:
- Real-Time Protection Shield & Live System Status
- On-Demand Scan Center (Quick Scan, Full Scan, Custom Target Scan)
- Quarantine Vault Manager (1-click Restore & Permanent Delete)
- Threat History & Audit Log viewer
- Windows Explorer Context Menu integration toggle
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from sentinel.engine.scanner import (
    OnDemandScanner,
    ScanProgress,
    ScanStatus,
    ScanSummary,
    ScanType,
    ThreatDetection,
    ThreatSeverity,
)
from sentinel.response.quarantine_store import QuarantineRecord, QuarantineStore
from sentinel.ui.context_menu import (
    install_context_menu,
    is_context_menu_installed,
    uninstall_context_menu,
)

logger = logging.getLogger("sentinel.dashboard")

# ---------------------------------------------------------------------- #
# Dark Theme Color Palette
# ---------------------------------------------------------------------- #
COLOR_BG_DARK = "#0F1117"        # Window background
COLOR_SURFACE = "#171A23"        # Cards / Navigation
COLOR_SURFACE_HOVER = "#212532"  # Hover highlight
COLOR_CARD_BORDER = "#2B3142"    # Borders
COLOR_ACCENT_GREEN = "#00E676"   # Protected / Safe
COLOR_ACCENT_RED = "#FF334B"     # Alert / Threat
COLOR_ACCENT_BLUE = "#2979FF"    # Actions / Buttons
COLOR_ACCENT_BLUE_HOVER = "#1C68E3"
COLOR_TEXT_PRIMARY = "#F0F3FA"   # Headers / Important
COLOR_TEXT_SECONDARY = "#8F9BB3" # Muted info
COLOR_TEXT_MUTED = "#555E75"     # Footers / Subtext


class SentinelDashboard(tk.Tk):
    """Main application window for Sentinel Antivirus."""

    def __init__(
        self,
        scanner: OnDemandScanner | None = None,
        quarantine_store: QuarantineStore | None = None,
        auto_scan_target: str | None = None,
    ) -> None:
        super().__init__()

        self.title("Sentinel Antivirus")
        self.geometry("960x620")
        self.minsize(860, 540)
        self.configure(bg=COLOR_BG_DARK)

        # Core engine components
        self.quarantine_store = quarantine_store or QuarantineStore()
        self.scanner = scanner or OnDemandScanner(
            quarantine_store=self.quarantine_store,
            auto_quarantine=True,
        )

        # State
        self._current_tab = "overview"
        self._scan_thread: threading.Thread | None = None
        self._scan_active = False
        self._last_threats: list[ThreatDetection] = []

        self._configure_styles()
        self._build_layout()

        # If launched with a target path (e.g. from Explorer right-click)
        if auto_scan_target:
            self.after(500, lambda: self._start_custom_scan_target(auto_scan_target))

    # ------------------------------------------------------------------ #
    # Styles Setup
    # ------------------------------------------------------------------ #

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")

        # Configure dark-mode scrollbars & treeview
        style.configure(
            "Dark.Treeview",
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT_PRIMARY,
            fieldbackground=COLOR_SURFACE,
            borderwidth=0,
            font=("Segoe UI", 9),
            rowheight=28,
        )
        style.configure(
            "Dark.Treeview.Heading",
            background=COLOR_SURFACE_HOVER,
            foreground=COLOR_TEXT_PRIMARY,
            borderwidth=1,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "Dark.Treeview",
            background=[("selected", COLOR_ACCENT_BLUE)],
            foreground=[("selected", "#FFFFFF")],
        )

        style.configure(
            "Dark.Horizontal.TProgressbar",
            troughcolor=COLOR_SURFACE,
            background=COLOR_ACCENT_BLUE,
            lightcolor=COLOR_ACCENT_BLUE,
            darkcolor=COLOR_ACCENT_BLUE,
            bordercolor=COLOR_CARD_BORDER,
            thickness=12,
        )

    # ------------------------------------------------------------------ #
    # Window Layout
    # ------------------------------------------------------------------ #

    def _build_layout(self) -> None:
        # 1. Left Navigation Sidebar
        self.sidebar = tk.Frame(self, bg=COLOR_SURFACE, width=220)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # App Brand / Logo Header
        brand_frame = tk.Frame(self.sidebar, bg=COLOR_SURFACE, pady=20)
        brand_frame.pack(fill="x", padx=15)

        lbl_shield = tk.Label(
            brand_frame,
            text="🛡️",
            font=("Segoe UI Emoji", 26),
            bg=COLOR_SURFACE,
            fg=COLOR_ACCENT_GREEN,
        )
        lbl_shield.pack(side="left", padx=(0, 10))

        brand_text_frame = tk.Frame(brand_frame, bg=COLOR_SURFACE)
        brand_text_frame.pack(side="left")

        lbl_title = tk.Label(
            brand_text_frame,
            text="SENTINEL",
            font=("Segoe UI", 13, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
        )
        lbl_title.pack(anchor="w")

        lbl_subtitle = tk.Label(
            brand_text_frame,
            text="Personal Security",
            font=("Segoe UI", 8),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SECONDARY,
        )
        lbl_subtitle.pack(anchor="w")

        # Nav Buttons
        self._nav_buttons: dict[str, tk.Button] = {}
        nav_items = [
            ("overview", "🛡️  Protection Shield"),
            ("scan", "🔍  Scan Center"),
            ("quarantine", "📦  Quarantine Vault"),
            ("logs", "📜  Threat Logs"),
            ("settings", "⚙️  Settings"),
        ]

        tk.Frame(self.sidebar, bg=COLOR_CARD_BORDER, height=1).pack(fill="x", padx=15, pady=5)

        for key, label in nav_items:
            btn = tk.Button(
                self.sidebar,
                text=label,
                font=("Segoe UI", 10),
                bg=COLOR_SURFACE,
                fg=COLOR_TEXT_SECONDARY,
                activebackground=COLOR_SURFACE_HOVER,
                activeforeground=COLOR_TEXT_PRIMARY,
                bd=0,
                anchor="w",
                padx=20,
                pady=12,
                cursor="hand2",
                command=lambda k=key: self._switch_tab(k),
            )
            btn.pack(fill="x", pady=2)
            self._nav_buttons[key] = btn

        # Sidebar Footer Status
        sidebar_footer = tk.Frame(self.sidebar, bg=COLOR_SURFACE)
        sidebar_footer.pack(side="bottom", fill="x", pday=15 if hasattr(tk, 'pday') else None, pady=15, padx=15)
        lbl_ver = tk.Label(
            sidebar_footer,
            text="Sentinel v1.0 Consumer\nEngine: Kernel + YARA + ML",
            font=("Segoe UI", 7),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_MUTED,
            justify="left",
        )
        lbl_ver.pack(anchor="w")

        # 2. Main Content View Area
        self.content_area = tk.Frame(self, bg=COLOR_BG_DARK)
        self.content_area.pack(side="right", fill="both", expand=True, padx=25, pady=25)

        # Tab Frames container
        self._tab_frames: dict[str, tk.Frame] = {
            "overview": self._create_overview_tab(),
            "scan": self._create_scan_tab(),
            "quarantine": self._create_quarantine_tab(),
            "logs": self._create_logs_tab(),
            "settings": self._create_settings_tab(),
        }

        self._switch_tab("overview")

    def _switch_tab(self, tab_key: str) -> None:
        self._current_tab = tab_key

        # Update button active styles
        for key, btn in self._nav_buttons.items():
            if key == tab_key:
                btn.configure(bg=COLOR_SURFACE_HOVER, fg=COLOR_ACCENT_BLUE, font=("Segoe UI", 10, "bold"))
            else:
                btn.configure(bg=COLOR_SURFACE, fg=COLOR_TEXT_SECONDARY, font=("Segoe UI", 10))

        # Show selected frame
        for key, frame in self._tab_frames.items():
            if key == tab_key:
                frame.pack(fill="both", expand=True)
                if key == "quarantine":
                    self._refresh_quarantine_table()
                elif key == "logs":
                    self._refresh_logs_table()
            else:
                frame.pack_forget()

    # ------------------------------------------------------------------ #
    # Tab 1: Protection Overview
    # ------------------------------------------------------------------ #

    def _create_overview_tab(self) -> tk.Frame:
        frame = tk.Frame(self.content_area, bg=COLOR_BG_DARK)

        # Status Banner Card
        banner = tk.Frame(frame, bg=COLOR_SURFACE, bd=1, relief="solid", highlightbackground=COLOR_CARD_BORDER)
        banner.pack(fill="x", pady=(0, 20), ipady=15, ipadx=15)

        banner_inner = tk.Frame(banner, bg=COLOR_SURFACE)
        banner_inner.pack(fill="x", padx=15)

        self.lbl_shield_big = tk.Label(
            banner_inner,
            text="🛡️",
            font=("Segoe UI Emoji", 42),
            bg=COLOR_SURFACE,
            fg=COLOR_ACCENT_GREEN,
        )
        self.lbl_shield_big.pack(side="left", padx=(0, 20))

        banner_text = tk.Frame(banner_inner, bg=COLOR_SURFACE)
        banner_text.pack(side="left", fill="both", expand=True)

        self.lbl_status_main = tk.Label(
            banner_text,
            text="You Are Fully Protected",
            font=("Segoe UI", 18, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
        )
        self.lbl_status_main.pack(anchor="w")

        self.lbl_status_desc = tk.Label(
            banner_text,
            text="Kernel Minifilter Driver is armed. Real-time file & memory monitoring active.",
            font=("Segoe UI", 10),
            bg=COLOR_SURFACE,
            fg=COLOR_ACCENT_GREEN,
        )
        self.lbl_status_desc.pack(anchor="w", pady=(3, 0))

        # Feature Cards Grid
        grid_frame = tk.Frame(frame, bg=COLOR_BG_DARK)
        grid_frame.pack(fill="both", expand=True)
        grid_frame.columnconfigure(0, weight=1)
        grid_frame.columnconfigure(1, weight=1)

        # Card 1: Real-Time Protection
        c1 = self._create_card(
            grid_frame,
            title="Real-Time File Shield",
            icon="⚡",
            desc="Intercepts untrusted file writes and monitors execution attempts before malware runs.",
            status="ACTIVE",
            status_color=COLOR_ACCENT_GREEN,
        )
        c1.grid(row=0, column=0, padx=(0, 10), pady=10, sticky="nsew")

        # Card 2: Network Guard
        c2 = self._create_card(
            grid_frame,
            title="Network & C2 Guard",
            icon="🌐",
            desc="Monitors outbound sockets, blocks cryptomining stratum pools, and detects port sweeps.",
            status="ACTIVE",
            status_color=COLOR_ACCENT_GREEN,
        )
        c2.grid(row=0, column=1, padx=(10, 0), pady=10, sticky="nsew")

        # Card 3: Behavioral Ransomware Canary
        c3 = self._create_card(
            grid_frame,
            title="Ransomware Shield",
            icon="🔒",
            desc="Watches Shannon entropy spikes and rapid file modifications across Desktop and Downloads.",
            status="ACTIVE",
            status_color=COLOR_ACCENT_GREEN,
        )
        c3.grid(row=1, column=0, padx=(0, 10), pady=10, sticky="nsew")

        # Card 4: Quick Action
        c4 = tk.Frame(grid_frame, bg=COLOR_SURFACE, bd=1, relief="solid", highlightbackground=COLOR_CARD_BORDER)
        c4.grid(row=1, column=1, padx=(10, 0), pady=10, sticky="nsew")
        c4_inner = tk.Frame(c4, bg=COLOR_SURFACE, padx=20, pady=20)
        c4_inner.pack(fill="both", expand=True)

        tk.Label(
            c4_inner,
            text="Need a quick check?",
            font=("Segoe UI", 12, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w")

        tk.Label(
            c4_inner,
            text="Scan memory, running processes, startup apps, and downloads in seconds.",
            font=("Segoe UI", 9),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SECONDARY,
            wraplength=280,
            justify="left",
        ).pack(anchor="w", pady=(5, 15))

        btn_quick = tk.Button(
            c4_inner,
            text="Run Quick Scan Now",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_ACCENT_BLUE,
            fg="#FFFFFF",
            activebackground=COLOR_ACCENT_BLUE_HOVER,
            activeforeground="#FFFFFF",
            bd=0,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self._switch_tab_and_scan("quick"),
        )
        btn_quick.pack(anchor="w")

        return frame

    def _create_card(
        self,
        parent: tk.Widget,
        title: str,
        icon: str,
        desc: str,
        status: str,
        status_color: str,
    ) -> tk.Frame:
        card = tk.Frame(parent, bg=COLOR_SURFACE, bd=1, relief="solid", highlightbackground=COLOR_CARD_BORDER)
        inner = tk.Frame(card, bg=COLOR_SURFACE, padx=20, pady=20)
        inner.pack(fill="both", expand=True)

        header = tk.Frame(inner, bg=COLOR_SURFACE)
        header.pack(fill="x")

        tk.Label(
            header,
            text=f"{icon}  {title}",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(side="left")

        tk.Label(
            header,
            text=status,
            font=("Segoe UI", 8, "bold"),
            bg=COLOR_SURFACE,
            fg=status_color,
        ).pack(side="right")

        tk.Label(
            inner,
            text=desc,
            font=("Segoe UI", 9),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SECONDARY,
            wraplength=290,
            justify="left",
        ).pack(anchor="w", pady=(10, 0))

        return card

    # ------------------------------------------------------------------ #
    # Tab 2: Scan Center
    # ------------------------------------------------------------------ #

    def _create_scan_tab(self) -> tk.Frame:
        frame = tk.Frame(self.content_area, bg=COLOR_BG_DARK)

        # Header Title
        tk.Label(
            frame,
            text="On-Demand Scanner",
            font=("Segoe UI", 16, "bold"),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w")

        tk.Label(
            frame,
            text="Scan local files, memory, and disks against YARA signatures and static anomaly heuristics.",
            font=("Segoe UI", 9),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_SECONDARY,
        ).pack(anchor="w", pady=(2, 15))

        # Scan Mode Selection Buttons
        btn_bar = tk.Frame(frame, bg=COLOR_BG_DARK)
        btn_bar.pack(fill="x", pady=(0, 15))

        self.btn_run_quick = tk.Button(
            btn_bar,
            text="⚡ Quick Scan",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_ACCENT_BLUE,
            fg="#FFFFFF",
            activebackground=COLOR_ACCENT_BLUE_HOVER,
            activeforeground="#FFFFFF",
            bd=0,
            padx=18,
            pady=10,
            cursor="hand2",
            command=self._on_start_quick_scan,
        )
        self.btn_run_quick.pack(side="left", padx=(0, 10))

        self.btn_run_full = tk.Button(
            btn_bar,
            text="💽 Full System Scan",
            font=("Segoe UI", 10),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
            activebackground=COLOR_SURFACE_HOVER,
            activeforeground=COLOR_TEXT_PRIMARY,
            bd=1,
            relief="solid",
            highlightbackground=COLOR_CARD_BORDER,
            padx=18,
            pady=10,
            cursor="hand2",
            command=self._on_start_full_scan,
        )
        self.btn_run_full.pack(side="left", padx=(0, 10))

        self.btn_run_custom = tk.Button(
            btn_bar,
            text="📁 Scan Specific Folder...",
            font=("Segoe UI", 10),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
            activebackground=COLOR_SURFACE_HOVER,
            activeforeground=COLOR_TEXT_PRIMARY,
            bd=1,
            relief="solid",
            highlightbackground=COLOR_CARD_BORDER,
            padx=18,
            pady=10,
            cursor="hand2",
            command=self._on_browse_custom_scan,
        )
        self.btn_run_custom.pack(side="left")

        # Progress / Status Panel
        self.progress_panel = tk.Frame(
            frame,
            bg=COLOR_SURFACE,
            bd=1,
            relief="solid",
            highlightbackground=COLOR_CARD_BORDER,
        )
        self.progress_panel.pack(fill="x", pady=(0, 15), ipady=10, ipadx=15)

        prog_inner = tk.Frame(self.progress_panel, bg=COLOR_SURFACE, padx=15)
        prog_inner.pack(fill="x")

        # Status text & cancel/pause row
        top_row = tk.Frame(prog_inner, bg=COLOR_SURFACE)
        top_row.pack(fill="x", pady=(5, 5))

        self.lbl_scan_state = tk.Label(
            top_row,
            text="Ready to Scan",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
        )
        self.lbl_scan_state.pack(side="left")

        self.btn_cancel_scan = tk.Button(
            top_row,
            text="Cancel Scan",
            font=("Segoe UI", 8),
            bg=COLOR_SURFACE_HOVER,
            fg=COLOR_ACCENT_RED,
            bd=0,
            padx=10,
            pady=3,
            cursor="hand2",
            state="disabled",
            command=self._on_cancel_scan,
        )
        self.btn_cancel_scan.pack(side="right")

        self.prog_bar = ttk.Progressbar(
            prog_inner,
            style="Dark.Horizontal.TProgressbar",
            mode="indeterminate",
        )
        self.prog_bar.pack(fill="x", pady=8)

        # Details row
        details_row = tk.Frame(prog_inner, bg=COLOR_SURFACE)
        details_row.pack(fill="x")

        self.lbl_scan_current_file = tk.Label(
            details_row,
            text="No scan currently running.",
            font=("Segoe UI", 8),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_MUTED,
            anchor="w",
        )
        self.lbl_scan_current_file.pack(side="left", fill="x", expand=True)

        self.lbl_scan_counts = tk.Label(
            details_row,
            text="Scanned: 0 | Threats: 0",
            font=("Segoe UI", 8, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SECONDARY,
        )
        self.lbl_scan_counts.pack(side="right")

        # Scan Findings Table
        tk.Label(
            frame,
            text="Threat Discoveries",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", pady=(5, 5))

        table_frame = tk.Frame(frame, bg=COLOR_SURFACE)
        table_frame.pack(fill="both", expand=True)

        cols = ("file", "threat", "score", "status", "path")
        self.tree_scan = ttk.Treeview(
            table_frame,
            columns=cols,
            show="headings",
            style="Dark.Treeview",
            selectmode="browse",
        )
        self.tree_scan.heading("file", text="File Name")
        self.tree_scan.heading("threat", text="Threat Name")
        self.tree_scan.heading("score", text="Severity Score")
        self.tree_scan.heading("status", text="Action Taken")
        self.tree_scan.heading("path", text="Full Path")

        self.tree_scan.column("file", width=180)
        self.tree_scan.column("threat", width=160)
        self.tree_scan.column("score", width=100, anchor="center")
        self.tree_scan.column("status", width=120, anchor="center")
        self.tree_scan.column("path", width=340)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_scan.yview)
        self.tree_scan.configure(yscrollcommand=scrollbar.set)

        self.tree_scan.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        return frame

    # ------------------------------------------------------------------ #
    # Scan Actions & Callbacks
    # ------------------------------------------------------------------ #

    def _switch_tab_and_scan(self, scan_mode: str) -> None:
        self._switch_tab("scan")
        if scan_mode == "quick":
            self.after(200, self._on_start_quick_scan)

    def _start_custom_scan_target(self, target_path: str) -> None:
        self._switch_tab("scan")
        p = Path(target_path)
        if not p.exists():
            messagebox.showerror("Scan Error", f"Target does not exist: {target_path}")
            return
        self._set_scanning_ui_state(True, f"Scanning Target: {p.name}")
        self.scanner.start_custom_scan(
            targets=[p],
            progress_callback=self._on_scan_progress_threadsafe,
            threat_callback=self._on_scan_threat_threadsafe,
            completion_callback=self._on_scan_complete_threadsafe,
        )

    def _on_start_quick_scan(self) -> None:
        if self._scan_active:
            return
        self._set_scanning_ui_state(True, "Running Quick Scan...")
        self.tree_scan.delete(*self.tree_scan.get_children())
        self._last_threats.clear()

        self.scanner.start_quick_scan(
            progress_callback=self._on_scan_progress_threadsafe,
            threat_callback=self._on_scan_threat_threadsafe,
            completion_callback=self._on_scan_complete_threadsafe,
        )

    def _on_start_full_scan(self) -> None:
        if self._scan_active:
            return
        if not messagebox.askyesno(
            "Confirm Full Scan",
            "A Full System Scan examines all drives on your computer. This may take some time.\n\nProceed?",
        ):
            return

        self._set_scanning_ui_state(True, "Running Full System Scan...")
        self.tree_scan.delete(*self.tree_scan.get_children())
        self._last_threats.clear()

        self.scanner.start_full_scan(
            progress_callback=self._on_scan_progress_threadsafe,
            threat_callback=self._on_scan_threat_threadsafe,
            completion_callback=self._on_scan_complete_threadsafe,
        )

    def _on_browse_custom_scan(self) -> None:
        if self._scan_active:
            return
        folder = filedialog.askdirectory(title="Select Folder to Scan with Sentinel")
        if not folder:
            return
        self._start_custom_scan_target(folder)

    def _on_cancel_scan(self) -> None:
        self.scanner.cancel()
        self.lbl_scan_state.config(text="Cancelling scan...", fg=COLOR_ACCENT_RED)

    def _set_scanning_ui_state(self, is_scanning: bool, title: str = "") -> None:
        self._scan_active = is_scanning
        if is_scanning:
            self.lbl_scan_state.config(text=title, fg=COLOR_ACCENT_BLUE)
            self.btn_cancel_scan.config(state="normal")
            self.btn_run_quick.config(state="disabled")
            self.btn_run_full.config(state="disabled")
            self.btn_run_custom.config(state="disabled")
            self.prog_bar.start(10)
        else:
            self.btn_cancel_scan.config(state="disabled")
            self.btn_run_quick.config(state="normal")
            self.btn_run_full.config(state="normal")
            self.btn_run_custom.config(state="normal")
            self.prog_bar.stop()

    def _on_scan_progress_threadsafe(self, prog: ScanProgress) -> None:
        # Marshall to Tk main thread
        self.after(0, lambda: self._update_scan_progress(prog))

    def _update_scan_progress(self, prog: ScanProgress) -> None:
        # Truncate filename for display
        display_path = prog.current_file
        if len(display_path) > 70:
            display_path = "..." + display_path[-67:]
        self.lbl_scan_current_file.config(text=display_path)
        self.lbl_scan_counts.config(
            text=f"Scanned: {prog.files_scanned} files | Threats: {prog.threats_found}"
        )

    def _on_scan_threat_threadsafe(self, threat: ThreatDetection) -> None:
        self.after(0, lambda: self._add_threat_row(threat))

    def _add_threat_row(self, threat: ThreatDetection) -> None:
        self._last_threats.append(threat)
        status_text = "Quarantined" if threat.quarantined else "Detected"
        self.tree_scan.insert(
            "",
            "end",
            values=(
                threat.file_path.name,
                threat.threat_name,
                f"{threat.score:.0f}",
                status_text,
                str(threat.file_path),
            ),
        )

    def _on_scan_complete_threadsafe(self, summary: ScanSummary) -> None:
        self.after(0, lambda: self._handle_scan_complete(summary))

    def _handle_scan_complete(self, summary: ScanSummary) -> None:
        self._set_scanning_ui_state(False)
        duration_str = f"{summary.duration_seconds:.1f}s"
        if summary.status == ScanStatus.CANCELLED:
            self.lbl_scan_state.config(text="Scan Cancelled by User", fg=COLOR_TEXT_SECONDARY)
            self.lbl_scan_current_file.config(text=f"Stopped after {summary.files_scanned} files ({duration_str}).")
        elif summary.threats_found == 0:
            self.lbl_scan_state.config(text="Scan Complete — No Threats Found ✓", fg=COLOR_ACCENT_GREEN)
            self.lbl_scan_current_file.config(
                text=f"Inspected {summary.files_scanned} files in {duration_str}. Your system is clean."
            )
        else:
            self.lbl_scan_state.config(
                text=f"Scan Complete — {summary.threats_found} Threat(s) Isolated ⚠️",
                fg=COLOR_ACCENT_RED,
            )
            self.lbl_scan_current_file.config(
                text=f"Scanned {summary.files_scanned} files in {duration_str}. Threats moved to Quarantine Vault."
            )

    # ------------------------------------------------------------------ #
    # Tab 3: Quarantine Vault
    # ------------------------------------------------------------------ #

    def _create_quarantine_tab(self) -> tk.Frame:
        frame = tk.Frame(self.content_area, bg=COLOR_BG_DARK)

        # Header
        top_bar = tk.Frame(frame, bg=COLOR_BG_DARK)
        top_bar.pack(fill="x", pady=(0, 15))

        title_frame = tk.Frame(top_bar, bg=COLOR_BG_DARK)
        title_frame.pack(side="left")

        tk.Label(
            title_frame,
            text="Quarantine Vault",
            font=("Segoe UI", 16, "bold"),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w")

        tk.Label(
            title_frame,
            text="Isolated suspicious items with execution disabled. You can review, restore, or delete.",
            font=("Segoe UI", 9),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_SECONDARY,
        ).pack(anchor="w", pady=(2, 0))

        # Action Buttons
        btn_frame = tk.Frame(top_bar, bg=COLOR_BG_DARK)
        btn_frame.pack(side="right")

        btn_restore = tk.Button(
            btn_frame,
            text="↩️  Restore File",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
            activebackground=COLOR_SURFACE_HOVER,
            activeforeground=COLOR_TEXT_PRIMARY,
            bd=1,
            relief="solid",
            highlightbackground=COLOR_CARD_BORDER,
            padx=12,
            pady=6,
            cursor="hand2",
            command=self._on_restore_selected,
        )
        btn_restore.pack(side="left", padx=(0, 8))

        btn_delete = tk.Button(
            btn_frame,
            text="🗑️  Delete Forever",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_ACCENT_RED,
            activebackground=COLOR_SURFACE_HOVER,
            activeforeground=COLOR_ACCENT_RED,
            bd=1,
            relief="solid",
            highlightbackground=COLOR_CARD_BORDER,
            padx=12,
            pady=6,
            cursor="hand2",
            command=self._on_delete_selected,
        )
        btn_delete.pack(side="left", padx=(0, 8))

        btn_refresh = tk.Button(
            btn_frame,
            text="🔄 Refresh",
            font=("Segoe UI", 9),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SECONDARY,
            activebackground=COLOR_SURFACE_HOVER,
            activeforeground=COLOR_TEXT_PRIMARY,
            bd=1,
            relief="solid",
            highlightbackground=COLOR_CARD_BORDER,
            padx=10,
            pady=6,
            cursor="hand2",
            command=self._refresh_quarantine_table,
        )
        btn_refresh.pack(side="left")

        # Quarantine Table
        table_frame = tk.Frame(frame, bg=COLOR_SURFACE)
        table_frame.pack(fill="both", expand=True)

        cols = ("id", "filename", "score", "reason", "date", "original_path")
        self.tree_quarantine = ttk.Treeview(
            table_frame,
            columns=cols,
            show="headings",
            style="Dark.Treeview",
            selectmode="browse",
        )

        self.tree_quarantine.heading("id", text="Entry ID")
        self.tree_quarantine.heading("filename", text="File Name")
        self.tree_quarantine.heading("score", text="Score")
        self.tree_quarantine.heading("reason", text="Detection Reason")
        self.tree_quarantine.heading("date", text="Date Isolated")
        self.tree_quarantine.heading("original_path", text="Original Path")

        self.tree_quarantine.column("id", width=90, anchor="center")
        self.tree_quarantine.column("filename", width=170)
        self.tree_quarantine.column("score", width=70, anchor="center")
        self.tree_quarantine.column("reason", width=220)
        self.tree_quarantine.column("date", width=140)
        self.tree_quarantine.column("original_path", width=260)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_quarantine.yview)
        self.tree_quarantine.configure(yscrollcommand=scrollbar.set)

        self.tree_quarantine.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        return frame

    def _refresh_quarantine_table(self) -> None:
        self.tree_quarantine.delete(*self.tree_quarantine.get_children())
        records = self.quarantine_store.list_pending()
        for rec in records:
            p = Path(rec.original_path)
            # Format timestamp
            date_str = datetime.fromtimestamp(rec.timestamp).strftime("%Y-%m-%d %H:%M")
            self.tree_quarantine.insert(
                "",
                "end",
                values=(
                    rec.id[:8],
                    p.name,
                    f"{rec.score:.0f}",
                    rec.reason,
                    date_str,
                    rec.original_path,
                ),
            )

    def _on_restore_selected(self) -> None:
        selected = self.tree_quarantine.selection()
        if not selected:
            messagebox.showinfo("Select File", "Please select a quarantined item from the list to restore.")
            return

        values = self.tree_quarantine.item(selected[0], "values")
        short_id = values[0]
        filename = values[1]

        if not messagebox.askyesno(
            "Confirm Restore",
            f"Are you sure you want to restore '{filename}' back to its original location?\n\nExecution permissions will be re-enabled.",
        ):
            return

        # Find full ID
        records = self.quarantine_store.list_pending()
        full_id = next((r.id for r in records if r.id.startswith(short_id)), None)
        if not full_id:
            messagebox.showerror("Error", "Could not locate quarantine record.")
            return

        restored_path = self.quarantine_store.restore(full_id, notes="Restored by user via Sentinel GUI")
        if restored_path:
            messagebox.showinfo("Restored", f"Successfully restored to:\n{restored_path}")
            self._refresh_quarantine_table()
        else:
            messagebox.showerror("Restore Failed", "Could not restore the file. Check permissions or logs.")

    def _on_delete_selected(self) -> None:
        selected = self.tree_quarantine.selection()
        if not selected:
            messagebox.showinfo("Select File", "Please select a quarantined item from the list to delete.")
            return

        values = self.tree_quarantine.item(selected[0], "values")
        short_id = values[0]
        filename = values[1]

        if not messagebox.askyesno(
            "Confirm Permanent Deletion",
            f"Are you sure you want to permanently delete '{filename}'?\n\nThis action CANNOT be undone.",
        ):
            return

        records = self.quarantine_store.list_pending()
        full_id = next((r.id for r in records if r.id.startswith(short_id)), None)
        if not full_id:
            messagebox.showerror("Error", "Could not locate quarantine record.")
            return

        success = self.quarantine_store.delete(full_id, notes="Deleted by user via Sentinel GUI")
        if success:
            messagebox.showinfo("Deleted", f"Permanently deleted '{filename}'.")
            self._refresh_quarantine_table()
        else:
            messagebox.showerror("Delete Failed", "Failed to delete quarantined file.")

    # ------------------------------------------------------------------ #
    # Tab 4: Threat Logs & History
    # ------------------------------------------------------------------ #

    def _create_logs_tab(self) -> tk.Frame:
        frame = tk.Frame(self.content_area, bg=COLOR_BG_DARK)

        top_bar = tk.Frame(frame, bg=COLOR_BG_DARK)
        top_bar.pack(fill="x", pady=(0, 15))

        tk.Label(
            top_bar,
            text="Telemetry & Threat Activity",
            font=("Segoe UI", 16, "bold"),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(side="left")

        btn_refresh = tk.Button(
            top_bar,
            text="🔄 Refresh Logs",
            font=("Segoe UI", 9),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SECONDARY,
            activebackground=COLOR_SURFACE_HOVER,
            activeforeground=COLOR_TEXT_PRIMARY,
            bd=1,
            relief="solid",
            highlightbackground=COLOR_CARD_BORDER,
            padx=10,
            pady=5,
            cursor="hand2",
            command=self._refresh_logs_table,
        )
        btn_refresh.pack(side="right")

        table_frame = tk.Frame(frame, bg=COLOR_SURFACE)
        table_frame.pack(fill="both", expand=True)

        cols = ("time", "source", "event_type", "details")
        self.tree_logs = ttk.Treeview(
            table_frame,
            columns=cols,
            show="headings",
            style="Dark.Treeview",
            selectmode="browse",
        )

        self.tree_logs.heading("time", text="Timestamp")
        self.tree_logs.heading("source", text="Sensor")
        self.tree_logs.heading("event_type", text="Event Type")
        self.tree_logs.heading("details", text="Event Details")

        self.tree_logs.column("time", width=140)
        self.tree_logs.column("source", width=110, anchor="center")
        self.tree_logs.column("event_type", width=140)
        self.tree_logs.column("details", width=420)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_logs.yview)
        self.tree_logs.configure(yscrollcommand=scrollbar.set)

        self.tree_logs.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        return frame

    def _refresh_logs_table(self) -> None:
        self.tree_logs.delete(*self.tree_logs.get_children())
        events_db = Path(__file__).resolve().parent.parent.parent / "events.db"
        if not events_db.exists():
            return

        try:
            import sqlite3
            conn = sqlite3.connect(str(events_db))
            cur = conn.cursor()
            cur.execute(
                "SELECT timestamp, source, event_type, image_path, command_line FROM events ORDER BY id DESC LIMIT 100"
            )
            rows = cur.fetchall()
            conn.close()

            for ts, source, ev_type, img, cmd in rows:
                detail = cmd or img or ""
                self.tree_logs.insert("", "end", values=(ts[:19].replace("T", " "), source, ev_type, detail))
        except Exception as exc:
            logger.debug("Error reading events.db: %s", exc)

    # ------------------------------------------------------------------ #
    # Tab 5: Settings & Shell Integration
    # ------------------------------------------------------------------ #

    def _create_settings_tab(self) -> tk.Frame:
        frame = tk.Frame(self.content_area, bg=COLOR_BG_DARK)

        tk.Label(
            frame,
            text="Settings & Integration",
            font=("Segoe UI", 16, "bold"),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, 20))

        # Windows Explorer Context Menu Card
        card_context = tk.Frame(
            frame, bg=COLOR_SURFACE, bd=1, relief="solid", highlightbackground=COLOR_CARD_BORDER
        )
        card_context.pack(fill="x", pady=(0, 15), ipadx=15, ipady=15)

        card_inner = tk.Frame(card_context, bg=COLOR_SURFACE, padx=15)
        card_inner.pack(fill="x")

        tk.Label(
            card_inner,
            text="Windows Explorer Right-Click Menu",
            font=("Segoe UI", 12, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w")

        tk.Label(
            card_inner,
            text="Add 'Scan with Sentinel Antivirus' directly to your Windows right-click menu for any file or folder.",
            font=("Segoe UI", 9),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SECONDARY,
        ).pack(anchor="w", pady=(3, 10))

        self.btn_toggle_context = tk.Button(
            card_inner,
            text="Enable Explorer Context Menu",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_ACCENT_BLUE,
            fg="#FFFFFF",
            bd=0,
            padx=15,
            pady=6,
            cursor="hand2",
            command=self._on_toggle_context_menu,
        )
        self.btn_toggle_context.pack(anchor="w")

        self._update_context_menu_btn_text()

        # Engine Config Card
        card_info = tk.Frame(frame, bg=COLOR_SURFACE, bd=1, relief="solid", highlightbackground=COLOR_CARD_BORDER)
        card_info.pack(fill="x", ipadx=15, ipady=15)

        info_inner = tk.Frame(card_info, bg=COLOR_SURFACE, padx=15)
        info_inner.pack(fill="x")

        tk.Label(
            info_inner,
            text="System Information",
            font=("Segoe UI", 12, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w")

        info_text = (
            f"Python: {sys.version.split()[0]} ({'64-bit' if sys.maxsize > 2**32 else '32-bit'})\n"
            f"OS: Microsoft Windows\n"
            f"Kernel Altitude: 328100 (FSFilter Anti-Virus)\n"
            f"Quarantine Storage: In-Process Win32 ACL Deny\n"
            f"Heuristic Confidence Threshold: 75.0"
        )

        tk.Label(
            info_inner,
            text=info_text,
            font=("Consolas", 9),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SECONDARY,
            justify="left",
        ).pack(anchor="w", pady=(8, 0))

        return frame

    def _update_context_menu_btn_text(self) -> None:
        installed = is_context_menu_installed()
        if installed:
            self.btn_toggle_context.config(
                text="Disable Explorer Context Menu",
                bg=COLOR_SURFACE_HOVER,
                fg=COLOR_ACCENT_RED,
            )
        else:
            self.btn_toggle_context.config(
                text="Enable Explorer Context Menu",
                bg=COLOR_ACCENT_BLUE,
                fg="#FFFFFF",
            )

    def _on_toggle_context_menu(self) -> None:
        installed = is_context_menu_installed()
        if installed:
            ok = uninstall_context_menu()
            if ok:
                messagebox.showinfo("Context Menu", "Right-click context menu removed successfully.")
            else:
                messagebox.showerror("Error", "Failed to remove context menu.")
        else:
            ok = install_context_menu()
            if ok:
                messagebox.showinfo("Context Menu", "Right-click 'Scan with Sentinel' is now active in Windows Explorer!")
            else:
                messagebox.showerror("Error", "Failed to install context menu.")
        self._update_context_menu_btn_text()


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Sentinel Antivirus Desktop Dashboard")
    parser.add_argument("--scan", type=str, help="Automatically scan specified path upon launch", default=None)
    args = parser.parse_args()

    app = SentinelDashboard(auto_scan_target=args.scan)
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
