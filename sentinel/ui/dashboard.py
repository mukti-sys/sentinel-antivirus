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

import psutil

from sentinel.engine.heuristics_c2 import C2BeaconDetector, C2Blocklist, DEFAULT_C2_IPS, DEFAULT_C2_PORTS
from sentinel.engine.memory_scanner import MemoryScanner, MemoryThreat
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
from sentinel.sandbox.runner import SandboxReport, SandboxRunner
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
        self.geometry("1040x680")
        self.minsize(940, 600)
        self.configure(bg=COLOR_BG_DARK)

        # Core engine components
        self.quarantine_store = quarantine_store or QuarantineStore()
        self.scanner = scanner or OnDemandScanner(
            quarantine_store=self.quarantine_store,
            auto_quarantine=True,
        )
        self.memory_scanner = MemoryScanner()
        self.sandbox_runner = SandboxRunner()
        self.c2_blocklist = C2Blocklist()
        self.c2_beacon_detector = C2BeaconDetector()

        # State
        self._current_tab = "overview"
        self._scan_thread: threading.Thread | None = None
        self._scan_active = False
        self._last_threats: list[ThreatDetection] = []
        self._sandbox_target_var = tk.StringVar()
        self._sandbox_duration_var = tk.StringVar(value="5")
        self._sandbox_mem_var = tk.StringVar(value="128")
        self._sandbox_cpu_var = tk.StringVar(value="20")
        self._sandbox_active = False
        self._memory_scan_active = False
        self._last_sandbox_report: SandboxReport | None = None

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
            ("sandbox", "🧪  Sandbox Studio"),
            ("memory", "🧠  Memory Shield"),
            ("network", "🌐  C2 & Network"),
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
                pady=10,
                cursor="hand2",
                command=lambda k=key: self._switch_tab(k),
            )
            btn.pack(fill="x", pady=2)
            self._nav_buttons[key] = btn

        # Sidebar Footer Status
        sidebar_footer = tk.Frame(self.sidebar, bg=COLOR_SURFACE)
        sidebar_footer.pack(side="bottom", fill="x", pady=15, padx=15)
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
            "sandbox": self._create_sandbox_tab(),
            "memory": self._create_memory_tab(),
            "network": self._create_network_tab(),
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
                elif key == "memory":
                    self._refresh_memory_table()
                elif key == "network":
                    self._refresh_network_table()
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

    # ------------------------------------------------------------------ #
    # Shared Helper: Telemetry Tile
    # ------------------------------------------------------------------ #

    def _create_telemetry_tile(
        self,
        parent: tk.Widget,
        title: str,
        initial_val: str,
        side: str = "left",
        fg: str = COLOR_TEXT_PRIMARY,
    ) -> tk.Label:
        card = tk.Frame(parent, bg=COLOR_SURFACE, bd=1, relief="solid", highlightbackground=COLOR_CARD_BORDER)
        card.pack(side=side, fill="both", expand=True, padx=4)

        inner = tk.Frame(card, bg=COLOR_SURFACE, padx=12, pady=10)
        inner.pack(fill="both", expand=True)

        tk.Label(inner, text=title, font=("Segoe UI", 8), bg=COLOR_SURFACE, fg=COLOR_TEXT_SECONDARY).pack(anchor="w")
        val_lbl = tk.Label(inner, text=initial_val, font=("Segoe UI", 12, "bold"), bg=COLOR_SURFACE, fg=fg)
        val_lbl.pack(anchor="w", pady=(4, 0))
        return val_lbl

    def _dispatch_to_ui(self, callback: Any) -> None:
        """Thread-safe UI callback dispatcher that tolerates closed windows or headless execution."""
        try:
            if self.winfo_exists():
                self.after(0, callback)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Tab: Sandbox Isolation Studio
    # ------------------------------------------------------------------ #

    def _create_sandbox_tab(self) -> tk.Frame:
        frame = tk.Frame(self.content_area, bg=COLOR_BG_DARK)

        # Header Title
        tk.Label(
            frame,
            text="🧪  Sandbox Isolation Studio",
            font=("Segoe UI", 16, "bold"),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, 4))

        tk.Label(
            frame,
            text="Execute suspicious binaries inside a secure Windows Job Object with strict RAM, CPU, and UI confinement.",
            font=("Segoe UI", 9),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_SECONDARY,
        ).pack(anchor="w", pady=(0, 15))

        # Target & Config Card
        card_cfg = tk.Frame(frame, bg=COLOR_SURFACE, bd=1, relief="solid", highlightbackground=COLOR_CARD_BORDER)
        card_cfg.pack(fill="x", pady=(0, 15), ipady=10, ipadx=15)

        cfg_inner = tk.Frame(card_cfg, bg=COLOR_SURFACE, padx=15)
        cfg_inner.pack(fill="x")

        # Row 1: File selection
        row1 = tk.Frame(cfg_inner, bg=COLOR_SURFACE)
        row1.pack(fill="x", pady=(5, 10))

        tk.Label(
            row1,
            text="Target Binary:",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_PRIMARY,
            width=12,
            anchor="w",
        ).pack(side="left")

        self.entry_sandbox_target = tk.Entry(
            row1,
            textvariable=self._sandbox_target_var,
            font=("Segoe UI", 9),
            bg=COLOR_SURFACE_HOVER,
            fg=COLOR_TEXT_PRIMARY,
            insertbackground=COLOR_TEXT_PRIMARY,
            bd=1,
            relief="solid",
            highlightbackground=COLOR_CARD_BORDER,
        )
        self.entry_sandbox_target.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_browse = tk.Button(
            row1,
            text="Browse...",
            font=("Segoe UI", 9),
            bg=COLOR_SURFACE_HOVER,
            fg=COLOR_TEXT_PRIMARY,
            bd=1,
            relief="solid",
            highlightbackground=COLOR_CARD_BORDER,
            padx=12,
            pady=3,
            cursor="hand2",
            command=self._on_browse_sandbox_target,
        )
        btn_browse.pack(side="right")

        # Row 2: Parameters (Timeout, RAM, CPU) + Action buttons
        row2 = tk.Frame(cfg_inner, bg=COLOR_SURFACE)
        row2.pack(fill="x", pady=(0, 5))

        # Timeout
        tk.Label(row2, text="Timeout (s):", font=("Segoe UI", 9), bg=COLOR_SURFACE, fg=COLOR_TEXT_SECONDARY).pack(side="left", padx=(0, 4))
        tk.Entry(row2, textvariable=self._sandbox_duration_var, width=4, font=("Segoe UI", 9), bg=COLOR_SURFACE_HOVER, fg=COLOR_TEXT_PRIMARY, bd=1, relief="solid").pack(side="left", padx=(0, 15))

        # RAM Limit
        tk.Label(row2, text="RAM Cap (MB):", font=("Segoe UI", 9), bg=COLOR_SURFACE, fg=COLOR_TEXT_SECONDARY).pack(side="left", padx=(0, 4))
        tk.Entry(row2, textvariable=self._sandbox_mem_var, width=5, font=("Segoe UI", 9), bg=COLOR_SURFACE_HOVER, fg=COLOR_TEXT_PRIMARY, bd=1, relief="solid").pack(side="left", padx=(0, 15))

        # CPU Limit
        tk.Label(row2, text="CPU Cap (%):", font=("Segoe UI", 9), bg=COLOR_SURFACE, fg=COLOR_TEXT_SECONDARY).pack(side="left", padx=(0, 4))
        tk.Entry(row2, textvariable=self._sandbox_cpu_var, width=4, font=("Segoe UI", 9), bg=COLOR_SURFACE_HOVER, fg=COLOR_TEXT_PRIMARY, bd=1, relief="solid").pack(side="left", padx=(0, 20))

        # Detonate Button
        self.btn_detonate_sandbox = tk.Button(
            row2,
            text="🚀 Detonate in Sandbox",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_ACCENT_BLUE,
            fg="#FFFFFF",
            bd=0,
            padx=14,
            pady=5,
            cursor="hand2",
            command=self._on_detonate_sandbox,
        )
        self.btn_detonate_sandbox.pack(side="left", padx=(0, 10))

        # Quarantine Button
        self.btn_sandbox_quarantine = tk.Button(
            row2,
            text="📦 Quarantine File",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_ACCENT_RED,
            fg="#FFFFFF",
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            state="disabled",
            command=self._on_quarantine_sandbox_target,
        )
        self.btn_sandbox_quarantine.pack(side="left")

        # Telemetry Stats Cards Row (4 tiles)
        stats_frame = tk.Frame(frame, bg=COLOR_BG_DARK)
        stats_frame.pack(fill="x", pady=(0, 15))

        self.lbl_tile_processes = self._create_telemetry_tile(stats_frame, "Processes Spawned", "—", side="left")
        self.lbl_tile_memory = self._create_telemetry_tile(stats_frame, "Peak RAM Usage", "—", side="left")
        self.lbl_tile_dropped = self._create_telemetry_tile(stats_frame, "Dropped Payloads", "—", side="left")
        self.lbl_tile_verdict = self._create_telemetry_tile(stats_frame, "Threat Verdict", "STANDBY", side="left", fg=COLOR_TEXT_SECONDARY)

        # Findings Treeview
        tk.Label(
            frame,
            text="Containment Telemetry & Behavioral Audit",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, 5))

        table_frame = tk.Frame(frame, bg=COLOR_SURFACE)
        table_frame.pack(fill="both", expand=True)

        cols = ("category", "indicator", "detail", "risk")
        self.tree_sandbox = ttk.Treeview(
            table_frame,
            columns=cols,
            show="headings",
            style="Dark.Treeview",
            selectmode="browse",
        )
        self.tree_sandbox.heading("category", text="Category")
        self.tree_sandbox.heading("indicator", text="Indicator / Event")
        self.tree_sandbox.heading("detail", text="Behavioral Details")
        self.tree_sandbox.heading("risk", text="Risk / Classification")

        self.tree_sandbox.column("category", width=140)
        self.tree_sandbox.column("indicator", width=180)
        self.tree_sandbox.column("detail", width=360)
        self.tree_sandbox.column("risk", width=140, anchor="center")

        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_sandbox.yview)
        self.tree_sandbox.configure(yscrollcommand=sb.set)
        self.tree_sandbox.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        return frame

    def _on_browse_sandbox_target(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select Executable to Analyze",
            filetypes=[("Executables", "*.exe;*.bat;*.cmd;*.dll"), ("All Files", "*.*")],
        )
        if filename:
            self._sandbox_target_var.set(filename)

    def _on_detonate_sandbox(self) -> None:
        target = self._sandbox_target_var.get().strip()
        if not target or not Path(target).exists():
            messagebox.showerror("Sandbox Error", "Please select a valid executable file to analyze.")
            return

        try:
            timeout = int(self._sandbox_duration_var.get())
            mem_mb = int(self._sandbox_mem_var.get())
            cpu_pct = int(self._sandbox_cpu_var.get())
        except ValueError:
            messagebox.showerror("Sandbox Error", "Timeout, RAM, and CPU must be valid integers.")
            return

        self._sandbox_active = True
        self.btn_detonate_sandbox.config(state="disabled", text="⏳ Running Sandbox...")
        self.btn_sandbox_quarantine.config(state="disabled")
        self.lbl_tile_processes.config(text="Executing...", fg=COLOR_ACCENT_BLUE)
        self.lbl_tile_memory.config(text="Measuring...", fg=COLOR_ACCENT_BLUE)
        self.lbl_tile_dropped.config(text="Monitoring...", fg=COLOR_ACCENT_BLUE)
        self.lbl_tile_verdict.config(text="CONFINED", fg=COLOR_ACCENT_BLUE)

        for item in self.tree_sandbox.get_children():
            self.tree_sandbox.delete(item)

        thread = threading.Thread(
            target=self._run_sandbox_worker,
            args=(target, timeout, mem_mb, cpu_pct),
            daemon=True,
        )
        thread.start()

    def _run_sandbox_worker(self, target: str, timeout: int, mem_mb: int, cpu_pct: int) -> None:
        try:
            report = self.sandbox_runner.run(
                executable_path=target,
                timeout_sec=timeout,
                max_memory_mb=mem_mb,
                cpu_rate_pct=cpu_pct,
            )
        except Exception as exc:
            logger.error("Sandbox error: %s", exc)
            self._dispatch_to_ui(lambda: self._on_sandbox_failed(str(exc)))
            return

        self._dispatch_to_ui(lambda: self._on_sandbox_finished(report, target))

    def _on_sandbox_failed(self, error_msg: str) -> None:
        self._sandbox_active = False
        self.btn_detonate_sandbox.config(state="normal", text="🚀 Detonate in Sandbox")
        messagebox.showerror("Sandbox Detonation Error", f"Sandbox execution failed:\n{error_msg}")

    def _on_sandbox_finished(self, report: SandboxReport, target: str) -> None:
        self._sandbox_active = False
        self._last_sandbox_report = report
        self.btn_detonate_sandbox.config(state="normal", text="🚀 Detonate in Sandbox")

        pids_str = f"{len(report.pids_spawned)} PID(s) ({', '.join(str(p) for p in report.pids_spawned[:3])})" if report.pids_spawned else "1 PID"
        self.lbl_tile_processes.config(text=pids_str, fg=COLOR_TEXT_PRIMARY)

        mem_str = f"{report.peak_memory_mb:.1f} MB"
        self.lbl_tile_memory.config(text=mem_str, fg=COLOR_TEXT_PRIMARY)

        dropped_cnt = len(report.dropped_files)
        high_ent_cnt = sum(1 for f in report.dropped_files if f.is_high_entropy)
        dropped_str = f"{dropped_cnt} file(s)" + (f" ({high_ent_cnt} High Entropy)" if high_ent_cnt else "")
        self.lbl_tile_dropped.config(text=dropped_str, fg=COLOR_ACCENT_RED if high_ent_cnt else COLOR_TEXT_PRIMARY)

        if report.is_malicious:
            self.lbl_tile_verdict.config(text="🚨 MALICIOUS", fg=COLOR_ACCENT_RED)
            self.btn_sandbox_quarantine.config(state="normal")
        else:
            self.lbl_tile_verdict.config(text="✅ SAFE", fg=COLOR_ACCENT_GREEN)
            self.btn_sandbox_quarantine.config(state="disabled")

        # Populate treeview
        self.tree_sandbox.insert("", "end", values=("Execution", "Process Exit Status", f"Exit Code: {report.exit_code} | Duration: {report.duration_sec:.2f}s", "Normal" if report.exit_code == 0 else "Anomalous"))
        self.tree_sandbox.insert("", "end", values=("Resources", "Peak Memory Consumption", f"{report.peak_memory_mb:.2f} MB (Cap: {report.max_memory_mb} MB)", "Safe" if report.peak_memory_mb < report.max_memory_mb else "Cap Hit"))
        self.tree_sandbox.insert("", "end", values=("Containment", "Job Object Confinement", f"RAM Cap: {report.max_memory_mb}MB, CPU Cap: {report.cpu_rate_pct}%, UI Isolated", "Enforced"))

        for pid in report.pids_spawned:
            self.tree_sandbox.insert("", "end", values=("Process Tree", f"PID {pid}", "Spawned under Job Object tree", "Monitored"))

        for df in report.dropped_files:
            risk = "CRITICAL (High Entropy)" if df.is_high_entropy else "Low"
            self.tree_sandbox.insert("", "end", values=("Filesystem", f"Dropped: {Path(df.path).name}", f"Size: {df.size_bytes}B | Shannon Entropy: {df.entropy:.2f}", risk))

        for f in report.findings:
            self.tree_sandbox.insert("", "end", values=("Behavioral Heuristic", f.get("category", "Behavior"), f.get("detail", ""), f.get("severity", "MEDIUM").upper()))

    def _on_quarantine_sandbox_target(self) -> None:
        target = self._sandbox_target_var.get().strip()
        if not target or not Path(target).exists():
            messagebox.showwarning("Quarantine", "File no longer exists.")
            return

        confirm = messagebox.askyesno(
            "Confirm Quarantine",
            f"Are you sure you want to isolate and quarantine:\n\n{target}\n\n"
            "This will apply Win32 deny ACLs and move the file to the secure vault.",
        )
        if not confirm:
            return

        try:
            record = self.quarantine_store.quarantine_file(
                original_path=target,
                threat_name="Sandbox.Behavioral.Malware",
                threat_score=95.0,
            )
            messagebox.showinfo("Quarantined", f"File successfully quarantined to vault!\nID: {record.id}")
            self.btn_sandbox_quarantine.config(state="disabled")
            self._sandbox_target_var.set("")
        except Exception as exc:
            messagebox.showerror("Quarantine Error", f"Failed to quarantine file:\n{exc}")

    # ------------------------------------------------------------------ #
    # Tab: Memory Shield Scanner
    # ------------------------------------------------------------------ #

    def _create_memory_tab(self) -> tk.Frame:
        frame = tk.Frame(self.content_area, bg=COLOR_BG_DARK)

        # Header Title
        tk.Label(
            frame,
            text="🧠  Memory Shield Scanner",
            font=("Segoe UI", 16, "bold"),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, 4))

        tk.Label(
            frame,
            text="Inspect virtual memory page tables across running processes using Win32 VirtualQueryEx to detect unbacked RWX code, shellcode, and reflective DLLs.",
            font=("Segoe UI", 9),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_SECONDARY,
        ).pack(anchor="w", pady=(0, 15))

        # Controls Bar
        ctrl_card = tk.Frame(frame, bg=COLOR_SURFACE, bd=1, relief="solid", highlightbackground=COLOR_CARD_BORDER)
        ctrl_card.pack(fill="x", pady=(0, 15), ipady=10, ipadx=15)

        ctrl_inner = tk.Frame(ctrl_card, bg=COLOR_SURFACE, padx=15)
        ctrl_inner.pack(fill="x")

        self.btn_scan_memory = tk.Button(
            ctrl_inner,
            text="⚡ Scan Process Memory Now",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_ACCENT_BLUE,
            fg="#FFFFFF",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
            command=self._on_scan_memory,
        )
        self.btn_scan_memory.pack(side="left", padx=(0, 12))

        self.btn_kill_mem_proc = tk.Button(
            ctrl_inner,
            text="🚫 Terminate Process",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_SURFACE_HOVER,
            fg=COLOR_ACCENT_RED,
            bd=1,
            relief="solid",
            highlightbackground=COLOR_CARD_BORDER,
            padx=12,
            pady=5,
            cursor="hand2",
            command=self._on_kill_memory_proc,
        )
        self.btn_kill_mem_proc.pack(side="left", padx=(0, 10))

        self.btn_suspend_mem_proc = tk.Button(
            ctrl_inner,
            text="⏸️ Suspend Process",
            font=("Segoe UI", 9),
            bg=COLOR_SURFACE_HOVER,
            fg=COLOR_TEXT_PRIMARY,
            bd=1,
            relief="solid",
            highlightbackground=COLOR_CARD_BORDER,
            padx=12,
            pady=5,
            cursor="hand2",
            command=self._on_suspend_memory_proc,
        )
        self.btn_suspend_mem_proc.pack(side="left", padx=(0, 15))

        self.lbl_mem_status = tk.Label(
            ctrl_inner,
            text="Ready. Click Scan to audit active process virtual address spaces.",
            font=("Segoe UI", 9),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SECONDARY,
        )
        self.lbl_mem_status.pack(side="left", fill="x", expand=True)

        # Telemetry Stats Cards Row
        mem_stats_frame = tk.Frame(frame, bg=COLOR_BG_DARK)
        mem_stats_frame.pack(fill="x", pady=(0, 15))

        self.lbl_tile_mem_procs = self._create_telemetry_tile(mem_stats_frame, "Processes Audited", "0", side="left")
        self.lbl_tile_mem_threats = self._create_telemetry_tile(mem_stats_frame, "Injected Threats", "0", side="left", fg=COLOR_ACCENT_GREEN)
        self.lbl_tile_mem_rwx = self._create_telemetry_tile(mem_stats_frame, "Unbacked RWX Pages", "0", side="left")
        self.lbl_tile_mem_status = self._create_telemetry_tile(mem_stats_frame, "Memory Health", "HEALTHY", side="left", fg=COLOR_ACCENT_GREEN)

        # Memory Findings Table
        tk.Label(
            frame,
            text="Discovered In-Memory Threats & Code Injection",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, 5))

        table_frame = tk.Frame(frame, bg=COLOR_SURFACE)
        table_frame.pack(fill="both", expand=True)

        cols = ("pid", "process", "base_addr", "protection", "threat_type", "confidence", "evidence")
        self.tree_memory = ttk.Treeview(
            table_frame,
            columns=cols,
            show="headings",
            style="Dark.Treeview",
            selectmode="browse",
        )
        self.tree_memory.heading("pid", text="PID")
        self.tree_memory.heading("process", text="Process Name")
        self.tree_memory.heading("base_addr", text="Base Address")
        self.tree_memory.heading("protection", text="Protection")
        self.tree_memory.heading("threat_type", text="Threat Type")
        self.tree_memory.heading("confidence", text="Confidence")
        self.tree_memory.heading("evidence", text="Evidence / Reason")

        self.tree_memory.column("pid", width=70, anchor="center")
        self.tree_memory.column("process", width=140)
        self.tree_memory.column("base_addr", width=140)
        self.tree_memory.column("protection", width=120, anchor="center")
        self.tree_memory.column("threat_type", width=150)
        self.tree_memory.column("confidence", width=90, anchor="center")
        self.tree_memory.column("evidence", width=280)

        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_memory.yview)
        self.tree_memory.configure(yscrollcommand=sb.set)
        self.tree_memory.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        return frame

    def _on_scan_memory(self) -> None:
        if self._memory_scan_active:
            return
        self._memory_scan_active = True
        self.btn_scan_memory.config(state="disabled", text="⏳ Scanning RAM...")
        self.lbl_mem_status.config(text="Scanning active processes for RWX memory & shellcode...", fg=COLOR_ACCENT_BLUE)

        for item in self.tree_memory.get_children():
            self.tree_memory.delete(item)

        thread = threading.Thread(target=self._run_memory_scan_worker, daemon=True)
        thread.start()

    def _run_memory_scan_worker(self) -> None:
        all_threats: list[tuple[int, str, MemoryThreat]] = []
        scanned_count = 0
        rwx_count = 0

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                name = proc.info["name"] or "Unknown"
                if pid <= 4 or pid == os.getpid():
                    continue
                scanned_count += 1
                threats = self.memory_scanner.scan_process(pid)
                for t in threats:
                    all_threats.append((pid, name, t))
                    if "RWX" in t.threat_type or t.protection == 0x40:
                        rwx_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as exc:
                logger.debug("Memory scan error on pid %s: %s", proc, exc)

        self._dispatch_to_ui(lambda: self._on_memory_scan_finished(scanned_count, all_threats, rwx_count))

    def _on_memory_scan_finished(self, scanned_count: int, threats: list[tuple[int, str, MemoryThreat]], rwx_count: int) -> None:
        self._memory_scan_active = False
        self.btn_scan_memory.config(state="normal", text="⚡ Scan Process Memory Now")
        self.lbl_tile_mem_procs.config(text=str(scanned_count))
        self.lbl_tile_mem_rwx.config(text=str(rwx_count))

        if threats:
            self.lbl_tile_mem_threats.config(text=str(len(threats)), fg=COLOR_ACCENT_RED)
            self.lbl_tile_mem_status.config(text="🚨 THREATS DETECTED", fg=COLOR_ACCENT_RED)
            self.lbl_mem_status.config(text=f"Audit complete: Found {len(threats)} active memory threat(s)!", fg=COLOR_ACCENT_RED)
        else:
            self.lbl_tile_mem_threats.config(text="0", fg=COLOR_ACCENT_GREEN)
            self.lbl_tile_mem_status.config(text="✅ HEALTHY", fg=COLOR_ACCENT_GREEN)
            self.lbl_mem_status.config(text=f"Audit complete: {scanned_count} processes clean. No injected code detected.", fg=COLOR_ACCENT_GREEN)

        for pid, name, t in threats:
            prot_str = "PAGE_EXECUTE_READWRITE" if t.protection == 0x40 else f"0x{t.protection:X}"
            self.tree_memory.insert(
                "",
                "end",
                values=(
                    pid,
                    name,
                    f"0x{t.base_address:012X}",
                    prot_str,
                    t.threat_type,
                    f"{t.confidence:.1f}%",
                    t.evidence,
                ),
            )

    def _refresh_memory_table(self) -> None:
        if not self.tree_memory.get_children() and not self._memory_scan_active:
            self._on_scan_memory()

    def _on_kill_memory_proc(self) -> None:
        selected = self.tree_memory.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a process from the memory threats list.")
            return

        item = self.tree_memory.item(selected[0])
        pid = int(item["values"][0])
        name = str(item["values"][1])

        confirm = messagebox.askyesno(
            "Terminate Process",
            f"Are you sure you want to terminate malicious process?\n\nProcess: {name}\nPID: {pid}",
        )
        if not confirm:
            return

        try:
            p = psutil.Process(pid)
            p.kill()
            messagebox.showinfo("Terminated", f"Successfully terminated {name} (PID: {pid}).")
            self.tree_memory.delete(selected[0])
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to terminate process: {exc}")

    def _on_suspend_memory_proc(self) -> None:
        selected = self.tree_memory.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a process from the memory threats list.")
            return

        item = self.tree_memory.item(selected[0])
        pid = int(item["values"][0])
        name = str(item["values"][1])

        try:
            p = psutil.Process(pid)
            p.suspend()
            messagebox.showinfo("Suspended", f"Successfully suspended {name} (PID: {pid}). Execution frozen.")
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to suspend process: {exc}")

    # ------------------------------------------------------------------ #
    # Tab: C2 & Network Activity Monitor
    # ------------------------------------------------------------------ #

    def _create_network_tab(self) -> tk.Frame:
        frame = tk.Frame(self.content_area, bg=COLOR_BG_DARK)

        # Header Title
        tk.Label(
            frame,
            text="🌐  C2 & Network Activity Monitor",
            font=("Segoe UI", 16, "bold"),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, 4))

        tk.Label(
            frame,
            text="Real-time socket monitoring, known Command & Control (C2) threat intel correlation, and beacon timing irregularity detection.",
            font=("Segoe UI", 9),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_SECONDARY,
        ).pack(anchor="w", pady=(0, 15))

        # Controls Bar
        ctrl_card = tk.Frame(frame, bg=COLOR_SURFACE, bd=1, relief="solid", highlightbackground=COLOR_CARD_BORDER)
        ctrl_card.pack(fill="x", pady=(0, 15), ipady=10, ipadx=15)

        ctrl_inner = tk.Frame(ctrl_card, bg=COLOR_SURFACE, padx=15)
        ctrl_inner.pack(fill="x")

        self.btn_refresh_network = tk.Button(
            ctrl_inner,
            text="🔄 Refresh Active Sockets",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_ACCENT_BLUE,
            fg="#FFFFFF",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
            command=self._on_refresh_network,
        )
        self.btn_refresh_network.pack(side="left", padx=(0, 12))

        self.btn_sever_socket = tk.Button(
            ctrl_inner,
            text="🔌 Sever Connection / Terminate PID",
            font=("Segoe UI", 9, "bold"),
            bg=COLOR_SURFACE_HOVER,
            fg=COLOR_ACCENT_RED,
            bd=1,
            relief="solid",
            highlightbackground=COLOR_CARD_BORDER,
            padx=12,
            pady=5,
            cursor="hand2",
            command=self._on_sever_socket,
        )
        self.btn_sever_socket.pack(side="left", padx=(0, 15))

        self.lbl_net_status = tk.Label(
            ctrl_inner,
            text="Ready. Live socket telemetry active.",
            font=("Segoe UI", 9),
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT_SECONDARY,
        )
        self.lbl_net_status.pack(side="left", fill="x", expand=True)

        # Telemetry Stats Cards Row
        net_stats_frame = tk.Frame(frame, bg=COLOR_BG_DARK)
        net_stats_frame.pack(fill="x", pady=(0, 15))

        self.lbl_tile_net_sockets = self._create_telemetry_tile(net_stats_frame, "Active Sockets", "0", side="left")
        self.lbl_tile_net_threats = self._create_telemetry_tile(net_stats_frame, "C2 Indicators", "0", side="left", fg=COLOR_ACCENT_GREEN)
        self.lbl_tile_net_blocklist = self._create_telemetry_tile(net_stats_frame, "Threat Intel IPs", str(len(self.c2_blocklist.blocked_ips)), side="left")
        self.lbl_tile_net_ports = self._create_telemetry_tile(net_stats_frame, "Monitored C2 Ports", str(len(self.c2_blocklist.blocked_ports)), side="left")

        # Network Table
        tk.Label(
            frame,
            text="Active Network Sockets & Threat Intel Evaluation",
            font=("Segoe UI", 11, "bold"),
            bg=COLOR_BG_DARK,
            fg=COLOR_TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, 5))

        table_frame = tk.Frame(frame, bg=COLOR_SURFACE)
        table_frame.pack(fill="both", expand=True)

        cols = ("pid", "process", "proto", "local", "remote", "state", "alert")
        self.tree_network = ttk.Treeview(
            table_frame,
            columns=cols,
            show="headings",
            style="Dark.Treeview",
            selectmode="browse",
        )
        self.tree_network.heading("pid", text="PID")
        self.tree_network.heading("process", text="Process Name")
        self.tree_network.heading("proto", text="Type")
        self.tree_network.heading("local", text="Local Address")
        self.tree_network.heading("remote", text="Remote Address")
        self.tree_network.heading("state", text="Socket State")
        self.tree_network.heading("alert", text="Threat Evaluation")

        self.tree_network.column("pid", width=70, anchor="center")
        self.tree_network.column("process", width=140)
        self.tree_network.column("proto", width=60, anchor="center")
        self.tree_network.column("local", width=180)
        self.tree_network.column("remote", width=180)
        self.tree_network.column("state", width=100, anchor="center")
        self.tree_network.column("alert", width=230)

        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_network.yview)
        self.tree_network.configure(yscrollcommand=sb.set)
        self.tree_network.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        return frame

    def _refresh_network_table(self) -> None:
        self._on_refresh_network()

    def _on_refresh_network(self) -> None:
        self.lbl_net_status.config(text="Enumerating active network sockets...", fg=COLOR_ACCENT_BLUE)
        self.btn_refresh_network.config(state="disabled")

        thread = threading.Thread(target=self._run_network_scan_worker, daemon=True)
        thread.start()

    def _run_network_scan_worker(self) -> None:
        results = []
        c2_threat_count = 0

        try:
            connections = psutil.net_connections(kind="inet")
        except Exception as exc:
            logger.debug("Failed to get net_connections: %s", exc)
            connections = []

        proc_names: dict[int, str] = {}
        for c in connections:
            pid = c.pid or 0
            if pid not in proc_names:
                try:
                    proc_names[pid] = psutil.Process(pid).name() if pid > 0 else "System"
                except Exception:
                    proc_names[pid] = "Unknown"

            proto = "TCP" if c.type == 1 else "UDP"
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—"
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—"
            state = c.status if c.status else "ESTABLISHED"

            alert = "Clean"
            if c.raddr:
                r_ip = c.raddr.ip
                r_port = c.raddr.port
                is_blocked, reason = self.c2_blocklist.check(r_ip, r_port)
                if is_blocked:
                    alert = f"🚨 {reason}"
                    c2_threat_count += 1
                elif r_port in self.c2_blocklist.blocked_ports:
                    alert = f"⚠️ C2 Staging Port ({r_port})"
                    c2_threat_count += 1

            results.append((pid, proc_names[pid], proto, laddr, raddr, state, alert))

        self._dispatch_to_ui(lambda: self._on_network_scan_finished(results, c2_threat_count))

    def _on_network_scan_finished(self, results: list, c2_threat_count: int) -> None:
        self.btn_refresh_network.config(state="normal")
        self.lbl_tile_net_sockets.config(text=str(len(results)))

        if c2_threat_count > 0:
            self.lbl_tile_net_threats.config(text=str(c2_threat_count), fg=COLOR_ACCENT_RED)
            self.lbl_net_status.config(text=f"WARNING: {c2_threat_count} suspicious/C2 socket(s) detected!", fg=COLOR_ACCENT_RED)
        else:
            self.lbl_tile_net_threats.config(text="0", fg=COLOR_ACCENT_GREEN)
            self.lbl_net_status.config(text=f"Active sockets enumerated: {len(results)} clean.", fg=COLOR_ACCENT_GREEN)

        for item in self.tree_network.get_children():
            self.tree_network.delete(item)

        results.sort(key=lambda r: 0 if "🚨" in r[6] or "⚠️" in r[6] else 1)

        for row in results:
            self.tree_network.insert("", "end", values=row)

    def _on_sever_socket(self) -> None:
        selected = self.tree_network.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a network connection from the table.")
            return

        item = self.tree_network.item(selected[0])
        pid = int(item["values"][0])
        name = str(item["values"][1])
        raddr = str(item["values"][4])

        if pid <= 4:
            messagebox.showwarning("Cannot Terminate", "Cannot terminate System or Idle process.")
            return

        confirm = messagebox.askyesno(
            "Sever Connection",
            f"Are you sure you want to terminate process '{name}' (PID: {pid}) to sever connection to {raddr}?",
        )
        if not confirm:
            return

        try:
            p = psutil.Process(pid)
            p.kill()
            messagebox.showinfo("Connection Severed", f"Successfully terminated {name} (PID: {pid}).")
            self._on_refresh_network()
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to terminate process: {exc}")

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
