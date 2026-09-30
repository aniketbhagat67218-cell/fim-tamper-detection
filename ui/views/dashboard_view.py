"""
Dashboard View presenting system integrity metrics, real-time monitor status,
and a live stream of tampering alerts.
"""
import customtkinter as ctk
from typing import Callable, Optional
from ui.theme import CyberTheme
from ui.components.stat_card import StatCard
from ui.components.data_table import DataTable
from database.db_manager import get_db

class DashboardView(ctk.CTkFrame):
    def __init__(self, master, app_controller, **kwargs):
        super().__init__(master, fg_color=CyberTheme.BG_MAIN, **kwargs)
        self.app = app_controller
        self.db = get_db()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header()
        self._build_stats_row()
        self._build_activity_section()

    def _build_header(self):
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 16))
        header_frame.grid_columnconfigure(0, weight=1)

        # Title & Subtitle
        title_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_box.grid(row=0, column=0, sticky="w")

        lbl_title = ctk.CTkLabel(
            title_box,
            text="SECURITY OPERATIONS DASHBOARD",
            font=(CyberTheme.FONT_FAMILY, 20, "bold"),
            text_color=CyberTheme.TEXT_PRIMARY
        )
        lbl_title.pack(anchor="w")

        lbl_sub = ctk.CTkLabel(
            title_box,
            text="Dual-Primitive Cryptographic Verification & Real-Time Tamper Triage",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        lbl_sub.pack(anchor="w")

        # Action Buttons
        btn_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_box.grid(row=0, column=1, sticky="e")

        self.btn_monitor_toggle = ctk.CTkButton(
            btn_box,
            text="▶ Start Real-Time Monitor",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#1F6FEB",
            hover_color="#388BFD",
            height=34,
            command=self._toggle_monitor
        )
        self.btn_monitor_toggle.pack(side="left", padx=6)

        self.btn_scan = ctk.CTkButton(
            btn_box,
            text="⚡ Run Integrity Scan",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color=CyberTheme.BG_CARD,
            border_color=CyberTheme.BORDER,
            border_width=1,
            hover_color=CyberTheme.BG_CARD_HOVER,
            height=34,
            command=self._run_integrity_scan
        )
        self.btn_scan.pack(side="left", padx=6)

    def _build_stats_row(self):
        stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        stats_frame.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 16))
        for i in range(4):
            stats_frame.grid_columnconfigure(i, weight=1, uniform="stat_cards")

        self.card_total = StatCard(
            stats_frame,
            title="Monitored Assets",
            value="0",
            accent_color=CyberTheme.ACCENT_CYAN,
            subtitle="Registered in database"
        )
        self.card_total.grid(row=0, column=0, padx=(0, 8), sticky="ew")

        self.card_clean = StatCard(
            stats_frame,
            title="Clean Assets",
            value="0",
            accent_color=CyberTheme.ACCENT_EMERALD,
            subtitle="Hashes verified intact"
        )
        self.card_clean.grid(row=0, column=1, padx=4, sticky="ew")

        self.card_alerts = StatCard(
            stats_frame,
            title="Tampering Alerts",
            value="0",
            accent_color=CyberTheme.ACCENT_CRIMSON,
            subtitle="Modifications detected"
        )
        self.card_alerts.grid(row=0, column=2, padx=4, sticky="ew")

        self.card_status = StatCard(
            stats_frame,
            title="Watchdog Engine",
            value="IDLE",
            accent_color=CyberTheme.TEXT_MUTED,
            subtitle="750ms lock debouncer"
        )
        self.card_status.grid(row=0, column=3, padx=(8, 0), sticky="ew")

    def _build_activity_section(self):
        activity_frame = ctk.CTkFrame(self, fg_color="transparent")
        activity_frame.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0, 20))
        activity_frame.grid_columnconfigure(0, weight=1)
        activity_frame.grid_rowconfigure(1, weight=1)

        lbl_section = ctk.CTkLabel(
            activity_frame,
            text="LIVE FORENSIC ACTIVITY FEED",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        lbl_section.grid(row=0, column=0, sticky="w", pady=(0, 8))

        columns = [
            {"key": "timestamp", "title": "Timestamp", "weight": 2, "max_chars": 22},
            {"key": "file_path", "title": "Target Asset", "weight": 4, "max_chars": 45},
            {"key": "event_type", "title": "Event", "weight": 2},
            {"key": "risk_level", "title": "Risk Level", "weight": 2},
            {"key": "diff_summary", "title": "Delta Highlights", "weight": 3, "max_chars": 35}
        ]

        self.activity_table = DataTable(
            activity_frame,
            columns=columns,
            on_select=self._on_incident_selected,
            height=280
        )
        self.activity_table.grid(row=1, column=0, sticky="nsew")

    def refresh_data(self):
        """Refreshes metrics and latest activity table."""
        stats = self.db.get_system_stats()
        self.card_total.update_value(stats["total_files"])
        self.card_clean.update_value(stats["clean_files"])
        self.card_alerts.update_value(stats["modified_files"] + stats["missing_files"])

        # Update monitor status card
        is_running = self.app.monitor.is_running
        if is_running:
            self.card_status.update_value("ACTIVE", subtitle="Watching parent dirs")
            self.card_status.lbl_value.configure(text_color=CyberTheme.ACCENT_EMERALD)
            self.btn_monitor_toggle.configure(
                text="⏹ Stop Real-Time Monitor",
                fg_color="#DA3633",
                hover_color="#F85149"
            )
        else:
            self.card_status.update_value("IDLE", subtitle="Monitoring paused")
            self.card_status.lbl_value.configure(text_color=CyberTheme.TEXT_MUTED)
            self.btn_monitor_toggle.configure(
                text="▶ Start Real-Time Monitor",
                fg_color="#1F6FEB",
                hover_color="#388BFD"
            )

        # Load recent events
        recent_events = self.db.get_event_history(limit=25)
        self.activity_table.set_rows(recent_events)

    def _toggle_monitor(self):
        if self.app.monitor.is_running:
            self.app.monitor.stop()
        else:
            self.app.monitor.start()
        self.refresh_data()

    def _run_integrity_scan(self):
        """Triggers manual re-verification of all registered files."""
        files = self.db.get_all_monitored_files()
        for f in files:
            self.app.monitor.manual_verify_file(f["id"])
        self.refresh_data()
        self.app.show_notification(f"Scanned {len(files)} monitored assets.")

    def _on_incident_selected(self, row):
        """When an incident is selected in table, navigate to Diff View."""
        if row.get("file_id"):
            self.app.open_diff_view(file_id=row["file_id"], event_id=row.get("id"))
