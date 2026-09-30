"""
Forensic Audit History View for querying, filtering, and exporting incident logs.
"""
from pathlib import Path
import customtkinter as ctk
from typing import Optional, Dict, Any

from ui.theme import CyberTheme
from ui.components.data_table import DataTable
from database.db_manager import get_db
from reports.report_generator import generate_audit_report

class HistoryView(ctk.CTkFrame):
    def __init__(self, master, app_controller, **kwargs):
        super().__init__(master, fg_color=CyberTheme.BG_MAIN, **kwargs)
        self.app = app_controller
        self.db = get_db()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header()
        self._build_filter_bar()
        self._build_table()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 12))

        lbl_title = ctk.CTkLabel(
            header,
            text="FORENSIC AUDIT TRAIL & INCIDENT HISTORY",
            font=(CyberTheme.FONT_FAMILY, 20, "bold"),
            text_color=CyberTheme.TEXT_PRIMARY
        )
        lbl_title.pack(anchor="w")

        lbl_sub = ctk.CTkLabel(
            header,
            text="Immutable tamper detection logs, heuristic scores, and remediation records",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        lbl_sub.pack(anchor="w")

    def _build_filter_bar(self):
        bar = ctk.CTkFrame(self, fg_color=CyberTheme.BG_CARD, border_color=CyberTheme.BORDER, border_width=1)
        bar.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 16))
        bar.grid_columnconfigure(3, weight=1)

        # Risk filter
        lbl_filter = ctk.CTkLabel(
            bar,
            text="Risk Filter:",
            font=(CyberTheme.FONT_FAMILY, 11, "bold"),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        lbl_filter.grid(row=0, column=0, padx=(12, 4), pady=10)

        self.risk_filter_var = ctk.StringVar(value="ALL")
        self.seg_risk = ctk.CTkSegmentedButton(
            bar,
            values=["ALL", "HIGH", "MEDIUM", "LOW"],
            variable=self.risk_filter_var,
            command=lambda v: self.refresh_data(),
            height=28
        )
        self.seg_risk.grid(row=0, column=1, padx=6, pady=10)

        # Search bar
        self.entry_search = ctk.CTkEntry(
            bar,
            placeholder_text="Search file path or keywords...",
            font=(CyberTheme.FONT_FAMILY, 11),
            width=220,
            height=28
        )
        self.entry_search.grid(row=0, column=2, padx=10, pady=10)
        self.entry_search.bind("<Return>", lambda e: self.refresh_data())

        btn_search = ctk.CTkButton(
            bar,
            text="🔍 Filter",
            width=70,
            height=28,
            fg_color="#21262D",
            hover_color="#30363D",
            command=self.refresh_data
        )
        btn_search.grid(row=0, column=3, padx=(0, 10), pady=10, sticky="w")

        # Action buttons
        self.btn_inspect = ctk.CTkButton(
            bar,
            text="📊 Inspect Incident",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#1F6FEB",
            hover_color="#388BFD",
            height=30,
            command=self._inspect_selected
        )
        self.btn_inspect.grid(row=0, column=4, padx=6, pady=10)

        self.btn_export_html = ctk.CTkButton(
            bar,
            text="📄 Export HTML",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#238636",
            hover_color="#2EA043",
            height=30,
            command=lambda: self._export_report("html")
        )
        self.btn_export_html.grid(row=0, column=5, padx=6, pady=10)

        self.btn_export_md = ctk.CTkButton(
            bar,
            text="📝 Export MD",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#21262D",
            hover_color="#30363D",
            height=30,
            command=lambda: self._export_report("md")
        )
        self.btn_export_md.grid(row=0, column=6, padx=(6, 12), pady=10)

    def _build_table(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0, 20))
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        cols = [
            {"key": "timestamp", "title": "Timestamp", "weight": 2, "max_chars": 20},
            {"key": "file_path", "title": "Target Asset", "weight": 4, "max_chars": 45},
            {"key": "event_type", "title": "Event", "weight": 1},
            {"key": "risk_level", "title": "Risk Level", "weight": 2},
            {"key": "risk_score", "title": "Score", "weight": 1},
            {"key": "diff_summary", "title": "Delta Highlights", "weight": 3, "max_chars": 35}
        ]

        self.table = DataTable(frame, columns=cols, height=350, on_select=self._on_row_select)
        self.table.grid(row=0, column=0, sticky="nsew")

    def refresh_data(self):
        risk_filter = self.risk_filter_var.get()
        query = self.entry_search.get().strip() or None
        rows = self.db.get_event_history(limit=150, risk_filter=risk_filter, search_query=query)
        self.table.set_rows(rows)

    def _on_row_select(self, row):
        pass

    def _inspect_selected(self):
        sel = self.table.get_selected()
        if not sel:
            self.app.show_notification("Please select an incident from the table first.")
            return
        if sel.get("file_id"):
            self.app.open_diff_view(file_id=sel["file_id"], event_id=sel["id"])
        else:
            self.app.show_notification(f"Viewing incident #{sel['id']}: File deleted or unregistered.")

    def _export_report(self, fmt: str):
        sel = self.table.get_selected()
        if not sel:
            self.app.show_notification("Please select an incident from the table to export.")
            return
        try:
            report_path = generate_audit_report(sel["id"], format=fmt)
            self.app.show_notification(f"Report exported: {report_path.name}")
        except Exception as e:
            self.app.show_notification(f"Failed to export report: {e}")
