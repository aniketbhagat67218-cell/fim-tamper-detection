"""
Reports View for managing, previewing, and opening generated forensic audit reports.
"""
import os
import webbrowser
from pathlib import Path
import customtkinter as ctk
from typing import List, Dict, Any

from ui.theme import CyberTheme
from ui.components.data_table import DataTable
import config

class ReportsView(ctk.CTkFrame):
    def __init__(self, master, app_controller, **kwargs):
        super().__init__(master, fg_color=CyberTheme.BG_MAIN, **kwargs)
        self.app = app_controller
        self.reports_dir = config.REPORTS_DIR

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header()
        self._build_toolbar()
        self._build_table()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 12))

        lbl_title = ctk.CTkLabel(
            header,
            text="INCIDENT & COMPLIANCE REPORTS",
            font=(CyberTheme.FONT_FAMILY, 20, "bold"),
            text_color=CyberTheme.TEXT_PRIMARY
        )
        lbl_title.pack(anchor="w")

        lbl_sub = ctk.CTkLabel(
            header,
            text="Printable HTML audit documentation, Markdown summaries, and legal-grade forensic artifacts",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        lbl_sub.pack(anchor="w")

    def _build_toolbar(self):
        toolbar = ctk.CTkFrame(self, fg_color=CyberTheme.BG_CARD, border_color=CyberTheme.BORDER, border_width=1)
        toolbar.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 16))
        toolbar.grid_columnconfigure(3, weight=1)

        btn_open = ctk.CTkButton(
            toolbar,
            text="🌐 Open Selected Report",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#1F6FEB",
            hover_color="#388BFD",
            height=32,
            command=self._open_selected
        )
        btn_open.grid(row=0, column=0, padx=12, pady=10)

        btn_open_dir = ctk.CTkButton(
            toolbar,
            text="📁 Open Reports Folder",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#21262D",
            hover_color="#30363D",
            height=32,
            command=self._open_folder
        )
        btn_open_dir.grid(row=0, column=1, padx=6, pady=10)

        btn_refresh = ctk.CTkButton(
            toolbar,
            text="🔄 Refresh List",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#21262D",
            hover_color="#30363D",
            height=32,
            command=self.refresh_data
        )
        btn_refresh.grid(row=0, column=2, padx=6, pady=10)

    def _build_table(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0, 20))
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        cols = [
            {"key": "file_name", "title": "Report Document", "weight": 4, "max_chars": 50},
            {"key": "format", "title": "Format", "weight": 1},
            {"key": "size_display", "title": "File Size", "weight": 1},
            {"key": "created_time", "title": "Creation Date", "weight": 2}
        ]

        self.table = DataTable(frame, columns=cols, height=350)
        self.table.grid(row=0, column=0, sticky="nsew")

    def refresh_data(self):
        rows = []
        if self.reports_dir.exists():
            for p in sorted(self.reports_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                if p.is_file() and p.suffix in (".html", ".md", ".txt"):
                    st = p.stat()
                    rows.append({
                        "file_name": p.name,
                        "full_path": str(p.resolve()),
                        "format": p.suffix.upper().replace(".", ""),
                        "size_display": f"{st.st_size:,} B",
                        "created_time": config.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    })
        self.table.set_rows(rows)

    def _open_selected(self):
        sel = self.table.get_selected()
        if not sel:
            self.app.show_notification("Please select a report document from the table.")
            return
        path = sel["full_path"]
        try:
            webbrowser.open(Path(path).as_uri())
        except Exception as e:
            self.app.show_notification(f"Could not open report: {e}")

    def _open_folder(self):
        try:
            os.startfile(self.reports_dir)
        except Exception:
            webbrowser.open(self.reports_dir.as_uri())
