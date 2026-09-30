"""
Monitored Files View displaying all registered baseline assets,
integrity verification actions, and baseline lifecycle management.
"""
from pathlib import Path
import customtkinter as ctk
from typing import Optional, Dict, Any

from ui.theme import CyberTheme
from ui.components.data_table import DataTable
from database.db_manager import get_db
from core.vault import get_vault
from core.hasher import compute_dual_hash

class MonitoredView(ctk.CTkFrame):
    def __init__(self, master, app_controller, **kwargs):
        super().__init__(master, fg_color=CyberTheme.BG_MAIN, **kwargs)
        self.app = app_controller
        self.db = get_db()
        self.vault = get_vault()

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
            text="MONITORED ASSET INVENTORY",
            font=(CyberTheme.FONT_FAMILY, 20, "bold"),
            text_color=CyberTheme.TEXT_PRIMARY
        )
        lbl_title.pack(anchor="w")

        lbl_sub = ctk.CTkLabel(
            header,
            text="Active Cryptographic Baselines & File Integrity Health",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        lbl_sub.pack(anchor="w")

    def _build_toolbar(self):
        toolbar = ctk.CTkFrame(self, fg_color=CyberTheme.BG_CARD, border_color=CyberTheme.BORDER, border_width=1)
        toolbar.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 16))
        toolbar.grid_columnconfigure(5, weight=1)

        self.btn_verify_sel = ctk.CTkButton(
            toolbar,
            text="🔍 Verify Selected",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#1F6FEB",
            hover_color="#388BFD",
            height=32,
            command=self._verify_selected
        )
        self.btn_verify_sel.grid(row=0, column=0, padx=10, pady=10)

        self.btn_verify_all = ctk.CTkButton(
            toolbar,
            text="⚡ Verify All Assets",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#21262D",
            hover_color="#30363D",
            height=32,
            command=self._verify_all
        )
        self.btn_verify_all.grid(row=0, column=1, padx=6, pady=10)

        self.btn_diff = ctk.CTkButton(
            toolbar,
            text="📊 Inspect Diff",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#21262D",
            hover_color="#30363D",
            height=32,
            command=self._inspect_diff
        )
        self.btn_diff.grid(row=0, column=2, padx=6, pady=10)

        self.btn_update_base = ctk.CTkButton(
            toolbar,
            text="🔄 Accept as New Baseline",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#238636",
            hover_color="#2EA043",
            height=32,
            command=self._update_baseline
        )
        self.btn_update_base.grid(row=0, column=3, padx=6, pady=10)

        self.btn_remove = ctk.CTkButton(
            toolbar,
            text="🗑️ Remove Asset",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#DA3633",
            hover_color="#F85149",
            height=32,
            command=self._remove_asset
        )
        self.btn_remove.grid(row=0, column=4, padx=6, pady=10)

    def _build_table(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0, 20))
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        cols = [
            {"key": "file_name", "title": "File Name", "weight": 2, "max_chars": 25},
            {"key": "file_path", "title": "Path", "weight": 4, "max_chars": 45},
            {"key": "status", "title": "Integrity Status", "weight": 2},
            {"key": "size_display", "title": "Size", "weight": 1},
            {"key": "sha256_short", "title": "Baseline SHA-256", "weight": 2},
            {"key": "last_checked_at", "title": "Last Verified", "weight": 2, "max_chars": 20}
        ]

        self.table = DataTable(frame, columns=cols, height=350)
        self.table.grid(row=0, column=0, sticky="nsew")

    def refresh_data(self):
        records = self.db.get_all_monitored_files()
        formatted = []
        for r in records:
            d = dict(r)
            d["size_display"] = f"{r['file_size']:,} B"
            d["sha256_short"] = r["sha256"][:16] + "..." if r["sha256"] else "None"
            formatted.append(d)
        self.table.set_rows(formatted)

    def _get_selected(self) -> Optional[Dict[str, Any]]:
        sel = self.table.get_selected()
        if not sel:
            self.app.show_notification("Please select a file from the list first.")
            return None
        return sel

    def _verify_selected(self):
        sel = self._get_selected()
        if not sel:
            return
        res = self.app.monitor.manual_verify_file(sel["id"])
        self.refresh_data()
        self.app.show_notification(f"{sel['file_name']}: {res['message']}")

    def _verify_all(self):
        records = self.db.get_all_monitored_files()
        for r in records:
            self.app.monitor.manual_verify_file(r["id"])
        self.refresh_data()
        self.app.show_notification(f"Verified {len(records)} assets.")

    def _inspect_diff(self):
        sel = self._get_selected()
        if not sel:
            return
        self.app.open_diff_view(file_id=sel["id"])

    def _update_baseline(self):
        """User confirms changes are authorized; establishes new baseline snapshot."""
        sel = self._get_selected()
        if not sel:
            return
        file_path = sel["file_path"]
        p = Path(file_path)
        if not p.exists():
            self.app.show_notification("Cannot update baseline: File does not exist on disk.")
            return

        res = compute_dual_hash(file_path)
        if res.error:
            self.app.show_notification(f"Error computing hash: {res.error}")
            return

        file_id = sel["id"]
        # 1. Update in DB
        self.db.update_file_baseline(
            file_id=file_id,
            sha256=res.sha256,
            sha3_256=res.sha3_256,
            file_size=res.file_size,
            last_modified=res.last_modified
        )
        # 2. Store new snapshot in vault
        self.vault.store_snapshot(
            file_path=file_path,
            file_id=file_id,
            sha256=res.sha256,
            file_size=res.file_size,
            is_binary=res.is_binary
        )
        self.app.monitor.reload_monitored_files()
        self.refresh_data()
        self.app.show_notification(f"New baseline established for {sel['file_name']}.")

    def _remove_asset(self):
        sel = self._get_selected()
        if not sel:
            return
        file_id = sel["id"]
        self.vault.purge_snapshot(file_id)
        self.db.remove_monitored_file(file_id)
        self.app.monitor.reload_monitored_files()
        self.refresh_data()
        self.app.show_notification(f"Removed {sel['file_name']} from monitoring.")
