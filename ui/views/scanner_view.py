"""
Scanner View for discovering assets, computing dual-hashes, and establishing baseline snapshots.
"""
import os
import threading
from pathlib import Path
import customtkinter as ctk
from tkinter import filedialog
from typing import List, Dict, Any

from ui.theme import CyberTheme
from ui.components.data_table import DataTable
from database.db_manager import get_db
from core.hasher import compute_dual_hash
from core.vault import get_vault

class ScannerView(ctk.CTkFrame):
    def __init__(self, master, app_controller, **kwargs):
        super().__init__(master, fg_color=CyberTheme.BG_MAIN, **kwargs)
        self.app = app_controller
        self.db = get_db()
        self.vault = get_vault()
        self.scanned_items: List[Dict[str, Any]] = []

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header()
        self._build_controls()
        self._build_table_section()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 12))

        lbl_title = ctk.CTkLabel(
            header,
            text="ASSET DISCOVERY & BASELINE SCANNER",
            font=(CyberTheme.FONT_FAMILY, 20, "bold"),
            text_color=CyberTheme.TEXT_PRIMARY
        )
        lbl_title.pack(anchor="w")

        lbl_sub = ctk.CTkLabel(
            header,
            text="Single-Pass Dual Hashing (SHA-256 + SHA-3-256) & Secure Snapshot Vaulting",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        lbl_sub.pack(anchor="w")

    def _build_controls(self):
        ctrl_frame = ctk.CTkFrame(self, fg_color=CyberTheme.BG_CARD, border_color=CyberTheme.BORDER, border_width=1)
        ctrl_frame.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 16))
        ctrl_frame.grid_columnconfigure(3, weight=1)

        btn_files = ctk.CTkButton(
            ctrl_frame,
            text="📂 Select Files...",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#21262D",
            hover_color="#30363D",
            height=32,
            command=self._pick_files
        )
        btn_files.grid(row=0, column=0, padx=12, pady=12)

        btn_folder = ctk.CTkButton(
            ctrl_frame,
            text="📁 Select Folder...",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#21262D",
            hover_color="#30363D",
            height=32,
            command=self._pick_folder
        )
        btn_folder.grid(row=0, column=1, padx=6, pady=12)

        lbl_ext = ctk.CTkLabel(
            ctrl_frame,
            text="Extension Filter:",
            font=(CyberTheme.FONT_FAMILY, 11, "bold"),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        lbl_ext.grid(row=0, column=2, padx=(12, 4), pady=12)

        self.entry_ext = ctk.CTkEntry(
            ctrl_frame,
            placeholder_text="e.g. .py, .env, .json, .ini, .yaml, .conf (or *.*)",
            font=(CyberTheme.FONT_FAMILY, 11),
            width=240,
            height=30
        )
        self.entry_ext.insert(0, ".py, .env, .json, .ini, .yaml, .conf, .sh, .bat")
        self.entry_ext.grid(row=0, column=3, padx=6, pady=12, sticky="w")

        self.btn_baseline = ctk.CTkButton(
            ctrl_frame,
            text="🛡️ Establish Baseline & Vault",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#238636",
            hover_color="#2EA043",
            height=32,
            command=self._baseline_scanned_files
        )
        self.btn_baseline.grid(row=0, column=4, padx=12, pady=12, sticky="e")

    def _build_table_section(self):
        section_frame = ctk.CTkFrame(self, fg_color="transparent")
        section_frame.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0, 20))
        section_frame.grid_columnconfigure(0, weight=1)
        section_frame.grid_rowconfigure(1, weight=1)

        self.lbl_status = ctk.CTkLabel(
            section_frame,
            text="Ready. Select files or directories to preview cryptographic fingerprints.",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_MUTED
        )
        self.lbl_status.grid(row=0, column=0, sticky="w", pady=(0, 8))

        cols = [
            {"key": "file_name", "title": "File Name", "weight": 2, "max_chars": 25},
            {"key": "file_path", "title": "Absolute File Path", "weight": 4, "max_chars": 50},
            {"key": "size_display", "title": "Size", "weight": 1},
            {"key": "sha256_short", "title": "SHA-256 (Streaming)", "weight": 2},
            {"key": "sha3_short", "title": "SHA-3-256 (Sponge)", "weight": 2}
        ]

        self.table = DataTable(section_frame, columns=cols, height=320)
        self.table.grid(row=1, column=0, sticky="nsew")

    def _pick_files(self):
        paths = filedialog.askopenfilenames(
            title="Select Files to Monitor",
            filetypes=[("All Files", "*.*")]
        )
        if paths:
            self._scan_paths([Path(p) for p in paths])

    def _pick_folder(self):
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if not folder:
            return

        exts_raw = self.entry_ext.get().strip()
        valid_exts = set()
        if exts_raw and "*.*" not in exts_raw and "*" not in exts_raw:
            valid_exts = {e.strip().lower() for e in exts_raw.split(",") if e.strip()}

        found_paths = []
        for root, _, files in os.walk(folder):
            # Skip hidden folders like .git, .fim_vault
            if ".git" in root or ".fim_vault" in root:
                continue
            for f in files:
                p = Path(root) / f
                if not valid_exts or p.suffix.lower() in valid_exts:
                    found_paths.append(p)
                if len(found_paths) >= 200:  # limit batch scan preview
                    break
            if len(found_paths) >= 200:
                break

        self._scan_paths(found_paths)

    def _scan_paths(self, paths: List[Path]):
        self.lbl_status.configure(text=f"Computing dual-hashes for {len(paths)} assets...")
        self.btn_baseline.configure(state="disabled")

        def worker():
            items = []
            for p in paths:
                if not p.is_file():
                    continue
                res = compute_dual_hash(p)
                if res.error:
                    continue
                items.append({
                    "file_name": p.name,
                    "file_path": str(p.resolve()),
                    "file_size": res.file_size,
                    "size_display": f"{res.file_size:,} B",
                    "sha256": res.sha256,
                    "sha256_short": res.sha256[:16] + "...",
                    "sha3_256": res.sha3_256,
                    "sha3_short": res.sha3_256[:16] + "...",
                    "last_modified": res.last_modified,
                    "is_binary": res.is_binary
                })
            self.scanned_items = items
            self.after(0, self._on_scan_complete)

        threading.Thread(target=worker, daemon=True).start()

    def _on_scan_complete(self):
        self.table.set_rows(self.scanned_items)
        self.lbl_status.configure(
            text=f"Prepared {len(self.scanned_items)} assets. Click 'Establish Baseline & Vault' to monitor."
        )
        self.btn_baseline.configure(state="normal")

    def _baseline_scanned_files(self):
        if not self.scanned_items:
            self.app.show_notification("No assets to baseline. Select files first.")
            return

        count = 0
        for item in self.scanned_items:
            # 1. Add to SQLite monitored_files
            file_id = self.db.add_monitored_file(
                file_path=item["file_path"],
                file_name=item["file_name"],
                sha256=item["sha256"],
                sha3_256=item["sha3_256"],
                file_size=item["file_size"],
                last_modified=item["last_modified"],
                is_binary=item["is_binary"]
            )
            # 2. Store trusted copy in .fim_vault/
            if file_id > 0:
                self.vault.store_snapshot(
                    file_path=item["file_path"],
                    file_id=file_id,
                    sha256=item["sha256"],
                    file_size=item["file_size"],
                    is_binary=item["is_binary"]
                )
                count += 1

        # Reload watchdog watch directories
        self.app.monitor.reload_monitored_files()

        self.scanned_items.clear()
        self.table.set_rows([])
        self.lbl_status.configure(text=f"Successfully baselined and vaulted {count} assets.")
        self.app.show_notification(f"Baselined {count} assets into secure snapshot vault.")
