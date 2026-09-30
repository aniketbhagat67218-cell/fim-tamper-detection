"""
Main Application Entry Point for the File Integrity Monitoring and Tampering Detection System.
Implements the CustomTkinter Cyber Dashboard with thread-safe Queue polling and modular views.
"""
import sys
import queue
import logging
from pathlib import Path
import customtkinter as ctk

# Ensure root directory is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config
from ui.theme import CyberTheme
from database.db_manager import get_db
from core.monitor import FileIntegrityMonitor
from core.vault import get_vault
from ui.views.dashboard_view import DashboardView
from ui.views.scanner_view import ScannerView
from ui.views.monitored_view import MonitoredView
from ui.views.diff_view import DiffView
from ui.views.history_view import HistoryView
from ui.views.reports_view import ReportsView
from ui.views.settings_view import SettingsView

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s"
)
logger = logging.getLogger("FIM_APP")

class FIMApplication(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Appearance & Geometry
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.title("File Integrity Monitoring & Tampering Detection System (FIM)")
        self.geometry("1280x800")
        self.minsize(1050, 680)

        # Thread-safe Event Queue for background Watchdog & AI dispatches (Flaw 3 Fix)
        self.event_queue = queue.Queue()

        # Database, Vault, and Monitor Subsystems
        self.db = get_db()
        self.vault = get_vault()
        self.monitor = FileIntegrityMonitor(event_queue=self.event_queue)

        # Main Layout: Sidebar (left) and Content Frame (right)
        self.grid_columnconfigure(0, weight=0)  # Fixed sidebar
        self.grid_columnconfigure(1, weight=1)  # Expandable content
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)     # Notification status bar

        self._build_sidebar()
        self._build_content_area()
        self._build_status_bar()

        # Wire close event
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Start periodic thread-safe queue polling (every 100ms)
        self.after(100, self._poll_event_queue)

        # Show initial view
        self.select_view("dashboard")

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(
            self,
            fg_color=CyberTheme.BG_SIDEBAR,
            width=230,
            corner_radius=0,
            border_color=CyberTheme.BORDER,
            border_width=1
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(9, weight=1)  # spacer

        # Brand / Title
        brand_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand_frame.pack(fill="x", padx=16, pady=(20, 24))

        lbl_badge = ctk.CTkLabel(
            brand_frame,
            text="FIM DEFENSE",
            font=(CyberTheme.FONT_FAMILY, 10, "bold"),
            text_color=CyberTheme.ACCENT_CYAN
        )
        lbl_badge.pack(anchor="w")

        lbl_logo = ctk.CTkLabel(
            brand_frame,
            text="INTEGRITY SENTINEL",
            font=(CyberTheme.FONT_FAMILY, 15, "bold"),
            text_color=CyberTheme.TEXT_PRIMARY
        )
        lbl_logo.pack(anchor="w")

        # Navigation Buttons
        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "⚡ Dashboard"),
            ("scanner", "🔍 Asset Scanner"),
            ("monitored", "🛡️ Monitored Assets"),
            ("diff", "📊 Change Analysis"),
            ("history", "📜 Audit History"),
            ("reports", "📑 Forensic Reports"),
            ("settings", "⚙️ Configuration")
        ]

        for key, label in nav_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=label,
                font=(CyberTheme.FONT_FAMILY, 13, "bold"),
                anchor="w",
                height=38,
                fg_color="transparent",
                hover_color=CyberTheme.BG_CARD_HOVER,
                text_color=CyberTheme.TEXT_SECONDARY,
                corner_radius=6,
                command=lambda k=key: self.select_view(k)
            )
            btn.pack(fill="x", padx=12, pady=3)
            self.nav_buttons[key] = btn

        # Bottom System Info in Sidebar
        bottom_box = ctk.CTkFrame(self.sidebar, fg_color=CyberTheme.BG_CARD, corner_radius=6)
        bottom_box.pack(side="bottom", fill="x", padx=12, pady=16)

        lbl_ver = ctk.CTkLabel(
            bottom_box,
            text="Dual-Hash FIM v2.4\nSHA-256 + SHA-3-256",
            font=(CyberTheme.FONT_FAMILY, 10),
            text_color=CyberTheme.TEXT_MUTED,
            justify="center"
        )
        lbl_ver.pack(pady=8)

    def _build_content_area(self):
        self.content_container = ctk.CTkFrame(self, fg_color=CyberTheme.BG_MAIN, corner_radius=0)
        self.content_container.grid(row=0, column=1, sticky="nsew")
        self.content_container.grid_columnconfigure(0, weight=1)
        self.content_container.grid_rowconfigure(0, weight=1)

        # Instantiate View Frames
        self.views = {
            "dashboard": DashboardView(self.content_container, self),
            "scanner": ScannerView(self.content_container, self),
            "monitored": MonitoredView(self.content_container, self),
            "diff": DiffView(self.content_container, self),
            "history": HistoryView(self.content_container, self),
            "reports": ReportsView(self.content_container, self),
            "settings": SettingsView(self.content_container, self)
        }

        for view in self.views.values():
            view.grid(row=0, column=0, sticky="nsew")

    def _build_status_bar(self):
        self.status_bar = ctk.CTkFrame(self, fg_color=CyberTheme.BG_SIDEBAR, height=28, corner_radius=0)
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky="ew")

        self.lbl_notification = ctk.CTkLabel(
            self.status_bar,
            text="System initialized. Thread-safe message dispatcher ready.",
            font=(CyberTheme.FONT_FAMILY, 11),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        self.lbl_notification.pack(side="left", padx=16, pady=4)

    def select_view(self, view_key: str):
        """Switches active view and updates sidebar highlight."""
        for key, btn in self.nav_buttons.items():
            if key == view_key:
                btn.configure(fg_color="#1F6FEB", text_color="#FFFFFF")
            else:
                btn.configure(fg_color="transparent", text_color=CyberTheme.TEXT_SECONDARY)

        target_view = self.views.get(view_key)
        if target_view:
            target_view.tkraise()
            if hasattr(target_view, "refresh_data"):
                target_view.refresh_data()

    def open_diff_view(self, file_id: int, event_id: int = None):
        """Switches to Diff View and automatically loads file for analysis."""
        self.select_view("diff")
        diff_view: DiffView = self.views["diff"]
        diff_view.load_file(file_id=file_id, event_id=event_id)

    def show_notification(self, message: str, duration_ms: int = 4000):
        """Displays status message in the bottom notification bar."""
        self.lbl_notification.configure(text=message, text_color=CyberTheme.ACCENT_CYAN)
        self.after(duration_ms, lambda: self.lbl_notification.configure(
            text="Monitoring system operational.",
            text_color=CyberTheme.TEXT_MUTED
        ))

    def _poll_event_queue(self):
        """
        Polls the thread-safe Queue every 100ms.
        Processes notifications from Watchdog or background AI calls without GUI locking.
        """
        try:
            while not self.event_queue.empty():
                event = self.event_queue.get_nowait()
                self._handle_background_event(event)
        except queue.Empty:
            pass
        finally:
            self.after(100, self._poll_event_queue)

    def _handle_background_event(self, event: dict):
        """Dispatches event to appropriate UI components."""
        event_type = event.get("type")
        if event_type == "TAMPER_ALERT":
            msg = event.get("message", "File integrity violation detected!")
            self.show_notification(f"⚠️ {msg}", duration_ms=6000)

            # Refresh Dashboard and History if visible
            if hasattr(self.views["dashboard"], "refresh_data"):
                self.views["dashboard"].refresh_data()
            if hasattr(self.views["monitored"], "refresh_data"):
                self.views["monitored"].refresh_data()
            if hasattr(self.views["history"], "refresh_data"):
                self.views["history"].refresh_data()

        elif event_type == "MONITOR_STATUS":
            msg = event.get("message", "")
            self.show_notification(msg)
            if hasattr(self.views["dashboard"], "refresh_data"):
                self.views["dashboard"].refresh_data()

    def _on_closing(self):
        """Gracefully shuts down background monitoring thread and closes application."""
        logger.info("Shutting down FIM System...")
        if self.monitor:
            self.monitor.stop()
        self.destroy()

def main():
    app = FIMApplication()
    app.mainloop()

if __name__ == "__main__":
    main()
