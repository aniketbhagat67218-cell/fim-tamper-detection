"""
Settings View for managing API keys, debounce thresholds, snapshot vault limits,
and threat heuristics configuration.
"""
import customtkinter as ctk
from pathlib import Path
from ui.theme import CyberTheme
from database.db_manager import get_db
import config

class SettingsView(ctk.CTkFrame):
    def __init__(self, master, app_controller, **kwargs):
        super().__init__(master, fg_color=CyberTheme.BG_MAIN, **kwargs)
        self.app = app_controller
        self.db = get_db()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_settings_content()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 12))

        lbl_title = ctk.CTkLabel(
            header,
            text="SYSTEM CONFIGURATION & SECURITY SETTINGS",
            font=(CyberTheme.FONT_FAMILY, 20, "bold"),
            text_color=CyberTheme.TEXT_PRIMARY
        )
        lbl_title.pack(anchor="w")

        lbl_sub = ctk.CTkLabel(
            header,
            text="Tune watchdog debouncers, snapshot vault limits, and AI API credentials",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        lbl_sub.pack(anchor="w")

    def _build_settings_content(self):
        container = ctk.CTkScrollableFrame(
            self,
            fg_color=CyberTheme.BG_CARD,
            border_color=CyberTheme.BORDER,
            border_width=1,
            corner_radius=8
        )
        container.grid(row=1, column=0, sticky="nsew", padx=24, pady=(0, 20))
        container.grid_columnconfigure(0, weight=1)

        # 1. AI API Configuration
        lbl_ai = ctk.CTkLabel(
            container,
            text="AI THREAT ADVISORY CONFIGURATION",
            font=(CyberTheme.FONT_FAMILY, 13, "bold"),
            text_color=CyberTheme.ACCENT_CYAN
        )
        lbl_ai.pack(anchor="w", padx=20, pady=(20, 8))

        # Provider Selector
        prov_frame = ctk.CTkFrame(container, fg_color="transparent")
        prov_frame.pack(fill="x", padx=20, pady=4)
        ctk.CTkLabel(
            prov_frame,
            text="Preferred AI Provider:",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            text_color=CyberTheme.TEXT_SECONDARY,
            width=160,
            anchor="w"
        ).pack(side="left")

        self.provider_var = ctk.StringVar(value=self.db.get_setting("ai_provider", "gemini"))
        self.seg_provider = ctk.CTkSegmentedButton(
            prov_frame,
            values=["gemini", "openai"],
            variable=self.provider_var
        )
        self.seg_provider.pack(side="left", padx=10)

        # Gemini Key
        g_frame = ctk.CTkFrame(container, fg_color="transparent")
        g_frame.pack(fill="x", padx=20, pady=6)
        ctk.CTkLabel(
            g_frame,
            text="Gemini API Key:",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_SECONDARY,
            width=160,
            anchor="w"
        ).pack(side="left")

        self.entry_gemini_key = ctk.CTkEntry(
            g_frame,
            placeholder_text="Enter Gemini API key (e.g. AIzaSy...)",
            show="*",
            width=360,
            font=(CyberTheme.FONT_MONO, 11)
        )
        cur_gkey = self.db.get_setting("gemini_api_key", "")
        if cur_gkey:
            self.entry_gemini_key.insert(0, cur_gkey)
        self.entry_gemini_key.pack(side="left", padx=10)

        # OpenAI Key
        o_frame = ctk.CTkFrame(container, fg_color="transparent")
        o_frame.pack(fill="x", padx=20, pady=6)
        ctk.CTkLabel(
            o_frame,
            text="OpenAI API Key:",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_SECONDARY,
            width=160,
            anchor="w"
        ).pack(side="left")

        self.entry_openai_key = ctk.CTkEntry(
            o_frame,
            placeholder_text="Enter OpenAI API key (e.g. sk-...)",
            show="*",
            width=360,
            font=(CyberTheme.FONT_MONO, 11)
        )
        cur_okey = self.db.get_setting("openai_api_key", "")
        if cur_okey:
            self.entry_openai_key.insert(0, cur_okey)
        self.entry_openai_key.pack(side="left", padx=10)

        # 2. Vault & Performance Parameters
        ctk.CTkFrame(container, height=1, fg_color=CyberTheme.BORDER).pack(fill="x", padx=20, pady=16)

        lbl_vault = ctk.CTkLabel(
            container,
            text="SNAPSHOT VAULT & DEBOUNCE TIMERS",
            font=(CyberTheme.FONT_FAMILY, 13, "bold"),
            text_color=CyberTheme.ACCENT_CYAN
        )
        lbl_vault.pack(anchor="w", padx=20, pady=(0, 8))

        # Vault path
        v_frame = ctk.CTkFrame(container, fg_color="transparent")
        v_frame.pack(fill="x", padx=20, pady=4)
        ctk.CTkLabel(
            v_frame,
            text="Snapshot Vault Path:",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_SECONDARY,
            width=160,
            anchor="w"
        ).pack(side="left")

        lbl_vpath = ctk.CTkLabel(
            v_frame,
            text=str(config.VAULT_DIR.resolve()),
            font=(CyberTheme.FONT_MONO, 11),
            text_color=CyberTheme.TEXT_MONO
        )
        lbl_vpath.pack(side="left", padx=10)

        # Debounce timer
        d_frame = ctk.CTkFrame(container, fg_color="transparent")
        d_frame.pack(fill="x", padx=20, pady=6)
        ctk.CTkLabel(
            d_frame,
            text="Debounce Interval (ms):",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_SECONDARY,
            width=160,
            anchor="w"
        ).pack(side="left")

        self.entry_debounce = ctk.CTkEntry(
            d_frame,
            width=100,
            font=(CyberTheme.FONT_FAMILY, 12)
        )
        self.entry_debounce.insert(0, str(int(config.DEBOUNCE_INTERVAL_SEC * 1000)))
        self.entry_debounce.pack(side="left", padx=10)

        # Max snapshot size
        m_frame = ctk.CTkFrame(container, fg_color="transparent")
        m_frame.pack(fill="x", padx=20, pady=6)
        ctk.CTkLabel(
            m_frame,
            text="Max Snapshot Size (MB):",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_SECONDARY,
            width=160,
            anchor="w"
        ).pack(side="left")

        self.entry_max_size = ctk.CTkEntry(
            m_frame,
            width=100,
            font=(CyberTheme.FONT_FAMILY, 12)
        )
        self.entry_max_size.insert(0, str(int(config.MAX_SNAPSHOT_SIZE_BYTES / (1024 * 1024))))
        self.entry_max_size.pack(side="left", padx=10)

        # 3. Novelty Statement Banner
        ctk.CTkFrame(container, height=1, fg_color=CyberTheme.BORDER).pack(fill="x", padx=20, pady=16)

        lbl_nov = ctk.CTkLabel(
            container,
            text="SYSTEM ARCHITECTURE & NOVELTY STATEMENT",
            font=(CyberTheme.FONT_FAMILY, 13, "bold"),
            text_color=CyberTheme.ACCENT_CYAN
        )
        lbl_nov.pack(anchor="w", padx=20, pady=(0, 6))

        txt_nov = ctk.CTkLabel(
            container,
            text=config.NOVELTY_STATEMENT,
            font=(CyberTheme.FONT_FAMILY, 11),
            text_color=CyberTheme.TEXT_SECONDARY,
            wraplength=650,
            justify="left"
        )
        txt_nov.pack(anchor="w", padx=20, pady=(0, 16))

        # Save Button
        self.btn_save = ctk.CTkButton(
            container,
            text="💾 Save All Configuration Settings",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#238636",
            hover_color="#2EA043",
            height=34,
            command=self._save_settings
        )
        self.btn_save.pack(anchor="w", padx=20, pady=(8, 24))

    def _save_settings(self):
        provider = self.provider_var.get().strip()
        gemini_key = self.entry_gemini_key.get().strip()
        openai_key = self.entry_openai_key.get().strip()

        self.db.set_setting("ai_provider", provider)
        if gemini_key:
            self.db.set_setting("gemini_api_key", gemini_key)
        if openai_key:
            self.db.set_setting("openai_api_key", openai_key)

        try:
            deb_ms = float(self.entry_debounce.get().strip())
            config.DEBOUNCE_INTERVAL_SEC = deb_ms / 1000.0
            self.app.monitor.debounce_sec = config.DEBOUNCE_INTERVAL_SEC
        except ValueError:
            pass

        try:
            mb = float(self.entry_max_size.get().strip())
            config.MAX_SNAPSHOT_SIZE_BYTES = int(mb * 1024 * 1024)
        except ValueError:
            pass

        self.app.show_notification("Configuration saved successfully.")
