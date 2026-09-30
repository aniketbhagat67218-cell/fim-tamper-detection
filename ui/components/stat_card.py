"""
Reusable Metric/Stat Card component for CustomTkinter.
"""
import customtkinter as ctk
from ui.theme import CyberTheme

class StatCard(ctk.CTkFrame):
    def __init__(self, master, title: str, value: str = "0",
                 accent_color: str = CyberTheme.ACCENT_CYAN,
                 subtitle: str = "", **kwargs):
        super().__init__(
            master,
            fg_color=CyberTheme.BG_CARD,
            border_color=CyberTheme.BORDER,
            border_width=1,
            corner_radius=8,
            **kwargs
        )
        self.accent_color = accent_color

        # Card container
        self.grid_columnconfigure(0, weight=1)

        # Title label
        self.lbl_title = ctk.CTkLabel(
            self,
            text=title.upper(),
            font=(CyberTheme.FONT_FAMILY, 11, "bold"),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        self.lbl_title.pack(anchor="w", padx=16, pady=(12, 4))

        # Main numeric/metric display
        self.lbl_value = ctk.CTkLabel(
            self,
            text=str(value),
            font=(CyberTheme.FONT_FAMILY, 28, "bold"),
            text_color=self.accent_color
        )
        self.lbl_value.pack(anchor="w", padx=16, pady=(0, 2))

        # Subtitle / trend
        self.lbl_sub = ctk.CTkLabel(
            self,
            text=subtitle,
            font=(CyberTheme.FONT_FAMILY, 11),
            text_color=CyberTheme.TEXT_MUTED
        )
        self.lbl_sub.pack(anchor="w", padx=16, pady=(0, 12))

    def update_value(self, value: str | int, subtitle: str = None):
        self.lbl_value.configure(text=str(value))
        if subtitle is not None:
            self.lbl_sub.configure(text=subtitle)
