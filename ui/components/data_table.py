"""
Reusable Data Table component for CustomTkinter with sorting, status badges,
and smooth row selection.
"""
import customtkinter as ctk
from typing import List, Dict, Any, Optional, Callable
from ui.theme import CyberTheme

class DataTable(ctk.CTkFrame):
    def __init__(self, master, columns: List[Dict[str, Any]],
                 on_select: Optional[Callable[[Dict[str, Any]], None]] = None,
                 height: int = 350, **kwargs):
        super().__init__(
            master,
            fg_color=CyberTheme.BG_CARD,
            border_color=CyberTheme.BORDER,
            border_width=1,
            corner_radius=8,
            **kwargs
        )
        self.columns = columns  # [{"key": "name", "title": "File Name", "width": 150, "weight": 2}]
        self.on_select = on_select
        self.rows_data: List[Dict[str, Any]] = []
        self.selected_row_data: Optional[Dict[str, Any]] = None
        self.selected_row_frame: Optional[ctk.CTkFrame] = None

        self._build_header()
        self.scroll_area = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            height=height
        )
        self.scroll_area.pack(fill="both", expand=True, padx=2, pady=(0, 2))

    def _build_header(self):
        header_frame = ctk.CTkFrame(
            self,
            fg_color=CyberTheme.BG_SIDEBAR,
            height=36,
            corner_radius=6
        )
        header_frame.pack(fill="x", padx=6, pady=(6, 4))

        for idx, col in enumerate(self.columns):
            header_frame.grid_columnconfigure(idx, weight=col.get("weight", 1))
            lbl = ctk.CTkLabel(
                header_frame,
                text=col.get("title", "").upper(),
                font=(CyberTheme.FONT_FAMILY, 11, "bold"),
                text_color=CyberTheme.TEXT_SECONDARY,
                anchor="w"
            )
            lbl.grid(row=0, column=idx, padx=10, pady=6, sticky="ew")

    def set_rows(self, data: List[Dict[str, Any]]):
        """Clears and re-populates table with data records."""
        self.rows_data = data
        self.selected_row_data = None
        self.selected_row_frame = None

        for child in self.scroll_area.winfo_children():
            child.destroy()

        if not data:
            empty_lbl = ctk.CTkLabel(
                self.scroll_area,
                text="No records found.",
                font=(CyberTheme.FONT_FAMILY, 12),
                text_color=CyberTheme.TEXT_MUTED
            )
            empty_lbl.pack(pady=30)
            return

        for r_idx, row in enumerate(data):
            bg_color = CyberTheme.BG_CARD if r_idx % 2 == 0 else CyberTheme.BG_MAIN
            row_frame = ctk.CTkFrame(
                self.scroll_area,
                fg_color=bg_color,
                corner_radius=4,
                cursor="hand2"
            )
            row_frame.pack(fill="x", pady=2, padx=4)

            # Bind click
            row_frame.bind("<Button-1>", lambda e, r=row, f=row_frame: self._on_row_click(r, f))

            for c_idx, col in enumerate(self.columns):
                row_frame.grid_columnconfigure(c_idx, weight=col.get("weight", 1))
                key = col.get("key")
                val = str(row.get(key, ""))

                # Status badge styling
                if key in ("status", "risk_level", "event_type"):
                    badge_color = CyberTheme.get_risk_color(val) if key == "risk_level" else CyberTheme.get_status_color(val)
                    lbl = ctk.CTkLabel(
                        row_frame,
                        text=f" {val} ",
                        font=(CyberTheme.FONT_FAMILY, 11, "bold"),
                        text_color=badge_color,
                        anchor="w"
                    )
                else:
                    # Mono font for hashes or paths
                    is_mono = "sha" in key or "path" in key
                    font_style = (CyberTheme.FONT_MONO, 11) if is_mono else (CyberTheme.FONT_FAMILY, 12)
                    text_col = CyberTheme.TEXT_MONO if is_mono else CyberTheme.TEXT_PRIMARY
                    
                    # Truncate long text
                    max_len = col.get("max_chars", 50)
                    display_text = (val[:max_len] + "...") if len(val) > max_len else val

                    lbl = ctk.CTkLabel(
                        row_frame,
                        text=display_text,
                        font=font_style,
                        text_color=text_col,
                        anchor="w"
                    )

                lbl.grid(row=0, column=c_idx, padx=10, pady=6, sticky="ew")
                lbl.bind("<Button-1>", lambda e, r=row, f=row_frame: self._on_row_click(r, f))

    def _on_row_click(self, row: Dict[str, Any], frame: ctk.CTkFrame):
        # Reset previous selection
        if self.selected_row_frame and self.selected_row_frame.winfo_exists():
            self.selected_row_frame.configure(border_width=0)

        # Highlight new selection
        self.selected_row_frame = frame
        self.selected_row_data = row
        frame.configure(border_width=1, border_color=CyberTheme.ACCENT_CYAN)

        if self.on_select:
            self.on_select(row)

    def get_selected(self) -> Optional[Dict[str, Any]]:
        return self.selected_row_data
