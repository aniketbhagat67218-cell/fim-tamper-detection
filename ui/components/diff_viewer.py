"""
Color-coded syntax diff viewer component for displaying unified diffs
with line numbers, addition/deletion styling, and binary delta support.
"""
import customtkinter as ctk
from typing import List, Optional
from ui.theme import CyberTheme
from core.comparator import ComparisonResult, DiffLine

class DiffViewer(ctk.CTkFrame):
    def __init__(self, master, height: int = 400, **kwargs):
        super().__init__(
            master,
            fg_color=CyberTheme.BG_CARD,
            border_color=CyberTheme.BORDER,
            border_width=1,
            corner_radius=8,
            **kwargs
        )
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Toolbar
        self.toolbar = ctk.CTkFrame(self, fg_color=CyberTheme.BG_SIDEBAR, height=36, corner_radius=6)
        self.toolbar.grid(row=0, column=0, sticky="ew", padx=6, pady=(6, 4))
        self.toolbar.grid_columnconfigure(0, weight=1)

        self.lbl_info = ctk.CTkLabel(
            self.toolbar,
            text="DIFF INSPECTION CONSOLE",
            font=(CyberTheme.FONT_FAMILY, 11, "bold"),
            text_color=CyberTheme.ACCENT_CYAN
        )
        self.lbl_info.grid(row=0, column=0, padx=12, pady=6, sticky="w")

        self.btn_copy = ctk.CTkButton(
            self.toolbar,
            text="Copy Diff",
            width=80,
            height=26,
            fg_color="#21262D",
            hover_color="#30363D",
            font=(CyberTheme.FONT_FAMILY, 11),
            command=self._copy_to_clipboard
        )
        self.btn_copy.grid(row=0, column=1, padx=8, pady=4)

        # Main Text Widget (supports tags for colored syntax)
        self.text_area = ctk.CTkTextbox(
            self,
            fg_color=CyberTheme.BG_DIFF,
            text_color=CyberTheme.TEXT_PRIMARY,
            font=(CyberTheme.FONT_MONO, 12),
            wrap="none",
            corner_radius=6,
            border_width=0
        )
        self.text_area.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

        # Configure color tags inside Tkinter Text widget
        self._setup_tags()

        self._raw_text = ""

    def _setup_tags(self):
        # Access underlying tk widget
        tk_txt = self.text_area._textbox
        tk_txt.tag_config("addition", foreground=CyberTheme.TEXT_DIFF_ADD, background="#0D281E")
        tk_txt.tag_config("deletion", foreground=CyberTheme.TEXT_DIFF_DEL, background="#2E1014")
        tk_txt.tag_config("context", foreground=CyberTheme.TEXT_SECONDARY)
        tk_txt.tag_config("header", foreground=CyberTheme.ACCENT_CYAN, font=(CyberTheme.FONT_MONO, 12, "bold"))
        tk_txt.tag_config("lineno", foreground=CyberTheme.TEXT_MUTED)
        tk_txt.tag_config("binary", foreground=CyberTheme.ACCENT_AMBER, font=(CyberTheme.FONT_FAMILY, 13))

    def display_diff(self, comparison: ComparisonResult):
        """Renders either formatted text diff or binary delta summary."""
        self.text_area.configure(state="normal")
        self.text_area.delete("1.0", "end")
        tk_txt = self.text_area._textbox

        if comparison.is_binary:
            self.lbl_info.configure(text=f"BINARY DELTA INSPECTION (Size Delta: {comparison.size_delta:+d} bytes)")
            text = (
                f"--- BINARY FILE VARIANCE DETECTED ---\n\n"
                f"File Size: {comparison.new_size:,} bytes (Baseline: {comparison.old_size:,} bytes)\n"
                f"Size Delta: {comparison.size_delta:+d} bytes\n\n"
                f"Baseline SHA-256: {comparison.old_sha256}\n"
                f"Current  SHA-256: {comparison.new_sha256}\n\n"
                f"Note: Text difflib is bypassed for compiled/binary assets to protect memory."
            )
            self._raw_text = text
            tk_txt.insert("end", text, "binary")
            self.text_area.configure(state="disabled")
            return

        if comparison.is_identical:
            self.lbl_info.configure(text="DIFF CONSOLE: Identical (No differences)")
            msg = "File contents match baseline snapshot byte-for-byte. No delta detected."
            self._raw_text = msg
            tk_txt.insert("end", msg, "context")
            self.text_area.configure(state="disabled")
            return

        self.lbl_info.configure(
            text=f"DIFF: +{comparison.added_count} Added | -{comparison.deleted_count} Deleted"
        )

        self._raw_text = comparison.raw_unified_diff

        # Render structured line diff
        for diff_line in comparison.diff_lines:
            old_num = f"{diff_line.line_no_old:4d} " if diff_line.line_no_old else "     "
            new_num = f"{diff_line.line_no_new:4d} " if diff_line.line_no_new else "     "
            line_prefix = f"{old_num} {new_num} | "

            tk_txt.insert("end", line_prefix, "lineno")

            if diff_line.line_type == "+":
                tk_txt.insert("end", f"+ {diff_line.content}\n", "addition")
            elif diff_line.line_type == "-":
                tk_txt.insert("end", f"- {diff_line.content}\n", "deletion")
            else:
                tk_txt.insert("end", f"  {diff_line.content}\n", "context")

        self.text_area.configure(state="disabled")

    def display_raw_text(self, text: str, header: str = "TEXT CONSOLE"):
        self.lbl_info.configure(text=header)
        self._raw_text = text
        self.text_area.configure(state="normal")
        self.text_area.delete("1.0", "end")
        self.text_area.insert("end", text)
        self.text_area.configure(state="disabled")

    def _copy_to_clipboard(self):
        if self._raw_text:
            self.clipboard_clear()
            self.clipboard_append(self._raw_text)
            prev_text = self.btn_copy.cget("text")
            self.btn_copy.configure(text="Copied!")
            self.after(1500, lambda: self.btn_copy.configure(text=prev_text))
