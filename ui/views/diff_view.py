"""
Change Analysis View providing cryptographic comparison, color-coded unified diffing,
deterministic heuristic risk assessment, and privacy-sanitized AI incident triage.
"""
import threading
from pathlib import Path
import customtkinter as ctk
from typing import Optional, Dict, Any

from ui.theme import CyberTheme
from ui.components.diff_viewer import DiffViewer
from database.db_manager import get_db
from core.hasher import compute_dual_hash
from core.comparator import compare_file_with_baseline, ComparisonResult
from core.risk_analyzer import analyze_diff_risk, RiskAssessment
from core.ai_advisor import get_ai_advisor, AIAdvisorResponse

class DiffView(ctk.CTkFrame):
    def __init__(self, master, app_controller, **kwargs):
        super().__init__(master, fg_color=CyberTheme.BG_MAIN, **kwargs)
        self.app = app_controller
        self.db = get_db()
        self.ai_advisor = get_ai_advisor()

        self.current_file_id: Optional[int] = None
        self.current_event_id: Optional[int] = None
        self.last_comparison: Optional[ComparisonResult] = None
        self.last_risk: Optional[RiskAssessment] = None

        self.grid_columnconfigure(0, weight=6)
        self.grid_columnconfigure(1, weight=4)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_left_diff_pane()
        self._build_right_triage_pane()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=24, pady=(20, 12))
        header.grid_columnconfigure(1, weight=1)

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.grid(row=0, column=0, sticky="w")

        self.lbl_title = ctk.CTkLabel(
            title_box,
            text="FORENSIC CHANGE & TAMPER ANALYSIS",
            font=(CyberTheme.FONT_FAMILY, 20, "bold"),
            text_color=CyberTheme.TEXT_PRIMARY
        )
        self.lbl_title.pack(anchor="w")

        self.lbl_target = ctk.CTkLabel(
            title_box,
            text="No file selected. Select a file from Monitored Files or Dashboard.",
            font=(CyberTheme.FONT_FAMILY, 12),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        self.lbl_target.pack(anchor="w")

        # Top Hash Indicators
        self.hash_box = ctk.CTkFrame(header, fg_color=CyberTheme.BG_CARD, corner_radius=6, border_width=1, border_color=CyberTheme.BORDER)
        self.hash_box.grid(row=0, column=1, sticky="e", padx=10)

        self.lbl_hash_stat = ctk.CTkLabel(
            self.hash_box,
            text="DUAL HASH: WAITING",
            font=(CyberTheme.FONT_MONO, 11, "bold"),
            text_color=CyberTheme.TEXT_MUTED
        )
        self.lbl_hash_stat.pack(padx=12, pady=6)

    def _build_left_diff_pane(self):
        left_frame = ctk.CTkFrame(self, fg_color="transparent")
        left_frame.grid(row=1, column=0, sticky="nsew", padx=(24, 12), pady=(0, 20))
        left_frame.grid_columnconfigure(0, weight=1)
        left_frame.grid_rowconfigure(1, weight=1)

        lbl_pane = ctk.CTkLabel(
            left_frame,
            text="SYNTACTIC DELTA RECONSTRUCTION (DIFFLIB)",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            text_color=CyberTheme.TEXT_SECONDARY
        )
        lbl_pane.grid(row=0, column=0, sticky="w", pady=(0, 6))

        self.diff_viewer = DiffViewer(left_frame, height=450)
        self.diff_viewer.grid(row=1, column=0, sticky="nsew")

    def _build_right_triage_pane(self):
        right_frame = ctk.CTkScrollableFrame(
            self,
            fg_color=CyberTheme.BG_CARD,
            border_color=CyberTheme.BORDER,
            border_width=1,
            corner_radius=8
        )
        right_frame.grid(row=1, column=1, sticky="nsew", padx=(0, 24), pady=(0, 20))
        right_frame.grid_columnconfigure(0, weight=1)

        # 1. Deterministic Heuristics Card
        lbl_sec1 = ctk.CTkLabel(
            right_frame,
            text="STATIC HEURISTIC RISK ENGINE",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            text_color=CyberTheme.ACCENT_CYAN
        )
        lbl_sec1.pack(anchor="w", padx=16, pady=(16, 4))

        self.risk_badge_box = ctk.CTkFrame(right_frame, fg_color=CyberTheme.BG_MAIN, corner_radius=6)
        self.risk_badge_box.pack(fill="x", padx=16, pady=(0, 10))

        self.lbl_risk_level = ctk.CTkLabel(
            self.risk_badge_box,
            text="STATUS: UNKNOWN",
            font=(CyberTheme.FONT_FAMILY, 14, "bold"),
            text_color=CyberTheme.TEXT_MUTED
        )
        self.lbl_risk_level.pack(padx=12, pady=8, anchor="w")

        self.heuristics_list_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        self.heuristics_list_frame.pack(fill="x", padx=16, pady=(0, 12))

        # Disclaimer
        self.lbl_disclaimer = ctk.CTkLabel(
            right_frame,
            text="Notice: Deterministic heuristic risk assessment, not definitive malicious intent.",
            font=(CyberTheme.FONT_FAMILY, 10),
            text_color=CyberTheme.TEXT_MUTED,
            wraplength=280,
            justify="left"
        )
        self.lbl_disclaimer.pack(anchor="w", padx=16, pady=(0, 16))

        # Divider
        ctk.CTkFrame(right_frame, height=1, fg_color=CyberTheme.BORDER).pack(fill="x", padx=16, pady=(0, 16))

        # 2. AI Threat Advisory Card
        lbl_sec2 = ctk.CTkLabel(
            right_frame,
            text="AI THREAT ADVISORY (PRIVACY SANITIZED)",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            text_color=CyberTheme.ACCENT_CYAN
        )
        lbl_sec2.pack(anchor="w", padx=16, pady=(0, 8))

        self.btn_ai_triage = ctk.CTkButton(
            right_frame,
            text="✨ Generate AI Threat Advisory",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg_color="#1F6FEB",
            hover_color="#388BFD",
            height=34,
            command=self._run_ai_triage
        )
        self.btn_ai_triage.pack(fill="x", padx=16, pady=(0, 12))

        self.lbl_ai_status = ctk.CTkLabel(
            right_frame,
            text="Click above to redact secrets and generate incident advice.",
            font=(CyberTheme.FONT_FAMILY, 11),
            text_color=CyberTheme.TEXT_MUTED,
            wraplength=280
        )
        self.lbl_ai_status.pack(anchor="w", padx=16, pady=(0, 10))

        # AI Result Container
        self.ai_result_box = ctk.CTkFrame(right_frame, fg_color=CyberTheme.BG_MAIN, corner_radius=6)
        self.ai_result_box.pack(fill="x", padx=16, pady=(0, 16))

        self.txt_ai_exec = ctk.CTkLabel(
            self.ai_result_box,
            text="",
            font=(CyberTheme.FONT_FAMILY, 11),
            text_color=CyberTheme.TEXT_PRIMARY,
            justify="left",
            wraplength=280
        )
        self.txt_ai_exec.pack(anchor="w", padx=12, pady=10)

    def load_file(self, file_id: int, event_id: Optional[int] = None):
        """Loads and diffs the specified file against its baseline snapshot."""
        self.current_file_id = file_id
        self.current_event_id = event_id

        rec = self.db.get_monitored_file_by_id(file_id)
        if not rec:
            self.lbl_target.configure(text=f"File #{file_id} not found in database.")
            return

        file_path = rec["file_path"]
        p = Path(file_path)

        self.lbl_title.configure(text=f"TAMPER ANALYSIS: {p.name}")
        self.lbl_target.configure(text=str(p.resolve()))

        # Check file exists
        if not p.exists():
            self.lbl_hash_stat.configure(text="STATUS: MISSING FROM DISK", text_color=CyberTheme.ACCENT_AMBER)
            self.diff_viewer.display_raw_text("Target file has been deleted from filesystem.", "FILE DELETED")
            self.lbl_risk_level.configure(text="CRITICAL: FILE REMOVED", text_color=CyberTheme.ACCENT_CRIMSON)
            return

        # Compute current dual hash
        res = compute_dual_hash(file_path)
        if res.error:
            self.lbl_hash_stat.configure(text=f"ERROR: {res.error[:30]}", text_color=CyberTheme.ACCENT_CRIMSON)
            return

        # Hash comparison
        hashes_match = (res.sha256 == rec["sha256"] and res.sha3_256 == rec["sha3_256"])
        if hashes_match:
            self.lbl_hash_stat.configure(text="DUAL HASH: VERIFIED MATCH", text_color=CyberTheme.ACCENT_EMERALD)
        else:
            self.lbl_hash_stat.configure(text="DUAL HASH: TAMPER MISMATCH", text_color=CyberTheme.ACCENT_CRIMSON)

        # 1. Granular Diffing
        self.last_comparison = compare_file_with_baseline(
            file_id=file_id,
            current_path=file_path,
            old_sha256=rec["sha256"],
            new_sha256=res.sha256,
            old_size=rec["file_size"]
        )
        self.diff_viewer.display_diff(self.last_comparison)

        # 2. Risk Heuristics
        self.last_risk = analyze_diff_risk(self.last_comparison, file_path=file_path)
        self._render_risk_heuristics(self.last_risk)

        # Reset AI advice box
        self.txt_ai_exec.configure(text="")
        self.lbl_ai_status.configure(text="Ready to analyze.")

        # If an existing event has an AI summary in DB, load it
        if event_id:
            ev = self.db.get_event_by_id(event_id)
            if ev and ev.get("ai_summary"):
                self.txt_ai_exec.configure(text=ev["ai_summary"])
                self.lbl_ai_status.configure(text="Loaded previously generated AI advisory.")

    def _render_risk_heuristics(self, risk: RiskAssessment):
        color = CyberTheme.get_risk_color(risk.risk_level)
        self.lbl_risk_level.configure(
            text=f"{risk.risk_level} RISK (Score: {risk.overall_score}/100)",
            text_color=color
        )

        for child in self.heuristics_list_frame.winfo_children():
            child.destroy()

        if not risk.triggered_rules:
            lbl_none = ctk.CTkLabel(
                self.heuristics_list_frame,
                text="No security heuristic violations triggered.",
                font=(CyberTheme.FONT_FAMILY, 11),
                text_color=CyberTheme.TEXT_MUTED
            )
            lbl_none.pack(anchor="w", pady=4)
            return

        for rule in risk.triggered_rules:
            rule_box = ctk.CTkFrame(self.heuristics_list_frame, fg_color=CyberTheme.BG_MAIN, corner_radius=4)
            rule_box.pack(fill="x", pady=3)

            r_col = CyberTheme.get_risk_color(rule.category)
            line_str = f" [Line {rule.line_number}]" if rule.line_number else ""

            lbl_name = ctk.CTkLabel(
                rule_box,
                text=f"• {rule.rule_name}{line_str}",
                font=(CyberTheme.FONT_FAMILY, 11, "bold"),
                text_color=r_col,
                anchor="w",
                justify="left"
            )
            lbl_name.pack(anchor="w", padx=8, pady=(4, 2))

            lbl_desc = ctk.CTkLabel(
                rule_box,
                text=rule.description,
                font=(CyberTheme.FONT_FAMILY, 10),
                text_color=CyberTheme.TEXT_SECONDARY,
                wraplength=260,
                justify="left"
            )
            lbl_desc.pack(anchor="w", padx=8, pady=(0, 4))

    def _run_ai_triage(self):
        if not self.last_comparison or not self.current_file_id:
            self.app.show_notification("No file loaded for AI triage.")
            return

        self.btn_ai_triage.configure(state="disabled", text="⏳ Sanitizing & Analyzing...")
        self.lbl_ai_status.configure(text="Redacting secrets and querying AI engine...")

        rec = self.db.get_monitored_file_by_id(self.current_file_id)
        file_path = rec["file_path"] if rec else ""
        diff_text = self.last_comparison.raw_unified_diff

        heuristics_data = [
            {"rule_name": r.rule_name, "category": r.category, "line_number": r.line_number, "description": r.description}
            for r in (self.last_risk.triggered_rules if self.last_risk else [])
        ]
        risk_level = self.last_risk.risk_level if self.last_risk else "LOW"

        def worker():
            resp = self.ai_advisor.analyze_incident(
                file_path=file_path,
                diff_text=diff_text,
                heuristics_summary=heuristics_data,
                risk_level=risk_level
            )
            self.after(0, lambda: self._on_ai_complete(resp))

        threading.Thread(target=worker, daemon=True).start()

    def _on_ai_complete(self, resp: AIAdvisorResponse):
        self.btn_ai_triage.configure(state="normal", text="✨ Generate AI Threat Advisory")

        formatted_text = f"EXECUTIVE SUMMARY:\n{resp.executive_summary}\n\n"
        if resp.security_implications:
            formatted_text += "ATTACK VECTORS & IMPLICATIONS:\n"
            for imp in resp.security_implications:
                formatted_text += f"• {imp}\n"
            formatted_text += "\n"

        if resp.recommended_actions:
            formatted_text += "RECOMMENDED ACTIONS:\n"
            for act in resp.recommended_actions:
                formatted_text += f"1. {act}\n"

        self.txt_ai_exec.configure(text=formatted_text)
        status_msg = "Operating in deterministic offline mode." if resp.is_offline_fallback else "AI analysis generated successfully."
        self.lbl_ai_status.configure(text=status_msg)

        # Update event record if exists
        if self.current_event_id:
            self.db.update_event_ai_summary(self.current_event_id, formatted_text)
