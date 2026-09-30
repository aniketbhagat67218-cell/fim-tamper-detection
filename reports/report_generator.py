"""
Forensic Audit Report Generator producing professional HTML (with printable styling)
and Markdown incident reports.
"""
import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import config
from database.db_manager import get_db

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FIM Forensic Audit Report - {file_name}</title>
    <style>
        :root {{
            --bg-primary: #0D1117;
            --bg-card: #161B22;
            --border-color: #30363D;
            --text-primary: #E6EDF3;
            --text-muted: #8B949E;
            --accent-cyan: #00F0FF;
            --accent-emerald: #00E676;
            --accent-amber: #FFB300;
            --accent-crimson: #FF5252;
            --code-bg: #090D13;
        }}
        @media print {{
            body {{ background-color: #FFFFFF !important; color: #000000 !important; }}
            .card {{ border: 1px solid #CCCCCC !important; background-color: #FAFAFA !important; page-break-inside: avoid; }}
            .diff-container {{ background-color: #F6F8FA !important; border: 1px solid #DDDDDD !important; }}
            .no-print {{ display: none !important; }}
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 30px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .logo-title {{
            display: flex;
            flex-direction: column;
        }}
        .system-badge {{
            display: inline-block;
            background: rgba(0, 240, 255, 0.15);
            color: var(--accent-cyan);
            border: 1px solid var(--accent-cyan);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: 700;
            margin-bottom: 8px;
            width: fit-content;
        }}
        h1 {{
            margin: 0;
            font-size: 26px;
            color: #FFFFFF;
        }}
        .report-meta {{
            text-align: right;
            font-size: 13px;
            color: var(--text-muted);
        }}
        .risk-badge {{
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .risk-HIGH {{ background: rgba(255, 82, 82, 0.2); color: var(--accent-crimson); border: 1px solid var(--accent-crimson); }}
        .risk-MEDIUM {{ background: rgba(255, 179, 0, 0.2); color: var(--accent-amber); border: 1px solid var(--accent-amber); }}
        .risk-LOW {{ background: rgba(0, 230, 118, 0.2); color: var(--accent-emerald); border: 1px solid var(--accent-emerald); }}
        .risk-CLEAN {{ background: rgba(0, 240, 255, 0.2); color: var(--accent-cyan); border: 1px solid var(--accent-cyan); }}

        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .card-title {{
            font-size: 16px;
            font-weight: 600;
            margin-top: 0;
            margin-bottom: 16px;
            color: var(--accent-cyan);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 8px;
        }}
        table.meta-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        table.meta-table td {{
            padding: 8px 12px;
            border-bottom: 1px solid rgba(48, 54, 61, 0.5);
        }}
        table.meta-table td.label {{
            color: var(--text-muted);
            width: 25%;
            font-weight: 600;
        }}
        table.meta-table td.mono {{
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            word-break: break-all;
            color: #7EE787;
        }}
        table.meta-table td.mono-alert {{
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            word-break: break-all;
            color: var(--accent-crimson);
            font-weight: bold;
        }}
        .heuristic-item {{
            background: rgba(22, 27, 34, 0.8);
            border-left: 4px solid var(--accent-amber);
            padding: 12px 16px;
            margin-bottom: 10px;
            border-radius: 0 6px 6px 0;
        }}
        .heuristic-item.high {{ border-left-color: var(--accent-crimson); }}
        .heuristic-title {{
            font-weight: 600;
            font-size: 14px;
            color: #FFFFFF;
        }}
        .heuristic-desc {{
            font-size: 13px;
            color: var(--text-muted);
            margin: 4px 0;
        }}
        .diff-container {{
            background: var(--code-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 12px;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 12px;
            overflow-x: auto;
            white-space: pre-wrap;
            line-height: 1.5;
        }}
        .diff-add {{ color: #7EE787; background: rgba(46, 160, 67, 0.15); display: block; }}
        .diff-del {{ color: #FF7B72; background: rgba(248, 81, 73, 0.15); display: block; }}
        .diff-ctx {{ color: #8B949E; display: block; }}
        .ai-box {{
            background: rgba(0, 240, 255, 0.05);
            border: 1px solid rgba(0, 240, 255, 0.3);
            border-radius: 6px;
            padding: 16px;
            margin-top: 10px;
        }}
        ul.recs {{
            margin: 8px 0 0 20px;
            padding: 0;
        }}
        ul.recs li {{
            margin-bottom: 6px;
            font-size: 13px;
        }}
        .footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 40px;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="logo-title">
            <span class="system-badge">FIM Security System &bull; Forensic Audit</span>
            <h1>File Integrity Incident Report</h1>
        </div>
        <div class="report-meta">
            <div>Incident ID: <strong>#{event_id}</strong></div>
            <div>Generated: <strong>{timestamp}</strong></div>
            <div style="margin-top: 8px;">
                <span class="risk-badge risk-{risk_level}">{risk_level} RISK (Score: {risk_score}/100)</span>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-title">1. Monitored Target Identification</div>
        <table class="meta-table">
            <tr>
                <td class="label">File Name:</td>
                <td><strong>{file_name}</strong></td>
            </tr>
            <tr>
                <td class="label">Full Filesystem Path:</td>
                <td class="mono">{file_path}</td>
            </tr>
            <tr>
                <td class="label">Event Classification:</td>
                <td><span style="font-weight: bold; color: {event_color};">{event_type}</span> ({diff_summary})</td>
            </tr>
            <tr>
                <td class="label">Tampering Timestamp:</td>
                <td>{timestamp}</td>
            </tr>
        </table>
    </div>

    <div class="card">
        <div class="card-title">2. Dual-Primitive Cryptographic Verification</div>
        <table class="meta-table">
            <tr>
                <td class="label">Baseline SHA-256:</td>
                <td class="mono">{old_sha256}</td>
            </tr>
            <tr>
                <td class="label">Current SHA-256:</td>
                <td class="mono-alert">{new_sha256}</td>
            </tr>
            <tr>
                <td class="label">Baseline SHA-3-256:</td>
                <td class="mono">{old_sha3_256}</td>
            </tr>
            <tr>
                <td class="label">Current SHA-3-256:</td>
                <td class="mono-alert">{new_sha3_256}</td>
            </tr>
            <tr>
                <td class="label">Collision Resistance:</td>
                <td>Sponge-construction SHA-3 validates absence of standard SHA-2 length-extension attacks.</td>
            </tr>
        </table>
    </div>

    <div class="card">
        <div class="card-title">3. Deterministic Heuristic Risk Analysis</div>
        <p style="font-size: 13px; color: var(--text-muted); margin-top: 0;">
            Static heuristic engine evaluated modification deltas against privilege escalation, defense evasion, and secret leakage rules.
        </p>
        {heuristics_html}
    </div>

    <div class="card">
        <div class="card-title">4. Unified Syntactic Diff Delta</div>
        <div class="diff-container">
{diff_html}
        </div>
    </div>

    <div class="card">
        <div class="card-title">5. AI Threat Advisory & Recommended Incident Response</div>
        <div class="ai-box">
            <h4 style="margin: 0 0 8px 0; color: var(--accent-cyan);">Executive Threat Summary</h4>
            <p style="font-size: 13px; margin: 0 0 12px 0;">{ai_summary}</p>

            <h4 style="margin: 12px 0 6px 0; color: var(--accent-amber);">Immediate Remediation Actions</h4>
            <ul class="recs">
                {remediation_items_html}
            </ul>
        </div>
    </div>

    <div class="footer">
        <p>Generated by <strong>File Integrity Monitoring & Tampering Detection System</strong></p>
        <p style="font-size: 11px; max-width: 800px; margin: 0 auto;">{novelty_statement}</p>
    </div>
</div>
</body>
</html>
"""

class ReportGenerator:
    def __init__(self):
        self.db = get_db()
        self.reports_dir = config.REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_html_report(self, event_id: int, output_path: Optional[Path] = None) -> Path:
        """Generates a standalone, beautifully formatted forensic audit report in HTML."""
        event = self.db.get_event_by_id(event_id)
        if not event:
            raise ValueError(f"Event ID {event_id} not found in database.")

        p = Path(event["file_path"])
        file_name = p.name

        # Parse AI summary if JSON or string
        ai_summary_text = "No AI analysis performed."
        remediation_items = ["Audit the file changes manually and revert if unauthorized."]
        if event["ai_summary"]:
            try:
                ai_parsed = json.loads(event["ai_summary"])
                ai_summary_text = ai_parsed.get("executive_summary", event["ai_summary"])
                remediation_items = ai_parsed.get("recommended_actions", remediation_items)
            except Exception:
                ai_summary_text = event["ai_summary"]

        remediation_html = "".join([f"<li>{item}</li>" for item in remediation_items])

        # Heuristics formatting
        heuristics_html = ""
        if event["detected_heuristics"]:
            for h in event["detected_heuristics"]:
                cat_class = "high" if h.get("category") == "HIGH" else "med"
                line_info = f" (Line {h.get('line_number')})" if h.get('line_number') else ""
                heuristics_html += f"""
                <div class="heuristic-item {cat_class}">
                    <div class="heuristic-title">{h.get('rule_name', 'Rule')} &bull; [{h.get('category')}] {line_info}</div>
                    <div class="heuristic-desc">{h.get('description', '')}</div>
                    <div style="font-family: monospace; font-size: 11px; color: #7EE787;">Matched: {h.get('line_content', '')}</div>
                </div>
                """
        else:
            heuristics_html = "<p style='font-size: 13px; color: #8B949E;'>No high or medium security patterns matched.</p>"

        # Diff rendering
        diff_summary = event["diff_summary"] or ""
        # If we have baseline snapshot, read it and generate formatted unified diff
        diff_html = ""
        if event["file_id"]:
            from core.comparator import compare_file_with_baseline
            comp = compare_file_with_baseline(
                file_id=event["file_id"],
                current_path=event["file_path"],
                old_sha256=event["old_sha256"] or "",
                new_sha256=event["new_sha256"] or ""
            )
            if comp.raw_unified_diff:
                for line in comp.raw_unified_diff.splitlines():
                    safe_line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    if safe_line.startswith("+"):
                        diff_html += f'<span class="diff-add">{safe_line}</span>\n'
                    elif safe_line.startswith("-"):
                        diff_html += f'<span class="diff-del">{safe_line}</span>\n'
                    else:
                        diff_html += f'<span class="diff-ctx">{safe_line}</span>\n'
            else:
                diff_html = f'<span class="diff-ctx">{diff_summary}</span>'
        else:
            diff_html = f'<span class="diff-ctx">{diff_summary}</span>'

        event_color = "#FF5252" if event["event_type"] in ("MODIFIED", "DELETED") else "#00E676"

        html_content = HTML_TEMPLATE.format(
            event_id=event["id"],
            timestamp=event["timestamp"],
            file_name=file_name,
            file_path=event["file_path"],
            event_type=event["event_type"],
            event_color=event_color,
            diff_summary=diff_summary,
            risk_level=event["risk_level"],
            risk_score=event["risk_score"],
            old_sha256=event["old_sha256"] or "N/A (New File)",
            new_sha256=event["new_sha256"] or "N/A (Deleted)",
            old_sha3_256=event["old_sha3_256"] or "N/A (New File)",
            new_sha3_256=event["new_sha3_256"] or "N/A (Deleted)",
            heuristics_html=heuristics_html,
            diff_html=diff_html,
            ai_summary=ai_summary_text,
            remediation_items_html=remediation_html,
            novelty_statement=config.NOVELTY_STATEMENT
        )

        target_file = output_path or (self.reports_dir / f"audit_report_event_{event_id}_{int(datetime.now().timestamp())}.html")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        return target_file

    def generate_markdown_report(self, event_id: int, output_path: Optional[Path] = None) -> Path:
        """Generates a compliance Markdown report for documentation or Git logging."""
        event = self.db.get_event_by_id(event_id)
        if not event:
            raise ValueError(f"Event ID {event_id} not found in database.")

        p = Path(event["file_path"])
        file_name = p.name

        md = f"""# Forensic Audit Report: {file_name}

**Incident ID:** #{event['id']}  
**Timestamp:** {event['timestamp']}  
**Risk Level:** {event['risk_level']} (Score: {event['risk_score']}/100)  
**Event Type:** {event['event_type']}  

---

## 1. Asset Identification
- **Target File:** `{event['file_path']}`
- **Classification:** {event['diff_summary']}

## 2. Dual-Primitive Cryptographic Verification
| Metric | Baseline Value | Current Value |
| :--- | :--- | :--- |
| **SHA-256** | `{event['old_sha256'] or 'N/A'}` | `{event['new_sha256'] or 'N/A'}` |
| **SHA-3-256** | `{event['old_sha3_256'] or 'N/A'}` | `{event['new_sha3_256'] or 'N/A'}` |

## 3. Heuristic Rules Triggered
"""
        if event["detected_heuristics"]:
            for h in event["detected_heuristics"]:
                md += f"- **[{h.get('category')}] {h.get('rule_name')}** (Line {h.get('line_number') or 'N/A'}): {h.get('description')}\n"
                md += f"  - Matched: `{h.get('line_content')}`\n"
        else:
            md += "No high or medium security heuristic triggers recorded.\n"

        md += f"""
## 4. AI Threat Advisory
{event['ai_summary'] or 'No AI advisory recorded.'}

---
*System Architecture: Dual SHA-2/SHA-3 verification, local delta vaulting, deterministic heuristics, and privacy-sanitized AI triage.*
"""
        target_file = output_path or (self.reports_dir / f"audit_report_event_{event_id}_{int(datetime.now().timestamp())}.md")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(md)

        return target_file

def generate_audit_report(event_id: int, format: str = "html") -> Path:
    gen = ReportGenerator()
    if format.lower() == "markdown" or format.lower() == "md":
        return gen.generate_markdown_report(event_id)
    return gen.generate_html_report(event_id)
