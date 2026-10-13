"""
Web-Based Dashboard for the File Integrity Monitoring and Tampering Detection System.
Provides a browser interface at http://127.0.0.1:5000 powered by Flask and our existing FIM core.
"""
import os
import sys
import queue
import json
import webbrowser
from threading import Timer
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_from_directory

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config
from database.db_manager import get_db
from core.vault import get_vault
from core.hasher import compute_dual_hash
from core.comparator import compare_file_with_baseline
from core.risk_analyzer import analyze_diff_risk
from core.ai_advisor import get_ai_advisor
from core.monitor import FileIntegrityMonitor
from reports.report_generator import generate_audit_report

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
db = get_db()
vault = get_vault()
ai_advisor = get_ai_advisor()
event_queue = queue.Queue()
monitor = FileIntegrityMonitor(event_queue=event_queue)

# --- Routes ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def api_stats():
    stats = db.get_system_stats()
    stats["monitor_running"] = monitor.is_running
    return jsonify(stats)

@app.route("/api/events")
def api_events():
    events = db.get_event_history(limit=50)
    return jsonify(events)

@app.route("/api/files")
def api_files():
    files = db.get_all_monitored_files()
    return jsonify(files)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json or {}
    path = data.get("path", "").strip()
    p = Path(path)
    if not p.exists() or not p.is_file():
        return jsonify({"error": f"File does not exist: {path}"}), 400

    h = compute_dual_hash(p)
    if h.error:
        return jsonify({"error": h.error}), 400

    return jsonify({
        "file_name": p.name,
        "file_path": str(p.resolve()),
        "file_size": h.file_size,
        "sha256": h.sha256,
        "sha3_256": h.sha3_256
    })

@app.route("/api/baseline", methods=["POST"])
def api_baseline():
    data = request.json or {}
    path = data.get("path", "").strip()
    p = Path(path)
    if not p.exists() or not p.is_file():
        return jsonify({"error": f"File not found: {path}"}), 400

    h = compute_dual_hash(p)
    if h.error:
        return jsonify({"error": h.error}), 400

    file_id = db.add_monitored_file(
        file_path=str(p.resolve()),
        file_name=p.name,
        sha256=h.sha256,
        sha3_256=h.sha3_256,
        file_size=h.file_size,
        last_modified=h.last_modified,
        is_binary=h.is_binary
    )

    vault.store_snapshot(
        file_path=p,
        file_id=file_id,
        sha256=h.sha256,
        file_size=h.file_size,
        is_binary=h.is_binary
    )

    monitor.reload_monitored_files()
    return jsonify({"success": True, "file_id": file_id})

@app.route("/api/verify_all", methods=["POST"])
def api_verify_all():
    files = db.get_all_monitored_files()
    for f in files:
        monitor.manual_verify_file(f["id"])
    return jsonify({"success": True, "count": len(files)})

@app.route("/api/verify/<int:file_id>", methods=["POST"])
def api_verify_single(file_id):
    res = monitor.manual_verify_file(file_id)
    return jsonify(res)

@app.route("/api/toggle_monitor", methods=["POST"])
def api_toggle_monitor():
    if getattr(config, "IS_SERVERLESS", False):
        return jsonify({
            "running": False,
            "serverless": True,
            "message": "Real-time filesystem observer operates locally; cloud deployment provides dashboard & audit analysis."
        })
    if monitor.is_running:
        monitor.stop()
    else:
        monitor.start()
    return jsonify({"running": monitor.is_running})

@app.route("/api/diff/<int:file_id>")
def api_diff(file_id):
    rec = db.get_monitored_file_by_id(file_id)
    if not rec:
        return jsonify({"error": "File not found"}), 404

    file_path = rec["file_path"]
    res = compute_dual_hash(file_path)

    comp = compare_file_with_baseline(
        file_id=file_id,
        current_path=file_path,
        old_sha256=rec["sha256"],
        new_sha256=res.sha256,
        old_size=rec["file_size"],
        vault=vault
    )
    risk = analyze_diff_risk(comp, file_path=file_path)

    return jsonify({
        "file_name": rec["file_name"],
        "file_path": rec["file_path"],
        "is_identical": comp.is_identical,
        "is_binary": comp.is_binary,
        "raw_diff": comp.raw_unified_diff,
        "added_count": comp.added_count,
        "deleted_count": comp.deleted_count,
        "risk_level": risk.risk_level,
        "risk_score": risk.overall_score,
        "triggered_rules": [
            {
                "rule_name": r.rule_name,
                "category": r.category,
                "line_number": r.line_number,
                "description": r.description
            }
            for r in risk.triggered_rules
        ]
    })

@app.route("/api/ai_triage/<int:file_id>", methods=["POST"])
def api_ai_triage(file_id):
    rec = db.get_monitored_file_by_id(file_id)
    if not rec:
        return jsonify({"error": "File not found"}), 404

    res = compute_dual_hash(rec["file_path"])
    comp = compare_file_with_baseline(
        file_id=file_id,
        current_path=rec["file_path"],
        old_sha256=rec["sha256"],
        new_sha256=res.sha256,
        old_size=rec["file_size"],
        vault=vault
    )
    risk = analyze_diff_risk(comp, file_path=rec["file_path"])

    heuristics_data = [
        {"rule_name": r.rule_name, "category": r.category, "line_number": r.line_number, "description": r.description}
        for r in risk.triggered_rules
    ]

    triage = ai_advisor.analyze_incident(
        file_path=rec["file_path"],
        diff_text=comp.raw_unified_diff,
        heuristics_summary=heuristics_data,
        risk_level=risk.risk_level
    )

    return jsonify({
        "executive_summary": triage.executive_summary,
        "security_implications": triage.security_implications,
        "recommended_actions": triage.recommended_actions,
        "is_offline": triage.is_offline_fallback
    })

@app.route("/api/reports")
def api_reports():
    reports = []
    if config.REPORTS_DIR.exists():
        for p in sorted(config.REPORTS_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if p.is_file() and p.suffix in (".html", ".md"):
                st = p.stat()
                reports.append({
                    "file_name": p.name,
                    "format": p.suffix.upper().replace(".", ""),
                    "size": f"{st.st_size:,} bytes"
                })
    return jsonify(reports)

@app.route("/api/generate_report/<int:event_id>", methods=["POST"])
def api_generate_report(event_id):
    out = generate_audit_report(event_id, format="html")
    return jsonify({"success": True, "filename": out.name})

@app.route("/reports/<path:filename>")
def serve_report(filename):
    return send_from_directory(config.REPORTS_DIR, filename)

def open_browser():
    webbrowser.open("http://127.0.0.1:5000")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("[*] FIM Sentinel Web Dashboard starting at: http://127.0.0.1:5000")
    print("="*60 + "\n")
    Timer(1.2, open_browser).start()
    app.run(host="127.0.0.1", port=5000, debug=False)

