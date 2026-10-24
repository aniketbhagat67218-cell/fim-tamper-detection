"""
Web-Based Dashboard for the File Integrity Monitoring and Tampering Detection System.
Provides a browser interface at http://127.0.0.1:5000 powered by Flask and our existing FIM core.

Serverless-safe: gracefully disables real-time watchdog monitoring on cloud deployments
(Vercel, AWS Lambda) while keeping all dashboard, scan, diff, risk, AI triage, and
report features fully functional.

File-upload workflow (replaces local path input):
  POST /api/upload_baseline   — multipart file → compute hashes → store baseline
  POST /api/upload_verify     — multipart file → compute hashes → compare to baseline
  GET  /api/view_report/<id>  — return report HTML inline (no filesystem required)
"""
import os
import sys
import io
import queue
import json
import hashlib
import webbrowser
import tempfile
from threading import Timer
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory, Response

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
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
from reports.report_generator import generate_audit_report, generate_report_html_string

# ---------------------------------------------------------------------------
# Optional: real-time watchdog monitor (disabled on serverless)
# ---------------------------------------------------------------------------
_SERVERLESS = getattr(config, "IS_SERVERLESS", False)

FileIntegrityMonitor = None  # type: ignore
monitor = None

if not _SERVERLESS:
    try:
        from core.monitor import FileIntegrityMonitor  # type: ignore
    except ImportError:
        FileIntegrityMonitor = None

# ---------------------------------------------------------------------------
# Application-level singletons
# ---------------------------------------------------------------------------
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload limit

db = get_db()
vault = get_vault()
ai_advisor = get_ai_advisor()
event_queue: queue.Queue = queue.Queue()

if FileIntegrityMonitor is not None:
    monitor = FileIntegrityMonitor(event_queue=event_queue)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _monitor_running() -> bool:
    return bool(monitor and getattr(monitor, "is_running", False))


def _hash_bytes(data: bytes) -> tuple[str, str]:
    """Compute SHA-256 and SHA-3-256 from raw bytes in one pass."""
    h256 = hashlib.sha256()
    h3 = hashlib.sha3_256()
    h256.update(data)
    h3.update(data)
    return h256.hexdigest(), h3.hexdigest()


def _save_upload_to_tmp(file_storage) -> Path:
    """Save a werkzeug FileStorage to a temp file and return the path."""
    suffix = Path(file_storage.filename).suffix or ".bin"
    fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    file_storage.save(tmp_path)
    return Path(tmp_path)


# ---------------------------------------------------------------------------
# Routes — Pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Routes — Stats & Events
# ---------------------------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    stats = db.get_system_stats()
    stats["monitor_running"] = _monitor_running()
    stats["serverless"] = _SERVERLESS
    return jsonify(stats)


@app.route("/api/events")
def api_events():
    events = db.get_event_history(limit=50)
    return jsonify(events)


@app.route("/api/files")
def api_files():
    files = db.get_all_monitored_files()
    return jsonify(files)


# ---------------------------------------------------------------------------
# Routes — File Upload Baseline (NEW — replaces /api/baseline path-based)
# ---------------------------------------------------------------------------

@app.route("/api/upload_baseline", methods=["POST"])
def api_upload_baseline():
    """
    Accept a browser file upload, compute dual hashes server-side,
    store a baseline record and vault snapshot.
    Form field: 'file'
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Use form field named 'file'."}), 400

    upload = request.files["file"]
    if not upload.filename:
        return jsonify({"error": "Empty filename."}), 400

    file_bytes = upload.read()
    file_size = len(file_bytes)

    if file_size == 0:
        return jsonify({"error": "Uploaded file is empty."}), 400

    sha256, sha3_256 = _hash_bytes(file_bytes)

    # Determine if binary
    is_binary = b"\x00" in file_bytes[:8192]
    filename = Path(upload.filename).name
    last_modified = datetime.utcnow().timestamp()

    # Use a stable virtual path for serverless (no real local path)
    virtual_path = f"[uploaded]/{filename}"

    # Check if already baselined (update existing record)
    existing = db.get_monitored_file_by_path(virtual_path)
    if existing:
        file_id = existing["id"]
        # Update hashes in-place (re-baselining the file)
        db.update_file_baseline(
            file_id=file_id,
            sha256=sha256,
            sha3_256=sha3_256,
            file_size=file_size,
            last_modified=last_modified,
            is_binary=is_binary
        )
    else:
        file_id = db.add_monitored_file(
            file_path=virtual_path,
            file_name=filename,
            sha256=sha256,
            sha3_256=sha3_256,
            file_size=file_size,
            last_modified=last_modified,
            is_binary=is_binary
        )

    # Store vault snapshot from bytes
    vault.store_snapshot_bytes(
        file_bytes=file_bytes,
        file_id=file_id,
        sha256=sha256,
        file_size=file_size,
        is_binary=is_binary,
        filename=filename
    )

    return jsonify({
        "success": True,
        "file_id": file_id,
        "file_name": filename,
        "file_size": file_size,
        "sha256": sha256,
        "sha3_256": sha3_256,
        "re_baselined": existing is not None
    })


# ---------------------------------------------------------------------------
# Routes — File Upload Verify (NEW)
# ---------------------------------------------------------------------------

@app.route("/api/upload_verify", methods=["POST"])
def api_upload_verify():
    """
    Accept a browser file upload of a previously-baselined file.
    Compute hashes, compare against stored baseline, log event if modified.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    upload = request.files["file"]
    if not upload.filename:
        return jsonify({"error": "Empty filename."}), 400

    file_bytes = upload.read()
    filename = Path(upload.filename).name
    virtual_path = f"[uploaded]/{filename}"

    rec = db.get_monitored_file_by_path(virtual_path)
    if not rec:
        return jsonify({
            "error": f"No baseline found for '{filename}'. Please establish a baseline first."
        }), 404

    sha256, sha3_256 = _hash_bytes(file_bytes)
    file_size = len(file_bytes)
    file_id = rec["id"]

    if sha256 == rec["sha256"] and sha3_256 == rec["sha3_256"]:
        db.update_file_status(file_id, "CLEAN")
        return jsonify({
            "status": "CLEAN",
            "file_name": filename,
            "file_id": file_id,
            "message": "✅ Integrity verified. Dual hashes match baseline exactly.",
            "sha256": sha256,
            "sha3_256": sha3_256,
            "baseline_sha256": rec["sha256"]
        })

    # --- Hashes differ: tampering detected ---
    db.update_file_status(file_id, "MODIFIED")
    is_binary = b"\x00" in file_bytes[:8192]

    # Write current bytes to tmp for diff engine
    suffix = Path(filename).suffix or ".bin"
    fd, tmp_current = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(file_bytes)

        comp = compare_file_with_baseline(
            file_id=file_id,
            current_path=tmp_current,
            old_sha256=rec["sha256"],
            new_sha256=sha256,
            old_size=rec["file_size"],
            vault=vault
        )
    finally:
        try:
            os.unlink(tmp_current)
        except Exception:
            pass

    risk = analyze_diff_risk(comp, file_path=filename)

    heuristics_data = [
        {
            "rule_id": t.rule_id,
            "rule_name": t.rule_name,
            "category": t.category,
            "line_number": t.line_number,
            "line_content": t.line_content,
            "description": t.description,
            "score": t.score
        }
        for t in risk.triggered_rules
    ]

    diff_summary = (
        f"+{comp.added_count} / -{comp.deleted_count} lines"
        if not comp.is_binary
        else f"Binary size delta: {comp.size_delta:+d} bytes"
    )

    event_id = db.log_event(
        file_id=file_id,
        file_path=virtual_path,
        event_type="MODIFIED",
        old_sha256=rec["sha256"],
        new_sha256=sha256,
        old_sha3_256=rec["sha3_256"],
        new_sha3_256=sha3_256,
        risk_level=risk.risk_level,
        risk_score=risk.overall_score,
        detected_heuristics=heuristics_data,
        diff_summary=diff_summary
    )

    return jsonify({
        "status": "MODIFIED",
        "file_name": filename,
        "file_id": file_id,
        "event_id": event_id,
        "risk_level": risk.risk_level,
        "risk_score": risk.overall_score,
        "diff_summary": diff_summary,
        "added_count": comp.added_count,
        "deleted_count": comp.deleted_count,
        "raw_diff": comp.raw_unified_diff,
        "triggered_rules": [
            {"rule_name": r.rule_name, "category": r.category,
             "line_number": r.line_number, "description": r.description}
            for r in risk.triggered_rules
        ],
        "message": f"⚠️ TAMPERING DETECTED — {risk.risk_level} Risk (Score: {risk.overall_score}/100)"
    })


# ---------------------------------------------------------------------------
# Routes — Legacy path-based scan/baseline (kept for local use)
# ---------------------------------------------------------------------------

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
    if monitor is not None:
        monitor.reload_monitored_files()
    return jsonify({"success": True, "file_id": file_id})


# ---------------------------------------------------------------------------
# Routes — Monitor control
# ---------------------------------------------------------------------------

@app.route("/api/verify_all", methods=["POST"])
def api_verify_all():
    files = db.get_all_monitored_files()
    if monitor is None:
        return jsonify({
            "success": False,
            "serverless": True,
            "message": "Upload-based verification available. Real-time monitoring runs locally only."
        })
    for f in files:
        monitor.manual_verify_file(f["id"])
    return jsonify({"success": True, "count": len(files)})


@app.route("/api/verify/<int:file_id>", methods=["POST"])
def api_verify_single(file_id):
    if monitor is None:
        return jsonify({
            "status": "SERVERLESS",
            "message": "Use the 'Upload & Verify' button to check file integrity."
        })
    res = monitor.manual_verify_file(file_id)
    return jsonify(res)


@app.route("/api/toggle_monitor", methods=["POST"])
def api_toggle_monitor():
    if _SERVERLESS or monitor is None:
        return jsonify({
            "running": False,
            "serverless": True,
            "message": "Real-time monitor runs locally only. Use Upload & Verify for cloud integrity checks."
        })
    if monitor.is_running:
        monitor.stop()
    else:
        monitor.start()
    return jsonify({"running": monitor.is_running})


# ---------------------------------------------------------------------------
# Routes — Diff & AI
# ---------------------------------------------------------------------------

@app.route("/api/diff/<int:file_id>")
def api_diff(file_id):
    rec = db.get_monitored_file_by_id(file_id)
    if not rec:
        return jsonify({"error": "File not found"}), 404

    file_path = rec["file_path"]

    # For upload-based files, read vault snapshot for comparison
    vault_bytes = vault.read_snapshot_bytes(file_id)
    if vault_bytes is not None:
        # Compare vault (baseline) vs vault (same — identical since no new upload)
        comp = compare_file_with_baseline(
            file_id=file_id,
            current_path=file_path,
            old_sha256=rec["sha256"],
            new_sha256=rec["sha256"],
            old_size=rec["file_size"],
            vault=vault
        )
    else:
        try:
            res = compute_dual_hash(file_path)
            comp = compare_file_with_baseline(
                file_id=file_id,
                current_path=file_path,
                old_sha256=rec["sha256"],
                new_sha256=res.sha256,
                old_size=rec["file_size"],
                vault=vault
            )
        except Exception:
            return jsonify({"error": "Cannot compute diff — file not accessible on server."}), 400

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
            {"rule_name": r.rule_name, "category": r.category,
             "line_number": r.line_number, "description": r.description}
            for r in risk.triggered_rules
        ]
    })


@app.route("/api/ai_triage/<int:file_id>", methods=["POST"])
def api_ai_triage(file_id):
    rec = db.get_monitored_file_by_id(file_id)
    if not rec:
        return jsonify({"error": "File not found"}), 404

    vault_bytes = vault.read_snapshot_bytes(file_id)
    if vault_bytes is not None:
        comp = compare_file_with_baseline(
            file_id=file_id,
            current_path=rec["file_path"],
            old_sha256=rec["sha256"],
            new_sha256=rec["sha256"],
            old_size=rec["file_size"],
            vault=vault
        )
    else:
        try:
            res = compute_dual_hash(rec["file_path"])
            comp = compare_file_with_baseline(
                file_id=file_id,
                current_path=rec["file_path"],
                old_sha256=rec["sha256"],
                new_sha256=res.sha256,
                old_size=rec["file_size"],
                vault=vault
            )
        except Exception:
            comp = None

    if comp is None:
        return jsonify({"error": "Cannot run triage — file not accessible."}), 400

    risk = analyze_diff_risk(comp, file_path=rec["file_path"])
    heuristics_data = [
        {"rule_name": r.rule_name, "category": r.category,
         "line_number": r.line_number, "description": r.description}
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


# ---------------------------------------------------------------------------
# Routes — Reports (inline serving — works on Vercel with no filesystem)
# ---------------------------------------------------------------------------

@app.route("/api/reports")
def api_reports():
    """Return list of events that have generated reports."""
    events = db.get_event_history(limit=100)
    reports = [
        {
            "event_id": ev["id"],
            "file_name": Path(ev["file_path"]).name,
            "risk_level": ev["risk_level"],
            "timestamp": ev["timestamp"],
            "diff_summary": ev.get("diff_summary", ""),
        }
        for ev in events
        if ev.get("id")
    ]
    return jsonify(reports)


@app.route("/api/generate_report/<int:event_id>", methods=["POST"])
def api_generate_report(event_id):
    """Generate report and return its content inline — no filesystem required."""
    try:
        html_content = generate_report_html_string(event_id)
        return jsonify({"success": True, "event_id": event_id, "html": html_content})
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {e}"}), 500


@app.route("/api/view_report/<int:event_id>")
def api_view_report(event_id):
    """Serve report HTML directly in the browser (no file system needed)."""
    try:
        html_content = generate_report_html_string(event_id)
        return Response(html_content, mimetype="text/html")
    except ValueError as e:
        return Response(f"<h2>Error: {e}</h2>", mimetype="text/html", status=404)
    except Exception as e:
        return Response(f"<h2>Report error: {e}</h2>", mimetype="text/html", status=500)


@app.route("/reports/<path:filename>")
def serve_report(filename):
    """Legacy: serve from filesystem if available (local mode)."""
    if config.REPORTS_DIR.exists():
        return send_from_directory(config.REPORTS_DIR, filename)
    return Response("<h2>Reports not available on serverless deployment. Use 'View Report' button.</h2>",
                    mimetype="text/html", status=404)


# ---------------------------------------------------------------------------
# Routes — Demo Mode seed
# ---------------------------------------------------------------------------

@app.route("/api/demo/seed", methods=["POST"])
def api_demo_seed():
    """
    Seed the database with realistic demo data for presentation.
    Creates 3 sample files with baseline + 2 tamper events.
    Idempotent — safe to call multiple times.
    """
    DEMO_FILES = [
        {
            "name": "config.ini",
            "path": "[demo]/config.ini",
            "content_baseline": b"[database]\nhost=localhost\nport=5432\npassword=secure_prod_pass\n\n[app]\ndebug=false\n",
            "content_modified": b"[database]\nhost=malicious-server.xyz\nport=5432\npassword=HACKED\n\n[app]\ndebug=true\n",
        },
        {
            "name": "auth_handler.py",
            "path": "[demo]/auth_handler.py",
            "content_baseline": b"def verify_user(username, password):\n    # Secure verification\n    return check_hash(password)\n\ndef check_admin(user):\n    return user.role == 'admin'\n",
            "content_modified": b"def verify_user(username, password):\n    # BACKDOOR ADDED\n    if password == 'x': return True\n    return check_hash(password)\n\ndef check_admin(user):\n    return True  # privilege escalation\n",
        },
        {
            "name": "readme.md",
            "path": "[demo]/readme.md",
            "content_baseline": b"# Project FIM Alpha\nThis system monitors file integrity.\n",
            "content_modified": None,  # stays clean
        },
    ]

    seeded = []
    for df in DEMO_FILES:
        existing = db.get_monitored_file_by_path(df["path"])
        sha256_b, sha3_b = _hash_bytes(df["content_baseline"])
        is_binary = b"\x00" in df["content_baseline"][:512]
        ts = datetime.utcnow().timestamp()

        if existing:
            fid = existing["id"]
        else:
            fid = db.add_monitored_file(
                file_path=df["path"],
                file_name=df["name"],
                sha256=sha256_b,
                sha3_256=sha3_b,
                file_size=len(df["content_baseline"]),
                last_modified=ts,
                is_binary=is_binary
            )
            vault.store_snapshot_bytes(
                file_bytes=df["content_baseline"],
                file_id=fid,
                sha256=sha256_b,
                file_size=len(df["content_baseline"]),
                is_binary=is_binary,
                filename=df["name"]
            )

        if df["content_modified"] and not existing:
            sha256_m, sha3_m = _hash_bytes(df["content_modified"])
            db.update_file_status(fid, "MODIFIED")
            db.log_event(
                file_id=fid,
                file_path=df["path"],
                event_type="MODIFIED",
                old_sha256=sha256_b,
                new_sha256=sha256_m,
                old_sha3_256=sha3_b,
                new_sha3_256=sha3_m,
                risk_level="HIGH" if "auth" in df["name"] else "MEDIUM",
                risk_score=85 if "auth" in df["name"] else 55,
                detected_heuristics=[
                    {"rule_id": "PE001", "rule_name": "Privilege Escalation",
                     "category": "HIGH", "line_number": 7,
                     "line_content": "    return True  # privilege escalation",
                     "description": "Unconditional return True bypasses access control",
                     "score": 50}
                ] if "auth" in df["name"] else [
                    {"rule_id": "SE002", "rule_name": "Secret Exfiltration",
                     "category": "MEDIUM", "line_number": 3,
                     "line_content": "password=HACKED",
                     "description": "Credential replacement detected in config",
                     "score": 35}
                ],
                diff_summary="+2 / -2 lines"
            )

        seeded.append({"name": df["name"], "file_id": fid})

    return jsonify({"success": True, "seeded": seeded})


@app.route("/api/demo/clear", methods=["POST"])
def api_demo_clear():
    """Remove all demo/uploaded files from monitoring (keeps real local files)."""
    files = db.get_all_monitored_files()
    removed = 0
    for f in files:
        if f["file_path"].startswith("[demo]/") or f["file_path"].startswith("[uploaded]/"):
            db.delete_monitored_file(f["id"])
            removed += 1
    return jsonify({"success": True, "removed": removed})


# ---------------------------------------------------------------------------
# Local development entry point
# ---------------------------------------------------------------------------
def _open_browser():
    webbrowser.open("http://127.0.0.1:5000")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("[*] FIM Sentinel Web Dashboard starting at: http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    Timer(1.2, _open_browser).start()
    app.run(host="127.0.0.1", port=5000, debug=False)
