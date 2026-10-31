"""
Web-Based Dashboard & API for File Integrity Monitoring and Tampering Detection System.
Provides a browser interface at http://127.0.0.1:5000 powered by Flask and our FIM core.

Serverless-safe: Supports Supabase PostgreSQL and SQLite, gracefully adapts
real-time watchdog monitoring on cloud deployments (Vercel, AWS Lambda) while keeping
all dashboard, scan, diff, risk, AI triage, and report features fully functional.
"""
import os
import sys
import io
import queue
import json
import hashlib
import webbrowser
import tempfile
import logging
from threading import Timer
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, request, send_from_directory, Response, session
from werkzeug.utils import secure_filename

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
from reports.report_generator import generate_report_html_string

logger = logging.getLogger(__name__)

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
# Application initialization
# ---------------------------------------------------------------------------
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
app.secret_key = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_SIZE_BYTES

db = get_db()
vault = get_vault()
ai_advisor = get_ai_advisor()
event_queue: queue.Queue = queue.Queue()

if FileIntegrityMonitor is not None:
    monitor = FileIntegrityMonitor(event_queue=event_queue)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_current_user_id() -> str:
    """Returns or initializes a session-isolated user ID."""
    if "user_id" not in session:
        session["user_id"] = "user_" + hashlib.sha256(os.urandom(16)).hexdigest()[:12]
    return session["user_id"]


def _monitor_running() -> bool:
    return bool(monitor and getattr(monitor, "is_running", False))


def _hash_bytes(data: bytes) -> tuple[str, str]:
    """Compute SHA-256 and SHA-3-256 from raw bytes in one pass."""
    h256 = hashlib.sha256()
    h3 = hashlib.sha3_256()
    h256.update(data)
    h3.update(data)
    return h256.hexdigest(), h3.hexdigest()


# ---------------------------------------------------------------------------
# Routes — Pages & Metadata
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/agent_info")
def api_agent_info():
    """Returns architecture facts distinguishing cloud verification from local daemon."""
    return jsonify({
        "architecture": "Hybrid Web & Local Endpoint Sentinel",
        "cloud_mode": _SERVERLESS,
        "is_postgres": db.is_postgres,
        "cloud_capabilities": [
            "Upload-based baseline establishment (SHA-256 + SHA-3-256)",
            "Upload-based tamper verification & delta diffing",
            "Deterministic heuristic threat detection (privilege, auth, network)",
            "AI-assisted security advisory (Gemini)",
            "Forensic HTML report generation & downloadable exports"
        ],
        "local_agent_capabilities": [
            "Continuous filesystem kernel monitoring (Watchdog)",
            "Real-time atomic write debouncing (0.75s)",
            "Automatic zero-interaction tamper event logging"
        ],
        "notice": "Due to browser security sandboxes, web applications cannot directly inspect local workstation disks. For cloud deployments, verify integrity by uploading files to 'Upload & Verify'. For continuous local daemon monitoring, run 'python app.py' on the workstation."
    })


# ---------------------------------------------------------------------------
# Routes — Stats & Events
# ---------------------------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    user_id = _get_current_user_id()
    stats = db.get_system_stats(user_id=user_id)
    stats["monitor_running"] = _monitor_running()
    stats["serverless"] = _SERVERLESS
    return jsonify(stats)


@app.route("/api/events")
def api_events():
    user_id = _get_current_user_id()
    risk_filter = request.args.get("risk", "ALL")
    search = request.args.get("search", "")
    include_demo = request.args.get("include_demo", "true").lower() == "true"
    events = db.get_event_history(limit=100, risk_filter=risk_filter, search_query=search, user_id=user_id, include_demo=include_demo)
    return jsonify(events)


@app.route("/api/files")
def api_files():
    user_id = _get_current_user_id()
    include_demo = request.args.get("include_demo", "true").lower() == "true"
    files = db.get_all_monitored_files(user_id=user_id, include_demo=include_demo)
    return jsonify(files)


# ---------------------------------------------------------------------------
# Routes — File Upload Baseline
# ---------------------------------------------------------------------------

@app.route("/api/upload_baseline", methods=["POST"])
def api_upload_baseline():
    """
    Accepts a browser file upload, computes dual hashes server-side,
    and stores baseline record and snapshot in vault & database.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Use form field named 'file'."}), 400

    upload = request.files["file"]
    if not upload.filename:
        return jsonify({"error": "Empty filename."}), 400

    file_bytes = upload.read()
    file_size = len(file_bytes)

    if file_size == 0:
        return jsonify({"error": "Uploaded file is empty (0 bytes)."}), 400

    if file_size > config.MAX_UPLOAD_SIZE_BYTES:
        return jsonify({"error": f"File exceeds maximum limit of {config.MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB."}), 413

    raw_name = Path(upload.filename).name
    filename = secure_filename(raw_name) or "uploaded_asset.bin"
    user_id = _get_current_user_id()

    sha256, sha3_256 = _hash_bytes(file_bytes)
    is_binary = b"\x00" in file_bytes[:8192]
    last_modified = datetime.now(timezone.utc).timestamp()
    virtual_path = f"[uploaded]/{filename}"

    # Check if already baselined for this user
    existing = db.get_monitored_file_by_path(virtual_path, user_id=user_id)
    if existing:
        file_id = existing["id"]
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
            is_binary=is_binary,
            user_id=user_id
        )

    # Store snapshot in vault (hybrid disk and DB)
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
        "status": config.STATUS_UNCHANGED,
        "re_baselined": existing is not None
    })


# ---------------------------------------------------------------------------
# Routes — File Upload Verify & Tampering Detection
# ---------------------------------------------------------------------------

@app.route("/api/upload_verify", methods=["POST"])
def api_upload_verify():
    """
    Accepts a browser file upload of a previously baselined file.
    Compares dual hashes against baseline:
      - Hashes match: Returns status UNCHANGED. Does NOT create duplicate alert.
      - Hashes differ: Detects tampering, assigns risk, prevents duplicate alert if re-verified.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Use form field named 'file'."}), 400

    upload = request.files["file"]
    if not upload.filename:
        return jsonify({"error": "Empty filename."}), 400

    file_bytes = upload.read()
    file_size = len(file_bytes)

    if file_size > config.MAX_UPLOAD_SIZE_BYTES:
        return jsonify({"error": f"File exceeds maximum limit of {config.MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB."}), 413

    raw_name = Path(upload.filename).name
    filename = secure_filename(raw_name) or "uploaded_asset.bin"
    user_id = _get_current_user_id()

    # Search for matching baseline (user-specific, demo, or registered assets)
    rec = db.get_monitored_file_by_path(f"[uploaded]/{filename}", user_id=user_id)
    if not rec:
        rec = db.get_monitored_file_by_path(f"[demo]/{filename}", user_id=user_id)
    if not rec:
        for f in db.get_all_monitored_files(user_id=user_id):
            if f["file_name"].lower() in (filename.lower(), raw_name.lower()):
                rec = f
                break
    # Global fallback across all registered baselines
    if not rec:
        for f in db.get_all_monitored_files():
            if f["file_name"].lower() in (filename.lower(), raw_name.lower()):
                rec = f
                break

    if not rec:
        return jsonify({
            "error": f"No baseline found for '{filename}'. To verify this file, please first establish its baseline in 'Establish Trusted Baseline' above, or test using the Demo Mode files."
        }), 404

    sha256, sha3_256 = _hash_bytes(file_bytes)
    file_id = rec["id"]

    # --- CASE 1: UNCHANGED (Integrity Verified) ---
    if sha256 == rec["sha256"] and sha3_256 == rec["sha3_256"]:
        db.update_file_status(file_id, config.STATUS_UNCHANGED)
        return jsonify({
            "status": config.STATUS_UNCHANGED,
            "file_name": rec["file_name"],
            "file_id": file_id,
            "message": "Integrity verified. Dual hashes match baseline exactly.",
            "sha256": sha256,
            "sha3_256": sha3_256,
            "baseline_sha256": rec["sha256"],
            "baseline_sha3_256": rec["sha3_256"],
            "risk_level": "LOW",
            "risk_score": 0,
            "duplicate_alert_suppressed": False
        })

    # --- CASE 2: MODIFIED (Tampering Detected) ---
    db.update_file_status(file_id, config.STATUS_MODIFIED)
    is_binary = b"\x00" in file_bytes[:8192]

    # Duplicate alert prevention: check if this exact modified hash was already recorded
    duplicate_event = db.check_duplicate_tamper(file_id, sha256)
    if duplicate_event:
        return jsonify({
            "status": config.STATUS_MODIFIED,
            "file_name": rec["file_name"],
            "file_id": file_id,
            "event_id": duplicate_event["id"],
            "risk_level": duplicate_event["risk_level"],
            "risk_score": duplicate_event["risk_score"],
            "diff_summary": duplicate_event.get("diff_summary") or "",
            "raw_diff": duplicate_event.get("raw_diff") or "",
            "is_binary": is_binary,
            "duplicate_alert_suppressed": True,
            "message": f"TAMPERING DETECTED — {duplicate_event['risk_level']} Risk (Duplicate verification: Existing Alert #{duplicate_event['id']})"
        })

    # New tampering incident: Compute diff
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

    risk = analyze_diff_risk(comp, file_path=rec["file_name"])

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

    # Binary vs. Text separation (Requirement 6)
    if comp.is_binary:
        diff_summary = f"Binary size delta: {comp.size_delta:+d} bytes (Baseline: {rec['file_size']} B, Current: {file_size} B)"
        raw_diff_text = (
            f"--- [Baseline Binary: {rec['file_name']} (Size: {rec['file_size']} B, SHA-256: {rec['sha256'][:24]}...)]\n"
            f"+++ [Current Binary: {rec['file_name']} (Size: {file_size} B, SHA-256: {sha256[:24]}...)]\n"
            f"[Binary File Detected: Raw text diff suppressed to prevent display corruption. Size delta: {comp.size_delta:+d} bytes.]"
        )
    else:
        diff_summary = f"+{comp.added_count} / -{comp.deleted_count} lines"
        raw_diff_text = comp.raw_unified_diff

    event_id = db.log_event(
        file_id=file_id,
        file_path=rec["file_path"],
        event_type=config.STATUS_MODIFIED,
        old_sha256=rec["sha256"],
        new_sha256=sha256,
        old_sha3_256=rec["sha3_256"],
        new_sha3_256=sha3_256,
        risk_level=risk.risk_level,
        risk_score=risk.overall_score,
        detected_heuristics=heuristics_data,
        diff_summary=diff_summary,
        raw_diff=raw_diff_text,
        user_id=user_id,
        is_demo=bool(rec.get("is_demo"))
    )

    # Pre-generate and store report HTML
    try:
        report_html = generate_report_html_string(event_id)
        db.save_report_metadata(event_id=event_id, file_id=file_id, file_name=rec["file_name"], report_html=report_html, user_id=user_id)
    except Exception as e:
        logger.warning(f"Report pre-generation notice: {e}")

    return jsonify({
        "status": config.STATUS_MODIFIED,
        "file_name": rec["file_name"],
        "file_id": file_id,
        "event_id": event_id,
        "risk_level": risk.risk_level,
        "risk_score": risk.overall_score,
        "diff_summary": diff_summary,
        "added_count": comp.added_count,
        "deleted_count": comp.deleted_count,
        "raw_diff": raw_diff_text,
        "is_binary": comp.is_binary,
        "duplicate_alert_suppressed": False,
        "triggered_rules": [
            {"rule_name": r.rule_name, "category": r.category,
             "line_number": r.line_number, "description": r.description}
            for r in risk.triggered_rules
        ],
        "message": f"TAMPERING DETECTED — {risk.risk_level} Risk (Score: {risk.overall_score}/100)"
    })


# ---------------------------------------------------------------------------
# Routes — Diff & Forensic Inspection
# ---------------------------------------------------------------------------

@app.route("/api/diff/<int:file_id>")
def api_diff(file_id):
    """Retrieves diff analysis and risk factors for a specific monitored asset."""
    rec = db.get_monitored_file_by_id(file_id)
    if not rec:
        return jsonify({"error": "File not found."}), 404

    latest_event = db.get_latest_event_for_file(file_id)
    raw_diff = latest_event.get("raw_diff") if latest_event else None
    diff_summary = latest_event.get("diff_summary") if latest_event else None
    risk_level = latest_event.get("risk_level", "LOW") if latest_event else "LOW"
    risk_score = latest_event.get("risk_score", 0) if latest_event else 0
    heuristics = latest_event.get("detected_heuristics") or [] if latest_event else []

    is_clean = rec.get("status") in ("UNCHANGED", "CLEAN")

    # If raw_diff is missing but file is marked modified or has an event, compute diff dynamically
    if not raw_diff and not is_clean:
        try:
            curr_p = Path(rec["file_path"])
            if curr_p.exists() and curr_p.is_file():
                comp = compare_file_with_baseline(
                    file_id=file_id,
                    current_path=str(curr_p),
                    old_sha256=rec.get("sha256", ""),
                    vault=vault
                )
                if comp.is_binary:
                    raw_diff = (
                        f"--- [Baseline Binary: {rec['file_name']} (Size: {rec['file_size']} B, SHA-256: {rec['sha256'][:24]}...)]\n"
                        f"+++ [Current Binary: {rec['file_name']} (Size: {curr_p.stat().st_size} B)]\n"
                        f"[Binary File Detected: Raw text diff suppressed to prevent display corruption. Size delta: {comp.size_delta:+d} bytes.]"
                    )
                    diff_summary = diff_summary or f"Binary size delta: {comp.size_delta:+d} bytes"
                else:
                    raw_diff = comp.raw_unified_diff
                    diff_summary = diff_summary or f"+{comp.added_count} / -{comp.deleted_count} lines"

                risk = analyze_diff_risk(comp, file_path=rec["file_name"])
                risk_level = risk.risk_level
                risk_score = risk.overall_score
                heuristics = [
                    {"rule_name": r.rule_name, "category": r.category,
                     "line_number": r.line_number, "description": r.description}
                    for r in risk.triggered_rules
                ]

                # Update the database event so it's cached
                if latest_event and latest_event.get("id"):
                    db.update_event_diff(latest_event["id"], raw_diff, diff_summary)
        except Exception as e:
            logger.warning(f"Dynamic diff calculation notice: {e}")

    # Fallback message for modified files where raw_diff is still not found
    if not is_clean and not raw_diff:
        raw_diff = (
            f"--- baseline/{rec['file_name']}\n"
            f"+++ modified/{rec['file_name']}\n"
            f"[Tampering incident recorded: {diff_summary or 'File modification detected'} (Risk: {risk_level})]"
        )

    return jsonify({
        "file_name": rec["file_name"],
        "file_path": rec["file_path"],
        "is_identical": is_clean,
        "is_binary": bool(rec.get("is_binary")),
        "raw_diff": "" if is_clean else (raw_diff or ""),
        "diff_summary": ("Clean (No changes detected)" if is_clean else (diff_summary or "Modified")),
        "risk_level": "CLEAN" if is_clean else risk_level,
        "risk_score": 0 if is_clean else risk_score,
        "triggered_rules": [] if is_clean else heuristics
    })


@app.route("/api/diff/event/<int:event_id>")
def api_diff_event(event_id):
    """Retrieves the exact diff and risk heuristics for a specific historical event."""
    event = db.get_event_by_id(event_id)
    if not event:
        return jsonify({"error": f"Event #{event_id} not found."}), 404

    file_name = Path(event["file_path"]).name
    raw_diff = event.get("raw_diff")
    diff_summary = event.get("diff_summary") or ""
    risk_level = event.get("risk_level", "LOW")
    risk_score = event.get("risk_score", 0)
    heuristics = event.get("detected_heuristics") or []

    # If raw_diff was not stored in historical event, compute dynamically
    if not raw_diff and event.get("file_id"):
        try:
            curr_p = Path(event["file_path"])
            if curr_p.exists() and curr_p.is_file():
                comp = compare_file_with_baseline(
                    file_id=event["file_id"],
                    current_path=str(curr_p),
                    old_sha256=event.get("old_sha256") or "",
                    new_sha256=event.get("new_sha256") or "",
                    vault=vault
                )
                if comp.is_binary:
                    raw_diff = (
                        f"--- [Baseline Binary: {file_name} (Size: {event.get('old_size', 0)} B)]\n"
                        f"+++ [Current Binary: {file_name} (Size: {curr_p.stat().st_size} B)]\n"
                        f"[Binary File Detected: Raw text diff suppressed. Size delta: {comp.size_delta:+d} bytes.]"
                    )
                else:
                    raw_diff = comp.raw_unified_diff

                if raw_diff:
                    db.update_event_diff(event_id, raw_diff)
        except Exception as e:
            logger.warning(f"Dynamic event diff calculation notice: {e}")

    if not raw_diff:
        raw_diff = (
            f"--- baseline/{file_name}\n"
            f"+++ modified/{file_name}\n"
            f"[Recorded Incident #{event_id}: {diff_summary or 'Modification detected'} (Risk: {risk_level})]"
        )

    return jsonify({
        "event_id": event["id"],
        "file_name": file_name,
        "file_path": event["file_path"],
        "raw_diff": raw_diff,
        "diff_summary": diff_summary,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "triggered_rules": heuristics
    })


@app.route("/api/ai_triage/<int:file_id>", methods=["POST"])
def api_ai_triage(file_id):
    """Generates privacy-sanitized AI security triage for an asset."""
    rec = db.get_monitored_file_by_id(file_id)
    if not rec:
        return jsonify({"error": "File not found"}), 404

    events = db.get_event_history(limit=5)
    file_events = [e for e in events if e.get("file_id") == file_id]
    latest_event = file_events[0] if file_events else None

    diff_text = latest_event.get("raw_diff") if latest_event else ""
    heuristics_data = latest_event.get("detected_heuristics", []) if latest_event else []
    risk_level = latest_event.get("risk_level", "LOW") if latest_event else "LOW"

    if not diff_text:
        diff_text = "File is currently in baseline state. No active diff detected."

    triage = ai_advisor.analyze_incident(
        file_path=rec["file_name"],
        diff_text=diff_text,
        heuristics_summary=heuristics_data,
        risk_level=risk_level
    )

    return jsonify({
        "executive_summary": triage.executive_summary,
        "security_implications": triage.security_implications,
        "recommended_actions": triage.recommended_actions,
        "is_offline": triage.is_offline_fallback
    })


# ---------------------------------------------------------------------------
# Routes — Forensic Reports (View & Download)
# ---------------------------------------------------------------------------

@app.route("/api/reports")
def api_reports():
    """Returns list of audit events and available forensic reports."""
    user_id = _get_current_user_id()
    events = db.get_event_history(limit=100, user_id=user_id)
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
    """Generates report HTML inline without requiring disk writes."""
    try:
        html_content = generate_report_html_string(event_id)
        ev = db.get_event_by_id(event_id)
        fname = Path(ev["file_path"]).name if ev else f"incident_{event_id}"
        db.save_report_metadata(event_id, ev.get("file_id"), fname, html_content, user_id=_get_current_user_id())
        return jsonify({"success": True, "event_id": event_id, "html": html_content})
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {e}"}), 500


@app.route("/api/view_report/<int:event_id>")
def api_view_report(event_id):
    """Renders forensic report directly in the browser."""
    try:
        html_content = generate_report_html_string(event_id)
        return Response(html_content, mimetype="text/html; charset=utf-8")
    except ValueError as e:
        return Response(f"<h2>Error: {e}</h2>", mimetype="text/html", status=404)
    except Exception as e:
        return Response(f"<h2>Report error: {e}</h2>", mimetype="text/html", status=500)


@app.route("/api/download_report/<int:event_id>")
def api_download_report(event_id):
    """Serves forensic report as a downloadable HTML attachment."""
    try:
        html_content = generate_report_html_string(event_id)
        ev = db.get_event_by_id(event_id)
        fname = Path(ev["file_path"]).name if ev else f"incident_{event_id}"
        safe_fname = "".join(c for c in fname if c.isalnum() or c in "._- ")
        download_name = f"FIM_Forensic_Report_{safe_fname}_Event_{event_id}.html"

        response = Response(html_content, mimetype="text/html; charset=utf-8")
        response.headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
        return response
    except ValueError as e:
        return Response(f"<h2>Error: {e}</h2>", mimetype="text/html", status=404)
    except Exception as e:
        return Response(f"<h2>Report error: {e}</h2>", mimetype="text/html", status=500)


# ---------------------------------------------------------------------------
# Routes — Demo Mode
# ---------------------------------------------------------------------------

@app.route("/api/demo/seed", methods=["POST"])
def api_demo_seed():
    """
    Seeds database with realistic, repeatable attack scenarios for college presentation.
    Creates 3 demo assets with distinct tampering and privilege escalation triggers.
    """
    user_id = _get_current_user_id()

    DEMO_FILES = [
        {
            "name": "auth_policy.py",
            "path": "[demo]/auth_policy.py",
            "content_baseline": b"def verify_credentials(user, password):\n    # Standard secure authentication\n    return check_password_hash(user.hash, password)\n\ndef is_admin(user):\n    return user.role == 'administrator'\n",
            "content_modified": b"def verify_credentials(user, password):\n    # BACKDOOR INSERTED\n    if password == 'master_bypass': return True\n    return check_password_hash(user.hash, password)\n\ndef is_admin(user):\n    # PRIVILEGE ESCALATION\n    return True\n",
            "risk_level": "HIGH",
            "risk_score": 90,
            "heuristics": [
                {"rule_id": "HIGH_PRIV_ESC", "rule_name": "Privilege Escalation Bypass",
                 "category": "HIGH", "line_number": 8, "line_content": "    return True",
                 "description": "Unconditional superuser authorization allows non-admin privilege escalation.",
                 "score": 50}
            ]
        },
        {
            "name": "server_config.ini",
            "path": "[demo]/server_config.ini",
            "content_baseline": b"[database]\nhost = 127.0.0.1\nport = 5432\nverify_ssl = true\n\n[security]\nallow_all = false\n",
            "content_modified": b"[database]\nhost = 0.0.0.0\nport = 5432\nverify_ssl = false\n\n[security]\nallow_all = true\n",
            "risk_level": "MEDIUM",
            "risk_score": 65,
            "heuristics": [
                {"rule_id": "MED_NETWORK_WILDCARD", "rule_name": "Wildcard Network Interface Binding",
                 "category": "MEDIUM", "line_number": 2, "line_content": "host = 0.0.0.0",
                 "description": "Binding to 0.0.0.0 exposes internal database to all network interfaces.",
                 "score": 35}
            ]
        },
        {
            "name": "system_manifest.json",
            "path": "[demo]/system_manifest.json",
            "content_baseline": b'{\n  "system": "FIM Sentinel",\n  "status": "operational",\n  "version": "2.0.0"\n}\n',
            "content_modified": None,  # Stays unchanged
            "risk_level": "LOW",
            "risk_score": 0,
            "heuristics": []
        }
    ]

    seeded = []
    for df in DEMO_FILES:
        sha256_b, sha3_b = _hash_bytes(df["content_baseline"])
        is_binary = b"\x00" in df["content_baseline"][:512]
        ts = datetime.now(timezone.utc).timestamp()

        fid = db.add_monitored_file(
            file_path=df["path"],
            file_name=df["name"],
            sha256=sha256_b,
            sha3_256=sha3_b,
            file_size=len(df["content_baseline"]),
            last_modified=ts,
            is_binary=is_binary,
            user_id=user_id,
            is_demo=True
        )

        vault.store_snapshot_bytes(
            file_bytes=df["content_baseline"],
            file_id=fid,
            sha256=sha256_b,
            file_size=len(df["content_baseline"]),
            is_binary=is_binary,
            filename=df["name"]
        )

        if df["content_modified"]:
            sha256_m, sha3_m = _hash_bytes(df["content_modified"])
            db.update_file_status(fid, config.STATUS_MODIFIED)

            # Write current content into tmp to compare with baseline snapshot
            fd, tmp = tempfile.mkstemp(suffix=".txt")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(df["content_modified"])
                comp = compare_file_with_baseline(
                    file_id=fid,
                    current_path=tmp,
                    old_sha256=sha256_b,
                    new_sha256=sha256_m,
                    old_size=len(df["content_baseline"]),
                    vault=vault
                )
            finally:
                try: os.unlink(tmp)
                except Exception: pass

            eid = db.log_event(
                file_id=fid,
                file_path=df["path"],
                event_type=config.STATUS_MODIFIED,
                old_sha256=sha256_b,
                new_sha256=sha256_m,
                old_sha3_256=sha3_b,
                new_sha3_256=sha3_m,
                risk_level=df["risk_level"],
                risk_score=df["risk_score"],
                detected_heuristics=df["heuristics"],
                diff_summary=f"+{comp.added_count} / -{comp.deleted_count} lines",
                raw_diff=comp.raw_unified_diff,
                user_id=user_id,
                is_demo=True
            )
            try:
                r_html = generate_report_html_string(eid)
                db.save_report_metadata(eid, fid, df["name"], r_html, user_id=user_id)
            except Exception:
                pass

        seeded.append({"name": df["name"], "file_id": fid})

    return jsonify({"success": True, "seeded": seeded})


@app.route("/api/demo/clear", methods=["POST"])
def api_demo_clear():
    """Removes only demo-marked files without affecting real monitoring records."""
    removed = db.clear_demo_data(user_id=_get_current_user_id())
    return jsonify({"success": True, "removed": removed})


# ---------------------------------------------------------------------------
# Legacy Routes (Maintained for backward compatibility and local agent)
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
        is_binary=h.is_binary,
        user_id=_get_current_user_id()
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


@app.route("/api/verify_all", methods=["POST"])
def api_verify_all():
    user_id = _get_current_user_id()
    files = db.get_all_monitored_files(user_id=user_id)
    if not files:
        files = db.get_all_monitored_files()

    if monitor is not None and getattr(monitor, "is_running", False):
        for f in files:
            monitor.manual_verify_file(f["id"])
        return jsonify({"success": True, "count": len(files), "message": f"Verified {len(files)} local assets."})

    # Cloud / Serverless mode verification:
    # Verifies integrity of all registered cloud assets & demo baselines against the cryptographic vault
    verified = 0
    now = datetime.now(timezone.utc).isoformat()
    for f in files:
        fid = f["id"]
        snap = vault.read_snapshot_bytes(fid)
        if snap is not None:
            h256, h3 = _hash_bytes(snap)
            if h256 == f["sha256"] and h3 == f["sha3_256"]:
                db.update_file_status(fid, config.STATUS_UNCHANGED)
            else:
                db.update_file_status(fid, config.STATUS_MODIFIED)
        verified += 1
        db._execute("UPDATE monitored_files SET last_checked_at = ? WHERE id = ?", (now, fid))

    return jsonify({
        "success": True,
        "count": verified,
        "serverless": _SERVERLESS,
        "message": f"Integrity scan verified {verified} registered asset(s) against the cryptographic baseline."
    })


@app.route("/api/verify/<int:file_id>", methods=["POST"])
def api_verify_single(file_id):
    if monitor is not None and getattr(monitor, "is_running", False):
        res = monitor.manual_verify_file(file_id)
        return jsonify(res)

    rec = db.get_monitored_file_by_id(file_id)
    if not rec:
        return jsonify({"error": "Asset not found."}), 404

    now = datetime.now(timezone.utc).isoformat()
    snap = vault.read_snapshot_bytes(file_id)
    if snap is not None:
        h256, h3 = _hash_bytes(snap)
        if h256 == rec["sha256"] and h3 == rec["sha3_256"]:
            db.update_file_status(file_id, config.STATUS_UNCHANGED)
            status = config.STATUS_UNCHANGED
            msg = "Integrity verified. Cryptographic baseline hashes intact."
        else:
            db.update_file_status(file_id, config.STATUS_MODIFIED)
            status = config.STATUS_MODIFIED
            msg = "Tampering detected. Hash mismatch against baseline."
    else:
        status = rec.get("status", "UNCHANGED")
        msg = f"Asset {rec['file_name']} verified. Status: {status}"

    db._execute("UPDATE monitored_files SET last_checked_at = ? WHERE id = ?", (now, file_id))
    return jsonify({
        "success": True,
        "file_id": file_id,
        "file_name": rec["file_name"],
        "status": status,
        "message": msg
    })


@app.route("/api/toggle_monitor", methods=["POST"])
def api_toggle_monitor():
    if _SERVERLESS or monitor is None:
        return jsonify({
            "running": False,
            "serverless": True,
            "message": "Real-time kernel monitoring runs locally only. Use Upload & Verify for cloud checks."
        })
    if monitor.is_running:
        monitor.stop()
    else:
        monitor.start()
    return jsonify({"running": monitor.is_running})


# ---------------------------------------------------------------------------
# Local development entry point
# ---------------------------------------------------------------------------
def _open_browser():
    webbrowser.open("http://127.0.0.1:5000")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("[*] FIM Sentinel Web Dashboard starting at: http://127.0.0.1:5000")
    print(f"[*] Database Engine: {'PostgreSQL / Supabase' if db.is_postgres else 'SQLite (WAL)'}")
    print("=" * 60 + "\n")
    Timer(1.2, _open_browser).start()
    app.run(host="127.0.0.1", port=5000, debug=False)
