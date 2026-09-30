"""
Real-time filesystem monitoring using Watchdog with directory tracking,
event debouncing, Windows file-lock handling, and thread-safe queue dispatching.
"""
import os
import time
import threading
import queue
import logging
from pathlib import Path
from typing import Dict, Set, Optional, Any, Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import config
from database.db_manager import get_db
from core.hasher import compute_dual_hash
from core.comparator import compare_file_with_baseline
from core.risk_analyzer import analyze_diff_risk

logger = logging.getLogger(__name__)

class DebouncedFileSystemHandler(FileSystemEventHandler):
    """
    Watchdog event handler that debounces rapid filesystem events (such as Windows atomic saves)
    and filters specifically for monitored files.
    """
    def __init__(self, monitor: "FileIntegrityMonitor"):
        super().__init__()
        self.monitor = monitor

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self.monitor.handle_raw_event("MODIFIED", event.src_path)

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self.monitor.handle_raw_event("CREATED", event.src_path)

    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory:
            self.monitor.handle_raw_event("DELETED", event.src_path)

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self.monitor.handle_raw_event("DELETED", event.src_path)
            if hasattr(event, "dest_path") and event.dest_path:
                self.monitor.handle_raw_event("CREATED", event.dest_path)


class FileIntegrityMonitor:
    def __init__(self, event_queue: Optional[queue.Queue] = None,
                 debounce_sec: float = config.DEBOUNCE_INTERVAL_SEC,
                 db: Optional[Any] = None,
                 vault: Optional[Any] = None):
        self.event_queue = event_queue or queue.Queue()
        self.debounce_sec = debounce_sec
        self.db = db or get_db()
        self.vault = vault or None  # Lazy imported/resolved if None


        self._observer: Optional[Observer] = None
        self._is_running = False
        self._lock = threading.Lock()

        # Normalized monitored paths lookup: {str(Path.resolve()): file_record}
        self._monitored_files: Dict[str, Dict[str, Any]] = {}
        # Parent directories actively scheduled with watchdog: {dir_path: watch_handle}
        self._watched_dirs: Dict[str, Any] = {}
        # Active debounce timers: {file_path: threading.Timer}
        self._debounce_timers: Dict[str, threading.Timer] = {}

        self.reload_monitored_files()

    @property
    def is_running(self) -> bool:
        return self._is_running

    def reload_monitored_files(self):
        """Loads active monitored files from database into fast in-memory lookup set."""
        with self._lock:
            records = self.db.get_all_monitored_files()
            self._monitored_files.clear()
            for r in records:
                norm_p = str(Path(r["file_path"]).resolve())
                self._monitored_files[norm_p] = r

        if self._is_running:
            self._sync_directory_watches()

    def _sync_directory_watches(self):
        """Synchronizes watchdog observer to watch parent directories of all monitored files."""
        if not self._observer:
            return

        needed_dirs: Set[str] = set()
        with self._lock:
            for p in self._monitored_files.keys():
                parent = str(Path(p).parent.resolve())
                if Path(parent).exists():
                    needed_dirs.add(parent)

        # Remove unwatched directories
        current_dirs = list(self._watched_dirs.keys())
        for d in current_dirs:
            if d not in needed_dirs:
                try:
                    self._observer.unschedule(self._watched_dirs[d])
                except Exception:
                    pass
                del self._watched_dirs[d]

        # Add new directories
        handler = DebouncedFileSystemHandler(self)
        for d in needed_dirs:
            if d not in self._watched_dirs:
                try:
                    watch = self._observer.schedule(handler, d, recursive=False)
                    self._watched_dirs[d] = watch
                    logger.info(f"Watchdog attached to parent directory: {d}")
                except Exception as e:
                    logger.error(f"Failed to watch directory {d}: {e}")

    def start(self):
        """Starts real-time monitoring thread."""
        if self._is_running:
            return

        self.reload_monitored_files()
        self._observer = Observer()
        self._sync_directory_watches()

        try:
            self._observer.start()
            self._is_running = True
            logger.info("Watchdog Real-Time Monitor started.")
            self.event_queue.put({
                "type": "MONITOR_STATUS",
                "status": "RUNNING",
                "message": "Real-time monitoring active."
            })
        except Exception as e:
            logger.error(f"Failed to start Observer: {e}")
            self._is_running = False

    def stop(self):
        """Stops the real-time monitoring thread."""
        if not self._is_running or not self._observer:
            return

        with self._lock:
            # Cancel all in-flight debounce timers
            for timer in self._debounce_timers.values():
                timer.cancel()
            self._debounce_timers.clear()

        try:
            self._observer.stop()
            self._observer.join(timeout=2.0)
        except Exception as e:
            logger.error(f"Error stopping Observer: {e}")
        finally:
            self._observer = None
            self._watched_dirs.clear()
            self._is_running = False
            logger.info("Watchdog Real-Time Monitor stopped.")
            self.event_queue.put({
                "type": "MONITOR_STATUS",
                "status": "STOPPED",
                "message": "Real-time monitoring stopped."
            })

    def handle_raw_event(self, event_type: str, raw_path: str):
        """
        Receives raw filesystem event, checks if file is monitored,
        and manages debouncing to coalesce rapid bursts.
        """
        try:
            norm_path = str(Path(raw_path).resolve())
        except Exception:
            return

        with self._lock:
            if norm_path not in self._monitored_files:
                # File is in the watched parent directory, but not on our monitored list! Ignore.
                return

            # Cancel previous debounce timer for this file if active
            if norm_path in self._debounce_timers:
                self._debounce_timers[norm_path].cancel()

            # Schedule debounced execution
            timer = threading.Timer(
                self.debounce_sec,
                self._process_settled_event,
                args=[event_type, norm_path]
            )
            self._debounce_timers[norm_path] = timer
            timer.start()

    def _process_settled_event(self, event_type: str, file_path: str):
        """
        Executes after file write settles (750ms debounce elapsed).
        Recomputes dual-hash, verifies hash mismatch, performs diff, risk assessment,
        and notifies GUI queue.
        """
        with self._lock:
            if file_path in self._debounce_timers:
                del self._debounce_timers[file_path]
            file_rec = self._monitored_files.get(file_path)

        if not file_rec:
            return

        file_id = file_rec["id"]
        baseline_sha256 = file_rec["sha256"]
        baseline_sha3 = file_rec["sha3_256"]
        baseline_size = file_rec["file_size"]
        p = Path(file_path)

        # 1. Handle file deletion
        if not p.exists() or event_type == "DELETED":
            self.db.update_file_status(file_id, "MISSING")
            event_id = self.db.log_event(
                file_id=file_id,
                file_path=file_path,
                event_type="DELETED",
                old_sha256=baseline_sha256,
                new_sha256="",
                old_sha3_256=baseline_sha3,
                new_sha3_256="",
                risk_level="HIGH",
                risk_score=75,
                detected_heuristics=[{
                    "rule_id": "CRIT_FILE_DELETED",
                    "rule_name": "Monitored File Deletion",
                    "category": "HIGH",
                    "line_number": None,
                    "description": f"Monitored file was deleted or unlinked: {p.name}",
                    "score": 75
                }],
                diff_summary="File deleted from filesystem."
            )
            self.event_queue.put({
                "type": "TAMPER_ALERT",
                "file_id": file_id,
                "file_path": file_path,
                "file_name": p.name,
                "event_id": event_id,
                "event_type": "DELETED",
                "risk_level": "HIGH",
                "risk_score": 75,
                "message": f"Monitored file was deleted: {p.name}"
            })
            return

        # 2. Compute Dual Hash with single-pass and lock resilience
        hash_res = compute_dual_hash(file_path)
        if hash_res.error:
            logger.warning(f"Error hashing file {file_path}: {hash_res.error}")
            return

        # 3. Guard against false alerts: check if hash actually changed
        if hash_res.sha256 == baseline_sha256 and hash_res.sha3_256 == baseline_sha3:
            # Metadata-only touch or false event; content is intact. Discard silently!
            return

        # 4. Hash mismatch confirmed -> Tampering Detected!
        logger.warning(f"Integrity violation detected on {file_path}!")

        # 5. Granular diff comparison against baseline snapshot
        comp = compare_file_with_baseline(
            file_id=file_id,
            current_path=file_path,
            old_sha256=baseline_sha256,
            new_sha256=hash_res.sha256,
            old_size=baseline_size,
            vault=self.vault
        )


        # 6. Static deterministic risk evaluation
        risk = analyze_diff_risk(comp, file_path=file_path)

        # 7. Update status in DB
        self.db.update_file_status(file_id, "MODIFIED")

        # 8. Log forensic event
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

        diff_summary = f"+{comp.added_count} / -{comp.deleted_count} lines" if not comp.is_binary else f"Binary size delta: {comp.size_delta:+d} bytes"

        event_id = self.db.log_event(
            file_id=file_id,
            file_path=file_path,
            event_type="MODIFIED",
            old_sha256=baseline_sha256,
            new_sha256=hash_res.sha256,
            old_sha3_256=baseline_sha3,
            new_sha3_256=hash_res.sha3_256,
            risk_level=risk.risk_level,
            risk_score=risk.overall_score,
            detected_heuristics=heuristics_data,
            diff_summary=diff_summary
        )

        # 9. Push to GUI Queue for smooth, thread-safe UI update
        self.event_queue.put({
            "type": "TAMPER_ALERT",
            "file_id": file_id,
            "file_path": file_path,
            "file_name": p.name,
            "event_id": event_id,
            "event_type": "MODIFIED",
            "risk_level": risk.risk_level,
            "risk_score": risk.overall_score,
            "added_count": comp.added_count,
            "deleted_count": comp.deleted_count,
            "summary": risk.summary_text,
            "message": f"Tampering Alert: {p.name} ({risk.risk_level} Risk)"
        })

    def manual_verify_file(self, file_id: int) -> Dict[str, Any]:
        """Manually runs integrity verification for a single file."""
        rec = self.db.get_monitored_file_by_id(file_id)
        if not rec:
            return {"status": "ERROR", "message": "File record not found."}

        file_path = rec["file_path"]
        p = Path(file_path)

        if not p.exists():
            self.db.update_file_status(file_id, "MISSING")
            return {"status": "MISSING", "message": "File does not exist on disk."}

        res = compute_dual_hash(file_path)
        if res.error:
            return {"status": "ERROR", "message": res.error}

        if res.sha256 == rec["sha256"] and res.sha3_256 == rec["sha3_256"]:
            self.db.update_file_status(file_id, "CLEAN")
            return {"status": "CLEAN", "message": "File integrity intact. Dual hashes match baseline."}
        else:
            self.db.update_file_status(file_id, "MODIFIED")
            # Run comparison and risk analysis
            comp = compare_file_with_baseline(
                file_id=file_id,
                current_path=file_path,
                old_sha256=rec["sha256"],
                new_sha256=res.sha256,
                old_size=rec["file_size"],
                vault=self.vault
            )

            risk = analyze_diff_risk(comp, file_path=file_path)
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
            diff_summary = f"+{comp.added_count} / -{comp.deleted_count} lines" if not comp.is_binary else f"Binary size delta: {comp.size_delta:+d} bytes"
            event_id = self.db.log_event(
                file_id=file_id,
                file_path=file_path,
                event_type="MODIFIED",
                old_sha256=rec["sha256"],
                new_sha256=res.sha256,
                old_sha3_256=rec["sha3_256"],
                new_sha3_256=res.sha3_256,
                risk_level=risk.risk_level,
                risk_score=risk.overall_score,
                detected_heuristics=heuristics_data,
                diff_summary=diff_summary
            )
            return {
                "status": "MODIFIED",
                "risk_level": risk.risk_level,
                "risk_score": risk.overall_score,
                "event_id": event_id,
                "message": f"Tampered! Hashes do not match baseline ({risk.risk_level} Risk)."
            }
