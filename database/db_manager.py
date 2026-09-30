"""
SQLite database manager with Write-Ahead Logging (WAL) mode and thread-safe operations.
"""
import sqlite3
import threading
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import config

class DBManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path: Optional[Path] = None):
        with cls._lock:
            if db_path is not None:
                # Direct instance for custom/test database paths
                instance = super(DBManager, cls).__new__(cls)
                instance._initialized = False
                return instance
            if cls._instance is None:
                cls._instance = super(DBManager, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance


    def __init__(self, db_path: Optional[Path] = None):
        if self._initialized:
            return
        self.db_path = str(db_path or config.DB_PATH)
        self._local = threading.local()
        self._all_conns = set()
        self._conn_lock = threading.Lock()
        self._init_db()
        self._initialized = True

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a thread-local SQLite connection with WAL mode enabled."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            # Enable WAL mode for high concurrency across threads
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._local.conn = conn
            with self._conn_lock:
                self._all_conns.add(conn)
        return self._local.conn


    def _init_db(self):
        """Initializes database schema if tables do not exist."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            cursor = conn.cursor()

            # Monitored files table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS monitored_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE NOT NULL,
                file_name TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                sha3_256 TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                last_modified REAL NOT NULL,
                is_binary INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'CLEAN',
                created_at TEXT NOT NULL,
                last_checked_at TEXT
            );
            """)

            # Baseline snapshots table (maps to vault copies)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS baseline_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                vault_path TEXT NOT NULL,
                snapshot_hash_sha256 TEXT NOT NULL,
                snapshot_size INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES monitored_files(id) ON DELETE CASCADE
            );
            """)

            # Forensic event history
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                file_path TEXT NOT NULL,
                event_type TEXT NOT NULL,
                old_sha256 TEXT,
                new_sha256 TEXT,
                old_sha3_256 TEXT,
                new_sha3_256 TEXT,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                detected_heuristics TEXT,
                diff_summary TEXT,
                ai_summary TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES monitored_files(id) ON DELETE SET NULL
            );
            """)

            # Application settings
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            """)

            conn.commit()
        finally:
            conn.close()


    # --- Monitored Files CRUD ---

    def add_monitored_file(self, file_path: str, file_name: str, sha256: str,
                           sha3_256: str, file_size: int, last_modified: float,
                           is_binary: bool) -> int:
        """Inserts or replaces a monitored file baseline."""
        conn = self._get_connection()
        now = datetime.now().isoformat()
        with conn:
            cursor = conn.execute("""
            INSERT INTO monitored_files (
                file_path, file_name, sha256, sha3_256, file_size,
                last_modified, is_binary, status, created_at, last_checked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'CLEAN', ?, ?)
            ON CONFLICT(file_path) DO UPDATE SET
                file_name=excluded.file_name,
                sha256=excluded.sha256,
                sha3_256=excluded.sha3_256,
                file_size=excluded.file_size,
                last_modified=excluded.last_modified,
                is_binary=excluded.is_binary,
                status='CLEAN',
                last_checked_at=excluded.last_checked_at
            RETURNING id;
            """, (file_path, file_name, sha256, sha3_256, file_size,
                  last_modified, 1 if is_binary else 0, now, now))
            row = cursor.fetchone()
            return row["id"] if row else -1

    def get_all_monitored_files(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM monitored_files ORDER BY id DESC")
        return [dict(row) for row in cursor.fetchall()]

    def get_monitored_file_by_id(self, file_id: int) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM monitored_files WHERE id = ?", (file_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_monitored_file_by_path(self, file_path: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM monitored_files WHERE file_path = ?", (file_path,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def update_file_status(self, file_id: int, status: str, last_checked: Optional[str] = None):
        conn = self._get_connection()
        now = last_checked or datetime.now().isoformat()
        with conn:
            conn.execute("""
            UPDATE monitored_files
            SET status = ?, last_checked_at = ?
            WHERE id = ?
            """, (status, now, file_id))

    def update_file_baseline(self, file_id: int, sha256: str, sha3_256: str,
                             file_size: int, last_modified: float):
        conn = self._get_connection()
        now = datetime.now().isoformat()
        with conn:
            conn.execute("""
            UPDATE monitored_files
            SET sha256 = ?, sha3_256 = ?, file_size = ?, last_modified = ?,
                status = 'CLEAN', last_checked_at = ?
            WHERE id = ?
            """, (sha256, sha3_256, file_size, last_modified, now, file_id))

    def remove_monitored_file(self, file_id: int):
        conn = self._get_connection()
        with conn:
            conn.execute("DELETE FROM monitored_files WHERE id = ?", (file_id,))

    # --- Baseline Snapshot Storage ---

    def add_baseline_snapshot(self, file_id: int, vault_path: str,
                              snapshot_hash: str, snapshot_size: int):
        conn = self._get_connection()
        now = datetime.now().isoformat()
        with conn:
            conn.execute("""
            INSERT INTO baseline_snapshots (file_id, vault_path, snapshot_hash_sha256, snapshot_size, created_at)
            VALUES (?, ?, ?, ?, ?)
            """, (file_id, vault_path, snapshot_hash, snapshot_size, now))

    def get_latest_snapshot(self, file_id: int) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        cursor = conn.execute("""
        SELECT * FROM baseline_snapshots WHERE file_id = ? ORDER BY id DESC LIMIT 1
        """, (file_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    # --- Event History Log ---

    def log_event(self, file_id: Optional[int], file_path: str, event_type: str,
                  old_sha256: Optional[str], new_sha256: Optional[str],
                  old_sha3_256: Optional[str], new_sha3_256: Optional[str],
                  risk_level: str, risk_score: int, detected_heuristics: List[Dict[str, Any]],
                  diff_summary: Optional[str] = None, ai_summary: Optional[str] = None) -> int:
        conn = self._get_connection()
        now = datetime.now().isoformat()
        heuristics_json = json.dumps(detected_heuristics)
        with conn:
            cursor = conn.execute("""
            INSERT INTO event_history (
                file_id, file_path, event_type, old_sha256, new_sha256,
                old_sha3_256, new_sha3_256, risk_level, risk_score,
                detected_heuristics, diff_summary, ai_summary, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id;
            """, (file_id, file_path, event_type, old_sha256, new_sha256,
                  old_sha3_256, new_sha3_256, risk_level, risk_score,
                  heuristics_json, diff_summary, ai_summary, now))
            row = cursor.fetchone()
            return row["id"] if row else -1

    def update_event_ai_summary(self, event_id: int, ai_summary: str):
        conn = self._get_connection()
        with conn:
            conn.execute("UPDATE event_history SET ai_summary = ? WHERE id = ?", (ai_summary, event_id))

    def get_event_history(self, limit: int = 100, risk_filter: Optional[str] = None,
                          search_query: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        query = "SELECT * FROM event_history WHERE 1=1"
        params: List[Any] = []

        if risk_filter and risk_filter.upper() != "ALL":
            query += " AND risk_level = ?"
            params.append(risk_filter.upper())

        if search_query:
            query += " AND (file_path LIKE ? OR diff_summary LIKE ? OR detected_heuristics LIKE ?)"
            pattern = f"%{search_query}%"
            params.extend([pattern, pattern, pattern])

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor = conn.execute(query, params)
        rows = []
        for r in cursor.fetchall():
            d = dict(r)
            try:
                d["detected_heuristics"] = json.loads(d["detected_heuristics"]) if d["detected_heuristics"] else []
            except Exception:
                d["detected_heuristics"] = []
            rows.append(d)
        return rows

    def get_event_by_id(self, event_id: int) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM event_history WHERE id = ?", (event_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["detected_heuristics"] = json.loads(d["detected_heuristics"]) if d["detected_heuristics"] else []
        except Exception:
            d["detected_heuristics"] = []
        return d

    # --- Aggregates / Stats ---

    def get_system_stats(self) -> Dict[str, Any]:
        conn = self._get_connection()
        total_files = conn.execute("SELECT COUNT(*) as cnt FROM monitored_files").fetchone()["cnt"]
        clean_files = conn.execute("SELECT COUNT(*) as cnt FROM monitored_files WHERE status = 'CLEAN'").fetchone()["cnt"]
        modified_files = conn.execute("SELECT COUNT(*) as cnt FROM monitored_files WHERE status = 'MODIFIED'").fetchone()["cnt"]
        missing_files = conn.execute("SELECT COUNT(*) as cnt FROM monitored_files WHERE status = 'MISSING'").fetchone()["cnt"]

        high_alerts = conn.execute("SELECT COUNT(*) as cnt FROM event_history WHERE risk_level = 'HIGH'").fetchone()["cnt"]
        medium_alerts = conn.execute("SELECT COUNT(*) as cnt FROM event_history WHERE risk_level = 'MEDIUM'").fetchone()["cnt"]
        low_alerts = conn.execute("SELECT COUNT(*) as cnt FROM event_history WHERE risk_level = 'LOW'").fetchone()["cnt"]
        total_events = conn.execute("SELECT COUNT(*) as cnt FROM event_history").fetchone()["cnt"]

        return {
            "total_files": total_files,
            "clean_files": clean_files,
            "modified_files": modified_files,
            "missing_files": missing_files,
            "high_alerts": high_alerts,
            "medium_alerts": medium_alerts,
            "low_alerts": low_alerts,
            "total_events": total_events
        }

    # --- App Settings ---

    def set_setting(self, key: str, value: str):
        conn = self._get_connection()
        with conn:
            conn.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)", (key, value))

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        conn = self._get_connection()
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def close(self):
        """Closes all connections opened across all threads."""
        with self._conn_lock:
            for c in list(self._all_conns):
                try:
                    c.close()
                except Exception:
                    pass
            self._all_conns.clear()
        if hasattr(self._local, "conn"):
            self._local.conn = None


def get_db() -> DBManager:
    return DBManager()

