"""
Database manager supporting Supabase PostgreSQL and SQLite with WAL mode.
Provides thread-safe connections, automatic schema migrations, and persistent forensic logging.
"""
import os
import ssl
import json
import sqlite3
import logging
import threading
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

import config

logger = logging.getLogger(__name__)


class DBManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path: Optional[Path] = None):
        with cls._lock:
            if db_path is not None:
                instance = super(DBManager, cls).__new__(cls)
                instance._initialized = False
                return instance
            if cls._instance is None:
                cls._instance = super(DBManager, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db_path: Optional[Path] = None):
        if getattr(self, "_initialized", False):
            return

        self.db_path = str(db_path or config.DB_PATH)
        self.database_url = getattr(config, "DATABASE_URL", "").strip()
        self.is_postgres = bool(
            self.database_url.startswith("postgres://") or
            self.database_url.startswith("postgresql://")
        )

        self._local = threading.local()
        self._all_conns = set()
        self._conn_lock = threading.Lock()

        self._init_db()
        self._initialized = True

    # ---------------------------------------------------------------------------
    # Connection Management
    # ---------------------------------------------------------------------------

    def _get_postgres_connection(self):
        """Creates a PostgreSQL connection using pg8000 with SSL."""
        try:
            import pg8000.dbapi
        except ImportError:
            raise RuntimeError("pg8000 package is required for PostgreSQL / Supabase connection.")

        url_str = self.database_url
        # Normalize protocol if needed
        if url_str.startswith("postgres://"):
            url_str = "postgresql://" + url_str[len("postgres://"):]

        parsed = urllib.parse.urlparse(url_str)
        username = urllib.parse.unquote(parsed.username or "postgres")
        password = urllib.parse.unquote(parsed.password or "")
        host = parsed.hostname or "localhost"
        port = parsed.port or 5432
        database = parsed.path.lstrip("/") or "postgres"

        # Supabase and cloud Postgres require SSL
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        conn = pg8000.dbapi.connect(
            user=username,
            password=password,
            host=host,
            port=port,
            database=database,
            ssl_context=ssl_context,
            timeout=15
        )
        conn.autocommit = True
        return conn

    def _get_connection(self):
        """Returns a thread-local database connection (PostgreSQL or SQLite)."""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            return self._local.conn

        if self.is_postgres:
            try:
                conn = self._get_postgres_connection()
                self._local.conn = conn
                with self._conn_lock:
                    self._all_conns.add(conn)
                return conn
            except Exception as e:
                logger.error(f"PostgreSQL connection failed ({e}). Falling back to SQLite: {self.db_path}")
                self.is_postgres = False

        # SQLite Connection
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
        except Exception:
            pass

        self._local.conn = conn
        with self._conn_lock:
            self._all_conns.add(conn)
        return conn

    # ---------------------------------------------------------------------------
    # Query Execution Helpers
    # ---------------------------------------------------------------------------

    def _execute(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Executes a query and returns results as a list of dictionaries."""
        conn = self._get_connection()

        if self.is_postgres:
            pg_query = query.replace("?", "%s")
            cursor = conn.cursor()
            try:
                cursor.execute(pg_query, params)
                if cursor.description:
                    cols = [col[0] for col in cursor.description]
                    return [dict(zip(cols, row)) for row in cursor.fetchall()]
                return []
            except Exception as e:
                logger.error(f"Postgres query error: {e} | Query: {pg_query}")
                raise
        else:
            with conn:
                cursor = conn.execute(query, params)
                if cursor.description:
                    return [dict(row) for row in cursor.fetchall()]
                return []

    def _execute_insert(self, query: str, params: tuple = ()) -> int:
        """Executes an INSERT statement and returns the inserted/returned ID."""
        conn = self._get_connection()

        if self.is_postgres:
            pg_query = query.replace("?", "%s")
            if "RETURNING id" not in pg_query:
                pg_query = pg_query.rstrip("; ") + " RETURNING id;"
            cursor = conn.cursor()
            cursor.execute(pg_query, params)
            row = cursor.fetchone()
            return row[0] if row else -1
        else:
            with conn:
                cursor = conn.execute(query, params)
                if cursor.description:
                    row = cursor.fetchone()
                    return row["id"] if row else -1
                return cursor.lastrowid or -1

    # ---------------------------------------------------------------------------
    # Schema Initialization & Migrations
    # ---------------------------------------------------------------------------

    def _init_db(self):
        """Initializes database schema and runs non-destructive migrations."""
        if self.is_postgres:
            self._init_postgres_schema()
        else:
            self._init_sqlite_schema()

    def _init_postgres_schema(self):
        try:
            conn = self._get_postgres_connection()
            cursor = conn.cursor()

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS monitored_files (
                id SERIAL PRIMARY KEY,
                file_path TEXT UNIQUE NOT NULL,
                file_name TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                sha3_256 TEXT NOT NULL,
                file_size BIGINT NOT NULL,
                last_modified DOUBLE PRECISION NOT NULL,
                is_binary INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'UNCHANGED',
                created_at TEXT NOT NULL,
                last_checked_at TEXT,
                user_id TEXT DEFAULT 'default_user',
                is_demo INTEGER DEFAULT 0
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS baseline_snapshots (
                id SERIAL PRIMARY KEY,
                file_id INTEGER NOT NULL,
                vault_path TEXT NOT NULL,
                snapshot_hash_sha256 TEXT NOT NULL,
                snapshot_size BIGINT NOT NULL,
                snapshot_content TEXT,
                created_at TEXT NOT NULL
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_history (
                id SERIAL PRIMARY KEY,
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
                raw_diff TEXT,
                ai_summary TEXT,
                timestamp TEXT NOT NULL,
                user_id TEXT DEFAULT 'default_user',
                is_demo INTEGER DEFAULT 0
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS report_metadata (
                id SERIAL PRIMARY KEY,
                event_id INTEGER NOT NULL,
                file_id INTEGER,
                file_name TEXT,
                report_html TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                user_id TEXT DEFAULT 'default_user'
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            """)
            cursor.close()
            conn.close()
            logger.info("Supabase / PostgreSQL schema initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize PostgreSQL schema: {e}. Falling back to SQLite.")
            self.is_postgres = False
            self._init_sqlite_schema()

    def _init_sqlite_schema(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            cursor = conn.cursor()

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
                status TEXT NOT NULL DEFAULT 'UNCHANGED',
                created_at TEXT NOT NULL,
                last_checked_at TEXT,
                user_id TEXT DEFAULT 'default_user',
                is_demo INTEGER DEFAULT 0
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS baseline_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                vault_path TEXT NOT NULL,
                snapshot_hash_sha256 TEXT NOT NULL,
                snapshot_size INTEGER NOT NULL,
                snapshot_content TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES monitored_files(id) ON DELETE CASCADE
            );
            """)

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
                raw_diff TEXT,
                ai_summary TEXT,
                timestamp TEXT NOT NULL,
                user_id TEXT DEFAULT 'default_user',
                is_demo INTEGER DEFAULT 0,
                FOREIGN KEY (file_id) REFERENCES monitored_files(id) ON DELETE SET NULL
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS report_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                file_id INTEGER,
                file_name TEXT,
                report_html TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                user_id TEXT DEFAULT 'default_user'
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            """)

            # Safe migrations for existing SQLite databases
            existing_cols = {row[1] for row in cursor.execute("PRAGMA table_info(monitored_files)").fetchall()}
            if "user_id" not in existing_cols:
                try: cursor.execute("ALTER TABLE monitored_files ADD COLUMN user_id TEXT DEFAULT 'default_user';")
                except Exception: pass
            if "is_demo" not in existing_cols:
                try: cursor.execute("ALTER TABLE monitored_files ADD COLUMN is_demo INTEGER DEFAULT 0;")
                except Exception: pass

            snap_cols = {row[1] for row in cursor.execute("PRAGMA table_info(baseline_snapshots)").fetchall()}
            if "snapshot_content" not in snap_cols:
                try: cursor.execute("ALTER TABLE baseline_snapshots ADD COLUMN snapshot_content TEXT;")
                except Exception: pass

            event_cols = {row[1] for row in cursor.execute("PRAGMA table_info(event_history)").fetchall()}
            if "user_id" not in event_cols:
                try: cursor.execute("ALTER TABLE event_history ADD COLUMN user_id TEXT DEFAULT 'default_user';")
                except Exception: pass
            if "is_demo" not in event_cols:
                try: cursor.execute("ALTER TABLE event_history ADD COLUMN is_demo INTEGER DEFAULT 0;")
                except Exception: pass
            if "raw_diff" not in event_cols:
                try: cursor.execute("ALTER TABLE event_history ADD COLUMN raw_diff TEXT;")
                except Exception: pass

            conn.commit()
        finally:
            conn.close()

    # ---------------------------------------------------------------------------
    # Monitored Files CRUD
    # ---------------------------------------------------------------------------

    def add_monitored_file(self, file_path: str, file_name: str, sha256: str,
                           sha3_256: str, file_size: int, last_modified: float,
                           is_binary: bool, user_id: str = "default_user",
                           is_demo: bool = False) -> int:
        """Inserts or updates a monitored file baseline."""
        now = datetime.now().isoformat()
        demo_flag = 1 if (is_demo or file_path.startswith("[demo]")) else 0

        existing = self.get_monitored_file_by_path(file_path, user_id=user_id)
        if existing:
            file_id = existing["id"]
            self.update_file_baseline(
                file_id=file_id,
                sha256=sha256,
                sha3_256=sha3_256,
                file_size=file_size,
                last_modified=last_modified,
                is_binary=is_binary
            )
            return file_id

        query = """
        INSERT INTO monitored_files (
            file_path, file_name, sha256, sha3_256, file_size,
            last_modified, is_binary, status, created_at, last_checked_at, user_id, is_demo
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'UNCHANGED', ?, ?, ?, ?)
        RETURNING id;
        """
        params = (
            file_path, file_name, sha256, sha3_256, file_size,
            last_modified, 1 if is_binary else 0, now, now, user_id, demo_flag
        )
        return self._execute_insert(query, params)

    def get_all_monitored_files(self, user_id: Optional[str] = None, include_demo: bool = True) -> List[Dict[str, Any]]:
        query = "SELECT * FROM monitored_files WHERE 1=1"
        params = []
        if user_id:
            query += " AND (user_id = ? OR user_id = 'default_user' OR is_demo = 1)"
            params.append(user_id)
        if not include_demo:
            query += " AND is_demo = 0"
        query += " ORDER BY id DESC"
        return self._execute(query, tuple(params))

    def get_monitored_file_by_id(self, file_id: int) -> Optional[Dict[str, Any]]:
        rows = self._execute("SELECT * FROM monitored_files WHERE id = ?", (file_id,))
        return rows[0] if rows else None

    def get_monitored_file_by_path(self, file_path: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if user_id:
            rows = self._execute("SELECT * FROM monitored_files WHERE file_path = ? AND (user_id = ? OR user_id = 'default_user')", (file_path, user_id))
        else:
            rows = self._execute("SELECT * FROM monitored_files WHERE file_path = ?", (file_path,))
        return rows[0] if rows else None

    def update_file_status(self, file_id: int, status: str, last_checked: Optional[str] = None):
        now = last_checked or datetime.now().isoformat()
        # Normalise status: CLEAN -> UNCHANGED
        norm_status = "UNCHANGED" if status.upper() in ("CLEAN", "UNCHANGED") else status.upper()
        self._execute("""
        UPDATE monitored_files
        SET status = ?, last_checked_at = ?
        WHERE id = ?
        """, (norm_status, now, file_id))

    def update_file_baseline(self, file_id: int, sha256: str, sha3_256: str,
                             file_size: int, last_modified: float,
                             is_binary: bool = False):
        now = datetime.now().isoformat()
        self._execute("""
        UPDATE monitored_files
        SET sha256 = ?, sha3_256 = ?, file_size = ?, last_modified = ?,
            is_binary = ?, status = 'UNCHANGED', last_checked_at = ?
        WHERE id = ?
        """, (sha256, sha3_256, file_size, last_modified, 1 if is_binary else 0, now, file_id))

    def remove_monitored_file(self, file_id: int):
        self._execute("DELETE FROM baseline_snapshots WHERE file_id = ?", (file_id,))
        self._execute("DELETE FROM monitored_files WHERE id = ?", (file_id,))

    def delete_monitored_file(self, file_id: int):
        self.remove_monitored_file(file_id)

    # ---------------------------------------------------------------------------
    # Baseline Snapshots Storage
    # ---------------------------------------------------------------------------

    def add_baseline_snapshot(self, file_id: int, vault_path: str,
                              snapshot_hash: str, snapshot_size: int,
                              snapshot_content: Optional[str] = None):
        """Stores baseline snapshot reference and snapshot content directly in database."""
        now = datetime.now().isoformat()
        query = """
        INSERT INTO baseline_snapshots (file_id, vault_path, snapshot_hash_sha256, snapshot_size, snapshot_content, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        self._execute(query, (file_id, vault_path, snapshot_hash, snapshot_size, snapshot_content, now))

    def get_latest_snapshot(self, file_id: int) -> Optional[Dict[str, Any]]:
        rows = self._execute("""
        SELECT * FROM baseline_snapshots WHERE file_id = ? ORDER BY id DESC LIMIT 1
        """, (file_id,))
        return rows[0] if rows else None

    # ---------------------------------------------------------------------------
    # Event History Log & Duplicate Prevention
    # ---------------------------------------------------------------------------

    def check_duplicate_tamper(self, file_id: int, new_sha256: str) -> Optional[Dict[str, Any]]:
        """
        Checks if the most recent event for this file was already logged
        with the exact same modified hash, preventing duplicate modification alerts.
        """
        rows = self._execute("""
        SELECT * FROM event_history
        WHERE file_id = ?
        ORDER BY id DESC LIMIT 1
        """, (file_id,))
        if rows and rows[0].get("new_sha256") == new_sha256 and rows[0].get("event_type") == "MODIFIED":
            return rows[0]
        return None

    def log_event(self, file_id: Optional[int], file_path: str, event_type: str,
                  old_sha256: Optional[str], new_sha256: Optional[str],
                  old_sha3_256: Optional[str], new_sha3_256: Optional[str],
                  risk_level: str, risk_score: int, detected_heuristics: List[Dict[str, Any]],
                  diff_summary: Optional[str] = None, ai_summary: Optional[str] = None,
                  raw_diff: Optional[str] = None, user_id: str = "default_user",
                  is_demo: bool = False) -> int:
        now = datetime.now().isoformat()
        heuristics_json = json.dumps(detected_heuristics) if isinstance(detected_heuristics, list) else str(detected_heuristics or "[]")
        demo_flag = 1 if (is_demo or file_path.startswith("[demo]")) else 0

        query = """
        INSERT INTO event_history (
            file_id, file_path, event_type, old_sha256, new_sha256,
            old_sha3_256, new_sha3_256, risk_level, risk_score,
            detected_heuristics, diff_summary, raw_diff, ai_summary, timestamp, user_id, is_demo
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id;
        """
        params = (
            file_id, file_path, event_type, old_sha256, new_sha256,
            old_sha3_256, new_sha3_256, risk_level, risk_score,
            heuristics_json, diff_summary, raw_diff, ai_summary, now, user_id, demo_flag
        )
        return self._execute_insert(query, params)

    def update_event_ai_summary(self, event_id: int, ai_summary: str):
        self._execute("UPDATE event_history SET ai_summary = ? WHERE id = ?", (ai_summary, event_id))

    def update_event_diff(self, event_id: int, raw_diff: str, diff_summary: Optional[str] = None):
        """Updates raw diff (and optional summary) for an event."""
        if diff_summary:
            self._execute("UPDATE event_history SET raw_diff = ?, diff_summary = ? WHERE id = ?", (raw_diff, diff_summary, event_id))
        else:
            self._execute("UPDATE event_history SET raw_diff = ? WHERE id = ?", (raw_diff, event_id))

    def get_latest_event_for_file(self, file_id: int) -> Optional[Dict[str, Any]]:
        """Returns the most recent event record for a specific file."""
        rows = self._execute("SELECT * FROM event_history WHERE file_id = ? ORDER BY id DESC LIMIT 1", (file_id,))
        if not rows:
            return None
        d = rows[0]
        if isinstance(d.get("detected_heuristics"), str):
            try:
                d["detected_heuristics"] = json.loads(d["detected_heuristics"])
            except Exception:
                d["detected_heuristics"] = []
        elif d.get("detected_heuristics") is None:
            d["detected_heuristics"] = []
        return d

    def get_event_history(self, limit: int = 100, risk_filter: Optional[str] = None,
                          search_query: Optional[str] = None, user_id: Optional[str] = None,
                          include_demo: bool = True) -> List[Dict[str, Any]]:
        query = "SELECT * FROM event_history WHERE 1=1"
        params: List[Any] = []

        if user_id:
            query += " AND (user_id = ? OR user_id = 'default_user' OR is_demo = 1)"
            params.append(user_id)

        if not include_demo:
            query += " AND is_demo = 0"

        if risk_filter and risk_filter.upper() != "ALL":
            query += " AND risk_level = ?"
            params.append(risk_filter.upper())

        if search_query:
            query += " AND (file_path LIKE ? OR diff_summary LIKE ? OR detected_heuristics LIKE ?)"
            pattern = f"%{search_query}%"
            params.extend([pattern, pattern, pattern])

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = self._execute(query, tuple(params))
        for r in rows:
            if isinstance(r.get("detected_heuristics"), str):
                try:
                    r["detected_heuristics"] = json.loads(r["detected_heuristics"])
                except Exception:
                    r["detected_heuristics"] = []
            elif r.get("detected_heuristics") is None:
                r["detected_heuristics"] = []
        return rows

    def get_event_by_id(self, event_id: int) -> Optional[Dict[str, Any]]:
        rows = self._execute("SELECT * FROM event_history WHERE id = ?", (event_id,))
        if not rows:
            return None
        d = rows[0]
        if isinstance(d.get("detected_heuristics"), str):
            try:
                d["detected_heuristics"] = json.loads(d["detected_heuristics"])
            except Exception:
                d["detected_heuristics"] = []
        return d

    # ---------------------------------------------------------------------------
    # Report Metadata CRUD
    # ---------------------------------------------------------------------------

    def save_report_metadata(self, event_id: int, file_id: Optional[int], file_name: str,
                             report_html: str, user_id: str = "default_user") -> int:
        now = datetime.now().isoformat()
        # Delete prior report for this event if exists
        self._execute("DELETE FROM report_metadata WHERE event_id = ?", (event_id,))
        query = """
        INSERT INTO report_metadata (event_id, file_id, file_name, report_html, generated_at, user_id)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING id;
        """
        return self._execute_insert(query, (event_id, file_id, file_name, report_html, now, user_id))

    def get_report_metadata(self, event_id: int) -> Optional[Dict[str, Any]]:
        rows = self._execute("SELECT * FROM report_metadata WHERE event_id = ?", (event_id,))
        return rows[0] if rows else None

    def get_all_reports(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM report_metadata WHERE 1=1"
        params = []
        if user_id:
            query += " AND (user_id = ? OR user_id = 'default_user' OR is_demo = 1)"
            params.append(user_id)
        query += " ORDER BY id DESC LIMIT 100"
        return self._execute(query, tuple(params))

    # ---------------------------------------------------------------------------
    # Aggregates / Stats
    # ---------------------------------------------------------------------------

    def get_system_stats(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        user_filter = " WHERE (user_id = ? OR user_id = 'default_user' OR is_demo = 1)" if user_id else ""
        user_param = (user_id,) if user_id else ()

        files = self._execute(f"SELECT status, COUNT(*) as cnt FROM monitored_files{user_filter} GROUP BY status", user_param)
        status_counts = {r["status"]: r["cnt"] for r in files}

        total_files = sum(status_counts.values())
        clean_files = status_counts.get("UNCHANGED", 0) + status_counts.get("CLEAN", 0)
        modified_files = status_counts.get("MODIFIED", 0)
        missing_files = status_counts.get("MISSING", 0)

        events = self._execute(f"SELECT risk_level, COUNT(*) as cnt FROM event_history{user_filter} GROUP BY risk_level", user_param)
        risk_counts = {r["risk_level"]: r["cnt"] for r in events}

        high_alerts = risk_counts.get("HIGH", 0)
        medium_alerts = risk_counts.get("MEDIUM", 0)
        low_alerts = risk_counts.get("LOW", 0)
        total_events = sum(risk_counts.values())

        return {
            "total_files": total_files,
            "clean_files": clean_files,
            "modified_files": modified_files,
            "missing_files": missing_files,
            "high_alerts": high_alerts,
            "medium_alerts": medium_alerts,
            "low_alerts": low_alerts,
            "total_events": total_events,
            "is_postgres": self.is_postgres
        }

    # ---------------------------------------------------------------------------
    # App Settings
    # ---------------------------------------------------------------------------

    def set_setting(self, key: str, value: str):
        query = "INSERT INTO app_settings (key, value) VALUES (?, ?)"
        if self.is_postgres:
            query += " ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value;"
        else:
            query = "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)"
        self._execute(query, (key, value))

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        rows = self._execute("SELECT value FROM app_settings WHERE key = ?", (key,))
        return rows[0]["value"] if rows else default

    # ---------------------------------------------------------------------------
    # Demo Data Cleanup
    # ---------------------------------------------------------------------------

    def clear_demo_data(self, user_id: Optional[str] = None) -> int:
        """Removes all demo-marked files, snapshots, and events."""
        files = self._execute("SELECT id FROM monitored_files WHERE is_demo = 1 OR file_path LIKE '[demo]%'")
        count = len(files)
        for f in files:
            self.remove_monitored_file(f["id"])
        self._execute("DELETE FROM event_history WHERE is_demo = 1 OR file_path LIKE '[demo]%'")
        return count

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
