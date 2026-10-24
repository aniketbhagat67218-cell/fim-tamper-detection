"""
Secure Snapshot Vault for caching baseline file content.
Enables syntactical delta reconstruction and difflib comparison upon tamper detection.
"""
import os
import shutil
import logging
from pathlib import Path
from typing import Optional, Any, Union
import config
from database.db_manager import get_db

logger = logging.getLogger(__name__)

class SnapshotVault:
    def __init__(self, vault_dir: Optional[Path] = None, max_size_bytes: int = config.MAX_SNAPSHOT_SIZE_BYTES,
                 db: Optional[Any] = None):
        self.vault_dir = Path(vault_dir or config.VAULT_DIR).resolve()
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.max_size_bytes = max_size_bytes
        self.db = db or get_db()


    def store_snapshot(self, file_path: Union[str, Path], file_id: int,
                       sha256: str, file_size: int, is_binary: bool = False) -> Optional[str]:
        """
        Stores an exact baseline copy of the file in the .fim_vault directory.
        If file exceeds max size limit or is large binary, stores metadata without full body.
        """
        src = Path(file_path).resolve()
        if not src.exists():
            return None

        # Determine snapshot filename
        vault_filename = f"{file_id}_{sha256[:16]}.snap"
        vault_target = self.vault_dir / vault_filename

        try:
            if not is_binary and file_size <= self.max_size_bytes:
                # Store text snapshot copy for line-by-line diffing
                shutil.copy2(src, vault_target)
                self.db.add_baseline_snapshot(
                    file_id=file_id,
                    vault_path=str(vault_target),
                    snapshot_hash=sha256,
                    snapshot_size=file_size
                )
                return str(vault_target)
            elif is_binary and file_size <= (2 * 1024 * 1024):  # store small binary up to 2MB if needed
                shutil.copy2(src, vault_target)
                self.db.add_baseline_snapshot(
                    file_id=file_id,
                    vault_path=str(vault_target),
                    snapshot_hash=sha256,
                    snapshot_size=file_size
                )
                return str(vault_target)
            else:
                # File exceeds max snapshot limit; diffing will fallback to metadata/hash variance
                self.db.add_baseline_snapshot(
                    file_id=file_id,
                    vault_path="[SIZE_LIMIT_EXCEEDED]",
                    snapshot_hash=sha256,
                    snapshot_size=file_size
                )
                return None
        except Exception as e:
            logger.error(f"Failed to store snapshot for file {file_id}: {e}")
            return None

    def get_snapshot_path(self, file_id: int) -> Optional[Path]:
        """Retrieves the on-disk path to the baseline snapshot for a file."""
        row = self.db.get_latest_snapshot(file_id)
        if not row or not row["vault_path"]:
            return None
        
        v_path = Path(row["vault_path"])
        return v_path if v_path.exists() else None

    def read_snapshot_text(self, file_id: int) -> Optional[str]:
        """Reads baseline content as string for unified diffing."""
        snap_path = self.get_snapshot_path(file_id)
        if not snap_path:
            return None
        try:
            with open(snap_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading snapshot file {snap_path}: {e}")
            return None

    def purge_snapshot(self, file_id: int):
        """Removes all snapshots associated with a file."""
        row = self.db.get_latest_snapshot(file_id)
        if row and row["vault_path"]:
            p = Path(row["vault_path"])
            if p.exists() and p.is_file():
                try:
                    p.unlink()
                except OSError:
                    pass

    def store_snapshot_bytes(self, file_bytes: bytes, file_id: int,
                             sha256: str, file_size: int,
                             is_binary: bool = False,
                             filename: str = "upload.bin") -> Optional[str]:
        """
        Store raw bytes as a vault snapshot (for browser-uploaded files).
        Works on Vercel where /tmp is writable.
        """
        vault_filename = f"{file_id}_{sha256[:16]}.snap"
        vault_target = self.vault_dir / vault_filename
        try:
            if file_size <= self.max_size_bytes:
                with open(vault_target, "wb") as f:
                    f.write(file_bytes)
                self.db.add_baseline_snapshot(
                    file_id=file_id,
                    vault_path=str(vault_target),
                    snapshot_hash=sha256,
                    snapshot_size=file_size
                )
                return str(vault_target)
            else:
                self.db.add_baseline_snapshot(
                    file_id=file_id,
                    vault_path="[SIZE_LIMIT_EXCEEDED]",
                    snapshot_hash=sha256,
                    snapshot_size=file_size
                )
                return None
        except Exception as e:
            logger.error(f"Failed to store snapshot bytes for file {file_id}: {e}")
            return None

    def read_snapshot_bytes(self, file_id: int) -> Optional[bytes]:
        """Read baseline snapshot as raw bytes (for upload-based diffing)."""
        snap_path = self.get_snapshot_path(file_id)
        if not snap_path:
            return None
        try:
            with open(snap_path, "rb") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading snapshot bytes for file {file_id}: {e}")
            return None


def get_vault() -> SnapshotVault:
    return SnapshotVault()
