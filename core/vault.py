"""
Secure Snapshot Vault for caching baseline file content.
Enables syntactical delta reconstruction and difflib comparison upon tamper detection.
Supports hybrid filesystem and database persistence for cloud/serverless resiliency.
"""
import os
import shutil
import base64
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
        try:
            self.vault_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        self.max_size_bytes = max_size_bytes
        self.db = db or get_db()

    def store_snapshot(self, file_path: Union[str, Path], file_id: int,
                       sha256: str, file_size: int, is_binary: bool = False) -> Optional[str]:
        """
        Stores an exact baseline copy in the vault and persists snapshot content in database.
        """
        src = Path(file_path).resolve()
        if not src.exists():
            return None

        vault_filename = f"{file_id}_{sha256[:16]}.snap"
        vault_target = self.vault_dir / vault_filename

        try:
            with open(src, "rb") as f:
                content_bytes = f.read()

            return self.store_snapshot_bytes(
                file_bytes=content_bytes,
                file_id=file_id,
                sha256=sha256,
                file_size=file_size,
                is_binary=is_binary,
                filename=src.name
            )
        except Exception as e:
            logger.error(f"Failed to store snapshot for file {file_id}: {e}")
            return None

    def store_snapshot_bytes(self, file_bytes: bytes, file_id: int,
                             sha256: str, file_size: int,
                             is_binary: bool = False,
                             filename: str = "upload.bin") -> Optional[str]:
        """
        Store raw bytes in .fim_vault (if writable) AND directly in database baseline_snapshots.
        Ensures baseline content survives Vercel container recycling.
        """
        vault_filename = f"{file_id}_{sha256[:16]}.snap"
        vault_target = self.vault_dir / vault_filename

        # Write to disk if directory is writable
        try:
            with open(vault_target, "wb") as f:
                f.write(file_bytes)
        except Exception as e:
            logger.warning(f"Disk write to vault failed ({e}). Relying on database persistence.")

        # Prepare database-persisted content
        snapshot_content = None
        if file_size <= self.max_size_bytes:
            if not is_binary:
                try:
                    snapshot_content = file_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    snapshot_content = "[BASE64]:" + base64.b64encode(file_bytes).decode("ascii")
            elif file_size <= (3 * 1024 * 1024):
                snapshot_content = "[BASE64]:" + base64.b64encode(file_bytes).decode("ascii")

        self.db.add_baseline_snapshot(
            file_id=file_id,
            vault_path=str(vault_target),
            snapshot_hash=sha256,
            snapshot_size=file_size,
            snapshot_content=snapshot_content
        )
        return str(vault_target)

    def get_snapshot_path(self, file_id: int) -> Optional[Path]:
        """Retrieves the on-disk path to the baseline snapshot for a file."""
        row = self.db.get_latest_snapshot(file_id)
        if not row or not row.get("vault_path"):
            return None
        v_path = Path(row["vault_path"])
        if v_path.exists():
            return v_path
        # Fallback to current vault_dir (handles directory relocation, renames, and serverless bundle paths)
        rel_path = self.vault_dir / v_path.name
        if rel_path.exists():
            return rel_path
        return None

    def read_snapshot_bytes(self, file_id: int) -> Optional[bytes]:
        """
        Reads baseline snapshot as raw bytes.
        Checks on-disk vault file first; if absent (cloud restart), retrieves from database.
        """
        snap_path = self.get_snapshot_path(file_id)
        if snap_path and snap_path.exists():
            try:
                with open(snap_path, "rb") as f:
                    data = f.read()
                    # Backfill to database if missing to guarantee serverless container persistence
                    row = self.db.get_latest_snapshot(file_id)
                    if row and not row.get("snapshot_content"):
                        try:
                            is_bin = b"\x00" in data[:8192]
                            content_str = f"[BASE64]:{base64.b64encode(data).decode('ascii')}" if is_bin else data.decode("utf-8", errors="replace")
                            self.db._execute("UPDATE baseline_snapshots SET snapshot_content = ? WHERE id = ?", (content_str, row["id"]))
                        except Exception:
                            pass
                    return data
            except Exception:
                pass

        # Fallback to database snapshot_content
        row = self.db.get_latest_snapshot(file_id)
        if row and row.get("snapshot_content"):
            content_str = row["snapshot_content"]
            if content_str.startswith("[BASE64]:"):
                try:
                    return base64.b64decode(content_str[len("[BASE64]:"):])
                except Exception:
                    return None
            return content_str.encode("utf-8")

        return None

    def read_snapshot_text(self, file_id: int) -> Optional[str]:
        """
        Reads baseline content as string for unified diffing.
        Checks on-disk vault file first; falls back to database snapshot content.
        """
        raw = self.read_snapshot_bytes(file_id)
        if raw is None:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def purge_snapshot(self, file_id: int):
        """Removes all snapshots associated with a file."""
        row = self.db.get_latest_snapshot(file_id)
        if row and row.get("vault_path"):
            p = Path(row["vault_path"])
            if p.exists() and p.is_file():
                try:
                    p.unlink()
                except OSError:
                    pass


def get_vault() -> SnapshotVault:
    return SnapshotVault()
