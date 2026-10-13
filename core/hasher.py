"""
Single-pass dual hashing module computing SHA-256 and SHA-3-256 simultaneously.
Includes Windows file lock retry mechanisms to prevent WinError 32 crashes.
"""
import os
import time
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union
import config

@dataclass
class DualHashResult:
    sha256: str
    sha3_256: str
    file_size: int
    last_modified: float
    is_binary: bool
    error: Optional[str] = None

def is_binary_buffer(buffer: bytes) -> bool:
    """Checks if a byte buffer contains null bytes or common binary markers."""
    if not buffer:
        return False
    # Check for null byte
    if b"\x00" in buffer:
        return True
    # Check ratio of non-text control characters
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
    non_text = buffer.translate(None, text_chars)
    return len(non_text) / len(buffer) > 0.30

def compute_dual_hash(file_path: Union[str, Path], retries: int = config.FILE_LOCK_RETRIES,
                      retry_delay: float = config.FILE_LOCK_RETRY_DELAY) -> DualHashResult:
    """
    Computes both SHA-256 and SHA-3-256 in a SINGLE I/O pass by streaming 64 KB chunks.
    Mitigates Windows file lock contention (WinError 32) via exponential backoff retries.
    """
    path = Path(file_path).resolve()

    if not path.exists():
        return DualHashResult(
            sha256="",
            sha3_256="",
            file_size=0,
            last_modified=0.0,
            is_binary=False,
            error=f"File not found: {path}"
        )

    last_error = None
    for attempt in range(retries):
        try:
            stat_info = path.stat()
            file_size = stat_info.st_size
            last_modified = stat_info.st_mtime

            h_sha256 = hashlib.sha256()
            h_sha3 = hashlib.sha3_256()
            is_binary = False
            first_chunk_inspected = False

            with open(path, "rb") as f:
                while True:
                    chunk = f.read(config.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    if not first_chunk_inspected:
                        is_binary = is_binary_buffer(chunk[:8192])
                        first_chunk_inspected = True

                    h_sha256.update(chunk)
                    h_sha3.update(chunk)

            return DualHashResult(
                sha256=h_sha256.hexdigest(),
                sha3_256=h_sha3.hexdigest(),
                file_size=file_size,
                last_modified=last_modified,
                is_binary=is_binary,
                error=None
            )

        except (PermissionError, OSError) as e:
            last_error = e
            # Wait for file locks to release (e.g. VS Code atomic write in flight)
            time.sleep(retry_delay * (2 ** attempt))

    return DualHashResult(
        sha256="",
        sha3_256="",
        file_size=0,
        last_modified=0.0,
        is_binary=False,
        error=f"Unable to read file after {retries} attempts: {last_error}"
    )

def quick_hash_string(content: str) -> Tuple[str, str]:
    """Generates dual hash for in-memory string content."""
    b_data = content.encode("utf-8", errors="replace")
    h256 = hashlib.sha256(b_data).hexdigest()
    h3 = hashlib.sha3_256(b_data).hexdigest()
    return h256, h3
