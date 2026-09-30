"""
Granular file comparison engine for text unified diffing and binary delta inspection.
"""
import difflib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple
from core.hasher import is_binary_buffer
from core.vault import get_vault

@dataclass
class DiffLine:
    line_type: str  # '+', '-', ' ', '?'
    line_no_old: Optional[int]
    line_no_new: Optional[int]
    content: str

@dataclass
class ComparisonResult:
    is_binary: bool
    is_identical: bool
    diff_lines: List[DiffLine] = field(default_factory=list)
    raw_unified_diff: str = ""
    added_count: int = 0
    deleted_count: int = 0
    size_delta: int = 0
    old_size: int = 0
    new_size: int = 0
    old_sha256: str = ""
    new_sha256: str = ""
    message: str = ""

def generate_line_diff(baseline_lines: List[str], current_lines: List[str]) -> Tuple[List[DiffLine], int, int]:
    """
    Computes line-by-line diff with accurate 1-based line numbers for both files.
    """
    diff_lines: List[DiffLine] = []
    added_count = 0
    deleted_count = 0

    matcher = difflib.SequenceMatcher(None, baseline_lines, current_lines)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                diff_lines.append(DiffLine(
                    line_type=" ",
                    line_no_old=i1 + offset + 1,
                    line_no_new=j1 + offset + 1,
                    content=baseline_lines[i1 + offset]
                ))
        elif tag == "delete":
            for offset in range(i2 - i1):
                deleted_count += 1
                diff_lines.append(DiffLine(
                    line_type="-",
                    line_no_old=i1 + offset + 1,
                    line_no_new=None,
                    content=baseline_lines[i1 + offset]
                ))
        elif tag == "insert":
            for offset in range(j2 - j1):
                added_count += 1
                diff_lines.append(DiffLine(
                    line_type="+",
                    line_no_old=None,
                    line_no_new=j1 + offset + 1,
                    content=current_lines[j1 + offset]
                ))
        elif tag == "replace":
            for offset in range(i2 - i1):
                deleted_count += 1
                diff_lines.append(DiffLine(
                    line_type="-",
                    line_no_old=i1 + offset + 1,
                    line_no_new=None,
                    content=baseline_lines[i1 + offset]
                ))
            for offset in range(j2 - j1):
                added_count += 1
                diff_lines.append(DiffLine(
                    line_type="+",
                    line_no_old=None,
                    line_no_new=j1 + offset + 1,
                    content=current_lines[j1 + offset]
                ))

    return diff_lines, added_count, deleted_count

def compare_file_with_baseline(file_id: int, current_path: str | Path,
                               old_sha256: str = "", new_sha256: str = "",
                               old_size: int = 0,
                               vault: Optional[Any] = None) -> ComparisonResult:
    """
    Retrieves the baseline copy from the vault and performs granular diffing.
    Supports both text line diffs and binary delta metadata.
    """
    curr = Path(current_path).resolve()
    if not curr.exists():
        return ComparisonResult(
            is_binary=False,
            is_identical=False,
            message=f"Current file missing: {curr.name}",
            old_sha256=old_sha256,
            new_sha256=new_sha256
        )

    current_size = curr.stat().st_size
    size_delta = current_size - old_size

    # Check if binary file
    with open(curr, "rb") as f:
        header = f.read(8192)
        is_binary = is_binary_buffer(header)

    active_vault = vault or get_vault()
    baseline_path = active_vault.get_snapshot_path(file_id)


    if not baseline_path or not baseline_path.exists():
        # Baseline snapshot not present or exceeded size limit
        msg = ("Baseline copy not stored (exceeded size limit or vault missing). "
               f"Size shift: {size_delta:+d} bytes. Hash: {new_sha256[:12]}...")
        return ComparisonResult(
            is_binary=is_binary,
            is_identical=(old_sha256 == new_sha256 and old_sha256 != ""),
            size_delta=size_delta,
            old_size=old_size,
            new_size=current_size,
            old_sha256=old_sha256,
            new_sha256=new_sha256,
            message=msg
        )

    if is_binary:
        return ComparisonResult(
            is_binary=True,
            is_identical=(old_sha256 == new_sha256),
            size_delta=size_delta,
            old_size=old_size,
            new_size=current_size,
            old_sha256=old_sha256,
            new_sha256=new_sha256,
            message=f"Binary file modified: Size delta {size_delta:+d} bytes."
        )

    # Read both text files
    try:
        with open(baseline_path, "r", encoding="utf-8", errors="replace") as f:
            base_text = f.read()
        with open(curr, "r", encoding="utf-8", errors="replace") as f:
            curr_text = f.read()
    except Exception as e:
        return ComparisonResult(
            is_binary=False,
            is_identical=False,
            message=f"Error reading file for diff: {e}",
            old_sha256=old_sha256,
            new_sha256=new_sha256
        )

    base_lines = base_text.splitlines()
    curr_lines = curr_text.splitlines()

    # Raw unified diff
    unified = list(difflib.unified_diff(
        base_lines, curr_lines,
        fromfile=f"baseline/{curr.name}",
        tofile=f"modified/{curr.name}",
        lineterm=""
    ))
    raw_unified = "\n".join(unified)

    # Structured line diff
    diff_lines, added_count, deleted_count = generate_line_diff(base_lines, curr_lines)

    return ComparisonResult(
        is_binary=False,
        is_identical=(old_sha256 == new_sha256 or (added_count == 0 and deleted_count == 0)),
        diff_lines=diff_lines,
        raw_unified_diff=raw_unified,
        added_count=added_count,
        deleted_count=deleted_count,
        size_delta=size_delta,
        old_size=old_size,
        new_size=current_size,
        old_sha256=old_sha256,
        new_sha256=new_sha256,
        message=f"Changes detected: +{added_count} lines, -{deleted_count} lines."
    )
