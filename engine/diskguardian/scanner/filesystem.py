"""Read-only filesystem measurement with hard budgets.

Nothing here deletes, moves, or opens file contents. Directories are scanned
with `os.scandir`, reparse points are skipped (never followed), and every walk
stops at a caller-provided entry/time budget.
"""

from __future__ import annotations

import heapq
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..permissions.paths import ensure_scan_path, is_reparse_point, is_system


@dataclass
class ScanBudget:
    max_entries: int
    max_seconds: int
    entries: int = 0
    truncated: bool = False
    reason: str | None = None
    _deadline: float = field(init=False)

    def __post_init__(self) -> None:
        self._deadline = time.monotonic() + self.max_seconds

    def tick(self) -> bool:
        """Account for one directory entry; False means the walk must stop."""
        self.entries += 1
        if self.entries > self.max_entries:
            self.truncated = True
            self.reason = "entries"
            return False
        if self.entries % 512 == 0 and time.monotonic() > self._deadline:
            self.truncated = True
            self.reason = "time"
            return False
        return True


@dataclass
class TreeUsage:
    bytes: int = 0
    files: int = 0
    directories: int = 0
    skipped_reparse: int = 0
    errors: int = 0


def _walk(root: Path, budget: ScanBudget, usage: TreeUsage) -> bool:
    """Measure one subtree. Returns False when the budget stopped the walk."""
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    if not budget.tick():
                        return False
                    try:
                        stat_result = entry.stat(follow_symlinks=False)
                    except OSError:
                        usage.errors += 1
                        continue
                    if is_reparse_point(stat_result):
                        usage.skipped_reparse += 1
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        usage.directories += 1
                        stack.append(Path(entry.path))
                    else:
                        usage.files += 1
                        usage.bytes += stat_result.st_size
        except OSError:
            usage.errors += 1
            continue
    return True


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def analyze_directories(paths: Iterable[str], *, max_depth: int, budget: ScanBudget) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for path_text in paths:
        root = ensure_scan_path(path_text)
        usage = TreeUsage()
        children: list[dict[str, Any]] = []
        try:
            with os.scandir(root) as iterator:
                for entry in iterator:
                    if not budget.tick():
                        break
                    try:
                        stat_result = entry.stat(follow_symlinks=False)
                    except OSError:
                        usage.errors += 1
                        continue
                    if is_reparse_point(stat_result):
                        usage.skipped_reparse += 1
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        usage.directories += 1
                        child_usage = TreeUsage()
                        if max_depth > 0:
                            _walk(Path(entry.path), budget, child_usage)
                        usage.bytes += child_usage.bytes
                        usage.files += child_usage.files
                        usage.directories += child_usage.directories
                        usage.skipped_reparse += child_usage.skipped_reparse
                        usage.errors += child_usage.errors
                        children.append({"name": entry.name, "path": entry.path, "bytes": child_usage.bytes, "is_directory": True})
                    else:
                        usage.files += 1
                        usage.bytes += stat_result.st_size
                        children.append({"name": entry.name, "path": entry.path, "bytes": stat_result.st_size, "is_directory": False})
        except OSError:
            usage.errors += 1

        children.sort(key=lambda item: item["bytes"], reverse=True)
        results.append(
            {
                "path": str(root),
                "bytes": usage.bytes,
                "files": usage.files,
                "directories": usage.directories,
                "skipped_reparse": usage.skipped_reparse,
                "errors": usage.errors,
                "truncated": budget.truncated,
                "top_children": children[:10],
            }
        )
        if budget.truncated:
            break
    return results


def find_large_files(
    roots: Iterable[str],
    *,
    min_bytes: int,
    limit: int,
    budget: ScanBudget,
) -> tuple[list[dict[str, Any]], int]:
    heap: list[tuple[int, str, dict[str, Any]]] = []
    scanned = 0

    def consider(path: str, size: int, modified: float, system: bool) -> None:
        item = {"path": path, "bytes": size, "modified_at": _iso(modified), "system_file": system}
        if len(heap) < limit:
            heapq.heappush(heap, (size, path, item))
        elif size > heap[0][0]:
            heapq.heapreplace(heap, (size, path, item))

    for path_text in roots:
        root = ensure_scan_path(path_text)
        stack: list[Path] = [root]
        while stack and not budget.truncated:
            current = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    for entry in iterator:
                        if not budget.tick():
                            break
                        try:
                            stat_result = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if is_reparse_point(stat_result):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                            continue
                        scanned += 1
                        size = stat_result.st_size
                        if size >= min_bytes:
                            consider(entry.path, size, stat_result.st_mtime, is_system(stat_result))
            except OSError:
                continue

    files = [item for _, _, item in sorted(heap, key=lambda row: row[0], reverse=True)]
    return files, scanned
