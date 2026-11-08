"""Enumerate L1 cleanup candidates under the known temporary and cache roots.

Read-only. This is the discovery step that makes "clean my temp files" possible:
it walks only the allowed roots, skips reparse points and fresh files, and returns
a bounded, size-sorted list plus totals. Planning still re-classifies every path
and execution re-validates it again.
"""

from __future__ import annotations

import heapq
import os
import time
from pathlib import Path
from typing import Any, Iterable

from .. import config
from ..permissions import rules
from ..protocol import E_INVALID_PARAMS, E_PATH_NOT_ALLOWED, EngineError
from ..util import iso_utc


def _category_for(path: Path, temp_roots: list[Path], cache_roots: list[Path]) -> str:
    if rules.find_root(path, temp_roots) is not None:
        return rules.CATEGORY_TEMP
    if path.name.casefold() == "temp":
        # LocalAppData\Temp is a temporary root even when reached through the
        # known-cache list; label it for what it is.
        return rules.CATEGORY_TEMP
    if rules.find_root(path, cache_roots) is not None:
        return rules.CATEGORY_CACHE
    return rules.CATEGORY_UNKNOWN


def _resolve_roots(requested: Iterable[str] | None) -> list[Path]:
    allowed = config.cleanup_roots()
    if not requested:
        return allowed
    roots: list[Path] = []
    for text in requested:
        candidate = Path(text)
        if not candidate.is_absolute() or config.is_unc(text):
            raise EngineError(E_INVALID_PARAMS, f"cleanup roots must be absolute local paths: {text}")
        if rules.find_root(candidate, allowed) is None:
            raise EngineError(E_PATH_NOT_ALLOWED, f"not a temporary or cache root: {text}")
        roots.append(candidate)
    return roots


def list_candidates(
    *,
    roots: Iterable[str] | None = None,
    min_age_seconds: int = config.MIN_TEMP_AGE_SECONDS,
    min_bytes: int = 0,
    limit: int = 200,
    max_entries: int = 200_000,
    max_seconds: int = 60,
) -> dict[str, Any]:
    temp_roots = config.temp_roots()
    cache_roots = config.known_cache_directories()
    resolved = _resolve_roots(roots)

    deadline = time.monotonic() + max_seconds
    entries = 0
    truncated = False
    eligible_count = 0
    eligible_bytes = 0
    skipped_recent = 0
    skipped_reparse = 0
    skipped_small = 0
    errors = 0
    newest = time.time() - min_age_seconds
    heap: list[tuple[int, str, dict[str, Any]]] = []

    for root in resolved:
        category = _category_for(root, temp_roots, cache_roots)
        stack: list[Path] = [root]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    for entry in iterator:
                        entries += 1
                        if entries > max_entries:
                            truncated = True
                            break
                        if entries % 1024 == 0 and time.monotonic() > deadline:
                            truncated = True
                            break
                        try:
                            info = entry.stat(follow_symlinks=False)
                        except OSError:
                            errors += 1
                            continue
                        if getattr(info, "st_file_attributes", 0) & 0x400:
                            skipped_reparse += 1
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                            continue
                        if info.st_mtime_ns / 1_000_000_000 >= newest:
                            skipped_recent += 1
                            continue
                        if info.st_size <= 0 or info.st_nlink > 1:
                            continue
                        if info.st_size < min_bytes:
                            skipped_small += 1
                            continue
                        eligible_count += 1
                        eligible_bytes += int(info.st_size)
                        item = {
                            "path": entry.path,
                            "bytes": int(info.st_size),
                            "category": category,
                            "modified_at": iso_utc(info.st_mtime_ns / 1_000_000_000),
                        }
                        if len(heap) < limit:
                            heapq.heappush(heap, (item["bytes"], entry.path, item))
                        elif item["bytes"] > heap[0][0]:
                            heapq.heapreplace(heap, (item["bytes"], entry.path, item))
                if truncated:
                    break
            except OSError:
                errors += 1
        if truncated:
            break

    candidates = [item for _, _, item in sorted(heap, key=lambda row: row[0], reverse=True)]
    return {
        "candidates": candidates,
        "eligible": eligible_count,
        "eligible_bytes": eligible_bytes,
        "returned": len(candidates),
        "truncated": truncated,
        "skipped_recent": skipped_recent,
        "skipped_reparse": skipped_reparse,
        "skipped_small": skipped_small,
        "entries_examined": entries,
        "errors": errors,
        "roots": [str(root) for root in resolved],
    }
