"""File classification and risk levels (L0–L4).

This module is the only place that decides what a path *is* and what may be
done with it. The model never supplies a risk level: an execution request only
carries a plan id, and the engine re-derives everything from the filesystem.
"""

from __future__ import annotations

import os
import stat as stat_module
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import config
from ..protocol import EngineError
from ..util import iso_utc

FILE_ATTRIBUTE_REPARSE_POINT = 0x400

CATEGORY_TEMP = "temporary-file"
CATEGORY_CACHE = "cache"
CATEGORY_RECYCLE = "recycle-bin"
CATEGORY_PERSONAL = "personal-document"
CATEGORY_SYSTEM = "system"
CATEGORY_UNKNOWN = "unknown"
CATEGORY_MISSING = "missing"

LEVEL_L1 = "L1"
LEVEL_L2 = "L2"
LEVEL_L4 = "L4"


@dataclass
class Classification:
    path: str
    category: str
    risk_level: str
    eligible: bool
    reasons: list[str] = field(default_factory=list)
    size_bytes: int | None = None
    mtime_ns: int | None = None
    file_index: int | None = None
    is_reparse: bool = False
    root: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "category": self.category,
            "risk_level": self.risk_level,
            "eligible": self.eligible,
            "reasons": self.reasons,
            "size_bytes": self.size_bytes,
            "modified_at": iso_utc(self.mtime_ns / 1_000_000_000) if self.mtime_ns else None,
            "is_reparse": self.is_reparse,
            "root": self.root,
        }


def _normalize(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def under(path: Path, root: Path) -> bool:
    target = _normalize(path)
    base = _normalize(root)
    return target == base or target.startswith(base.rstrip("\\/") + os.sep)


def find_root(path: Path, roots: list[Path]) -> Path | None:
    for root in roots:
        if under(path, root):
            return root
    return None


def has_reparse_ancestor(path: Path) -> bool:
    """True when any component between the drive root and the path is a reparse point."""
    try:
        current = path if path.is_dir() else path.parent
    except OSError:
        return True
    while current.parent != current:
        try:
            info = os.lstat(current)
        except OSError:
            return True
        if getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
            return True
        current = current.parent
    return False


def classify(path_text: str) -> Classification:
    try:
        path = Path(path_text)
        absolute = path if path.is_absolute() else path.absolute()
    except (OSError, ValueError):
        return Classification(str(path_text), CATEGORY_UNKNOWN, LEVEL_L4, False, ["path is not usable"])

    if config.is_unc(str(absolute)):
        return Classification(str(absolute), CATEGORY_UNKNOWN, LEVEL_L4, False, ["network paths are never cleaned"])

    try:
        info = os.lstat(absolute)
    except OSError:
        return Classification(str(absolute), CATEGORY_MISSING, LEVEL_L4, False, ["path does not exist"])

    reparse = bool(getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)
    result = Classification(
        path=str(absolute),
        category=CATEGORY_UNKNOWN,
        risk_level=LEVEL_L4,
        eligible=False,
        size_bytes=int(info.st_size) if not stat_module.S_ISDIR(info.st_mode) else None,
        mtime_ns=int(info.st_mtime_ns),
        file_index=int(info.st_ino) if getattr(info, "st_ino", 0) else None,
        is_reparse=reparse,
    )

    personal = find_root(absolute, config.personal_roots())
    if personal is not None:
        result.category = CATEGORY_PERSONAL
        result.risk_level = LEVEL_L4
        result.reasons.append(f"inside a user content directory ({personal})")
        return result

    system = find_root(absolute, config.system_roots())
    recycle = find_root(absolute, [Path(os.environ.get("SystemDrive", "C:") + "\\$Recycle.Bin")])
    cleanup_root = find_root(absolute, config.cleanup_roots())

    if recycle is not None:
        result.category = CATEGORY_RECYCLE
        result.risk_level = LEVEL_L2
        result.reasons.append("recycle bin contents are not planned by this build; empty them in Windows")
        return result

    if cleanup_root is None:
        if system is not None:
            result.category = CATEGORY_SYSTEM
            result.reasons.append("inside a Windows or Program Files directory")
        else:
            result.category = CATEGORY_UNKNOWN
            result.reasons.append("outside every known temporary or cache directory")
        return result

    # Inside a cleanup root: still apply the strict L1 rules.
    result.root = str(cleanup_root)
    result.category = CATEGORY_CACHE if "Cache" in str(cleanup_root) or "INetCache" in str(cleanup_root) else CATEGORY_TEMP
    result.risk_level = LEVEL_L1

    if reparse:
        result.reasons.append("target is a reparse point or symlink")
        return result
    if has_reparse_ancestor(absolute):
        result.reasons.append("path contains a reparse point")
        return result
    if stat_module.S_ISDIR(info.st_mode):
        result.reasons.append("directories are not planned by this build; only files are")
        return result
    if info.st_nlink > 1:
        result.reasons.append("file has multiple hard links")
        return result
    age_seconds = time.time() - (info.st_mtime_ns / 1_000_000_000)
    if age_seconds < config.MIN_TEMP_AGE_SECONDS:
        result.reasons.append("modified within the safety window (24h)")
        return result

    result.eligible = True
    result.reasons.append("temporary or cache file inside an allowed root")
    return result


def classify_many(paths: list[str]) -> list[Classification]:
    return [classify(item) for item in paths]


def classify_or_raise(path_text: str) -> Classification:
    result = classify(path_text)
    if result.category == CATEGORY_MISSING:
        raise EngineError("E_NOT_FOUND", f"path does not exist: {path_text}")
    return result
