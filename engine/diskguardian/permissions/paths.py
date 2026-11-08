"""Path validation shared by every read-only scan.

The engine is not protected by the harness file sandbox, so it enforces its own
boundary: absolute local paths on a fixed disk only. Network shares, removable
media, and UNC paths are rejected before any directory is opened. Writes are
handled by the permission layer (Phase D), which is stricter than this module.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Iterable

from .. import config
from ..protocol import E_INVALID_PARAMS, E_NOT_FOUND, E_PATH_NOT_ALLOWED, EngineError

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
_kernel32.GetDriveTypeW.restype = ctypes.c_uint
DRIVE_FIXED = 3


def drive_type(path: Path) -> int:
    drive = os.path.splitdrive(str(path))[0]
    if not drive:
        return 0
    return int(_kernel32.GetDriveTypeW(drive + "\\"))


def _normalize(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def under_any(path: Path, roots: Iterable[Path]) -> bool:
    target = _normalize(path)
    for root in roots:
        base = _normalize(root)
        if target == base:
            return True
        if target.startswith(base.rstrip("\\/") + os.sep):
            return True
    return False


def ensure_local(path_text: str) -> Path:
    if not isinstance(path_text, str) or not path_text.strip():
        raise EngineError(E_INVALID_PARAMS, "path must be a non-empty string")
    if config.is_unc(path_text):
        raise EngineError(E_PATH_NOT_ALLOWED, f"network paths are not scanned: {path_text}")
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        raise EngineError(E_INVALID_PARAMS, f"path must be absolute: {path_text}")
    return path


def ensure_readable_path(path_text: str) -> Path:
    """Validate a read-only target: local, absolute, existing, fixed disk."""
    path = ensure_local(path_text)
    if not path.exists():
        raise EngineError(E_NOT_FOUND, f"path does not exist: {path}")
    kind = drive_type(path)
    if kind != DRIVE_FIXED:
        raise EngineError(
            E_PATH_NOT_ALLOWED,
            f"only local fixed disks are scanned, not drive type {kind}: {path}",
        )
    return path


def ensure_scan_path(path_text: str, roots: Iterable[Path] | None = None) -> Path:
    path = ensure_readable_path(path_text)
    if roots is not None and not under_any(path, roots):
        allowed = [str(root) for root in roots]
        raise EngineError(E_PATH_NOT_ALLOWED, f"path is outside the allowed roots: {path}", {"allowed_roots": allowed})
    return path


def is_reparse_point(stat_result: os.stat_result) -> bool:
    attributes = getattr(stat_result, "st_file_attributes", 0)
    return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def is_system(stat_result: os.stat_result) -> bool:
    attributes = getattr(stat_result, "st_file_attributes", 0)
    return bool(attributes & 0x4)  # FILE_ATTRIBUTE_SYSTEM
