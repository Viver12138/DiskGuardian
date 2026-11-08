"""Fixed-drive inventory through the Windows API (no shell, no WMI)."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import Any

from ..protocol import E_ENGINE, EngineError

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_kernel32.GetLogicalDrives.argtypes = []
_kernel32.GetLogicalDrives.restype = wintypes.DWORD
_kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
_kernel32.GetDriveTypeW.restype = wintypes.UINT
_kernel32.GetDiskFreeSpaceExW.argtypes = [
    wintypes.LPCWSTR,
    ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.POINTER(ctypes.c_ulonglong),
]
_kernel32.GetDiskFreeSpaceExW.restype = wintypes.BOOL
_kernel32.GetVolumeInformationW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPWSTR,
    wintypes.DWORD,
]
_kernel32.GetVolumeInformationW.restype = wintypes.BOOL

DRIVE_TYPES = {
    0: "unknown",
    1: "no_root",
    2: "removable",
    3: "fixed",
    4: "network",
    5: "cdrom",
    6: "ramdisk",
}


def _volume_metadata(root: str) -> dict[str, Any]:
    label = ctypes.create_unicode_buffer(261)
    filesystem = ctypes.create_unicode_buffer(261)
    serial = wintypes.DWORD()
    max_component = wintypes.DWORD()
    flags = wintypes.DWORD()
    ok = _kernel32.GetVolumeInformationW(
        root,
        label,
        261,
        ctypes.byref(serial),
        ctypes.byref(max_component),
        ctypes.byref(flags),
        filesystem,
        261,
    )
    if not ok:
        return {"label": None, "filesystem": None}
    return {"label": label.value or None, "filesystem": filesystem.value or None}


def _space(root: str) -> dict[str, int] | None:
    free_available = ctypes.c_ulonglong(0)
    total = ctypes.c_ulonglong(0)
    total_free = ctypes.c_ulonglong(0)
    ok = _kernel32.GetDiskFreeSpaceExW(
        root,
        ctypes.byref(free_available),
        ctypes.byref(total),
        ctypes.byref(total_free),
    )
    if not ok:
        return None
    total_bytes = int(total.value)
    free_bytes = int(total_free.value)
    return {
        "total_bytes": total_bytes,
        "free_bytes": free_bytes,
        "used_bytes": max(total_bytes - free_bytes, 0),
        "available_bytes": int(free_available.value),
    }


def scan_volumes() -> dict[str, Any]:
    mask = _kernel32.GetLogicalDrives()
    if mask == 0:
        raise EngineError(E_ENGINE, "GetLogicalDrives failed", ctypes.get_last_error())

    disks: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for index in range(26):
        if not mask & (1 << index):
            continue
        letter = chr(ord("A") + index)
        root = f"{letter}:\\"
        drive_type = int(_kernel32.GetDriveTypeW(root))
        kind = DRIVE_TYPES.get(drive_type, "unknown")
        if drive_type != 3:  # V1 reports local fixed disks only.
            skipped.append({"root": root, "drive_type": kind, "reason": "not a local fixed disk"})
            continue
        space = _space(root)
        if space is None:
            skipped.append({"root": root, "drive_type": kind, "reason": "space query failed"})
            continue
        metadata = _volume_metadata(root)
        total = space["total_bytes"]
        disks.append(
            {
                "root": root,
                "label": metadata["label"],
                "filesystem": metadata["filesystem"],
                "drive_type": kind,
                **space,
                "used_ratio": round(space["used_bytes"] / total, 4) if total else None,
            }
        )
    return {"disks": disks, "skipped": skipped}
