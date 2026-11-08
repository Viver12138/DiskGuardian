"""Paths and limits. Every path decision the engine makes starts here."""

from __future__ import annotations

import os
from pathlib import Path

APP_DIR_NAME = "DiskGuardian"
DB_FILE_NAME = "diskguardian.db"

# Scan budgets. They are deliberately conservative: a scan must finish inside the
# tool timeout instead of leaving an orphan process behind.
DEFAULT_MAX_ENTRIES = 200_000
DEFAULT_MAX_SECONDS = 90
MAX_MAX_ENTRIES = 2_000_000
MAX_MAX_SECONDS = 600
DEFAULT_DIRECTORY_DEPTH = 2
MAX_DIRECTORY_DEPTH = 6
DEFAULT_LARGE_FILE_BYTES = 100 * 1024 * 1024
MAX_LARGE_FILE_RESULTS = 500


def data_dir() -> Path:
    """Per-user application data directory (never a network or system path)."""
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        base = os.path.join(os.path.expanduser("~"), "AppData", "Local")
    return Path(base) / APP_DIR_NAME


def database_path() -> Path:
    return data_dir() / DB_FILE_NAME


def is_unc(path: str) -> bool:
    return path.startswith("\\\\") or path.startswith("//")


def system_drive() -> str:
    drive = os.environ.get("SystemDrive")
    return (drive + "\\") if drive else "C:\\"


def user_profile() -> Path:
    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    return Path(home)


def scan_roots() -> list[Path]:
    """Directories a read-only scan may touch.

    Only local, well-known roots are included. UNC paths are rejected before
    reaching this list, and drive roots outside these entries are not scanned
    implicitly.
    """
    candidates = [
        system_drive(),
        os.environ.get("USERPROFILE"),
        os.environ.get("ProgramData"),
        os.environ.get("WINDIR"),
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("TEMP"),
    ]
    roots: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate:
            continue
        try:
            path = Path(candidate)
        except (OSError, ValueError):
            continue
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            continue
        seen.add(key)
        roots.append(path)
    return roots


_BROWSER_CACHE_SUBDIRS = (
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "GrShaderCache",
    "ShaderCache",
    "Service Worker",
)


def browser_cache_dirs() -> list[Path]:
    """Chrome and Edge cache directories across the profiles that actually exist."""
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return []
    roots = [Path(local) / "Google" / "Chrome" / "User Data", Path(local) / "Microsoft" / "Edge" / "User Data"]
    found: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            profiles = [item for item in root.iterdir() if item.is_dir()]
        except OSError:
            continue
        for profile in profiles:
            if profile.name != "Default" and not profile.name.startswith("Profile"):
                continue
            for name in _BROWSER_CACHE_SUBDIRS:
                candidate = profile / name
                if candidate.is_dir():
                    found.append(candidate)
    return found


def known_cache_directories() -> list[Path]:
    """Well-known cache directories, still subject to classification rules."""
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return []
    base = Path(local)
    names = [
        "Temp",
        "Microsoft\\Windows\\INetCache",
        "Microsoft\\Windows\\Explorer",
        "Google\\Chrome\\User Data\\Default\\Cache",
        "Microsoft\\Edge\\User Data\\Default\\Cache",
        "CrashDumps",
    ]
    roots = [base / name for name in names]
    roots.extend(browser_cache_dirs())
    deduped: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = os.path.normcase(os.path.abspath(root))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(root)
    return deduped


def temp_roots() -> list[Path]:
    """Directories whose contents may be classified as temporary files."""
    candidates = [os.environ.get("TEMP"), os.environ.get("TMP"), os.path.join(system_drive(), "Temp")]
    roots: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate:
            continue
        key = os.path.normcase(os.path.abspath(candidate))
        if key in seen:
            continue
        seen.add(key)
        roots.append(Path(candidate))
    return roots


def cleanup_roots() -> list[Path]:
    """Every directory a cleanup plan may target. Nothing else is eligible."""
    return [*temp_roots(), *known_cache_directories()]


def personal_roots() -> list[Path]:
    """User content that must never be classified as junk."""
    home = user_profile()
    return [
        home / name
        for name in ("Documents", "Desktop", "Downloads", "Pictures", "Videos", "Music", "OneDrive", "Favorites")
    ]


def system_roots() -> list[Path]:
    candidates = [os.environ.get("WINDIR"), os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramData")]
    return [Path(candidate) for candidate in candidates if candidate]


def quarantine_dir() -> Path:
    return data_dir() / "quarantine"


# Cleanup safety policy (L1 rules).
MIN_TEMP_AGE_SECONDS = 24 * 60 * 60
MAX_PLAN_ITEMS = 500
PLAN_TTL_SECONDS = 30 * 60
APPROVAL_TTL_SECONDS = 15 * 60

# Quarantine policy: a bounded area with a retention window, so cleanup cannot
# fill the disk it was meant to free.
QUARANTINE_MAX_BYTES = 5 * 1024 * 1024 * 1024
QUARANTINE_RETENTION_DAYS = 30
