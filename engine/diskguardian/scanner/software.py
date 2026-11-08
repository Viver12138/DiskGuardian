"""Installed-software inventory from the Windows uninstall registry keys.

Read-only. Missing entries and unreadable keys are reported as coverage counts,
never guessed. A missing signature is one weak signal, not a verdict: verdicts
belong to the analyzer (Phase C/D), which combines evidence.
"""

from __future__ import annotations

import winreg
from typing import Any

from ..util import clamp_text, executable_from_command
from . import signature

MAX_SOFTWARE = 2000

_UNINSTALL_KEYS = (
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY, "machine-64"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY, "machine-32"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, "user"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY, "user-32"),
)

_VALUE_NAMES = (
    "DisplayName",
    "DisplayVersion",
    "Publisher",
    "InstallLocation",
    "UninstallString",
    "QuietUninstallString",
    "DisplayIcon",
    "InstallDate",
    "EstimatedSize",
    "SystemComponent",
    "ReleaseType",
    "ParentKeyName",
    "WindowsInstaller",
)


def _read_values(key: winreg.HKEYType) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for name in _VALUE_NAMES:
        try:
            values[name], _ = winreg.QueryValueEx(key, name)
        except OSError:
            continue
    return values


def _is_noise(values: dict[str, Any]) -> bool:
    if int(values.get("SystemComponent", 0) or 0) == 1:
        return True
    release = str(values.get("ReleaseType") or "").lower()
    if release in {"security update", "update rollup", "hotfix", "servicepack"}:
        return True
    return "ParentKeyName" in values


def _signature_target(values: dict[str, Any]) -> str | None:
    for field in ("UninstallString", "QuietUninstallString", "DisplayIcon"):
        candidate = values.get(field)
        if isinstance(candidate, str) and candidate:
            executable = executable_from_command(candidate)
            if executable:
                return executable
    return None


def scan_installed_software(*, include_signature: bool, limit: int) -> dict[str, Any]:
    entries: dict[tuple[str, str], dict[str, Any]] = {}
    coverage = {"keys_examined": 0, "keys_unreadable": 0, "entries_filtered": 0}
    errors: list[dict[str, str]] = []

    for root, path, flags, source in _UNINSTALL_KEYS:
        try:
            key = winreg.OpenKey(root, path, 0, winreg.KEY_READ | flags)
        except OSError:
            coverage["keys_unreadable"] += 1
            continue
        with key:
            coverage["keys_examined"] += 1
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        values = _read_values(subkey)
                except OSError:
                    coverage["entries_filtered"] += 1
                    continue
                name = clamp_text(values.get("DisplayName"), 200)
                if not name or _is_noise(values):
                    coverage["entries_filtered"] += 1
                    continue
                version = clamp_text(values.get("DisplayVersion"), 80) or ""
                identity = (name.casefold(), version.casefold())
                if identity in entries:
                    continue
                target = _signature_target(values)
                entries[identity] = {
                    "name": name,
                    "version": version or None,
                    "publisher": clamp_text(values.get("Publisher"), 200),
                    "install_location": clamp_text(values.get("InstallLocation"), 500),
                    "uninstall_string": clamp_text(values.get("UninstallString"), 500),
                    "quiet_uninstall_string": clamp_text(values.get("QuietUninstallString"), 500),
                    "signature_target": target,
                    "signature": signature.verify(target) if include_signature and target else None,
                    "install_date": clamp_text(values.get("InstallDate"), 20),
                    "estimated_size_kb": int(values.get("EstimatedSize", 0) or 0) or None,
                    "source": source,
                    "registry_key": subkey_name,
                }

    software = sorted(entries.values(), key=lambda item: item["name"].casefold())
    truncated = len(software) > limit
    if truncated:
        software = software[:limit]
    if include_signature:
        unsigned = sum(1 for item in software if item["signature"] and item["signature"] != "valid")
        coverage["signature_non_valid"] = unsigned

    return {
        "software": software,
        "total": len(entries),
        "returned": len(software),
        "truncated": truncated,
        "coverage": coverage,
        "errors": errors,
    }
