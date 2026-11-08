"""Windows service inventory from the registry plus `sc.exe query`.

No WMI: WMI/DCOM is often blocked by sandboxes and hardened hosts, while the
registry and the Service Control Manager query are local and reliable. Only
read-only calls are made.
"""

from __future__ import annotations

import os
import subprocess
import winreg
from typing import Any

from ..util import clamp_text
from . import signature

SERVICE_ROOT = r"SYSTEM\CurrentControlSet\Services"
CREATE_NO_WINDOW = 0x08000000

START_TYPES = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}
_STATE_WORDS = {
    "STOPPED": "stopped",
    "START_PENDING": "start-pending",
    "STOP_PENDING": "stop-pending",
    "RUNNING": "running",
    "CONTINUE_PENDING": "continue-pending",
    "PAUSE_PENDING": "pause-pending",
    "PAUSED": "paused",
}

# Win32 service types occupy these bits; drivers use 0x1/0x2.
_WIN32_TYPE_MASK = 0x30


def _expand_image_path(raw: str) -> str:
    text = raw.strip()
    if text.lower().startswith("\\??\\"):
        text = text[4:]
    if text.lower().startswith("\\systemroot\\"):
        text = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), text[len("\\systemroot\\") :])
    return text


def service_states(timeout: int = 30) -> dict[str, str]:
    """One read-only SCM query: case-folded service name → lower-case state word."""
    states: dict[str, str] = {}
    try:
        process = subprocess.run(
            ["sc.exe", "query", "state=", "all"],
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired):
        return states
    if process.returncode != 0:
        return states
    current: str | None = None
    for line in process.stdout.decode("utf-8", "replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("SERVICE_NAME:"):
            current = stripped.split(":", 1)[1].strip().casefold()
            continue
        if current and stripped.startswith("STATE") and ":" in stripped:
            word = stripped.split(":", 1)[1].strip().split()
            if len(word) >= 2:
                states[current] = _STATE_WORDS.get(word[1].upper(), word[1].lower())
            current = None
    return states


def registry_services() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE_ROOT)
    except OSError:
        return entries
    with root:
        count = winreg.QueryInfoKey(root)[0]
        for index in range(count):
            try:
                name = winreg.EnumKey(root, index)
            except OSError:
                break
            try:
                with winreg.OpenKey(root, name) as key:
                    def value(field: str, default: Any = None) -> Any:
                        try:
                            data, _ = winreg.QueryValueEx(key, field)
                            return data
                        except OSError:
                            return default

                    service_type = int(value("Type", 0) or 0)
                    raw_path = str(value("ImagePath", "") or "")
                    entries.append(
                        {
                            "name": name,
                            "display_name": clamp_text(value("DisplayName"), 200),
                            "description": clamp_text(value("Description"), 300),
                            "start_type": START_TYPES.get(int(value("Start", -1)), "unknown"),
                            "service_type": "win32" if service_type & _WIN32_TYPE_MASK else "driver",
                            "interactive": bool(service_type & 0x100),
                            "account": clamp_text(value("ObjectName"), 120),
                            "path": clamp_text(_expand_image_path(raw_path), 600),
                            "raw_image_path": clamp_text(raw_path, 600),
                            "is_win32": bool(service_type & _WIN32_TYPE_MASK),
                        }
                    )
            except OSError:
                continue
    return entries


def inspect_services(*, include_signature: bool, include_running_only: bool, include_drivers: bool = False) -> dict[str, Any]:
    states = service_states()
    entries: list[dict[str, Any]] = []
    for service in registry_services():
        if not include_drivers and not service["is_win32"]:
            continue
        state = states.get(service["name"].casefold(), "unknown")
        if include_running_only and state != "running":
            continue
        path = service["path"]
        executable = None
        if path:
            from ..util import executable_from_command

            executable = executable_from_command(path) or (path if os.path.isfile(path) else None)
        entry = {
            **{key: value for key, value in service.items() if key != "is_win32"},
            "state": state,
            "executable": executable,
            "executable_exists": os.path.isfile(executable) if executable else None,
        }
        if include_signature:
            entry["signature"] = signature.verify(executable) if executable and entry["executable_exists"] else None
        entries.append(entry)

    entries.sort(key=lambda item: ((item["display_name"] or item["name"]).casefold()))
    return {
        "services": entries,
        "total": len(entries),
        "coverage": {"states_queried": bool(states), "count": len(entries)},
        "errors": [],
    }
