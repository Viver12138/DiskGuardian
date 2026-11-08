"""Startup-entry inspection: Run keys, Startup folders, and scheduled tasks.

Read-only. V1 never disables anything here; the entries are evidence for the
user and for the analyzer, and any change requires a plan (Phase D/E).
"""

from __future__ import annotations

import os
import winreg
from pathlib import Path
from typing import Any

from ..util import clamp_text, executable_from_command
from . import powershell, signature

_RUN_KEYS = (
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, "user", "run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 0, "user", "run-once"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", winreg.KEY_WOW64_64KEY, "machine", "run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", winreg.KEY_WOW64_64KEY, "machine", "run-once"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", winreg.KEY_WOW64_32KEY, "machine", "run-32"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", winreg.KEY_WOW64_32KEY, "machine", "run-once-32"),
)

TASK_QUERY = r"""
$ErrorActionPreference = 'Stop'
Get-ScheduledTask | ForEach-Object {
  $action = $_.Actions | Select-Object -First 1
  [pscustomobject]@{
    name = $_.TaskName
    path = $_.TaskPath
    state = [string]$_.State
    author = $_.Author
    command = $action.Execute
    arguments = $action.Arguments
  }
} | ConvertTo-Json -Compress -Depth 3
"""


def _entry(source: str, scope: str, name: str, command: str | None, location: str, **extra: Any) -> dict[str, Any]:
    executable = executable_from_command(command or "")
    return {
        "source": source,
        "scope": scope,
        "name": name,
        "command": clamp_text(command, 600),
        "executable": executable,
        "executable_exists": os.path.isfile(executable) if executable else None,
        "location": location,
        **extra,
    }


def _registry_entries() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    coverage = {"keys_examined": 0, "keys_unreadable": 0}
    for root, path, flags, scope, kind in _RUN_KEYS:
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
                    name, value, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                if not isinstance(value, str):
                    continue
                entries.append(_entry(f"registry-{kind}", scope, name, value, path))
    return entries, coverage


def _startup_folder_entries() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    coverage = {"folders_examined": 0, "folders_unreadable": 0}
    folders = [
        (os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"), "user"),
        (os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"), "machine"),
    ]
    for folder, scope in folders:
        if not folder or not os.path.isdir(folder):
            coverage["folders_unreadable"] += 1
            continue
        coverage["folders_examined"] += 1
        for item in Path(folder).iterdir():
            if item.name.lower() == "desktop.ini":
                continue
            entries.append(
                _entry(
                    "startup-folder",
                    scope,
                    item.stem,
                    str(item),
                    folder,
                    file_type=item.suffix.lower() or None,
                )
            )
    return entries, coverage


def _strip_namespaces(root: Any) -> None:
    for node in root.iter():
        tag = getattr(node, "tag", None)
        if isinstance(tag, str) and "}" in tag:
            node.tag = tag.split("}", 1)[1]


def _task_files_directory() -> str:
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks")


def _task_entry_from_root(root: Any, relative: str) -> dict[str, Any]:
    task_path = "\\" + relative.replace(os.sep, "\\")
    command = root.findtext("Actions/Exec/Command")
    arguments = root.findtext("Actions/Exec/Arguments")
    enabled_text = (root.findtext("Settings/Enabled") or "true").strip().lower()
    triggers = root.find("Triggers")
    command_line = f"{command} {arguments}".strip() if command else None
    return _entry(
        "scheduled-task",
        "system" if task_path.lower().startswith("\\microsoft\\") else "other",
        relative.split("\\")[-1],
        command_line,
        task_path,
        state="ready" if enabled_text != "false" else "disabled",
        author=clamp_text(root.findtext("RegistrationInfo/Author"), 120),
        triggers=len(list(triggers)) if triggers is not None else 0,
        run_level=clamp_text(root.findtext("Principal/RunLevel"), 40),
    )


def _task_file_entries() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read task definitions from the official XML files (no COM, no WMI)."""
    import xml.etree.ElementTree as ElementTree

    coverage: dict[str, Any] = {"source": "task-files", "files_examined": 0, "files_unreadable": 0}
    directory = _task_files_directory()
    if not os.path.isdir(directory):
        coverage["source"] = "unavailable"
        return [], coverage

    entries: list[dict[str, Any]] = []
    for current, _subdirs, files in os.walk(directory):
        for file_name in files:
            if not file_name.lower().endswith(".xml"):
                continue
            full_path = os.path.join(current, file_name)
            coverage["files_examined"] += 1
            try:
                tree = ElementTree.parse(full_path)
            except (ElementTree.ParseError, OSError):
                coverage["files_unreadable"] += 1
                continue
            root = tree.getroot()
            _strip_namespaces(root)
            relative = os.path.relpath(full_path, directory)[: -len(".xml")]
            entries.append(_task_entry_from_root(root, relative))
    coverage["count"] = len(entries)
    return entries, coverage


def _task_cmdlet_entries() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fallback when the task files are unreadable: ScheduledTasks cmdlet."""
    coverage: dict[str, Any] = {"source": "scheduled-tasks-cmdlet", "query": "ok", "count": 0}
    try:
        payload = powershell.run_json(TASK_QUERY, timeout=90)
    except powershell.PowerShellUnavailable as error:
        coverage["query"] = "unavailable"
        return [], {**coverage, "error": clamp_text(str(error), 300)}
    except ValueError:
        coverage["query"] = "invalid-json"
        return [], coverage
    if payload is None:
        return [], coverage
    rows = payload if isinstance(payload, list) else [payload]
    entries: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = clamp_text(row.get("name"), 200)
        if not name:
            continue
        task_path = str(row.get("path") or "")
        command = row.get("command")
        arguments = row.get("arguments")
        command_line = f"{command} {arguments}".strip() if command else None
        entries.append(
            _entry(
                "scheduled-task",
                "system" if task_path.lower().startswith("\\microsoft\\") else "other",
                name,
                command_line,
                task_path,
                state=clamp_text(row.get("state"), 40),
                author=clamp_text(row.get("author"), 120),
            )
        )
    coverage["count"] = len(entries)
    return entries, coverage


def _scheduled_task_entries() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    entries, coverage = _task_file_entries()
    if entries:
        return entries, coverage
    fallback_entries, fallback_coverage = _task_cmdlet_entries()
    return fallback_entries, {"primary": coverage, "fallback": fallback_coverage, "count": len(fallback_entries)}


def inspect_startup_entries(*, include_signature: bool, include_tasks: bool) -> dict[str, Any]:
    registry_entries, registry_coverage = _registry_entries()
    folder_entries, folder_coverage = _startup_folder_entries()
    entries = [*registry_entries, *folder_entries]

    task_coverage: dict[str, Any] = {"query": "skipped"}
    if include_tasks:
        task_entries, task_coverage = _scheduled_task_entries()
        entries.extend(task_entries)

    if include_signature:
        for entry in entries:
            executable = entry.get("executable")
            if executable and entry.get("executable_exists"):
                entry["signature"] = signature.verify(executable)
            else:
                entry["signature"] = None

    return {
        "entries": entries,
        "total": len(entries),
        "coverage": {
            "registry": registry_coverage,
            "startup_folders": folder_coverage,
            "scheduled_tasks": task_coverage,
        },
        "errors": [],
    }
