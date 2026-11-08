"""Read-only residue inspection after an uninstall.

Answers one question without touching anything: did the uninstaller leave
something behind? It never deletes residue; leftovers usually live in Program
Files or ProgramData, which are L4 for this engine.
"""

from __future__ import annotations

from typing import Any

from ..protocol import E_INVALID_PARAMS, EngineError
from ..scanner import filesystem
from . import removal


def inspect_residue(
    name: str,
    *,
    install_location: str | None = None,
    candidate_paths: list[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(name, str) or not name.strip():
        raise EngineError(E_INVALID_PARAMS, "software name must be a non-empty string")

    registrations = [entry for entry in removal._iter_uninstall_entries() if entry["name"].casefold() == name.casefold()]

    targets: list[str] = []
    for candidate in [install_location, *(candidate_paths or [])]:
        if isinstance(candidate, str) and candidate.strip() and candidate not in targets:
            targets.append(candidate)
    if len(targets) > 16:
        raise EngineError(E_INVALID_PARAMS, "at most 16 paths can be inspected")

    budget = filesystem.ScanBudget(max_entries=50_000, max_seconds=20)
    leftovers: list[dict[str, Any]] = []
    missing: list[str] = []
    for target in targets:
        try:
            analysis = filesystem.analyze_directories([target], max_depth=1, budget=budget)
        except EngineError as error:
            missing.append(target)
            leftovers.append({"path": target, "status": "unavailable", "reason": error.message})
            continue
        for entry in analysis:
            leftovers.append(
                {
                    "path": entry["path"],
                    "status": "present",
                    "bytes": entry["bytes"],
                    "files": entry["files"],
                    "directories": entry["directories"],
                    "truncated": entry["truncated"],
                }
            )

    notes = [
        "This is a read-only check: nothing was removed.",
        "Residue under Program Files, ProgramData, or the registry is not eligible for automatic cleanup; review it manually or with the vendor's tool.",
    ]
    if registrations:
        notes.append("The software is still registered, so the uninstall may not have completed.")
    if not targets:
        notes.append("No paths were supplied; pass the install location to measure leftover files.")

    return {
        "software": name,
        "registered": bool(registrations),
        "registrations": registration_summary(registrations),
        "leftovers": leftovers,
        "missing_paths": missing,
        "notes": notes,
        "checked_paths": len(targets),
        "truncated": budget.truncated,
        "errors": [],
    }


def registration_summary(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": entry["name"],
            "version": entry.get("version"),
            "publisher": entry.get("publisher"),
            "hive": entry.get("hive"),
            "key_path": entry.get("key_path"),
        }
        for entry in entries
    ]
