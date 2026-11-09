"""Software removal: plan, execute the vendor uninstaller, verify, audit.

Safety rules enforced here:
- only the software's own uninstall command from the registry is used;
- the executable must be a local .exe outside temp/download directories, and
  never a command interpreter;
- MSI removal must carry an explicit /X or /uninstall argument; a maintenance
  `/I{ProductCode}` entry is normalized to `/X{ProductCode} /qn`;
- no elevation is attempted: a 740/access-denied result is reported, not retried;
- execution needs a one-time engine approval bound to the plan.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
import winreg
from pathlib import Path
from typing import Any, Callable

from ..protocol import (
    E_APPROVAL_STALE,
    E_INVALID_PARAMS,
    E_TARGET_CHANGED,
    E_TARGET_LOCKED,
    EngineError,
)
from ..storage import db
from ..util import parse_command_line
from . import approval, planner

CREATE_NO_WINDOW = 0x08000000

_BLOCKED_HOSTS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
}
_UNSAFE_MARKERS = ("\\temp\\", "\\downloads\\", "\\users\\public\\", "\\$recycle.bin\\")

UNINSTALL_REGISTRY_KEYS = (
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0),
)


def _registry_read(root, path: str, flags: int, subkey: str, fields: tuple[str, ...]) -> dict[str, Any] | None:
    try:
        with winreg.OpenKey(root, f"{path}\\{subkey}", 0, winreg.KEY_READ | flags) as key:
            values: dict[str, Any] = {}
            for field in fields:
                try:
                    values[field], _ = winreg.QueryValueEx(key, field)
                except OSError:
                    continue
            return values
    except OSError:
        return None


def _iter_uninstall_entries():
    """Yield one record per uninstall registry entry (the only registry access)."""
    for root, path, flags in UNINSTALL_REGISTRY_KEYS:
        hive = "HKLM" if root == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ | flags) as key:
                count = winreg.QueryInfoKey(key)[0]
                for index in range(count):
                    try:
                        subkey = winreg.EnumKey(key, index)
                    except OSError:
                        break
                    values = _registry_read(
                        root,
                        path,
                        flags,
                        subkey,
                        ("DisplayName", "DisplayVersion", "Publisher", "UninstallString", "QuietUninstallString"),
                    )
                    if not values:
                        continue
                    display = str(values.get("DisplayName") or "").strip()
                    if not display:
                        continue
                    yield {
                        "hive": hive,
                        "key_path": f"{path}\\{subkey}",
                        "name": display,
                        "version": str(values.get("DisplayVersion") or "").strip() or None,
                        "publisher": str(values.get("Publisher") or "").strip() or None,
                        "uninstall_string": values.get("UninstallString"),
                        "quiet_uninstall_string": values.get("QuietUninstallString"),
                    }
        except OSError:
            continue


def find_software(name: str, *, publisher: str | None = None, version: str | None = None) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for entry in _iter_uninstall_entries():
        if entry["name"].casefold() != name.casefold():
            continue
        if publisher and (entry["publisher"] or "").casefold() != publisher.casefold():
            continue
        if version and (entry["version"] or "").casefold() != version.casefold():
            continue
        matches.append(entry)
    if not matches:
        raise EngineError("E_NOT_FOUND", f"no installed software named {name!r}")
    if len(matches) > 1 and not (publisher or version):
        raise EngineError(
            "E_AMBIGUOUS_TARGET",
            f"{len(matches)} entries match {name!r}; pass publisher or version to choose one",
            {"candidates": [{"name": item["name"], "version": item["version"], "publisher": item["publisher"]} for item in matches]},
        )
    return matches[0]


def _msiexec_product_code(value: str) -> str | None:
    """Return `{GUID}` when the argument is a braced MSI product code."""
    text = value.strip()
    if len(text) < 2 or not text.startswith("{") or not text.endswith("}"):
        return None
    try:
        uuid.UUID(text[1:-1])
    except (ValueError, AttributeError):
        return None
    return text


def _normalize_msiexec_arguments(arguments: list[str]) -> list[str]:
    """Rewrite `msiexec /I{ProductCode}` maintenance commands to a real uninstall.

    Some MSIs, notably per-user packages, register their ARP UninstallString as
    `MsiExec.exe /I{GUID}`. `/I` opens maintenance mode; `/X` is the actual
    uninstall. The rewrite keeps the vendor product code, preserves every other
    flag, and forces exactly one `/qn` so the headless tool never stops on a
    maintenance dialog.
    """
    normalized = list(arguments)
    changed = False
    index = 0
    while index < len(normalized):
        argument = normalized[index]
        lowered = argument.casefold()
        if lowered.startswith(("/i", "-i")) and len(argument) > 2:
            code = _msiexec_product_code(argument[2:])
            if code is not None:
                normalized[index] = "/X" + code
                changed = True
        elif lowered in {"/i", "-i"} and index + 1 < len(normalized):
            code = _msiexec_product_code(normalized[index + 1])
            if code is not None:
                normalized[index] = "/X" + code
                del normalized[index + 1]
                changed = True
        index += 1
    if changed:
        # The tool is headless: force exactly one silent switch. An MSI that
        # registered `/I{GUID} /qb` would otherwise show a progress UI.
        normalized = [item for item in normalized if not item.casefold().startswith(("/q", "-q"))]
        normalized.append("/qn")
    return normalized


def validate_uninstaller(entry: dict[str, Any]) -> tuple[str, list[str]]:
    command = entry.get("quiet_uninstall_string") or entry.get("uninstall_string")
    if not command:
        raise EngineError(E_INVALID_PARAMS, "this entry has no uninstall command")
    executable, arguments = parse_command_line(str(command))
    if not executable:
        raise EngineError(E_INVALID_PARAMS, "the uninstall command has no executable")
    path = Path(executable)
    basename = path.name.casefold()
    if basename == "msiexec.exe" and not path.is_absolute():
        # ARP entries commonly register the bare name "MsiExec.exe". Resolve it
        # to the system copy instead of trusting PATH or the working directory.
        system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
        candidate = Path(system_root) / "System32" / "msiexec.exe"
        if candidate.is_file():
            path = candidate
    if not path.is_absolute() or not path.is_file():
        raise EngineError(E_INVALID_PARAMS, f"the uninstall executable is missing: {executable}")
    basename = path.name.casefold()
    if basename in _BLOCKED_HOSTS:
        raise EngineError(E_INVALID_PARAMS, f"refusing to run a command interpreter as an uninstaller: {basename}")
    lowered = str(path).casefold()
    if any(marker in lowered for marker in _UNSAFE_MARKERS):
        raise EngineError(E_INVALID_PARAMS, "refusing to run an uninstaller from a temporary or download directory")
    if basename == "msiexec.exe":
        has_remove = any(
            argument.casefold().startswith(("/x", "-x", "/uninstall")) for argument in arguments
        )
        if not has_remove:
            arguments = _normalize_msiexec_arguments(arguments)
            has_remove = any(
                argument.casefold().startswith(("/x", "-x", "/uninstall")) for argument in arguments
            )
        if not has_remove:
            raise EngineError(E_INVALID_PARAMS, "msiexec removal must carry /X or /uninstall")
    return str(path), arguments


def create_removal_plan(connection, requests: list[dict[str, Any]]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for request in requests:
        name = request.get("name")
        if not isinstance(name, str) or not name.strip():
            raise EngineError(E_INVALID_PARAMS, "each request needs a software name")
        try:
            entry = find_software(name, publisher=request.get("publisher"), version=request.get("version"))
            executable, arguments = validate_uninstaller(entry)
        except EngineError as error:
            excluded.append({"name": name, "code": error.code, "reason": error.message})
            continue
        command_line = " ".join([executable, *arguments])
        identity = hashlib.sha256(
            f"{entry['hive']}|{entry['key_path']}|{entry['name'].casefold()}|{command_line.casefold()}".encode("utf-8")
        ).hexdigest()
        items.append(
            {
                "item_id": db.new_id("act"),
                "action_type": "run-uninstaller",
                "target": f"{entry['hive']}\\{entry['key_path']}",
                "target_hash": identity,
                "order_index": len(items),
                "software": entry["name"],
                "version": entry["version"],
                "publisher": entry["publisher"],
                "uninstaller": executable,
                "arguments": arguments,
                "registry_key": entry["key_path"],
                "hive": entry["hive"],
                "risk_level": "L3",
            }
        )

    if not items:
        raise EngineError("E_PLAN_EMPTY", "no software could be planned for removal", {"excluded": excluded})

    plan_id = db.new_id("plan")
    plan_hash = planner.compute_plan_hash("removal", items)
    summary = {
        "expires_at": planner.iso_in(600),
        "counts": {"requested": len(requests), "items": len(items), "excluded": len(excluded)},
        "excluded": excluded,
        "risk_levels": ["L3"],
        "note": "The vendor uninstaller runs interactively; a UAC prompt or vendor dialog may appear.",
    }
    with db.transaction(connection):
        connection.execute(
            "INSERT INTO action_plans (plan_id, plan_type, created_at, status, risk_level, plan_hash, requires_approval, summary_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (plan_id, "removal", db.utc_now(), "pending", "L3", plan_hash, 1, json.dumps(summary, ensure_ascii=False)),
        )
        for item in items:
            connection.execute(
                "INSERT INTO action_items (item_id, plan_id, action_type, target, target_hash, metadata_json, order_index)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    item["item_id"],
                    plan_id,
                    item["action_type"],
                    item["target"],
                    item["target_hash"],
                    json.dumps({key: item[key] for key in ("software", "version", "publisher", "uninstaller", "arguments", "registry_key", "hive", "risk_level")}, ensure_ascii=False),
                    item["order_index"],
                ),
            )
    return planner.load_plan(connection, plan_id)


def _entry_still_matches(software: str, item: dict[str, Any]) -> bool:
    hive = item.get("hive")
    root = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
    key_path = str(item.get("registry_key") or "")
    parent, _, subkey = key_path.rpartition("\\")
    if not parent or not subkey:
        return False
    for candidate_flags in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        values = _registry_read(root, parent, candidate_flags, subkey, ("DisplayName",))
        if values:
            return str(values.get("DisplayName") or "").casefold() == software.casefold()
    return False


def _default_runner(executable: str, arguments: list[str], timeout: int) -> tuple[int | None, str, str | None]:
    try:
        process = subprocess.run(
            [executable, *arguments],
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
            cwd=str(Path(executable).parent),
        )
    except subprocess.TimeoutExpired:
        return None, "", "E_TIMEOUT"
    except OSError as error:
        winerror = getattr(error, "winerror", None)
        if winerror == 740:
            return None, "", "E_ELEVATION_REQUIRED"
        return None, "", f"E_IO: {error}"
    output = (process.stdout or b"")[-4000:].decode("utf-8", "replace")
    error_output = (process.stderr or b"")[-2000:].decode("utf-8", "replace")
    return process.returncode, output, error_output or None


def execute_removal_plan(
    connection,
    plan_id: str,
    approval_id: str,
    *,
    runner: Callable[[str, list[str], int], tuple[int | None, str, str | None]] | None = None,
    lookup: Callable[[str, dict[str, Any]], bool] | None = None,
    timeout: int = 600,
) -> dict[str, Any]:
    record = approval.validate(connection, approval_id=approval_id, plan_id=plan_id)
    plan = planner.load_plan(connection, plan_id)
    if plan["plan_type"] != "removal":
        raise EngineError(E_INVALID_PARAMS, "this plan is not a removal plan")
    items = planner.load_plan_items(connection, plan_id)
    if planner.compute_manifest_hash(items) != record["target_manifest_hash"]:
        raise EngineError(E_APPROVAL_STALE, "the approved software list no longer matches the plan")

    approval.consume(connection, approval_id)
    run = runner or _default_runner
    still_installed = lookup or _entry_still_matches

    action_id = db.new_id("action")
    affected: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    for item in items:
        if not still_installed(item["software"], item):
            failed.append({"software": item["software"], "code": E_TARGET_CHANGED, "message": "the software entry disappeared before execution"})
            continue
        code, output, error_text = run(item["uninstaller"], list(item.get("arguments") or []), timeout)
        if error_text and str(error_text).startswith("E_"):
            failed.append({"software": item["software"], "code": str(error_text).split(":")[0], "message": error_text})
            db.record_audit(connection, operation="removal.run", result="failed", target=item["software"], plan_id=plan_id, action_id=action_id, detail={"error": error_text})
            continue

        verified = not still_installed(item["software"], item) if error_text is None else False
        audit_id = db.record_audit(
            connection,
            operation="removal.run",
            result="completed" if verified else "verify-failed",
            target=item["software"],
            plan_id=plan_id,
            action_id=action_id,
            detail={"exit_code": code, "verified": verified, "output_tail": output[-500:]},
        )
        if verified:
            affected.append({"software": item["software"], "version": item.get("version"), "exit_code": code, "audit_id": audit_id})
        else:
            failed.append(
                {
                    "software": item["software"],
                    "code": "E_VERIFY_FAILED",
                    "message": "the uninstaller finished but the software is still registered",
                    "audit_id": audit_id,
                    "exit_code": code,
                    "output_tail": output[-500:],
                }
            )

    status = "completed" if not failed else ("partial" if affected else "failed")
    with db.transaction(connection):
        connection.execute("UPDATE action_plans SET status = ? WHERE plan_id = ?", (status, plan_id))
    audit_id = db.record_audit(connection, operation="removal.execute", result=status, plan_id=plan_id, action_id=action_id, detail={"affected": len(affected), "failed": len(failed)})
    return {
        "action_id": action_id,
        "plan_id": plan_id,
        "success": not failed,
        "status": status,
        "affected_items": affected,
        "failed_items": failed,
        "verification": {"verified": not failed, "checked": len(items)},
        "audit_id": audit_id,
        "executed_at": db.utc_now(),
    }
