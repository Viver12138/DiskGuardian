"""Reversible startup-entry management (registry Run / RunOnce values).

A disable is a move, not a loss: the original value data is stored in
`startup_changes`, the registry value is removed, and "enable" writes it back to
the exact key it came from. Both directions need a one-time engine approval bound
to the plan, and every change is audited.
"""

from __future__ import annotations

import hashlib
import json
import winreg
from typing import Any, Protocol

from ..protocol import (
    E_APPROVAL_STALE,
    E_ELEVATION_REQUIRED,
    E_INVALID_PARAMS,
    E_INVALID_STATE,
    E_TARGET_CHANGED,
    EngineError,
)
from ..storage import db
from . import approval, planner

RUN_KEYS = (
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", 0, "user"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 0, "user"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", winreg.KEY_WOW64_64KEY, "machine"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", winreg.KEY_WOW64_32KEY, "machine"),
)


class RunRegistry(Protocol):
    def list_values(self, hive: str, path: str, view: int) -> list[tuple[str, str]]: ...
    def read_value(self, hive: str, path: str, view: int, name: str) -> str | None: ...
    def write_value(self, hive: str, path: str, view: int, name: str, data: str) -> None: ...
    def delete_value(self, hive: str, path: str, view: int, name: str) -> None: ...


def _root(hive: str):
    if hive == "HKLM":
        return winreg.HKEY_LOCAL_MACHINE
    if hive == "HKCU":
        return winreg.HKEY_CURRENT_USER
    raise EngineError(E_INVALID_PARAMS, f"unsupported hive: {hive}")


class Win32RunRegistry:
    def open(self, hive: str, path: str, view: int, access: int):
        return winreg.OpenKey(_root(hive), path, 0, access | view)

    def list_values(self, hive: str, path: str, view: int) -> list[tuple[str, str]]:
        values: list[tuple[str, str]] = []
        try:
            with self.open(hive, path, view, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    if isinstance(data, str):
                        values.append((name, data))
        except OSError:
            return values
        return values

    def read_value(self, hive: str, path: str, view: int, name: str) -> str | None:
        try:
            with self.open(hive, path, view, winreg.KEY_READ) as key:
                data, _ = winreg.QueryValueEx(key, name)
                return data if isinstance(data, str) else None
        except OSError:
            return None

    def write_value(self, hive: str, path: str, view: int, name: str, data: str) -> None:
        try:
            with self.open(hive, path, view, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, data)
        except PermissionError as error:
            raise EngineError(E_ELEVATION_REQUIRED, f"cannot write {hive}\\{path}: administrator rights required") from error
        except OSError as error:
            raise EngineError("E_IO", f"cannot write {hive}\\{path}: {error}") from error

    def delete_value(self, hive: str, path: str, view: int, name: str) -> None:
        try:
            with self.open(hive, path, view, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
        except PermissionError as error:
            raise EngineError(E_ELEVATION_REQUIRED, f"cannot modify {hive}\\{path}: administrator rights required") from error
        except FileNotFoundError:
            return
        except OSError as error:
            raise EngineError("E_IO", f"cannot modify {hive}\\{path}: {error}") from error


def _default_registry() -> Win32RunRegistry:
    return Win32RunRegistry()


def locate_entry(registry: RunRegistry, name: str, scope: str | None = None) -> dict[str, Any]:
    for hive, path, view, entry_scope in RUN_KEYS:
        if scope and scope.casefold() not in {entry_scope, "any"}:
            continue
        for value_name, value_data in registry.list_values(hive, path, view):
            if value_name.casefold() == name.casefold():
                return {"hive": hive, "key_path": path, "view": view, "scope": entry_scope, "value_name": value_name, "value_data": value_data}
    raise EngineError("E_NOT_FOUND", f"no startup entry named {name!r} in the registry Run keys")


def _target(item: dict[str, Any]) -> str:
    return f"{item['hive']}\\{item['key_path']}\\{item['value_name']}"


def compute_item_hash(item: dict[str, Any], action: str) -> str:
    payload = f"{item['hive']}|{item['key_path']}|{item['view']}|{item['value_name']}|{item['value_data']}|{action}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def create_startup_plan(
    connection,
    *,
    name: str,
    action: str,
    scope: str | None = None,
    registry: RunRegistry | None = None,
) -> dict[str, Any]:
    if action not in {"disable", "enable"}:
        raise EngineError(E_INVALID_PARAMS, "action must be disable or enable")
    backend = registry or _default_registry()

    if action == "disable":
        entry = locate_entry(backend, name, scope)
        item = {
            "item_id": db.new_id("act"),
            "action_type": "disable-run-value",
            "target": _target(entry),
            "target_hash": compute_item_hash(entry, "disable"),
            "order_index": 0,
            "hive": entry["hive"],
            "key_path": entry["key_path"],
            "view": entry["view"],
            "value_name": entry["value_name"],
            "value_data": entry["value_data"],
            "risk_level": "L3",
        }
    else:
        record = connection.execute(
            "SELECT * FROM startup_changes WHERE status = 'disabled' AND value_name = ? COLLATE NOCASE ORDER BY changed_at DESC LIMIT 1",
            (name,),
        ).fetchone()
        if record is None:
            raise EngineError("E_NOT_FOUND", f"no disabled startup entry named {name!r} was recorded by DiskGuardian")
        entry = {
            "hive": record["hive"],
            "key_path": record["key_path"],
            "view": int(record["view"]),
            "value_name": record["value_name"],
            "value_data": record["value_data"],
        }
        item = {
            "item_id": db.new_id("act"),
            "action_type": "enable-run-value",
            "target": _target(entry),
            "target_hash": compute_item_hash(entry, "enable"),
            "order_index": 0,
            "hive": entry["hive"],
            "key_path": entry["key_path"],
            "view": entry["view"],
            "value_name": entry["value_name"],
            "value_data": entry["value_data"],
            "risk_level": "L3",
        }

    plan_id = db.new_id("plan")
    plan_hash = planner.compute_plan_hash("startup", [item])
    summary = {
        "expires_at": planner.iso_in(600),
        "counts": {"items": 1},
        "action": action,
        "scope": item.get("hive"),
        "risk_levels": ["L3"],
        "reversible": True,
    }
    with db.transaction(connection):
        connection.execute(
            "INSERT INTO action_plans (plan_id, plan_type, created_at, status, risk_level, plan_hash, requires_approval, summary_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (plan_id, "startup", db.utc_now(), "pending", "L3", plan_hash, 1, json.dumps(summary, ensure_ascii=False)),
        )
        connection.execute(
            "INSERT INTO action_items (item_id, plan_id, action_type, target, target_hash, metadata_json, order_index)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                item["item_id"],
                plan_id,
                item["action_type"],
                item["target"],
                item["target_hash"],
                json.dumps(
                    {
                        "hive": item["hive"],
                        "key_path": item["key_path"],
                        "view": item["view"],
                        "value_name": item["value_name"],
                        "value_data": item["value_data"],
                        "risk_level": "L3",
                    },
                    ensure_ascii=False,
                ),
                0,
            ),
        )
    return planner.load_plan(connection, plan_id)


def execute_startup_plan(
    connection,
    plan_id: str,
    approval_id: str,
    *,
    registry: RunRegistry | None = None,
) -> dict[str, Any]:
    record = approval.validate(connection, approval_id=approval_id, plan_id=plan_id)
    plan = planner.load_plan(connection, plan_id)
    if plan["plan_type"] != "startup":
        raise EngineError(E_INVALID_PARAMS, "this plan is not a startup plan")
    items = planner.load_plan_items(connection, plan_id)
    if planner.compute_manifest_hash(items) != record["target_manifest_hash"]:
        raise EngineError(E_APPROVAL_STALE, "the approved startup entry no longer matches the plan")

    approval.consume(connection, approval_id)
    backend = registry or _default_registry()
    action_id = db.new_id("action")
    affected: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    # Pre-flight check before consuming anything: the registry state the user
    # approved must still hold, otherwise the whole plan is refused.
    for item in items:
        current = backend.read_value(item["hive"], item["key_path"], int(item["view"]), item["value_name"])
        if item["action_type"] == "disable-run-value" and current != item["value_data"]:
            raise EngineError(E_TARGET_CHANGED, "the startup value changed after the plan was approved")
        if item["action_type"] == "enable-run-value" and current is not None and current != item["value_data"]:
            raise EngineError(E_TARGET_CHANGED, "a different value now exists at this startup name")

    for item in items:
        hive, path, view = item["hive"], item["key_path"], int(item["view"])
        name, data = item["value_name"], item["value_data"]
        try:
            current = backend.read_value(hive, path, view, name)
            if item["action_type"] == "disable-run-value":
                if current != data:
                    raise EngineError(E_TARGET_CHANGED, "the startup value changed after the plan was approved")
                change_id = db.new_id("startup")
                backend.delete_value(hive, path, view, name)
                with db.transaction(connection):
                    connection.execute(
                        "INSERT INTO startup_changes (change_id, hive, key_path, view, value_name, value_data, plan_id, changed_at, status)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'disabled')",
                        (change_id, hive, path, view, name, data, plan_id, db.utc_now()),
                    )
                if backend.read_value(hive, path, view, name) is not None:
                    raise EngineError("E_VERIFY_FAILED", "the startup value still exists after the change")
                audit_id = db.record_audit(
                    connection,
                    operation="startup.disable",
                    result="completed",
                    target=_target(item),
                    plan_id=plan_id,
                    action_id=action_id,
                    detail={"change_id": change_id},
                )
                affected.append({"target": _target(item), "change_id": change_id, "state": "disabled", "audit_id": audit_id})
            else:
                if current is not None and current != data:
                    raise EngineError(E_TARGET_CHANGED, "a different value now exists at this startup name")
                if current is None:
                    backend.write_value(hive, path, view, name, data)
                with db.transaction(connection):
                    connection.execute(
                        "UPDATE startup_changes SET status = 'restored', restored_at = ?"
                        " WHERE status = 'disabled' AND hive = ? AND key_path = ? AND value_name = ?",
                        (db.utc_now(), hive, path, name),
                    )
                if backend.read_value(hive, path, view, name) != data:
                    raise EngineError("E_VERIFY_FAILED", "the startup value did not come back")
                audit_id = db.record_audit(
                    connection,
                    operation="startup.enable",
                    result="completed",
                    target=_target(item),
                    plan_id=plan_id,
                    action_id=action_id,
                    detail={},
                )
                affected.append({"target": _target(item), "state": "enabled", "audit_id": audit_id})
        except EngineError as error:
            failed.append({"target": _target(item), "code": error.code, "message": error.message})
            db.record_audit(
                connection,
                operation="startup.change",
                result="failed",
                target=_target(item),
                plan_id=plan_id,
                action_id=action_id,
                detail={"code": error.code, "message": error.message},
            )

    status = "completed" if not failed else ("partial" if affected else "failed")
    with db.transaction(connection):
        connection.execute("UPDATE action_plans SET status = ? WHERE plan_id = ?", (status, plan_id))
    audit_id = db.record_audit(connection, operation="startup.execute", result=status, plan_id=plan_id, action_id=action_id, detail={"affected": len(affected), "failed": len(failed)})
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


def list_startup_changes(connection, limit: int = 100) -> dict[str, Any]:
    rows = connection.execute(
        "SELECT * FROM startup_changes ORDER BY changed_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return {"items": [dict(row) for row in rows], "total": len(rows)}
