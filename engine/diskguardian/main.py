"""Line-oriented JSON dispatcher for the DiskGuardian engine."""

from __future__ import annotations

import ctypes
import json
import os
import sys
import time
import traceback
from typing import Any, BinaryIO, Callable

from . import __version__, config
from .protocol import (
    E_ENGINE,
    E_INVALID_PARAMS,
    E_UNKNOWN_OPERATION,
    decode_line,
    encode_response,
    failure,
    optional_bool,
    optional_int,
    optional_str_list,
    require_mapping,
    success,
)
from .protocol import EngineError, Request
from .actions import approval as approvals
from .actions import cleaner, planner, removal, residue, startup as startup_actions
from .analyzers import browser as browser_analyzer
from .analyzers import security as security_analyzer
from .analyzers import software as software_analyzer
from .analyzers import startup as startup_analyzer
from .scanner import browser, candidates, filesystem, security, services, software, startup, volumes
from .storage import db

Handler = Callable[[dict[str, Any]], dict[str, Any]]


def _log(message: str) -> None:
    sys.stderr.write(f"[diskguardian {time.strftime('%H:%M:%S')}] {message}\n")
    sys.stderr.flush()


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def _record_scan(scan_type: str, started_at: str, summary: dict[str, Any]) -> dict[str, Any]:
    """Persist one scan session. Storage trouble must not hide scan results."""
    try:
        connection = db.connect()
        try:
            scan_id = db.record_scan(
                connection,
                scan_type=scan_type,
                started_at=started_at,
                completed_at=db.utc_now(),
                status="completed",
                summary=summary,
            )
        finally:
            connection.close()
        return {"scan_id": scan_id}
    except Exception as error:  # noqa: BLE001 - surfaced to the caller as data
        _log(f"scan record failed: {error!r}")
        return {"storage_error": f"{type(error).__name__}: {error}"}


def _default_directories() -> list[str]:
    candidates = [os.environ.get("TEMP"), os.path.join(config.system_drive(), "Temp"), os.environ.get("LOCALAPPDATA")]
    seen: set[str] = set()
    result: list[str] = []
    for candidate in candidates:
        if not candidate:
            continue
        key = os.path.normcase(candidate)
        if key in seen:
            continue
        seen.add(key)
        result.append(candidate)
    return result


def op_scan_disk(params: dict[str, Any]) -> dict[str, Any]:
    require_mapping(params)
    started = db.utc_now()
    data = volumes.scan_volumes()
    data.update(_record_scan("disk", started, {"disks": len(data["disks"])}))
    return data


def op_scan_directories(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    max_depth = optional_int(params, "max_depth", config.DEFAULT_DIRECTORY_DEPTH, minimum=0, maximum=config.MAX_DIRECTORY_DEPTH)
    max_entries = optional_int(
        params, "max_entries", config.DEFAULT_MAX_ENTRIES, minimum=1, maximum=config.MAX_MAX_ENTRIES
    )
    max_seconds = optional_int(
        params, "max_seconds", config.DEFAULT_MAX_SECONDS, minimum=1, maximum=config.MAX_MAX_SECONDS
    )
    paths = optional_str_list(params, "paths") or _default_directories()
    budget = filesystem.ScanBudget(max_entries=max_entries, max_seconds=max_seconds)
    started = db.utc_now()
    analysis = filesystem.analyze_directories(paths, max_depth=max_depth, budget=budget)
    result: dict[str, Any] = {
        "analysis": analysis,
        "entries_examined": budget.entries,
        "truncated": budget.truncated,
        "truncated_reason": budget.reason,
    }
    result.update(_record_scan("directories", started, {"paths": len(paths), "entries": budget.entries}))
    return result


def op_find_large_files(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    min_bytes = optional_int(
        params, "min_bytes", config.DEFAULT_LARGE_FILE_BYTES, minimum=1, maximum=10**15
    )
    limit = optional_int(params, "limit", 50, minimum=1, maximum=config.MAX_LARGE_FILE_RESULTS)
    max_entries = optional_int(
        params, "max_entries", config.DEFAULT_MAX_ENTRIES, minimum=1, maximum=config.MAX_MAX_ENTRIES
    )
    max_seconds = optional_int(
        params, "max_seconds", config.DEFAULT_MAX_SECONDS, minimum=1, maximum=config.MAX_MAX_SECONDS
    )
    roots = optional_str_list(params, "roots") or [str(config.user_profile())]
    budget = filesystem.ScanBudget(max_entries=max_entries, max_seconds=max_seconds)
    started = db.utc_now()
    files, scanned = filesystem.find_large_files(roots, min_bytes=min_bytes, limit=limit, budget=budget)
    result: dict[str, Any] = {
        "files": files,
        "files_scanned": scanned,
        "min_bytes": min_bytes,
        "limit": limit,
        "truncated": budget.truncated,
        "truncated_reason": budget.reason,
    }
    result.update(_record_scan("large_files", started, {"roots": len(roots), "matches": len(files)}))
    return result


def op_list_installed_software(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    include_signature = optional_bool(params, "include_signature", False)
    limit = optional_int(params, "limit", 300, minimum=1, maximum=2000)
    started = db.utc_now()
    data = software.scan_installed_software(include_signature=include_signature, limit=limit)
    data.update(_record_scan("software", started, {"total": data["total"], "returned": data["returned"]}))
    return data


def op_inspect_startup_entries(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    include_signature = optional_bool(params, "include_signature", False)
    include_tasks = optional_bool(params, "include_tasks", True)
    started = db.utc_now()
    data = startup.inspect_startup_entries(include_signature=include_signature, include_tasks=include_tasks)
    data.update(_record_scan("startup", started, {"total": data["total"]}))
    return data


def op_inspect_services(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    include_signature = optional_bool(params, "include_signature", False)
    running_only = optional_bool(params, "running_only", False)
    started = db.utc_now()
    data = services.inspect_services(include_signature=include_signature, include_running_only=running_only)
    data.update(_record_scan("services", started, {"total": data["total"]}))
    return data


def op_inspect_browser_extensions(params: dict[str, Any]) -> dict[str, Any]:
    require_mapping(params)
    started = db.utc_now()
    data = browser.inspect_browser_extensions()
    data.update(_record_scan("browser_extensions", started, {"extensions": data["coverage"].get("extensions_found", 0)}))
    return data


def op_inspect_browser_settings(params: dict[str, Any]) -> dict[str, Any]:
    require_mapping(params)
    started = db.utc_now()
    data = browser.inspect_browser_settings()
    data.update(_record_scan("browser_settings", started, {"browsers": data["coverage"].get("browsers_present", 0)}))
    return data


def op_inspect_security_status(params: dict[str, Any]) -> dict[str, Any]:
    require_mapping(params)
    started = db.utc_now()
    data = security.inspect_security_status()
    data.update(_record_scan("security", started, {"query": data["coverage"].get("query", "unknown")}))
    return data


def _require_paths(params: dict[str, Any]) -> list[str]:
    paths = optional_str_list(params, "paths", maximum_items=200)
    if not paths:
        raise EngineError(E_INVALID_PARAMS, "paths must contain at least one absolute path")
    return paths


def op_classify_files(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    from .permissions import rules

    paths = _require_paths(params)
    results = rules.classify_many(paths)
    return {
        "files": [item.to_dict() for item in results],
        "eligible": sum(1 for item in results if item.eligible),
        "excluded": sum(1 for item in results if not item.eligible),
    }


def op_create_cleanup_plan(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    paths = _require_paths(params)
    max_items = optional_int(params, "max_items", config.MAX_PLAN_ITEMS, minimum=1, maximum=config.MAX_PLAN_ITEMS)
    connection = db.connect()
    try:
        return planner.create_cleanup_plan(connection, paths, max_items=max_items)
    finally:
        connection.close()


def op_preview_action_plan(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    plan_id = params.get("plan_id")
    if not isinstance(plan_id, str) or not plan_id:
        raise EngineError(E_INVALID_PARAMS, "plan_id must be a non-empty string")
    connection = db.connect()
    try:
        plan = planner.load_plan(connection, plan_id)
        plan["expired"] = planner.plan_expired(plan)
        return plan
    finally:
        connection.close()


def op_issue_approval(params: dict[str, Any]) -> dict[str, Any]:
    """Internal: the plugin calls this only after a real user confirmation."""
    params = require_mapping(params)
    plan_id = params.get("plan_id")
    if not isinstance(plan_id, str) or not plan_id:
        raise EngineError(E_INVALID_PARAMS, "plan_id must be a non-empty string")
    source = params.get("source", "harness-user-question")
    if not isinstance(source, str) or source not in {"harness-user-question"}:
        raise EngineError(E_INVALID_PARAMS, "unsupported approval source")
    connection = db.connect()
    try:
        return approvals.issue_approval(connection, plan_id, source=source)
    finally:
        connection.close()


def op_execute_cleanup_plan(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    plan_id = params.get("plan_id")
    approval_id = params.get("approval_id")
    if not isinstance(plan_id, str) or not plan_id:
        raise EngineError(E_INVALID_PARAMS, "plan_id must be a non-empty string")
    if not isinstance(approval_id, str) or not approval_id:
        raise EngineError(E_INVALID_PARAMS, "approval_id must be a non-empty string")
    connection = db.connect()
    try:
        return cleaner.execute_cleanup_plan(connection, plan_id, approval_id)
    finally:
        connection.close()


def op_restore_quarantined_item(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    quarantine_id = params.get("quarantine_id")
    if not isinstance(quarantine_id, str) or not quarantine_id:
        raise EngineError(E_INVALID_PARAMS, "quarantine_id must be a non-empty string")
    connection = db.connect()
    try:
        return cleaner.restore_quarantined_item(connection, quarantine_id)
    finally:
        connection.close()


def op_list_quarantine(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    limit = optional_int(params, "limit", 100, minimum=1, maximum=500)
    connection = db.connect()
    try:
        return cleaner.list_quarantine(connection, limit=limit)
    finally:
        connection.close()


def op_get_audit_log(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    limit = optional_int(params, "limit", 100, minimum=1, maximum=500)
    connection = db.connect()
    try:
        return cleaner.get_audit_log(connection, limit=limit)
    finally:
        connection.close()


def op_analyze_software(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    include_signature = optional_bool(params, "include_signature", True)
    limit = optional_int(params, "limit", 300, minimum=1, maximum=2000)
    inventory = software.scan_installed_software(include_signature=include_signature, limit=limit)
    return software_analyzer.analyze_software(inventory["software"], inventory.get("coverage"))


def op_analyze_startup(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    include_signature = optional_bool(params, "include_signature", True)
    include_tasks = optional_bool(params, "include_tasks", True)
    inventory = startup.inspect_startup_entries(include_signature=include_signature, include_tasks=include_tasks)
    return startup_analyzer.analyze_startup(inventory["entries"], inventory.get("coverage"))


def op_analyze_browser(params: dict[str, Any]) -> dict[str, Any]:
    require_mapping(params)
    extensions = browser.inspect_browser_extensions()
    settings = browser.inspect_browser_settings()
    coverage = {"extensions": extensions.get("coverage"), "settings": settings.get("coverage")}
    return browser_analyzer.analyze_browser(extensions, settings, coverage)


def op_analyze_security_status(params: dict[str, Any]) -> dict[str, Any]:
    require_mapping(params)
    return security_analyzer.analyze_security_status(security.inspect_security_status())


def op_create_removal_plan(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    raw = params.get("software")
    if not isinstance(raw, list) or not raw:
        raise EngineError(E_INVALID_PARAMS, "software must be a non-empty array")
    if len(raw) > 16:
        raise EngineError(E_INVALID_PARAMS, "software accepts at most 16 entries")
    requests: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, str):
            requests.append({"name": item})
            continue
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise EngineError(E_INVALID_PARAMS, "each software entry must be a name or an object with name")
        requests.append(
            {
                "name": item["name"],
                "publisher": item.get("publisher") if isinstance(item.get("publisher"), str) else None,
                "version": item.get("version") if isinstance(item.get("version"), str) else None,
            }
        )
    connection = db.connect()
    try:
        return removal.create_removal_plan(connection, requests)
    finally:
        connection.close()


def op_execute_removal_plan(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    plan_id = params.get("plan_id")
    approval_id = params.get("approval_id")
    if not isinstance(plan_id, str) or not plan_id:
        raise EngineError(E_INVALID_PARAMS, "plan_id must be a non-empty string")
    if not isinstance(approval_id, str) or not approval_id:
        raise EngineError(E_INVALID_PARAMS, "approval_id must be a non-empty string")
    connection = db.connect()
    try:
        return removal.execute_removal_plan(connection, plan_id, approval_id)
    finally:
        connection.close()


def op_create_startup_plan(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    name = params.get("name")
    action = params.get("action")
    scope = params.get("scope")
    if not isinstance(name, str) or not name:
        raise EngineError(E_INVALID_PARAMS, "name must be a non-empty string")
    if action not in {"disable", "enable"}:
        raise EngineError(E_INVALID_PARAMS, "action must be disable or enable")
    if scope is not None and not isinstance(scope, str):
        raise EngineError(E_INVALID_PARAMS, "scope must be a string when provided")
    connection = db.connect()
    try:
        return startup_actions.create_startup_plan(connection, name=name, action=action, scope=scope)
    finally:
        connection.close()


def op_execute_startup_plan(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    plan_id = params.get("plan_id")
    approval_id = params.get("approval_id")
    if not isinstance(plan_id, str) or not plan_id:
        raise EngineError(E_INVALID_PARAMS, "plan_id must be a non-empty string")
    if not isinstance(approval_id, str) or not approval_id:
        raise EngineError(E_INVALID_PARAMS, "approval_id must be a non-empty string")
    connection = db.connect()
    try:
        return startup_actions.execute_startup_plan(connection, plan_id, approval_id)
    finally:
        connection.close()


def op_list_startup_changes(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    limit = optional_int(params, "limit", 100, minimum=1, maximum=500)
    connection = db.connect()
    try:
        return startup_actions.list_startup_changes(connection, limit=limit)
    finally:
        connection.close()


def op_inspect_removal_residue(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    name = params.get("software")
    if not isinstance(name, str) or not name.strip():
        raise EngineError(E_INVALID_PARAMS, "software must be a non-empty string")
    install_location = params.get("install_location")
    if install_location is not None and not isinstance(install_location, str):
        raise EngineError(E_INVALID_PARAMS, "install_location must be a string")
    candidates = optional_str_list(params, "candidate_paths", maximum_items=16)
    return residue.inspect_residue(name, install_location=install_location, candidate_paths=candidates)


def op_list_cleanup_candidates(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    roots = optional_str_list(params, "roots", maximum_items=16) or None
    min_age_hours = optional_int(params, "min_age_hours", 24, minimum=1, maximum=24 * 30)
    min_bytes = optional_int(params, "min_bytes", 0, minimum=0, maximum=10**15)
    limit = optional_int(params, "limit", 200, minimum=1, maximum=500)
    max_entries = optional_int(params, "max_entries", config.DEFAULT_MAX_ENTRIES, minimum=1, maximum=config.MAX_MAX_ENTRIES)
    max_seconds = optional_int(params, "max_seconds", 60, minimum=1, maximum=300)
    started = db.utc_now()
    data = candidates.list_candidates(
        roots=roots,
        min_age_seconds=min_age_hours * 3600,
        min_bytes=min_bytes,
        limit=limit,
        max_entries=max_entries,
        max_seconds=max_seconds,
    )
    data.update(_record_scan("cleanup_candidates", started, {"eligible": data["eligible"]}))
    return data


def op_purge_quarantine(params: dict[str, Any]) -> dict[str, Any]:
    params = require_mapping(params)
    ids = optional_str_list(params, "quarantine_ids", maximum_items=200) or None
    older_than_days = params.get("older_than_days")
    if older_than_days is not None and (isinstance(older_than_days, bool) or not isinstance(older_than_days, int)):
        raise EngineError(E_INVALID_PARAMS, "older_than_days must be an integer")
    if isinstance(older_than_days, int) and not 1 <= older_than_days <= 3650:
        raise EngineError(E_INVALID_PARAMS, "older_than_days must be between 1 and 3650")
    purge_all = optional_bool(params, "all", False)
    dry_run = optional_bool(params, "dry_run", False)
    connection = db.connect()
    try:
        return cleaner.purge_quarantine(
            connection,
            quarantine_ids=ids,
            older_than_days=older_than_days,
            purge_all=purge_all,
            dry_run=dry_run,
        )
    finally:
        connection.close()


def op_self_check(params: dict[str, Any]) -> dict[str, Any]:
    require_mapping(params)
    import sqlite3

    return {
        "engine_version": __version__,
        "python": sys.version.split()[0],
        "implementation": sys.implementation.name,
        "sqlite": sqlite3.sqlite_version,
        "platform": sys.platform,
        "frozen": bool(getattr(sys, "frozen", False)),
        "admin": _is_admin(),
        "database": str(config.database_path()),
        "operations": sorted(OPERATIONS),
    }


OPERATIONS: dict[str, Handler] = {
    "scan_disk": op_scan_disk,
    "scan_directories": op_scan_directories,
    "find_large_files": op_find_large_files,
    "list_installed_software": op_list_installed_software,
    "inspect_startup_entries": op_inspect_startup_entries,
    "inspect_services": op_inspect_services,
    "inspect_browser_extensions": op_inspect_browser_extensions,
    "inspect_browser_settings": op_inspect_browser_settings,
    "inspect_security_status": op_inspect_security_status,
    "classify_files": op_classify_files,
    "create_cleanup_plan": op_create_cleanup_plan,
    "preview_action_plan": op_preview_action_plan,
    "issue_approval": op_issue_approval,
    "execute_cleanup_plan": op_execute_cleanup_plan,
    "restore_quarantined_item": op_restore_quarantined_item,
    "list_quarantine": op_list_quarantine,
    "get_audit_log": op_get_audit_log,
    "analyze_software": op_analyze_software,
    "analyze_startup": op_analyze_startup,
    "analyze_browser": op_analyze_browser,
    "analyze_security_status": op_analyze_security_status,
    "create_removal_plan": op_create_removal_plan,
    "execute_removal_plan": op_execute_removal_plan,
    "create_startup_plan": op_create_startup_plan,
    "execute_startup_plan": op_execute_startup_plan,
    "list_startup_changes": op_list_startup_changes,
    "inspect_removal_residue": op_inspect_removal_residue,
    "list_cleanup_candidates": op_list_cleanup_candidates,
    "purge_quarantine": op_purge_quarantine,
    "self_check": op_self_check,
}


def dispatch(request: Request) -> dict[str, Any]:
    handler = OPERATIONS.get(request.operation)
    try:
        if handler is None:
            raise EngineError(E_UNKNOWN_OPERATION, f"unknown operation: {request.operation}")
        data = handler(request.params)
        return success(request.request_id, data)
    except EngineError as error:
        _log(f"{request.operation} rejected: {error.code} {error.message}")
        return failure(request.request_id, error.code, error.message, error.details)
    except Exception as error:  # noqa: BLE001 - the wire must always answer
        _log(f"{request.operation} failed: {error!r}")
        traceback.print_exc(file=sys.stderr)
        return failure(request.request_id, E_ENGINE, f"{type(error).__name__}: {error}")


def serve(stdin: BinaryIO, stdout: BinaryIO) -> int:
    for raw in stdin:
        if not raw.strip():
            continue
        try:
            request = decode_line(raw)
        except EngineError as error:
            stdout.write(encode_response(failure(None, error.code, error.message, error.details)))
            stdout.flush()
            continue
        except Exception as error:  # noqa: BLE001
            stdout.write(encode_response(failure(None, E_INVALID_PARAMS, f"{type(error).__name__}: {error}")))
            stdout.flush()
            continue
        stdout.write(encode_response(dispatch(request)))
        stdout.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "--self-check":
        payload = op_self_check({})
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdout.write(json.dumps(payload, ensure_ascii=False))
        sys.stdout.write("\n")
        return 0
    if args and args[0] in {"-h", "--help"}:
        sys.stderr.write("usage: run.py [--self-check]\nreads JSONL requests on stdin, writes JSONL responses on stdout\n")
        return 0
    if args:
        sys.stderr.write(f"unknown argument: {args[0]}\n")
        return 2
    return serve(sys.stdin.buffer, sys.stdout.buffer)
