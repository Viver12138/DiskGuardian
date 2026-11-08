"""Quarantine-first cleanup execution and restore.

Order of operations is the safety contract:
1. validate the approval (exists, unused, unexpired, same plan hash);
2. recompute every target's live identity and refuse the whole plan if any moved;
3. consume the approval exactly once;
4. per item: re-classify, check locks, hash, move to quarantine, verify, audit.

Nothing here trusts a model-supplied risk level, target list, or approval flag.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .. import config
from ..permissions import rules
from ..protocol import (
    E_APPROVAL_STALE,
    E_INVALID_PARAMS,
    E_INVALID_STATE,
    E_TARGET_CHANGED,
    E_TARGET_EXISTS,
    E_TARGET_LOCKED,
    EngineError,
)
from ..storage import db
from . import approval, planner


def _sha256(path: Path, chunk: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _live_identity(item: dict[str, Any]) -> tuple[int | None, int | None, int | None]:
    try:
        info = os.lstat(item["target"])
    except OSError:
        return None, None, None
    return int(info.st_size), int(info.st_mtime_ns), int(info.st_ino) if getattr(info, "st_ino", 0) else None


def _assert_unlocked(path: Path) -> None:
    try:
        handle = os.open(str(path), os.O_RDWR)
    except OSError as error:
        raise EngineError(E_TARGET_LOCKED, f"target is locked or not writable: {path} ({error})") from error
    else:
        os.close(handle)


def _quarantine_destination(quarantine_id: str, original: Path) -> Path:
    directory = config.quarantine_dir() / quarantine_id
    directory.mkdir(parents=True, exist_ok=True)
    return directory / original.name


def _quarantine_usage(connection) -> int:
    row = connection.execute(
        "SELECT COALESCE(SUM(size_bytes), 0) AS total FROM quarantine_records WHERE status = 'quarantined'"
    ).fetchone()
    return int(row["total"] or 0)


def _assert_quarantine_capacity(connection, planned_bytes: int) -> None:
    used = _quarantine_usage(connection)
    limit = config.QUARANTINE_MAX_BYTES
    if used + planned_bytes > limit:
        raise EngineError(
            "E_QUARANTINE_FULL",
            "the quarantine does not have room for this plan; restore or discard quarantined items first",
            {"used_bytes": used, "planned_bytes": planned_bytes, "limit_bytes": limit},
        )


def execute_cleanup_plan(connection, plan_id: str, approval_id: str) -> dict[str, Any]:
    record = approval.validate(connection, approval_id=approval_id, plan_id=plan_id)
    plan = planner.load_plan(connection, plan_id)
    if plan["plan_type"] != "cleanup":
        raise EngineError(E_INVALID_PARAMS, "this plan is not a cleanup plan")
    items = planner.load_plan_items(connection, plan_id)
    if not items:
        raise EngineError(E_INVALID_STATE, "the plan has no items")

    # Live revalidation before touching anything: any drift invalidates the
    # whole approval, not just the changed item.
    for item in items:
        size, mtime_ns, file_index = _live_identity(item)
        if (size, mtime_ns, file_index) != (item.get("size_bytes"), item.get("mtime_ns"), item.get("file_index")):
            raise EngineError(
                E_TARGET_CHANGED,
                "a target changed after the plan was approved; create a new plan",
                {"target": item["target"]},
            )

    live_manifest = planner.compute_manifest_hash(items)
    if live_manifest != record["target_manifest_hash"]:
        raise EngineError(E_APPROVAL_STALE, "the approved target manifest no longer matches")

    planned_bytes = sum(int(item.get("size_bytes") or 0) for item in items)
    _assert_quarantine_capacity(connection, planned_bytes)

    approval.consume(connection, approval_id)

    action_id = db.new_id("action")
    affected: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    for item in items:
        target = Path(item["target"])
        try:
            classification = rules.classify(item["target"])
            if not classification.eligible:
                raise EngineError(
                    E_TARGET_CHANGED,
                    "target is no longer eligible for cleanup",
                    {"reasons": classification.reasons},
                )
            _assert_unlocked(target)
            digest = _sha256(target)
            quarantine_id = db.new_id("quarantine")
            destination = _quarantine_destination(quarantine_id, target)
            shutil.move(str(target), str(destination))
            if os.path.exists(target):
                raise EngineError("E_VERIFY_FAILED", "source still exists after the move")
            if not destination.is_file() or destination.stat().st_size != int(item.get("size_bytes") or 0):
                raise EngineError("E_VERIFY_FAILED", "quarantined copy does not match the planned size")
            with db.transaction(connection):
                connection.execute(
                    "INSERT INTO quarantine_records"
                    " (quarantine_id, original_path, quarantine_path, size_bytes, sha256, plan_id, quarantined_at, status)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, 'quarantined')",
                    (
                        quarantine_id,
                        str(target),
                        str(destination),
                        destination.stat().st_size,
                        digest,
                        plan_id,
                        db.utc_now(),
                    ),
                )
            audit_id = db.record_audit(
                connection,
                operation="cleanup.quarantine",
                result="completed",
                target=str(target),
                plan_id=plan_id,
                action_id=action_id,
                detail={"quarantine_id": quarantine_id, "bytes": destination.stat().st_size},
            )
            affected.append(
                {
                    "target": str(target),
                    "quarantine_id": quarantine_id,
                    "bytes": destination.stat().st_size,
                    "sha256": digest,
                    "audit_id": audit_id,
                }
            )
        except EngineError as error:
            failed.append({"target": str(target), "code": error.code, "message": error.message, "details": error.details})
            db.record_audit(
                connection,
                operation="cleanup.quarantine",
                result="failed",
                target=str(target),
                plan_id=plan_id,
                action_id=action_id,
                detail={"code": error.code, "message": error.message},
            )
        except OSError as error:
            failed.append({"target": str(target), "code": "E_IO", "message": str(error)})
            db.record_audit(
                connection,
                operation="cleanup.quarantine",
                result="failed",
                target=str(target),
                plan_id=plan_id,
                action_id=action_id,
                detail={"code": "E_IO", "message": str(error)},
            )

    status = "completed" if not failed else ("partial" if affected else "failed")
    with db.transaction(connection):
        connection.execute("UPDATE action_plans SET status = ? WHERE plan_id = ?", (status, plan_id))

    verification = {
        "verified": not failed,
        "checked": len(affected) + len(failed),
        "details": (
            [f"moved {len(affected)} item(s) to quarantine"] if not failed else [f"{len(failed)} item(s) failed"]
        ),
    }
    audit_id = db.record_audit(
        connection,
        operation="cleanup.execute",
        result=status,
        plan_id=plan_id,
        action_id=action_id,
        detail={"affected": len(affected), "failed": len(failed)},
    )
    return {
        "action_id": action_id,
        "plan_id": plan_id,
        "success": not failed,
        "status": status,
        "affected_items": affected,
        "failed_items": failed,
        "verification": verification,
        "audit_id": audit_id,
        "executed_at": db.utc_now(),
    }


def restore_quarantined_item(connection, quarantine_id: str) -> dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM quarantine_records WHERE quarantine_id = ?", (quarantine_id,)
    ).fetchone()
    if row is None:
        raise EngineError("E_NOT_FOUND", f"unknown quarantine record: {quarantine_id}")
    if row["status"] != "quarantined":
        raise EngineError(E_INVALID_STATE, f"record state is {row['status']}, not quarantined")

    source = Path(row["quarantine_path"])
    target = Path(row["original_path"])
    if not source.is_file():
        raise EngineError("E_NOT_FOUND", "the quarantined copy is missing")
    if target.exists():
        raise EngineError(E_TARGET_EXISTS, f"the original path already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(target))

    info = target.stat()
    verified = int(info.st_size) == int(row["size_bytes"]) and _sha256(target) == row["sha256"]
    with db.transaction(connection):
        connection.execute(
            "UPDATE quarantine_records SET status = 'restored', restored_at = ? WHERE quarantine_id = ?",
            (db.utc_now(), quarantine_id),
        )
    audit_id = db.record_audit(
        connection,
        operation="quarantine.restore",
        result="completed" if verified else "verify-failed",
        target=str(target),
        plan_id=row["plan_id"],
        detail={"quarantine_id": quarantine_id, "verified": verified},
    )
    return {
        "quarantine_id": quarantine_id,
        "restored_to": str(target),
        "verified": verified,
        "audit_id": audit_id,
    }


def list_quarantine(connection, limit: int = 100) -> dict[str, Any]:
    rows = connection.execute(
        "SELECT * FROM quarantine_records ORDER BY quarantined_at DESC LIMIT ?", (limit,)
    ).fetchall()
    retention = config.QUARANTINE_RETENTION_DAYS
    now = datetime.now(timezone.utc)
    items: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            changed = datetime.fromisoformat(str(item["quarantined_at"]).replace("Z", "+00:00"))
            expires = changed + timedelta(days=retention)
            item["expires_at"] = expires.isoformat(timespec="seconds").replace("+00:00", "Z")
            item["expired"] = expires <= now
        except (ValueError, TypeError):
            item["expires_at"] = None
            item["expired"] = False
        items.append(item)
    return {
        "items": items,
        "total": len(items),
        "quarantine_directory": str(config.quarantine_dir()),
        "usage": {"bytes": _quarantine_usage(connection), "limit_bytes": config.QUARANTINE_MAX_BYTES},
        "retention_days": retention,
    }


def purge_quarantine(
    connection,
    *,
    quarantine_ids: list[str] | None = None,
    older_than_days: int | None = None,
    purge_all: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Permanently delete quarantined copies. Irreversible by design.

    Only rows still `quarantined`, only files inside the quarantine directory, and
    only after the recorded SHA-256 matches. Everything is audited.
    """
    conditions = ["status = 'quarantined'"]
    parameters: list[Any] = []
    if quarantine_ids:
        placeholders = ",".join("?" for _ in quarantine_ids)
        conditions.append(f"quarantine_id IN ({placeholders})")
        parameters.extend(quarantine_ids)
    if older_than_days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        conditions.append("quarantined_at <= ?")
        parameters.append(cutoff.isoformat(timespec="seconds").replace("+00:00", "Z"))
    if not quarantine_ids and older_than_days is None and not purge_all:
        raise EngineError(E_INVALID_PARAMS, "pass quarantine_ids, older_than_days, or all=true")

    rows = connection.execute(
        f"SELECT * FROM quarantine_records WHERE {' AND '.join(conditions)} ORDER BY quarantined_at",
        parameters,
    ).fetchall()
    total_bytes = sum(int(row["size_bytes"]) for row in rows)

    if dry_run:
        return {
            "dry_run": True,
            "count": len(rows),
            "bytes": total_bytes,
            "items": [
                {
                    "quarantine_id": row["quarantine_id"],
                    "original_path": row["original_path"],
                    "bytes": int(row["size_bytes"]),
                    "quarantined_at": row["quarantined_at"],
                }
                for row in rows[:200]
            ],
        }

    quarantine_root = config.quarantine_dir().resolve()
    purged: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    freed = 0
    for row in rows:
        path = Path(row["quarantine_path"])
        try:
            resolved = path.resolve()
            if not str(resolved).casefold().startswith(str(quarantine_root).casefold()):
                raise EngineError(E_INVALID_PARAMS, "record path is outside the quarantine directory")
            if not resolved.is_file():
                raise EngineError("E_NOT_FOUND", "the quarantined copy is already missing")
            if _sha256(resolved) != row["sha256"]:
                raise EngineError("E_VERIFY_FAILED", "content changed since quarantine; refusing to delete")
            resolved.unlink()
            parent = resolved.parent
            try:
                if parent != quarantine_root and not any(parent.iterdir()):
                    parent.rmdir()
            except OSError:
                pass
            with db.transaction(connection):
                connection.execute(
                    "UPDATE quarantine_records SET status = 'purged', purged_at = ? WHERE quarantine_id = ?",
                    (db.utc_now(), row["quarantine_id"]),
                )
            db.record_audit(
                connection,
                operation="quarantine.purge",
                result="completed",
                target=row["original_path"],
                plan_id=row["plan_id"],
                detail={"quarantine_id": row["quarantine_id"], "bytes": int(row["size_bytes"])},
            )
            purged.append({"quarantine_id": row["quarantine_id"], "bytes": int(row["size_bytes"])})
            freed += int(row["size_bytes"])
        except EngineError as error:
            failed.append({"quarantine_id": row["quarantine_id"], "code": error.code, "message": error.message})
            db.record_audit(
                connection,
                operation="quarantine.purge",
                result="failed",
                target=row["original_path"],
                plan_id=row["plan_id"],
                detail={"quarantine_id": row["quarantine_id"], "code": error.code},
            )
        except OSError as error:
            failed.append({"quarantine_id": row["quarantine_id"], "code": "E_IO", "message": str(error)})

    status = "completed" if not failed else ("partial" if purged else "failed")
    audit_id = db.record_audit(
        connection,
        operation="quarantine.purge_all",
        result=status,
        detail={"purged": len(purged), "failed": len(failed), "bytes": freed},
    )
    return {
        "dry_run": False,
        "status": status,
        "purged": len(purged),
        "failed": failed,
        "bytes_freed": freed,
        "audit_id": audit_id,
    }


def get_audit_log(connection, limit: int = 100) -> dict[str, Any]:
    rows = connection.execute("SELECT * FROM action_logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return {"entries": [dict(row) for row in rows], "total": len(rows)}


__all__ = [
    "E_TARGET_CHANGED",
    "execute_cleanup_plan",
    "get_audit_log",
    "list_quarantine",
    "restore_quarantined_item",
]
